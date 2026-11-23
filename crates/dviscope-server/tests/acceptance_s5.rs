//! Acceptance at the app+DB layer. Invented records only.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use serde_json::json;
use time::OffsetDateTime;

/// The pipeline digest a facts row recorded for an attempt revision.
async fn recorded_pipeline(t: &TestDb, attempt_ref: &str, rev: i32) -> String {
    sqlx::query_scalar(
        "SELECT f.pipeline_digest FROM attempt_facts f
           JOIN attempts a ON a.project_id = f.project_id AND a.id = f.attempt_id
          WHERE a.attempt_ref = $1 AND f.report_revision = $2",
    )
    .bind(attempt_ref)
    .bind(rev)
    .fetch_one(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"))
}

/// A12 (B.9.5): an unknown digest is ineligible with a visible blocker; a delayed delivery
/// across an activation keeps pipeline A; a correction keeps its attempt's generation (a
/// correction under another pipeline is refused, never relabelled); a new attempt uses the
/// new pipeline.
#[tokio::test]
async fn a12_pipelines_and_generations() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let pass = passing();
    let pipeline_a = pass.pipeline_digest.as_str().to_string();
    let pipeline_b = format!("sha256:{}", "b".repeat(64));
    accept_pipeline(&t.pool, &pass).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    let with_pipeline = |s: &str, a: &str, seq: u32, rev: u32, pipeline: &str| {
        let mut r = report("r1", s, a, seq, rev, &pass, &[]);
        r["evidence"]["pipeline_digest"] = json!(pipeline);
        r
    };

    // s1: evidence from pipeline B, not yet accepted: ineligible, with a blocker.
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &with_pipeline("s1", "a1", 1, 1, &pipeline_b)).await);
    let now = OffsetDateTime::now_utc();
    let v = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let s1 = v["blockers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .find(|b| b["slot"] == "s1")
        .unwrap_or_else(|| panic!("a blocker for s1: {v}"));
    assert_eq!(s1["kind"]["kind"], "insufficient_evidence", "{v}");
    assert_eq!(s1["exceptable"], false);

    // Activation of B (A stays accepted). s2's run was extracted and spooled under A
    // before the activation and is delivered after it: it stays A, and is eligible.
    dviscope_server::admin::set_pipeline(&t.pool, "p1", &pipeline_b, "accepted")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    ok(ingest(&app, &c, &started("r1", "s2", "a2", 1, &[])).await);
    ok(ingest(&app, &c, &with_pipeline("s2", "a2", 1, 1, &pipeline_a)).await);
    assert_eq!(recorded_pipeline(&t, "a2", 1).await, pipeline_a);

    // A correction keeps the attempt's generation: under B it is refused; under A it is
    // accepted.
    let relabel = ingest(&app, &c, &with_pipeline("s2", "a2", 1, 2, &pipeline_b)).await;
    assert!(
        matches!(&relabel, Err(e) if e.code == ErrorCode::NotSupported),
        "{relabel:?}"
    );
    ok(ingest(&app, &c, &with_pipeline("s2", "a2", 1, 2, &pipeline_a)).await);
    assert_eq!(recorded_pipeline(&t, "a2", 2).await, pipeline_a);

    // A new attempt uses the new pipeline.
    ok(ingest(&app, &c, &started("r1", "s2", "a3", 2, &[])).await);
    ok(ingest(&app, &c, &with_pipeline("s2", "a3", 2, 1, &pipeline_b)).await);
    assert_eq!(recorded_pipeline(&t, "a3", 1).await, pipeline_b);

    // With both accepted, every slot is eligible and passes.
    finish(&app, &c, "r1").await;
    let v = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["verdict"], "pass", "{v}");
    t.drop().await;
}

mod a18 {
    use super::*;
    use dviscope_core::rule_check::{self, Expectation, SAMPLE_FORMAT, SampleCase, SampleManifest};
    use dviscope_model::canonical::Digest;
    use dviscope_server::app::App;
    use dviscope_server::app::rules::{PackText, PipelineDefinition};
    use dviscope_server::auth::{Actor, Role};

    const LOG: &str = "ERROR: serious\n";

    fn pack(name: &str, diag: &str) -> PackText {
        PackText {
            name: format!("{name}.yaml"),
            text: format!(
                "format: dviscope.rules/1.0\npack: {name}\nversion: 1.0.0\ntier: project\nrules:\n  - {{id: q, version: 1.0.0, kind: suppression, owner: o, reason: r, action: not_an_error,\n     diag_ids: ['{diag}']}}\n"
            ),
        }
    }

    fn definition(packs: Vec<PackText>) -> PipelineDefinition {
        PipelineDefinition {
            packs,
            ..PipelineDefinition::shipped()
        }
    }

    fn manifest() -> SampleManifest {
        let x: Expectation = serde_json::from_value(json!({
            "format": "dviscope.expect/1", "simulator": "vcs",
            "failures": {"display:error": 1}, "must_survive": ["display:error"],
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        SampleManifest {
            format: SAMPLE_FORMAT.into(),
            cases: vec![SampleCase {
                case: "serious".into(),
                log_sha256: Digest::of_bytes(LOG.as_bytes())
                    .as_str()
                    .trim_start_matches("sha256:")
                    .into(),
                bytes: LOG.len() as u64,
                expect: x,
            }],
        }
    }

    /// The client's check (the same core code the server runs).
    fn client_check(old: &PipelineDefinition, new: &PipelineDefinition) -> rule_check::Structural {
        let (o, n) = (
            old.compile().unwrap_or_else(|e| panic!("{e:?}")),
            new.compile().unwrap_or_else(|e| panic!("{e:?}")),
        );
        rule_check::check(&o, &n, &manifest(), &[LOG.as_bytes()]).unwrap_or_else(|e| panic!("{e}"))
    }

    async fn upload(app: &App, admin: &Actor) {
        let m = manifest();
        let sha = m.cases[0].log_sha256.clone();
        let size = LOG.len() as i64;
        let (a, b) = LOG.as_bytes().split_at(5);
        let st = app
            .sample_chunk(admin, "p1", &sha, size, 0, a)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(st["received"], 5);
        // A wrong offset is refused, naming where to resume.
        let wrong = app.sample_chunk(admin, "p1", &sha, size, 3, b).await;
        assert!(
            matches!(&wrong, Err(e) if e.field.as_deref() == Some("offset")),
            "{wrong:?}"
        );
        let resume = app
            .sample_file(admin, "p1", &sha)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(resume["received"], 5);
        let done = app
            .sample_chunk(admin, "p1", &sha, size, 5, b)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(done["complete"], true, "{done}");
        app.register_sample(admin, "p1", &m)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
    }

    /// A18 (B.9.4): missing sample blocks; a lost must-survive failure blocks; a stale
    /// or different check is rejected; local and server checks are identical; a passing
    /// activation accepts the new pipeline.
    #[tokio::test]
    async fn a18_rule_activation() {
        let Some(t) = TestDb::new().await else { return };
        let app = t.app();
        let pid = project(&t.pool).await;
        let uid = dviscope_server::admin::create_user(&t.pool, "ada", "correct horse battery")
            .await
            .unwrap_or_else(|e| panic!("{e:#}"))["id"]
            .as_i64()
            .unwrap_or(0);
        let admin = Actor::User {
            user_id: uid,
            token_id: None,
            roles: vec![(pid, Role::Admin)],
        };
        let shipped = PipelineDefinition::shipped();
        let quiet = definition(vec![pack("quiet", "display:error")]);
        let harmless = definition(vec![pack("harmless", "proj:never")]);

        // Missing sample: activation blocked.
        let none = app
            .activate_rules(&admin, "p1", &harmless, &client_check(&shipped, &harmless))
            .await;
        assert!(
            matches!(&none, Err(e) if e.field.as_deref() == Some("sample")),
            "{none:?}"
        );
        // A viewer cannot upload.
        let v = app.sample_file(&viewer(pid), "p1", &"0".repeat(64)).await;
        assert!(matches!(v, Err(e) if e.code == ErrorCode::Forbidden));
        // A file that does not match its digest is discarded.
        let bad = app
            .sample_chunk(&admin, "p1", &"0".repeat(64), 3, 0, b"abc")
            .await;
        assert!(
            matches!(&bad, Err(e) if e.code == ErrorCode::Unprocessable),
            "{bad:?}"
        );
        upload(&app, &admin).await;

        // A lost must-survive failure blocks (the client sees it too).
        let lost = client_check(&shipped, &quiet);
        assert!(!lost.pass);
        assert_eq!(lost.cases[0].lost_must_survive, ["display:error"]);
        let r = app.activate_rules(&admin, "p1", &quiet, &lost).await;
        assert!(
            matches!(&r, Err(e) if e.code == ErrorCode::Unprocessable),
            "{r:?}"
        );

        // A check that differs from the server's (here: claimed passing) is rejected.
        let mut forged = lost.clone();
        forged.pass = true;
        forged.cases[0].ok = true;
        forged.cases[0].lost_must_survive.clear();
        let r = app.activate_rules(&admin, "p1", &quiet, &forged).await;
        assert!(
            matches!(&r, Err(e) if e.code == ErrorCode::Unprocessable && e.message.contains("differs")),
            "{r:?}"
        );

        // A passing check activates; the server's stored result equals the client's.
        let good = client_check(&shipped, &harmless);
        assert!(good.pass, "{good:?}");
        let out = app
            .activate_rules(&admin, "p1", &harmless, &good)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(out["new_pipeline"], good.new_pipeline.as_str());
        let stored: serde_json::Value =
            sqlx::query_scalar("SELECT result FROM activations WHERE project_id = $1")
                .bind(pid)
                .fetch_one(&t.pool)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(stored, serde_json::to_value(&good).unwrap_or_default());
        let state: String =
            sqlx::query_scalar("SELECT state FROM pipelines WHERE project_id = $1 AND digest = $2")
                .bind(pid)
                .bind(good.new_pipeline.as_str())
                .fetch_one(&t.pool)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(state, "accepted");
        let status = app
            .rules_status(&viewer(pid), "p1")
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            status["active_pipeline"],
            good.new_pipeline.as_str(),
            "{status}"
        );
        assert_eq!(status["activations"].as_array().map_or(0, Vec::len), 1);

        // Stale: the same check again (its old pipeline is no longer the active one).
        let r = app.activate_rules(&admin, "p1", &harmless, &good).await;
        assert!(
            matches!(&r, Err(e) if e.code == ErrorCode::StaleRevision),
            "{r:?}"
        );
        // A fresh check against the active pipeline is accepted.
        let next = definition(vec![
            pack("harmless", "proj:never"),
            pack("more", "proj:other"),
        ]);
        let fresh = client_check(&harmless, &next);
        app.activate_rules(&admin, "p1", &next, &fresh)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        t.drop().await;
    }
}

mod ledger {
    use super::*;
    use dviscope_server::app::decisions::{ExceptionRequest, TriageEdit};
    use dviscope_server::auth::{Actor, Role};
    use std::collections::BTreeMap;

    async fn user(t: &TestDb, name: &str, roles: Vec<(i64, Role)>) -> Actor {
        let id = dviscope_server::admin::create_user(&t.pool, name, "correct horse battery")
            .await
            .unwrap_or_else(|e| panic!("{e:#}"))["id"]
            .as_i64()
            .unwrap_or(0);
        Actor::User {
            user_id: id,
            token_id: None,
            roles,
        }
    }

    /// B.10 ledger: export (admins) and import by fingerprint into another project: what
    /// the importer may do applies (triage for a triager; exceptions for an admin),
    /// existing decisions are kept, unmatched and expired records are listed, a mapping
    /// file rescues a changed fingerprint, attribution names the original author.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn ledger_export_and_import() {
        let Some(t) = TestDb::new().await else { return };
        let app = t.app();
        let p1 = project(&t.pool).await;
        let (c1, _) = collector(&t.pool).await;
        accept_pipeline(&t.pool, &passing()).await;
        // p2, with the same pipeline and a collector of its own.
        dviscope_server::admin::create_project(&t.pool, "p2", "strict")
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        dviscope_server::admin::create_producer(&t.pool, "p2", "pilot")
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        dviscope_server::admin::set_pipeline(
            &t.pool,
            "p2",
            passing().pipeline_digest.as_str(),
            "accepted",
        )
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
        let p2: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'p2'")
            .fetch_one(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let scopes: Vec<String> = dviscope_server::auth::SCOPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let tok = dviscope_server::admin::issue_token(&t.pool, "p2", "pilot", &scopes, 1, "t")
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        let c2 =
            dviscope_server::auth::actor_from_token(&t.pool, tok["token"].as_str().unwrap_or(""))
                .await
                .unwrap_or_else(|e| panic!("{e:?}"));
        // The same failure in both projects (same fingerprint).
        for c in [&c1, &c2] {
            sealed(&app, c, "r1", &[slot("s1")]).await;
            ok(ingest(&app, c, &started("r1", "s1", "a1", 1, &[])).await);
            ok(ingest(&app, c, &report("r1", "s1", "a1", 1, 1, &failing(), &[])).await);
        }
        let ada = user(&t, "ada", vec![(p1, Role::Admin), (p2, Role::Admin)]).await;
        let tim = user(&t, "tim", vec![(p2, Role::Triager)]).await;
        let sig: i64 = sqlx::query_scalar("SELECT number FROM signatures WHERE project_id = $1")
            .bind(p1)
            .fetch_one(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let now = OffsetDateTime::now_utc();
        app.set_triage(
            &ada,
            "p1",
            sig,
            "rtl/main",
            None,
            &TriageEdit {
                state: "open".into(),
                owner: Some("ana".into()),
                notes: "seen before".into(),
                bug_urls: vec!["https://bugs.example/1".into()],
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
        let in_days = |d: i64| {
            (now + time::Duration::days(d))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        };
        app.create_exception(
            &ada,
            "p1",
            &ExceptionRequest {
                signature: sig,
                branch: "rtl/main".into(),
                suite: "nightly".into(),
                reason: "known".into(),
                expires_at: in_days(10),
            },
            None,
            now,
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));

        // Export: admins only.
        let denied = app.export_ledger(&viewer(p1), "p1", now).await;
        assert!(matches!(denied, Err(e) if e.code == ErrorCode::Forbidden));
        let mut l = app
            .export_ledger(&ada, "p1", now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!((l.triage.len(), l.exceptions.len()), (1, 1), "{l:?}");
        assert_eq!(l.triage[0].author, "ada");
        let fp = l.triage[0].fingerprint.clone();
        // An unmatched record, and an expired exception.
        let mut stray = l.triage[0].clone();
        stray.fingerprint = format!("sha256:{}", "0".repeat(64));
        stray.branch = "rtl/dev".into();
        l.triage.push(stray.clone());
        // An invalid record (r1 finding 9: the dry run validates as the import does).
        let mut weird = l.triage[0].clone();
        weird.branch = "rtl/weird".into();
        weird.state = "maybe".into();
        l.triage.push(weird);
        let mut old = l.exceptions[0].clone();
        old.suite = "weekly".into();
        old.expires_at = in_days(-1);
        l.exceptions.push(old);
        let none = BTreeMap::new();

        // A triager: triage applies; exceptions are not theirs to make.
        let r = app
            .import_ledger(&tim, "p2", &l, &none, false, now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        let outcome = |r: &serde_json::Value, kind: &str, branch: &str, suite: Option<&str>| {
            r["records"]
                .as_array()
                .and_then(|a| {
                    a.iter().find(|x| {
                        x["kind"] == kind
                            && x["branch"] == branch
                            && suite.is_none_or(|s| x["suite"] == s)
                    })
                })
                .map(|x| x["outcome"].as_str().unwrap_or("").to_string())
                .unwrap_or_default()
        };
        assert_eq!(outcome(&r, "triage", "rtl/main", None), "applied", "{r}");
        assert_eq!(outcome(&r, "triage", "rtl/dev", None), "unmatched");
        assert_eq!(
            outcome(&r, "exception", "rtl/main", Some("nightly")),
            "not_permitted"
        );
        // Attribution: the importer acted; the original author is recorded.
        // In the decision's own history entry (same transaction: r1 finding 8).
        let detail: serde_json::Value = sqlx::query_scalar(
            "SELECT detail FROM history WHERE project_id = $1 AND action = 'triage.revise'",
        )
        .bind(p2)
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(detail["imported"]["original_author"], "ada", "{detail}");
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT r.owner FROM triage_revisions r JOIN triage_cases c
               ON c.project_id = r.project_id AND c.id = r.case_id AND c.revision = r.revision
              WHERE c.project_id = $1",
        )
        .bind(p2)
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(owner.as_deref(), Some("ana"));

        // An admin's dry run: the exception would apply, the triage exists; nothing written.
        let r = app
            .import_ledger(&ada, "p2", &l, &none, true, now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            outcome(&r, "exception", "rtl/main", Some("nightly")),
            "would_apply",
            "{r}"
        );
        assert_eq!(outcome(&r, "triage", "rtl/main", None), "exists");
        assert!(
            outcome(&r, "triage", "rtl/weird", None).starts_with("invalid: state"),
            "{r}"
        );
        assert_eq!(
            outcome(&r, "exception", "rtl/main", Some("weekly")),
            "expired"
        );
        let live: i64 = sqlx::query_scalar("SELECT count(*) FROM exceptions WHERE project_id = $1")
            .bind(p2)
            .fetch_one(&t.pool)
            .await
            .unwrap_or(-1);
        assert_eq!(live, 0, "a dry run writes nothing");
        // The admin's import applies the exception; a mapping rescues the stray record.
        let map: BTreeMap<String, String> = [(stray.fingerprint.clone(), fp)].into();
        let r = app
            .import_ledger(&ada, "p2", &l, &map, false, now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            outcome(&r, "exception", "rtl/main", Some("nightly")),
            "applied",
            "{r}"
        );
        assert_eq!(outcome(&r, "triage", "rtl/dev", None), "applied");
        // Revoked locally, then the same ledger again: the revocation stands (r2 finding 3).
        let id: i64 = sqlx::query_scalar(
            "SELECT id FROM exceptions WHERE project_id = $1 AND revoked_at IS NULL",
        )
        .bind(p2)
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        app.revoke_exception(&ada, "p2", id)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        let r = app
            .import_ledger(&ada, "p2", &l, &map, false, now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            outcome(&r, "exception", "rtl/main", Some("nightly")),
            "exists",
            "{r}"
        );
        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM exceptions WHERE project_id = $1 AND revoked_at IS NULL",
        )
        .bind(p2)
        .fetch_one(&t.pool)
        .await
        .unwrap_or(-1);
        assert_eq!(live, 0);
        // The write itself re-checks under the scope lock (r3 finding 1: a revocation
        // between the import's check and its write).
        let raced = app
            .create_exception_attributed(
                &ada,
                "p2",
                &ExceptionRequest {
                    signature: sqlx::query_scalar(
                        "SELECT number FROM signatures WHERE project_id = $1",
                    )
                    .bind(p2)
                    .fetch_one(&t.pool)
                    .await
                    .unwrap_or_else(|e| panic!("{e}")),
                    branch: "rtl/main".into(),
                    suite: "nightly".into(),
                    reason: "imported".into(),
                    expires_at: in_days(5),
                },
                None,
                now,
                Some(&json!({"original_author": "ada"})),
            )
            .await;
        assert!(
            matches!(&raced, Err(e) if e.code == ErrorCode::StaleRevision),
            "{raced:?}"
        );
        t.drop().await;
    }
}

/// A24 (B.18): the assurance profile follows what each producer sends. A producer with
/// sealed manifests but no build attempts and no source identity (its source manifest names
/// no repository) shows: counting available; build provenance missing; merge gating
/// unavailable. A producer that sends builds and sources shows them available.
#[tokio::test]
async fn a24_assurance_profile() {
    use dviscope_server::auth::{Actor, Role};
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (pilot, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    // "bare": sealed manifests only.
    dviscope_server::admin::create_producer(&t.pool, "p1", "bare")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let tok = dviscope_server::admin::issue_token(&t.pool, "p1", "bare", &scopes, 1, "t")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let bare =
        dviscope_server::auth::actor_from_token(&t.pool, tok["token"].as_str().unwrap_or(""))
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
    let mut sm = source_manifest();
    sm["producer_id"] = json!("bare");
    sm["repositories"] = json!([]);
    ok(app.create_source_manifest(&bare, &sm).await);
    let mut reg = regression("b1");
    reg["producer_id"] = json!("bare");
    ok(app.create_regression(&bare, &reg).await);
    let decls = [slot("s1")];
    ok(app.manifest_chunk(&bare, "b1", 1, &chunk(&decls)).await);
    ok(app.manifest_seal(&bare, "b1", &seal(&decls)).await);
    // "pilot": sources and a build.
    sealed(&app, &pilot, "r1", &[built_slot("s1")]).await;
    ok(ingest(&app, &pilot, &build_started("b1")).await);
    let admin = Actor::User {
        user_id: 1,
        token_id: None,
        roles: vec![(pid, Role::Admin)],
    };
    let o = app
        .admin_overview(&admin, "p1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let profile = |name: &str| {
        o["producers"]
            .as_array()
            .and_then(|a| a.iter().find(|p| p["name"] == name))
            .map(|p| p["assurance"].clone())
            .unwrap_or_else(|| panic!("no producer {name}: {o}"))
    };
    assert_eq!(
        profile("bare"),
        json!([
            "Counting available (sealed expected sets)",
            "Build provenance missing (no build attempts)",
            "Merge gating unavailable (no source manifests)",
        ]),
        "{o}"
    );
    assert_eq!(
        profile("pilot"),
        json!([
            "Counting available (sealed expected sets)",
            "Build provenance available (build attempts)",
            "Merge gating available (source manifests)",
        ]),
        "{o}"
    );
    t.drop().await;
}

/// A build correction keeps its generation, as a simulation one.
#[tokio::test]
async fn a12_build_corrections_keep_their_generation() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let _pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let other = format!("sha256:{}", "c".repeat(64));
    dviscope_server::admin::set_pipeline(&t.pool, "p1", &other, "accepted")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    sealed(&app, &c, "r1", &[built_slot("s1")]).await;
    ok(ingest(&app, &c, &build_started("b1")).await);
    ok(ingest(&app, &c, &build_report("b1", "fail")).await);
    let mut relabel = build_report("b1", "pass");
    relabel["report_revision"] = json!(2);
    relabel["evidence"]["pipeline_digest"] = json!(other);
    let r = ingest(&app, &c, &relabel).await;
    assert!(
        matches!(&r, Err(e) if e.code == ErrorCode::NotSupported),
        "{r:?}"
    );
    let mut same = build_report("b1", "pass");
    same["report_revision"] = json!(2);
    ok(ingest(&app, &c, &same).await);
    t.drop().await;
}
