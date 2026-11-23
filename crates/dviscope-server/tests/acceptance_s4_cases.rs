//! Acceptance cases at the app+DB layer: A02 (retries and inputs), A06c (snapshot
//! digest), A17 (comparison: branch isolation, distinct counts, corrections, default
//! baseline), A22 (quarantined expected-set removal). Invented records only.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_server::app::App;
use dviscope_server::auth::Actor;
use serde_json::{Value, json};
use time::OffsetDateTime;

fn reg_on(r: &str, repo: &str, started: &str) -> Value {
    let mut v = regression(r);
    v["branch"] = json!({"repository": repo, "name": "main"});
    v["started_at"] = json!(started);
    v
}

async fn sealed_on(app: &App, c: &Actor, r: &str, repo: &str, started: &str, slots: &[Value]) {
    let _ = app.create_source_manifest(c, &source_manifest()).await;
    ok(app.create_regression(c, &reg_on(r, repo, started)).await);
    ok(app.manifest_chunk(c, r, 1, &chunk(slots)).await);
    ok(app.manifest_seal(c, r, &seal(slots)).await);
}

/// A02 (server part): another seed is refused naming the field; a report from another
/// source is stored but not eligible (B.7.2), so it never passes the slot.
#[tokio::test]
async fn a02_retry_inputs_and_sources() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let mut other_seed = report("r1", "s1", "a1", 1, 1, &passing(), &[]);
    other_seed["execution"]["seed"] = json!("7");
    let e = ingest(&app, &c, &other_seed).await.err();
    assert!(
        matches!(&e, Some(e) if e.code == ErrorCode::RetryInputsDiffer && e.field.as_deref() == Some("execution")),
        "{e:?}"
    );
    // Another source manifest: accepted, ineligible, the slot stays missing.
    let mut sm2 = source_manifest();
    sm2["source_manifest_ref"] = json!("sm2");
    sm2["repositories"][0]["revision"] = json!("def456");
    ok(app.create_source_manifest(&c, &sm2).await);
    let mut other_src = report("r1", "s1", "a1", 1, 1, &passing(), &[]);
    other_src["source_manifest_ref"] = json!("sm2");
    ok(ingest(&app, &c, &other_src).await);
    let r = read(&app, pid, "r1").await;
    assert_eq!(state(&r, "s1")["state"], "missing", "{:?}", r.slots);
    let rl = app
        .repair_list(&viewer(pid), "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        rl["groups"][0]["slots"][0]["reason"],
        "Report received; not eligible: source"
    );
    t.drop().await;
}

/// A06c: the same snapshot evaluated at the same instant yields the same digest.
#[tokio::test]
async fn a06c_same_snapshot_same_digest() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &failing(), &[])).await);
    finish(&app, &c, "r1").await;
    let now = OffsetDateTime::now_utc();
    let eval = || async {
        app.read_readiness(&viewer(pid), "p1", "r1", None, None, now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"))
    };
    let (a, b) = (eval().await, eval().await);
    assert_eq!(a["digest"], b["digest"]);
    assert_eq!(a, b);
    let later = app
        .read_readiness(
            &viewer(pid),
            "p1",
            "r1",
            None,
            None,
            now + time::Duration::seconds(1),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(
        later["digest"], a["digest"],
        "the evaluation time is an input"
    );
    t.drop().await;
}

/// A17: the default baseline is the most recent earlier finished regression of the same
/// suite on the same repository-qualified branch (another repository's `main` is never
/// used); counts are distinct slots whatever the number of attempts; a correction replaces
/// the old classification.
#[tokio::test]
async fn a17_comparison() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    let v = viewer(pid);
    // rtl/main yesterday: s1 failed with the signature.
    sealed_on(
        &app,
        &c,
        "old",
        "rtl",
        "2026-11-06T01:00:00Z",
        &[slot("s1")],
    )
    .await;
    ok(ingest(&app, &c, &started("old", "s1", "o1", 1, &[])).await);
    ok(ingest(&app, &c, &report("old", "s1", "o1", 1, 1, &fail, &[])).await);
    finish(&app, &c, "old").await;
    // dv/main (another repository, same branch name), more recent: s1 passed.
    sealed_on(
        &app,
        &c,
        "dvmain",
        "dv",
        "2026-11-07T01:00:00Z",
        &[slot("s1")],
    )
    .await;
    ok(ingest(&app, &c, &started("dvmain", "s1", "d1", 1, &[])).await);
    ok(ingest(&app, &c, &report("dvmain", "s1", "d1", 1, 1, &pass, &[])).await);
    finish(&app, &c, "dvmain").await;
    // rtl/main today: s1 fails twice (two attempts), s2 fails once.
    sealed_on(
        &app,
        &c,
        "cur",
        "rtl",
        "2026-11-08T01:00:00Z",
        &[slot("s1"), slot("s2")],
    )
    .await;
    for (s, a, seq) in [("s1", "c1", 1), ("s1", "c2", 2), ("s2", "c3", 1)] {
        ok(ingest(&app, &c, &started("cur", s, a, seq, &[])).await);
        ok(ingest(&app, &c, &report("cur", s, a, seq, 1, &fail, &[])).await);
    }
    finish(&app, &c, "cur").await;
    let cmp = app
        .read_comparison(&v, "p1", "cur", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(cmp.baseline["ref"], "old", "{}", cmp.baseline);
    assert!(
        cmp.baseline["reason"]
            .as_str()
            .unwrap_or("")
            .contains("rtl/main")
    );
    let row = &cmp.comparison.rows[0];
    assert_eq!(row.failed_slots, 2, "distinct slots");
    assert_eq!(row.failing_attempts, 3);
    assert_eq!(
        serde_json::to_value(row.baseline).unwrap_or_default(),
        "in_baseline"
    );
    // Explicitly none.
    let none = app
        .read_comparison(&v, "p1", "cur", Some("none"), None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(none.baseline["ref"], Value::Null);
    // The oldest regression of rtl/main has no earlier baseline.
    let first = app
        .read_comparison(&v, "p1", "old", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(first.baseline["ref"], Value::Null);
    assert!(
        first.baseline["reason"]
            .as_str()
            .unwrap_or("")
            .starts_with("none")
    );
    // A correction (revision 2 passes) replaces s2's classification: one slot left.
    ok(ingest(&app, &c, &report("cur", "s2", "c3", 1, 2, &pass, &[])).await);
    let cmp = app
        .read_comparison(&v, "p1", "cur", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(cmp.comparison.rows[0].failed_slots, 1);
    assert_eq!(cmp.comparison.header.passed, 1);
    t.drop().await;
}

/// A22: a removal by a credential quarantined since before it does not shrink the expected
/// set, and readiness is insufficient until the removal is re-made with a valid credential.
#[tokio::test]
async fn a22_quarantined_removal() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, token) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &passing(), &[])).await);
    let since = OffsetDateTime::now_utc() - time::Duration::seconds(5);
    let amend = json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2,
                       "remove": [{"slot_ref": "s2", "reason": "dropped"}]});
    ok(app.manifest_amend(&c, "r1", &amend).await);
    finish(&app, &c, "r1").await;
    let now = OffsetDateTime::now_utc() + time::Duration::seconds(1);
    let ready = |at| {
        let app = app.clone();
        async move {
            app.read_readiness(&viewer(pid), "p1", "r1", None, None, at)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"))
        }
    };
    assert_eq!(ready(now).await["verdict"], "pass");
    assert_eq!(read(&app, pid, "r1").await.header.planned, 1);
    // The removing credential is quarantined since before the removal.
    dviscope_server::admin::quarantine_token(
        &t.pool,
        token,
        &since
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:#}"));
    let r = read(&app, pid, "r1").await;
    assert_eq!(r.header.planned, 2, "the denominator does not shrink");
    assert_eq!(state(&r, "s2")["state"], "missing");
    let v = ready(now).await;
    assert_eq!(v["verdict"], "insufficient_evidence", "{v}");
    assert!(v["warnings"].to_string().contains("quarantined credential"));
    // Released: the removal counts again.
    dviscope_server::admin::release_token(&t.pool, token)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(read(&app, pid, "r1").await.header.planned, 1);
    assert_eq!(ready(now).await["verdict"], "pass");

    // Re-made before finishing: a removal by a quarantined credential is removed again
    // with a valid one.
    let (c2, token2) = collector(&t.pool).await;
    sealed(&app, &c2, "r2", &[slot("s1"), slot("s2")]).await;
    ok(ingest(&app, &c2, &started("r2", "s1", "b1", 1, &[])).await);
    ok(ingest(&app, &c2, &report("r2", "s1", "b1", 1, 1, &passing(), &[])).await);
    let since2 = OffsetDateTime::now_utc() - time::Duration::seconds(1);
    ok(app.manifest_amend(&c2, "r2", &amend).await);
    dviscope_server::admin::quarantine_token(
        &t.pool,
        token2,
        &since2
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(read(&app, pid, "r2").await.header.planned, 2);
    let (c3, _) = collector(&t.pool).await;
    let mut again = amend.clone();
    again["revision"] = json!(3);
    ok(app.manifest_amend(&c3, "r2", &again).await);
    // s1's report came from the quarantined credential too: a clean retry clears it.
    ok(ingest(&app, &c3, &started("r2", "s1", "b2", 2, &[])).await);
    ok(ingest(&app, &c3, &report("r2", "s1", "b2", 2, 1, &passing(), &[])).await);
    finish(&app, &c3, "r2").await;
    assert_eq!(read(&app, pid, "r2").await.header.planned, 1);
    let v = app
        .read_readiness(
            &viewer(pid),
            "p1",
            "r2",
            None,
            None,
            OffsetDateTime::now_utc() + time::Duration::seconds(1),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["verdict"], "pass", "{v}");
    t.drop().await;
}

/// A15 (app part): a producer-reported pass whose evidence fails is a contradiction that an
/// exception for its signature cannot cover; under retry-pass-accepted an eligible
/// fail -> pass retry passes without using an exception, and the failure stays visible.
#[tokio::test]
async fn a15_contradiction_and_accepted_retry() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let mut rep = report("r1", "s1", "a1", 1, 1, &fail, &[]);
    rep["result"]["outcome_reported"] = json!("pass");
    ok(ingest(&app, &c, &rep).await);
    finish(&app, &c, "r1").await;
    let now = OffsetDateTime::now_utc();
    let v = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["verdict"], "fail", "{v}");
    // The signature of the failing diagnostic (from the comparison).
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let sig = cmp.decisions[cmp.comparison.rows[0].signature.as_str()]
        .number
        .unwrap_or(0);
    assert!(sig > 0);
    let admin_id = dviscope_server::admin::create_user(&t.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"))["id"]
        .as_i64()
        .unwrap_or(0);
    let admin = Actor::User {
        user_id: admin_id,
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    app.create_exception(
        &admin,
        "p1",
        &dviscope_server::app::decisions::ExceptionRequest {
            signature: sig,
            branch: "rtl/main".into(),
            suite: "nightly".into(),
            reason: "known".into(),
            expires_at: (now + time::Duration::days(5))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        },
        None,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let v = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["verdict"], "fail", "{v}");
    let kinds: Vec<&str> = v["blockers"]
        .as_array()
        .map(|b| {
            b.iter()
                .filter_map(|x| x["kind"]["kind"].as_str())
                .collect()
        })
        .unwrap_or_default();
    assert!(kinds.contains(&"contradiction"), "{v}");
    assert_eq!(v["exceptions_used"], json!([]));
    // The comparison agrees: the exception does not cover the contradicted slot.
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let d = &cmp.decisions[cmp.comparison.rows[0].signature.as_str()];
    assert!(d.exception.is_some());
    assert_eq!(d.disposition, "needs_decision", "{d:?}");
    assert_eq!(cmp.finish["covered"], 0);
    assert_eq!(cmp.finish["blocking_groups"], 1);

    // retry-pass-accepted: fail then pass passes; no exception used; history kept.
    sqlx::query("UPDATE projects SET policy = 'retry-pass-accepted' WHERE id = $1")
        .bind(pid)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    sealed(&app, &c, "r2", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r2", "s1", "b1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r2", "s1", "b1", 1, 1, &fail, &[])).await);
    ok(ingest(&app, &c, &started("r2", "s1", "b2", 2, &[])).await);
    ok(ingest(&app, &c, &report("r2", "s1", "b2", 2, 1, &pass, &[])).await);
    finish(&app, &c, "r2").await;
    let r = read(&app, pid, "r2").await;
    let s = state(&r, "s1");
    assert_eq!(s["state"], "passed", "{s}");
    let row = r
        .slots
        .iter()
        .find(|x| x.slot_ref == "s1")
        .cloned()
        .unwrap_or_else(|| panic!("no s1"));
    assert_eq!(
        row.note.as_deref(),
        Some("cleared by accepted retry (retry-pass-accepted v1)")
    );
    assert_eq!(row.attempts, 2);
    let v = app
        .read_readiness(&viewer(pid), "p1", "r2", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["verdict"], "pass", "{v}");
    assert_eq!(v["exceptions_used"], json!([]));
    // The failed first attempt stays readable.
    let a1 = app
        .attempt_detail(&viewer(pid), "p1", "r2", "s1", 1, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(a1["revisions"][0]["effective"], "failed", "{a1}");
    t.drop().await;
}

/// A25 (app part, pipelines): withdrawing the pipeline that classified a failing retry,
/// also when the retry is delivered after the withdrawal, never turns the verdict into
/// pass or accepted_with_exceptions.
#[tokio::test]
async fn a25_withdrawn_pipeline_of_a_failing_retry() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    sqlx::query("UPDATE projects SET policy = 'retry-pass-accepted' WHERE id = $1")
        .bind(pid)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let (c, _) = collector(&t.pool).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    let withdraw = || async {
        dviscope_server::admin::set_pipeline(
            &t.pool,
            "p1",
            fail.pipeline_digest.as_str(),
            "withdrawn",
        )
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    };
    let now = OffsetDateTime::now_utc() + time::Duration::seconds(1);
    let green = |v: &Value| v["verdict"] == "pass" || v["verdict"] == "accepted_with_exceptions";
    // r1: pass, then a failing retry; its pipeline is withdrawn afterwards.
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &pass, &[])).await);
    ok(ingest(&app, &c, &started("r1", "s1", "a2", 2, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a2", 2, 1, &fail, &[])).await);
    finish(&app, &c, "r1").await;
    let before = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(!green(&before), "{before}");
    withdraw().await;
    let after = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(!green(&after), "{after}");
    // r2: the failing retry is delivered after the withdrawal.
    accept_pipeline(&t.pool, &pass).await;
    sealed(&app, &c, "r2", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r2", "s1", "b1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r2", "s1", "b1", 1, 1, &pass, &[])).await);
    withdraw().await;
    ok(ingest(&app, &c, &started("r2", "s1", "b2", 2, &[])).await);
    ok(ingest(&app, &c, &report("r2", "s1", "b2", 2, 1, &fail, &[])).await);
    finish(&app, &c, "r2").await;
    let v = app
        .read_readiness(&viewer(pid), "p1", "r2", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(!green(&v), "{v}");
    t.drop().await;
}

/// Slots without a build requirement that name their simulator in
/// `exec_inputs.extra.tool.simulator` are distinct configurations per simulator, with that
/// label in the candidate index (pilot finding: Questa and VCS runs of one test collapsed).
#[tokio::test]
async fn simulator_named_in_extra_separates_configurations() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let _pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let on = |s: &str, sim: &str| {
        let mut v = slot(s);
        v["exec_inputs"]["test"] = json!("t_same");
        v["exec_inputs"]["extra"] = json!({"tool": {"simulator": sim}});
        v
    };
    sealed(&app, &c, "rq", &[on("q", "questa")]).await;
    sealed(&app, &c, "rv", &[on("v", "vcs")]).await;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT simulator, config_digest FROM candidate_index WHERE test = 't_same' ORDER BY simulator",
    )
    .fetch_all(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!((rows[0].0.as_str(), rows[1].0.as_str()), ("questa", "vcs"));
    assert_ne!(rows[0].1, rows[1].1, "distinct configurations");
    t.drop().await;
}

/// R1 finding 1: a producer-reported failure with a clean log is an unexplained failure
/// that no exception can cover.
#[tokio::test]
async fn unexplained_failure_is_never_excepted() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let mut rep = report("r1", "s1", "a1", 1, 1, &passing(), &[]);
    rep["result"]["outcome_reported"] = json!("fail");
    ok(ingest(&app, &c, &rep).await);
    finish(&app, &c, "r1").await;
    let now = OffsetDateTime::now_utc();
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let sig = cmp.decisions[cmp.comparison.rows[0].signature.as_str()]
        .number
        .unwrap_or(0);
    let admin_id = dviscope_server::admin::create_user(&t.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"))["id"]
        .as_i64()
        .unwrap_or(0);
    let admin = Actor::User {
        user_id: admin_id,
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    let expires = (now + time::Duration::days(5))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // The preview already says so, and refuses an impossible expiry (R1 finding 14).
    let pv = app
        .preview_exception(
            &viewer(pid),
            "p1",
            "r1",
            None,
            dviscope_server::app::readiness::ExceptionPreview {
                signature: sig,
                expires_at: expires.clone(),
            },
            now,
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(pv["not_exceptable"], true, "{pv}");
    assert_eq!(pv["verdict_after"], "fail");
    for bad in [
        (now - time::Duration::days(1))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        (now + time::Duration::days(200))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    ] {
        let e = app
            .preview_exception(
                &viewer(pid),
                "p1",
                "r1",
                None,
                dviscope_server::app::readiness::ExceptionPreview {
                    signature: sig,
                    expires_at: bad,
                },
                now,
            )
            .await;
        assert!(
            matches!(&e, Err(e) if e.code == ErrorCode::Invalid),
            "{e:?}"
        );
    }
    app.create_exception(
        &admin,
        "p1",
        &dviscope_server::app::decisions::ExceptionRequest {
            signature: sig,
            branch: "rtl/main".into(),
            suite: "nightly".into(),
            reason: "known".into(),
            expires_at: expires,
        },
        None,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let v = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["verdict"], "fail", "{v}");
    assert_eq!(v["blockers"][0]["kind"]["kind"], "unexplained", "{v}");
    assert_eq!(v["exceptions_used"], json!([]));
    t.drop().await;
}

/// R1 finding 9: evidence and trust changes advance the project watermark and the change
/// feed (not only decisions), so a recorded evaluation goes stale.
#[tokio::test]
async fn watermark_follows_evidence_and_trust_changes() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, token) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1"), built_slot("s2")]).await;
    let v = viewer(pid);
    let seq = || async {
        app.changes_since(&viewer(pid), "p1", 0)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"))["change_seq"]
            .as_i64()
            .unwrap_or(0)
    };
    let mut last = seq().await;
    let mut check = |what: &str, now: i64| {
        assert!(
            now > last,
            "{what} did not advance the watermark ({last} -> {now})"
        );
        last = now;
    };
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    check("attempt start", seq().await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &passing(), &[])).await);
    check("report", seq().await);
    ok(ingest(&app, &c, &build_started("b1")).await);
    check("build start", seq().await);
    ok(ingest(&app, &c, &build_report("b1", "pass")).await);
    check("build report", seq().await);
    dviscope_server::admin::set_pipeline(
        &t.pool,
        "p1",
        passing().pipeline_digest.as_str(),
        "withdrawn",
    )
    .await
    .unwrap_or_else(|e| panic!("{e:#}"));
    check("pipeline withdrawal", seq().await);
    dviscope_server::admin::quarantine_token(&t.pool, token, "2026-01-01T00:00:00Z")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    check("quarantine", seq().await);
    let feed = app
        .changes_since(&v, "p1", 0)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let kinds: Vec<&str> = feed["changes"]
        .as_array()
        .map(|a| a.iter().filter_map(|c| c["kind"].as_str()).collect())
        .unwrap_or_default();
    for k in ["regression", "build", "pipeline", "quarantine"] {
        assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
    }
    t.drop().await;
}

/// R1 findings 11 and 16: an attempt is looked up within its producer (two producers may
/// share references: ambiguity is refused, never guessed); the regression list pages by
/// the full (start, id) key, so a late-delivered older regression is not skipped.
#[tokio::test]
async fn attempts_by_producer_and_paging_by_start() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    dviscope_server::admin::create_producer(&t.pool, "p1", "other")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let tok = dviscope_server::admin::issue_token(&t.pool, "p1", "other", &scopes, 1, "o")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let o = dviscope_server::auth::actor_from_token(&t.pool, tok["token"].as_str().unwrap_or(""))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    accept_pipeline(&t.pool, &passing()).await;
    let with_producer = |v: &Value, name: &str| {
        let mut v = v.clone();
        v["producer_id"] = json!(name);
        v
    };
    // "pilot": r1/s1 fails; "other": r1/s1 passes.
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &failing(), &[])).await);
    ok(app
        .create_source_manifest(&o, &with_producer(&source_manifest(), "other"))
        .await);
    ok(app
        .create_regression(&o, &with_producer(&regression("r1"), "other"))
        .await);
    ok(app.manifest_chunk(&o, "r1", 1, &chunk(&[slot("s1")])).await);
    ok(app.manifest_seal(&o, "r1", &seal(&[slot("s1")])).await);
    ok(ingest(
        &app,
        &o,
        &with_producer(&started("r1", "s1", "b1", 1, &[]), "other"),
    )
    .await);
    ok(ingest(
        &app,
        &o,
        &with_producer(&report("r1", "s1", "b1", 1, 1, &passing(), &[]), "other"),
    )
    .await);
    let v = viewer(pid);
    let e = app.attempt_detail(&v, "p1", "r1", "s1", 1, None).await;
    assert!(
        matches!(&e, Err(e) if e.code == ErrorCode::Invalid && e.field.as_deref() == Some("producer")),
        "{e:?}"
    );
    for (who, want) in [("pilot", "failed"), ("other", "passed")] {
        let a = app
            .attempt_detail(&v, "p1", "r1", "s1", 1, Some(who))
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(a["revisions"][0]["effective"], want, "{who}: {a}");
    }

    // Paging: a regression started earlier but delivered later has a larger id.
    for (r, at) in [
        ("A", "2026-11-08T03:00:00Z"),
        ("B", "2026-11-08T02:00:00Z"),
        ("C", "2026-11-07T01:00:00Z"),
    ] {
        let mut body = regression(r);
        body["started_at"] = json!(at);
        ok(app.create_regression(&c, &body).await);
    }
    let mut seen = vec![];
    let mut cursor: Option<String> = None;
    loop {
        let page = app
            .list_regressions(&v, "p1", cursor.as_deref(), Some(1))
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        for r in page["regressions"].as_array().cloned().unwrap_or_default() {
            seen.push(format!(
                "{}:{}",
                r["producer"].as_str().unwrap_or(""),
                r["ref"].as_str().unwrap_or("")
            ));
        }
        match page["next"].as_str() {
            Some(n) => cursor = Some(n.to_string()),
            None => break,
        }
    }
    let mine: Vec<&String> = seen
        .iter()
        .filter(|s| ["pilot:A", "pilot:B", "pilot:C"].contains(&s.as_str()))
        .collect();
    assert_eq!(mine, ["pilot:A", "pilot:B", "pilot:C"], "{seen:?}");
    assert_eq!(seen.len(), 5, "{seen:?}");
    // A malformed cursor is refused.
    let bad = app.list_regressions(&v, "p1", Some("nope"), None).await;
    assert!(matches!(&bad, Err(e) if e.code == ErrorCode::Invalid));
    t.drop().await;
}

/// R2 finding 6: the finish card's merge line follows readiness: an open collection, a
/// required skip and a quarantined pass all block, though no signature row exists.
#[tokio::test]
async fn finish_card_merge_line_follows_readiness() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, token) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &passing(), &[])).await);
    let card = || async {
        app.read_comparison(&viewer(pid), "p1", "r1", None, None)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"))
            .finish
    };
    // Not finished, s2 missing.
    let f = card().await;
    assert_eq!(f["merge_blocker_kinds"]["collection_open"], 1, "{f}");
    assert_eq!(f["merge_blocker_kinds"]["missing"], 1, "{f}");
    // s2 skipped (required) and finished: required_not_run.
    let mark = json!({"schema": dviscope_model::schema::MANIFEST, "slot_refs": ["s2"],
                      "state": "skipped", "reason": "no license"});
    ok(app.slot_mark(&c, "r1", &mark).await);
    finish(&app, &c, "r1").await;
    let f = card().await;
    assert_eq!(f["merge_blocker_kinds"]["required_not_run"], 1, "{f}");
    assert!(
        f["merge_blocker_kinds"].get("collection_open").is_none(),
        "{f}"
    );
    // The pass is quarantined: insufficient evidence, still no signature row.
    dviscope_server::admin::quarantine_token(&t.pool, token, "2026-01-01T00:00:00Z")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let f = card().await;
    assert_eq!(f["merge_blocker_kinds"]["insufficient_evidence"], 1, "{f}");
    assert_eq!(f["groups"], 0);
    assert_eq!(f["merge_verdict"], "insufficient_evidence");
    t.drop().await;
}

/// R2 finding 8: under strict policy every authoritative attempt needs its own build proof:
/// an earlier failure built with an unproven build keeps readiness from accepting, even when
/// a later attempt with a proven build fails the same way and an exception covers it.
#[tokio::test]
async fn every_authoritative_attempt_needs_its_build_proof() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[built_slot("s1")]).await;
    // B1 started, never reported; B2 passes.
    ok(ingest(&app, &c, &build_started("b1")).await);
    ok(ingest(&app, &c, &build_started("b2")).await);
    ok(ingest(&app, &c, &build_report("b2", "pass")).await);
    for (a, seq, b) in [("a1", 1, "b1"), ("a2", 2, "b2")] {
        ok(ingest(&app, &c, &started("r1", "s1", a, seq, &[b])).await);
        ok(ingest(&app, &c, &report("r1", "s1", a, seq, 1, &failing(), &[b])).await);
    }
    finish(&app, &c, "r1").await;
    let now = OffsetDateTime::now_utc();
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let row = cmp
        .comparison
        .rows
        .iter()
        .find(|r| r.group.is_none())
        .unwrap_or_else(|| panic!("a signature row: {:?}", cmp.comparison.rows));
    let sig = cmp.decisions[row.signature.as_str()].number.unwrap_or(0);
    let admin_id = dviscope_server::admin::create_user(&t.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"))["id"]
        .as_i64()
        .unwrap_or(0);
    let admin = Actor::User {
        user_id: admin_id,
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    app.create_exception(
        &admin,
        "p1",
        &dviscope_server::app::decisions::ExceptionRequest {
            signature: sig,
            branch: "rtl/main".into(),
            suite: "nightly".into(),
            reason: "known".into(),
            expires_at: (now + time::Duration::days(5))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        },
        None,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let v = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(v["verdict"], "accepted_with_exceptions", "{v}");
    assert_ne!(v["verdict"], "pass", "{v}");
    assert_eq!(v["exceptions_used"], json!([]), "{v}");
    t.drop().await;
}

/// R15 finding 1: under strict policy an earlier timeout stays a timeout after a later
/// functional failure: exceptions covering every signature never accept the slot.
#[tokio::test]
async fn an_earlier_timeout_is_never_excepted() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    // a1 times out after complete evidence; a2 fails functionally.
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let mut timed_out = report("r1", "s1", "a1", 1, 1, &failing(), &[]);
    timed_out["result"]["runner"]["termination"] = json!({"kind": "timeout"});
    ok(ingest(&app, &c, &timed_out).await);
    ok(ingest(&app, &c, &started("r1", "s1", "a2", 2, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a2", 2, 1, &failing(), &[])).await);
    finish(&app, &c, "r1").await;
    let now = OffsetDateTime::now_utc();
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let admin_id = dviscope_server::admin::create_user(&t.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"))["id"]
        .as_i64()
        .unwrap_or(0);
    let admin = Actor::User {
        user_id: admin_id,
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    let mut excepted = 0;
    for row in cmp.comparison.rows.iter().filter(|r| r.group.is_none()) {
        let sig = cmp.decisions[row.signature.as_str()].number.unwrap_or(0);
        app.create_exception(
            &admin,
            "p1",
            &dviscope_server::app::decisions::ExceptionRequest {
                signature: sig,
                branch: "rtl/main".into(),
                suite: "nightly".into(),
                reason: "known".into(),
                expires_at: (now + time::Duration::days(5))
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            },
            None,
            now,
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
        excepted += 1;
    }
    assert!(excepted > 0, "{:?}", cmp.comparison.rows);
    let v = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["verdict"], "fail", "{v}");
    assert_eq!(v["exceptions_used"], json!([]), "{v}");
    let blockers = v["blockers"].as_array().cloned().unwrap_or_default();
    assert!(
        blockers.iter().any(|b| b["kind"]["kind"] == "failed"
            && b["kind"]["reason"] == "timeout"
            && b["exceptable"] == false
            && b["clearing_action"] == "fix the failure (no exception can cover it)"),
        "{v}"
    );
    t.drop().await;
}

/// R16 finding 1: under retry-pass-accepted an earlier attempt blocked in elaboration keeps
/// the slot non-exceptable after a later functional failure (exceptions cover every
/// signature); a passing retry still clears it.
#[tokio::test]
async fn an_earlier_blocked_attempt_is_never_excepted() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sqlx::query("UPDATE projects SET policy = 'retry-pass-accepted' WHERE id = $1")
        .bind(pid)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    sealed(&app, &c, "r1", &[built_slot("s1")]).await;
    ok(ingest(&app, &c, &build_started("b1")).await);
    ok(ingest(&app, &c, &build_report("b1", "pass")).await);
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &["b1"])).await);
    ok(ingest(
        &app,
        &c,
        &report("r1", "s1", "a1", 1, 1, &elaboration_failure(), &["b1"]),
    )
    .await);
    ok(ingest(&app, &c, &started("r1", "s1", "a2", 2, &["b1"])).await);
    ok(ingest(
        &app,
        &c,
        &report("r1", "s1", "a2", 2, 1, &failing(), &["b1"]),
    )
    .await);
    finish(&app, &c, "r1").await;
    let now = OffsetDateTime::now_utc();
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let admin_id = dviscope_server::admin::create_user(&t.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"))["id"]
        .as_i64()
        .unwrap_or(0);
    let admin = Actor::User {
        user_id: admin_id,
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    let mut excepted = 0;
    for row in cmp.comparison.rows.iter().filter(|r| r.group.is_none()) {
        let sig = cmp.decisions[row.signature.as_str()].number.unwrap_or(0);
        app.create_exception(
            &admin,
            "p1",
            &dviscope_server::app::decisions::ExceptionRequest {
                signature: sig,
                branch: "rtl/main".into(),
                suite: "nightly".into(),
                reason: "known".into(),
                expires_at: (now + time::Duration::days(5))
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            },
            None,
            now,
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
        excepted += 1;
    }
    assert!(
        excepted >= 2,
        "both attempts' signatures: {:?}",
        cmp.comparison.rows
    );
    let v = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["verdict"], "fail", "{v}");
    assert_eq!(v["exceptions_used"], json!([]), "{v}");
    assert!(
        v["blockers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .any(|b| b["kind"]["kind"] == "blocked" && b["exceptable"] == false),
        "{v}"
    );
    // Control: a passing retry clears the slot under retry-pass-accepted.
    ok(ingest(&app, &c, &started("r1", "s1", "a3", 3, &["b1"])).await);
    let late = app
        .read_readiness(&viewer(pid), "p1", "r1", None, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(late["verdict"], "accepted_with_exceptions", "{late}");
    t.drop().await;
}

/// An attempt recovered as interrupted (termination unknown, no log, so
/// no accepted pipeline) is listed for repair as interrupted, with re-running as the action,
/// never as a pipeline decision.
#[tokio::test]
async fn an_interrupted_attempt_is_repaired_by_a_rerun() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let mut rep = report("r1", "s1", "a1", 1, 1, &passing(), &[]);
    rep["result"]["runner"]["termination"] = json!({"kind": "unknown"});
    ok(ingest(&app, &c, &rep).await);
    finish(&app, &c, "r1").await;
    let rl = app
        .repair_list(&viewer(pid), "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let s1 = &rl["groups"][0]["slots"][0];
    assert_eq!(s1["slot"], "s1", "{rl}");
    assert_eq!(
        s1["reason"], "Attempt interrupted; no result (termination unknown)",
        "{rl}"
    );
    assert!(
        s1["action"]
            .as_str()
            .unwrap_or_default()
            .starts_with("re-run the slot"),
        "{rl}"
    );
    t.drop().await;
}

/// The default baseline stays the most recent earlier finished regression of
/// the stream whatever its simulator, and the comparison names each side's simulators and
/// flags a mismatch ("new" would mix simulators).
#[tokio::test]
async fn baseline_names_its_simulators_and_flags_a_mismatch() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let v = viewer(pid);
    let on = |s: &str, sim: &str| {
        let mut x = slot(s);
        x["exec_inputs"]["extra"] = json!({"tool": {"simulator": sim}});
        x
    };
    // n0 declares no simulator.
    sealed_on(&app, &c, "n0", "rtl", "2026-11-05T01:00:00Z", &[slot("s1")]).await;
    finish(&app, &c, "n0").await;
    for (r, at, sim) in [
        ("q1", "2026-11-06T01:00:00Z", "questa"),
        ("v1", "2026-11-07T01:00:00Z", "vcs"),
        ("v2", "2026-11-08T01:00:00Z", "vcs"),
    ] {
        sealed_on(&app, &c, r, "rtl", at, &[on("s1", sim)]).await;
        finish(&app, &c, r).await;
    }
    // n3 declares no simulator again.
    sealed_on(&app, &c, "n3", "rtl", "2026-11-09T01:00:00Z", &[slot("s1")]).await;
    finish(&app, &c, "n3").await;
    let read = |r: &'static str| {
        let app = &app;
        let v = &v;
        async move {
            app.read_comparison(v, "p1", r, None, None)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"))
                .baseline
        }
    };
    // VCS after Questa: the rule is unchanged, the mismatch is flagged.
    let b = read("v1").await;
    assert_eq!(b["ref"], "q1", "{b}");
    assert_eq!(b["simulators"]["current"], json!(["vcs"]), "{b}");
    assert_eq!(b["simulators"]["baseline"], json!(["questa"]), "{b}");
    assert_eq!(b["simulators_differ"], true, "{b}");
    // VCS after VCS: no mismatch.
    let b = read("v2").await;
    assert_eq!(b["ref"], "v1", "{b}");
    assert_eq!(b["simulators_differ"], false, "{b}");
    // A baseline naming no simulator: nothing to compare, no mismatch.
    let b = read("q1").await;
    assert_eq!(b["ref"], "n0", "{b}");
    assert_eq!(b["simulators"]["current"], json!(["questa"]), "{b}");
    assert_eq!(b["simulators"]["baseline"], json!([]), "{b}");
    assert_eq!(b["simulators_differ"], false, "{b}");
    // The current side naming no simulator: no mismatch either.
    let b = read("n3").await;
    assert_eq!(b["ref"], "v2", "{b}");
    assert_eq!(b["simulators"]["baseline"], json!(["vcs"]), "{b}");
    assert_eq!(b["simulators_differ"], false, "{b}");
    // No baseline: the current side only (none named here), no mismatch.
    let b = read("n0").await;
    assert_eq!(b["ref"], Value::Null, "{b}");
    assert_eq!(b["simulators"]["current"], json!([]), "{b}");
    assert_eq!(b["simulators"]["baseline"], Value::Null, "{b}");
    assert_eq!(b["simulators_differ"], false, "{b}");
    t.drop().await;
}
