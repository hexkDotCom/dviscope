//! Acceptance: backup, safe restore and its verification.
//! Invented records only. Needs `pg_dump`/`pg_restore` on PATH (skipped without them).

mod common;

use std::path::Path;

use common::*;
use serde_json::json;
use time::OffsetDateTime;

fn tools() -> bool {
    std::process::Command::new("pg_dump")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Backup → restore into another database → safe state (maintenance on, sessions gone,
/// tokens disabled until re-enabled) → verify holds; a changed row or archive is caught.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn backup_restore_verify() {
    if !tools() {
        eprintln!("skipped: pg_dump not on PATH");
        return;
    }
    let Some(a) = TestDb::new().await else { return };
    let app = a.app();
    let _pid = project(&a.pool).await;
    let (c, _) = collector(&a.pool).await;
    accept_pipeline(&a.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &failing(), &[])).await);
    finish(&app, &c, "r1").await;
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    // Another producer uses the same regression reference (and passes).
    dviscope_server::admin::create_producer(&a.pool, "p1", "other")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let ot = dviscope_server::admin::issue_token(&a.pool, "p1", "other", &scopes, 1, "o")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let o = dviscope_server::auth::actor_from_token(&a.pool, ot["token"].as_str().unwrap_or(""))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut sm = source_manifest();
    sm["producer_id"] = json!("other");
    ok(app.create_source_manifest(&o, &sm).await);
    let mut reg = regression("r1");
    reg["producer_id"] = json!("other");
    ok(app.create_regression(&o, &reg).await);
    ok(app.manifest_chunk(&o, "r1", 1, &chunk(&[slot("s1")])).await);
    ok(app.manifest_seal(&o, "r1", &seal(&[slot("s1")])).await);
    let mut st = started("r1", "s1", "o1", 1, &[]);
    st["producer_id"] = json!("other");
    ok(ingest(&app, &o, &st).await);
    let mut rp = report("r1", "s1", "o1", 1, 1, &passing(), &[]);
    rp["producer_id"] = json!("other");
    ok(ingest(&app, &o, &rp).await);
    ok(app
        .finish(&o, "r1", &json!({"kind": "finish", "regression_ref": "r1"}))
        .await);
    let tok = dviscope_server::admin::issue_token(&a.pool, "p1", "pilot", &scopes, 1, "kept")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let token = tok["token"].as_str().unwrap_or_default().to_string();
    let u = dviscope_server::admin::create_user(&a.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    // Health data of schema 20 round-trips: a hierarchy and retained runner metrics.
    let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'p1'")
        .fetch_one(&a.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let admin = dviscope_server::auth::Actor::User {
        user_id: u["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    let tree: dviscope_model::wire::hierarchy::Hierarchy = serde_json::from_value(json!({
        "nodes": [{"path": "soc"}, {"path": "soc/cpu"}],
        "streams": [{"node": "soc/cpu", "producer": "pilot", "suite": "nightly",
                     "branch": "rtl/main", "cadence": "nightly"}],
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    app.import_hierarchy(&admin, "p1", &tree)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    // An administrator's own SQL-standard function (its body is dumped unquoted).
    sqlx::raw_sql(
        "CREATE FUNCTION public.one() RETURNS integer LANGUAGE sql BEGIN ATOMIC SELECT 1; END",
    )
    .execute(&a.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let d = std::env::temp_dir().join(format!("dviscope-backup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    let archive = d.join("pilot.dump");
    let now = OffsetDateTime::now_utc();
    let m = match dviscope_server::backup::backup(&a.pool, &a.url(), &archive, now).await {
        Ok(m) => m,
        // A server before 17 with newer client tools: refused before anything is written
        // (the archive could not be restored); the rest needs DVISCOPE_PG_BIN_DIR there.
        Err(e) if format!("{e:#}").contains("cannot back up PostgreSQL") => {
            eprintln!("backup refused as documented: {e:#}");
            assert!(!archive.exists(), "nothing written");
            let _ = std::fs::remove_dir_all(&d);
            a.drop().await;
            return;
        }
        Err(e) => panic!("{e:#}"),
    };
    assert!(m.pg_dump_major > 0, "the writer's version is recorded");
    for t in ["area_trees", "areas", "area_streams", "attempt_metrics"] {
        assert!(
            m.counts.get(t).copied().unwrap_or(0) >= 1,
            "{t} in the backup: {m:?}"
        );
    }
    assert!(m.counts.get("attempts").copied().unwrap_or(0) >= 1, "{m:?}");
    // Each producer's regression, with its own verdict (no candidate binding).
    let mut fixtures: Vec<(&str, &str)> = m
        .readiness
        .iter()
        .map(|f| (f.producer.as_str(), f.verdict.as_str()))
        .collect();
    fixtures.sort_unstable();
    assert_eq!(
        fixtures,
        [("other", "pass"), ("pilot", "fail")],
        "pilot's s2 never reported: {m:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for p in [
            archive.clone(),
            dviscope_server::backup::manifest_path(&archive),
        ] {
            let mode = std::fs::metadata(&p)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0);
            assert_eq!(mode, 0o600, "{}", p.display());
        }
    }
    // A backup never overwrites.
    assert!(
        dviscope_server::backup::backup(&a.pool, &a.url(), &archive, now)
            .await
            .is_err()
    );

    // Restore into another database.
    let Some(b) = TestDb::new().await else { return };
    // An archive older than the safe-restore schema is refused.
    let old = d.join("old.dump");
    std::fs::copy(&archive, &old).ok();
    let mut om = m.clone();
    om.schema_version = 18;
    std::fs::write(
        dviscope_server::backup::manifest_path(&old),
        serde_json::to_vec(&om).unwrap_or_default(),
    )
    .ok();
    let e = dviscope_server::backup::restore(&b.url(), &old).await;
    assert!(
        e.as_ref()
            .is_err_and(|e| format!("{e:#}").contains("schema 18")),
        "{e:?}"
    );
    // Rolling an upgrade back: an archive of an older schema (here claimed 19) over a
    // database already at a newer one is refused before anything changes, with the
    // instruction to restore into a new, empty database.
    let current: i32 =
        sqlx::query_scalar("SELECT coalesce(max(version), 0) FROM schema_migrations")
            .fetch_one(&b.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    let older = d.join("older.dump");
    std::fs::copy(&archive, &older).ok();
    let mut prev = m.clone();
    prev.schema_version = current - 1;
    std::fs::write(
        dviscope_server::backup::manifest_path(&older),
        serde_json::to_vec(&prev).unwrap_or_default(),
    )
    .ok();
    let e = dviscope_server::backup::restore(&b.url(), &older).await;
    assert!(
        e.as_ref()
            .is_err_and(|e| format!("{e:#}").contains("new, empty database")),
        "{e:?}"
    );
    assert!(
        !dviscope_server::backup::maintenance_on(&b.pool)
            .await
            .unwrap_or(true),
        "a refused restore changes nothing"
    );
    // A restore that fails part-way (here: a table of the target depends on one the
    // archive replaces) leaves the target exactly as it was: nothing half-restored, no
    // half-applied safe state.
    sqlx::query("CREATE TABLE blocker (p BIGINT REFERENCES projects (id))")
        .execute(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    dviscope_server::admin::create_project(&b.pool, "kept", "strict")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let shape = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
              WHERE n.nspname = 'public'",
        )
        .fetch_one(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
    };
    let before = shape().await;
    let failed = dviscope_server::backup::restore(&b.url(), &archive).await;
    if !failed
        .as_ref()
        .is_err_and(|e| format!("{e:#}").contains("cannot restore into PostgreSQL"))
    {
        assert!(failed.is_err(), "{failed:?}");
        let projects: i64 = sqlx::query_scalar("SELECT count(*) FROM projects")
            .fetch_one(&b.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            projects, 1,
            "the target's own project, nothing of the archive"
        );
        assert_eq!(
            shape().await,
            before,
            "no statement of the failed restore stayed"
        );
        assert!(
            !dviscope_server::backup::maintenance_on(&b.pool)
                .await
                .unwrap_or(true),
            "no half-applied safe state"
        );
    }
    // The successful restore below replaces the target's own data (`--clean`).
    for q in ["DROP TABLE blocker"] {
        sqlx::query(q)
            .execute(&b.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let out = match dviscope_server::backup::restore(&b.url(), &archive).await {
        Ok(v) => v,
        // A newer pg_restore and a server before 17 are refused before anything is touched
        // (the documented pairing rule); the rest needs DVISCOPE_PG_BIN_DIR there.
        Err(e) if format!("{e:#}").contains("cannot restore into PostgreSQL") => {
            eprintln!("restore refused as documented: {e:#}");
            assert!(
                !dviscope_server::backup::maintenance_on(&b.pool)
                    .await
                    .unwrap_or(true),
                "nothing was touched"
            );
            let _ = std::fs::remove_dir_all(&d);
            b.drop().await;
            a.drop().await;
            return;
        }
        Err(e) => panic!("{e:#}"),
    };
    assert_eq!(out["maintenance"], true, "{out}");
    let one: i32 = sqlx::query_scalar("SELECT public.one()")
        .fetch_one(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(one, 1, "the BEGIN ATOMIC function came back");
    assert!(
        dviscope_server::backup::maintenance_on(&b.pool)
            .await
            .unwrap_or(false)
    );
    // Tokens are disabled until re-enabled.
    let refused = dviscope_server::auth::actor_from_token(&b.pool, &token).await;
    assert!(refused.is_err(), "a restored token is disabled");
    let id = tok["token_id"].as_i64().unwrap_or(0);
    // The admin page says why.
    let pid_b: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'p1'")
        .fetch_one(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let admin = dviscope_server::auth::Actor::User {
        user_id: u["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid_b, dviscope_server::auth::Role::Admin)],
    };
    let ov = b
        .app()
        .admin_overview(&admin, "p1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let states: Vec<_> = ov["tokens"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|t| (t["id"].as_i64().unwrap_or(0), t["state"].clone()))
                .collect()
        })
        .unwrap_or_default();
    assert!(states.contains(&(id, json!("restore_disabled"))), "{ov}");
    // A credential change and its audit record commit together: with the audit log
    // unwritable, re-enabling (and revoking) fails and changes nothing.
    let audit_table = |name: &'static str| {
        let pool = b.pool.clone();
        async move {
            sqlx::query(sqlx::AssertSqlSafe(name.to_string()))
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
    };
    audit_table("ALTER TABLE audit RENAME TO audit_away").await;
    assert!(
        dviscope_server::backup::reenable_token(&b.pool, id)
            .await
            .is_err()
    );
    assert!(
        dviscope_server::admin::revoke_token(&b.pool, id)
            .await
            .is_err()
    );
    audit_table("ALTER TABLE audit_away RENAME TO audit").await;
    assert!(
        dviscope_server::auth::actor_from_token(&b.pool, &token)
            .await
            .is_err(),
        "still disabled"
    );
    let revoked: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT revoked_at FROM api_tokens WHERE id = $1")
            .bind(id)
            .fetch_one(&b.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(revoked, None, "not revoked without its record");
    dviscope_server::backup::reenable_token(&b.pool, id)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        dviscope_server::auth::actor_from_token(&b.pool, &token)
            .await
            .is_ok()
    );
    // Verify: the restored database holds the backup's values.
    let v = dviscope_server::backup::verify(&b.pool, &archive)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(v["ok"], true, "{v}");
    // A lost row is a difference.
    sqlx::query("DELETE FROM attempt_reports")
        .execute(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let v = dviscope_server::backup::verify(&b.pool, &archive)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(v["ok"], false, "{v}");
    assert!(
        v["differences"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x["table"] == "attempt_reports")),
        "{v}"
    );
    // A replaced archive is refused.
    std::fs::write(&archive, b"not the archive").ok();
    assert!(
        dviscope_server::backup::restore(&b.url(), &archive)
            .await
            .is_err()
    );
    let _ = json!(null);
    let _ = std::fs::remove_dir_all(&d);
    b.drop().await;
    a.drop().await;
}

/// The retention preview: each regression with its cohort and action, for one
/// project; it waits on no lock a writer holds, changes nothing, and the real run then does
/// what it said. The project's preview is for admins.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn retention_preview_changes_nothing_and_blocks_nobody() {
    use dviscope_server::retention::{Policy, preview, run};
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &passing(), &[])).await);
    finish(&app, &c, "r1").await;
    sealed(&app, &c, "r2", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r2", "s1", "a2", 1, &[])).await);
    ok(ingest(&app, &c, &report("r2", "s1", "a2", 1, 1, &failing(), &[])).await);
    finish(&app, &c, "r2").await;
    // rb passes on build b1; the build is referenced by nothing else: once rb is removed,
    // the run deletes b1 too, and the preview must say so.
    sealed(&app, &c, "rb", &[built_slot("s1")]).await;
    ok(ingest(&app, &c, &build_started("b1")).await);
    ok(ingest(&app, &c, &build_report("b1", "pass")).await);
    ok(ingest(&app, &c, &started("rb", "s1", "ab", 1, &["b1"])).await);
    ok(ingest(
        &app,
        &c,
        &report("rb", "s1", "ab", 1, 1, &passing(), &["b1"]),
    )
    .await);
    finish(&app, &c, "rb").await;
    dviscope_server::admin::create_project(&t.pool, "p2", "strict")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let p2: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'p2'")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // A checklist whose item selects t_s1: per configuration the newest candidate (r2 over
    // r1 on the plain configuration, rb alone on the built one); another item selects
    // nothing of these.
    let cl_admin =
        dviscope_server::admin::create_user(&t.pool, "cl-admin", "correct horse battery")
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
    let cl_admin = dviscope_server::auth::Actor::User {
        user_id: cl_admin["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    let cl: dviscope_model::wire::checklist::Checklist = serde_json::from_value(json!({
    "schema": "dviscope.checklist/1.0", "checklist_id": "fs", "title": "sign-off",
    "version": "1", "feature": "f", "owner": "Ana",
    "items": [
        {"item_id": "s1", "title": "s1 works", "requires": {"tests": ["t_*"],
         "min_passing_seeds": 1}, "freshness_days": 30},
        {"item_id": "other", "title": "other", "requires": {"tests": ["nope_*"],
         "min_passing_seeds": 1}, "freshness_days": 30},
    ]}))
    .unwrap_or_else(|e| panic!("{e}"));
    app.import_checklist(&cl_admin, "p1", &cl)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    // Version 2 drops the item: an evaluation pinned to version 1 still selects rb.
    let cl2: dviscope_model::wire::checklist::Checklist = serde_json::from_value(json!({
    "schema": "dviscope.checklist/1.0", "checklist_id": "fs", "title": "sign-off",
    "version": "2", "feature": "f", "owner": "Ana",
    "items": [
        {"item_id": "other", "title": "other", "requires": {"tests": ["nope_*"],
         "min_passing_seeds": 1}, "freshness_days": 30},
    ]}))
    .unwrap_or_else(|e| panic!("{e}"));
    app.import_checklist(&cl_admin, "p1", &cl2)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    // A monitored publication of r1 (removed by the run) and a retired one (not monitored).
    for (digest, retired) in [("sha256:aa", false), ("sha256:bb", true)] {
        sqlx::query(
            "INSERT INTO publication_receipts (project_id, digest, summary, regression_ref,
                                               producer_id, target_repository, target_commit,
                                               retired_at)
             SELECT $1, $2, '{}', 'r1', id, 'rtl', 'abc', CASE WHEN $3 THEN now() END
               FROM producers WHERE project_id = $1 AND name = 'pilot'",
        )
        .bind(pid)
        .bind(digest)
        .bind(retired)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    }
    let reports = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM attempt_reports")
            .fetch_one(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
    };
    let before = reports().await;
    // 100 days on: r1 (all pass) is past its facts period, r2 (a failure) past its payload
    // period only.
    let policy = Policy::default();
    let now = OffsetDateTime::now_utc() + time::Duration::days(100);

    // A writer holds the trust gate and the regression heads: the preview does not wait.
    let mut blocker = t.pool.begin().await.unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(dviscope_server::app::TRUST_GATE)
        .execute(&mut *blocker)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("SELECT 1 FROM regressions FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let rep = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        preview(&t.pool, now, policy, Some(pid)),
    )
    .await
    .unwrap_or_else(|_| panic!("the preview waited on a writer's lock"))
    .unwrap_or_else(|e| panic!("{e}"));
    blocker.rollback().await.unwrap_or_else(|e| panic!("{e}"));
    assert!(rep.dry_run);
    assert_eq!(rep.regressions, 2, "{rep:?}");
    assert_eq!(rep.builds, 1, "b1 goes with rb: {rep:?}");
    assert!(rep.payloads >= 1, "{rep:?}");
    let got: Vec<_> = rep
        .items
        .iter()
        .map(|i| {
            (
                i.project.as_str(),
                i.regression.as_str(),
                i.cohort,
                i.action,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("p1", "r1", "all_pass", "remove"),
            ("p1", "r2", "with_failures", "expire_payloads"),
            ("p1", "rb", "all_pass", "remove"),
        ],
        "{rep:?}"
    );
    assert!(!rep.items_truncated);
    // The impact: rb was the newest evidence of its configuration (r1's test has r2's newer
    // entry); r1's monitored publication.
    let cands: Vec<_> = rep
        .candidates
        .iter()
        .map(|c| {
            (
                c.checklist.as_str(),
                c.version.as_str(),
                c.item.as_str(),
                c.branch.as_str(),
                c.test.as_str(),
                c.regression.as_str(),
                c.producer.as_str(),
            )
        })
        .collect();
    assert_eq!(
        cands,
        [("fs", "1", "s1", "rtl/main", "t_s1", "rb", "pilot")],
        "the evaluator's selection: r1 is not selected (r2 is newer): {rep:?}"
    );
    let pubs: Vec<_> = rep
        .publications
        .iter()
        .map(|p| {
            (
                p.digest.as_str(),
                p.regression.as_str(),
                p.target.as_deref(),
            )
        })
        .collect();
    assert_eq!(pubs, [("sha256:aa", "r1", Some("rtl@abc"))], "{rep:?}");
    assert!(!rep.impact_truncated);
    assert!(rep.items.iter().all(|i| !i.ended_at.is_empty()));
    // Nothing changed.
    assert_eq!(reports().await, before);
    let _ = read(&app, pid, "r1").await;
    // Another project's preview is its own.
    let other = preview(&t.pool, now, policy, Some(p2))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(other.items.is_empty() && other.regressions == 0 && other.payloads == 0);
    assert_eq!(
        preview(&t.pool, now, policy, None)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
            .items,
        rep.items
    );
    // The real run does what the preview said.
    let real = run(&t.pool, now, policy, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!real.dry_run);
    assert_eq!(real.items, rep.items);
    assert_eq!(
        (&real.candidates, &real.publications),
        (&rep.candidates, &rep.publications)
    );
    assert_eq!(
        (real.regressions, real.payloads, real.builds),
        (rep.regressions, rep.payloads, rep.builds)
    );
    assert!(reports().await < before);

    // The project's preview (database clock: nothing expires yet) is for admins only.
    let e = app.retention_preview(&viewer(pid), "p1").await;
    assert!(
        matches!(e, Err(ref e) if e.code == dviscope_model::errors::ErrorCode::Forbidden),
        "{e:?}"
    );
    let v = dviscope_server::admin::create_user(&t.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let admin = dviscope_server::auth::Actor::User {
        user_id: v["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    let v = app
        .retention_preview(&admin, "p1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["policy_days"]["pass_payload"], 30, "{v}");
    assert_eq!(v["policy_days"]["fail_facts"], 730, "{v}");
    assert_eq!(v["report"]["dry_run"], true, "{v}");
    assert!(v["as_of"].as_str().is_some_and(|s| !s.is_empty()), "{v}");
    assert_eq!(v["report"]["items"], json!([]), "{v}");
    t.drop().await;
}

/// Upgrade from the earliest released schema (the baseline, 0001-0010) with data
/// written by that version's own code: the database migrates to the current schema; reads,
/// readiness (with the baseline's triage case and exception), new ingestion and retention
/// all work on the upgraded data.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn upgrade_from_the_stage3_baseline() {
    let Some(t) = TestDb::new_at(10).await else {
        return;
    };
    sqlx::raw_sql(include_str!("fixtures/stage3-baseline.sql"))
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("loading the baseline: {e}"));
    // The baseline's token expired a day after it was written (wall time); this test is
    // about the upgrade, not about that clock: keep it valid.
    sqlx::query("UPDATE api_tokens SET expires_at = now() + interval '30 days'")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !dviscope_server::db::schema_ready(&t.pool)
            .await
            .unwrap_or(true)
    );
    dviscope_server::db::migrate(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        dviscope_server::db::schema_ready(&t.pool)
            .await
            .unwrap_or(false)
    );
    let app = t.app();
    let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'p1'")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let finished: OffsetDateTime = sqlx::query_scalar("SELECT max(finished_at) FROM regressions")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let now = finished + time::Duration::hours(1);

    // Reads.
    let st = |r: &dviscope_server::app::read::RegressionRead, s: &str| state(r, s)["state"].clone();
    let green = read(&app, pid, "green").await;
    assert_eq!(st(&green, "s1"), "passed");
    let partial = read(&app, pid, "partial").await;
    assert_eq!(st(&partial, "s1"), "passed");
    assert_eq!(st(&partial, "s2"), "missing", "{:?}", state(&partial, "s2"));
    let red = read(&app, pid, "red").await;
    assert_eq!(st(&red, "s2"), "failed");
    let built = read(&app, pid, "built").await;
    assert_eq!(st(&built, "s1"), "blocked", "{:?}", state(&built, "s1"));
    assert_eq!(st(&read(&app, pid, "retry").await, "s1"), "failed");

    // Readiness, with the baseline's exception covering red's failure; retry's failure has
    // red's signature, so the same exception covers it (strict policy: the failed attempt
    // is never a pass).
    let mut got = vec![];
    for r in ["green", "red", "partial", "built", "retry"] {
        let v = app
            .read_readiness(&viewer(pid), "p1", r, None, None, now)
            .await
            .unwrap_or_else(|e| panic!("{r}: {e:?}"));
        let kinds: Vec<String> = v["blockers"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|b| b["kind"]["kind"].as_str().unwrap_or("").to_string())
                    .collect()
            })
            .unwrap_or_default();
        got.push((r, v["verdict"].as_str().unwrap_or("").to_string(), kinds));
    }
    let s = |x: &str| x.to_string();
    assert_eq!(
        got,
        [
            ("green", s("pass"), vec![]),
            ("red", s("accepted_with_exceptions"), vec![]),
            ("partial", s("fail"), vec![s("missing")]),
            ("built", s("fail"), vec![s("blocked"), s("blocked")]),
            ("retry", s("accepted_with_exceptions"), vec![]),
        ]
    );

    // The decisions survive: the ledger names the triage case and the exception.
    let u: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'ada'")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let admin = dviscope_server::auth::Actor::User {
        user_id: u,
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    let ledger = serde_json::to_value(
        app.export_ledger(&admin, "p1", now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}")),
    )
    .unwrap_or_default();
    let text = ledger.to_string();
    assert!(text.contains("scoreboard model gap"), "{ledger}");
    assert!(text.contains("known model gap, fix scheduled"), "{ledger}");
    let ov = app
        .admin_overview(&admin, "p1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ov["tokens"][0]["state"], "active", "{ov}");

    // New ingestion on the upgraded database.
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "after", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("after", "s1", "n1", 1, &[])).await);
    ok(ingest(
        &app,
        &c,
        &report("after", "s1", "n1", 1, 1, &passing(), &[]),
    )
    .await);
    finish(&app, &c, "after").await;
    // The baseline accepted its own pipeline only: this version's results are not eligible
    // (never a pass) until the operator accepts the new digest.
    assert_eq!(st(&read(&app, pid, "after").await, "s1"), "missing");
    accept_pipeline(&t.pool, &passing()).await;
    assert_eq!(st(&read(&app, pid, "after").await, "s1"), "passed");

    // Retention on upgraded data: 100 days on, green (all pass) is removed and answers
    // E_EXPIRED; red keeps its facts and loses its payloads.
    let later = finished + time::Duration::days(100);
    let policy = dviscope_server::retention::Policy::default();
    let p = dviscope_server::retention::preview(&t.pool, later, policy, Some(pid))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let r = dviscope_server::retention::run(&t.pool, later, policy, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.items, p.items);
    assert!(
        r.items
            .iter()
            .any(|i| i.regression == "green" && i.action == "remove"),
        "{r:?}"
    );
    let gone = app.read_regression(&viewer(pid), "p1", "green", None).await;
    assert!(
        matches!(gone, Err(ref e) if e.code == dviscope_model::errors::ErrorCode::Expired),
        "{:?}",
        gone.err()
    );
    let red = read(&app, pid, "red").await;
    assert_eq!(st(&red, "s2"), "failed");
    t.drop().await;
}

/// Reconciliation (B.19) answers for the collector's own producer only: another producer's
/// collector sees nothing of it; users are refused; the request size is bounded.
#[tokio::test]
async fn reconcile_is_scoped_to_the_producer() {
    use dviscope_server::app::reconcile::{MAX_IDENTITIES, Request};
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2"), slot("s3")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &passing(), &[])).await);
    ok(ingest(&app, &c, &started("r1", "s2", "a2", 1, &[])).await);
    ok(ingest(&app, &c, &started("r1", "s3", "a3", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s3", "a3", 1, 1, &passing(), &[])).await);
    let req = Request {
        identities: vec!["attempt_started:a1".into(), "nothing:here".into()],
        regressions: vec!["r1".into(), "r9".into()],
    };
    let v = app
        .reconcile(&c, &req)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let revs = &v["receipts"]["attempt_started:a1"]["revisions"];
    assert_eq!(revs[0]["revision"], 1, "{v}");
    assert!(
        revs[0]["digest"].as_str().is_some_and(|d| d.len() == 64),
        "{v}"
    );
    assert!(v["receipts"].get("nothing:here").is_none(), "{v}");
    assert_eq!(
        v["regressions"][0],
        json!({"regression_ref": "r1", "found": true, "expired": false, "state": "sealed",
               "slots": 3, "slots_started": 3, "slots_reported": 2}),
        "{v}"
    );
    assert_eq!(
        v["regressions"][1],
        json!({"regression_ref": "r9", "found": false, "expired": false})
    );
    // Another producer's collector sees nothing of pilot's.
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
    let other =
        dviscope_server::auth::actor_from_token(&t.pool, tok["token"].as_str().unwrap_or(""))
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
    let v = app
        .reconcile(&other, &req)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v["receipts"], json!({}), "{v}");
    assert_eq!(v["regressions"][0]["found"], false, "{v}");
    // Users are refused; the size is bounded.
    let e = app.reconcile(&viewer(pid), &req).await;
    assert!(matches!(e, Err(ref e) if e.code == dviscope_model::errors::ErrorCode::Forbidden));
    let big = Request {
        identities: (0..=MAX_IDENTITIES).map(|i| format!("x:{i}")).collect(),
        regressions: vec![],
    };
    let e = app.reconcile(&c, &big).await;
    assert!(matches!(e, Err(ref e) if e.code == dviscope_model::errors::ErrorCode::TooLarge));
    t.drop().await;
}

/// The "bad nightly" demo: a separate project whose last nightly shows a repeated
/// failure (with its triage case), a failure whose exception expired, a missing result and
/// slots blocked by a failed build; the earlier nightlies pass and fail as the story says.
/// The generator leaves no usable credential and refuses an existing project.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn demo_dataset_tells_the_bad_nightly_story() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let now = OffsetDateTime::now_utc();
    let out = dviscope_server::demo::generate(&t.pool, "demo", now)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(out["bad_nightly"], "nightly-3", "{out}");
    let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'demo'")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let v = dviscope_server::auth::Actor::User {
        user_id: 0,
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Viewer)],
    };
    let readiness = |r: &'static str| {
        let (app, v) = (&app, &v);
        async move {
            app.read_readiness(v, "demo", r, None, None, now)
                .await
                .unwrap_or_else(|e| panic!("{r}: {e:?}"))
        }
    };
    assert_eq!(readiness("nightly-1").await["verdict"], "pass");
    let n2 = readiness("nightly-2").await;
    assert_eq!(n2["verdict"], "fail", "{n2}");
    let n3 = readiness("nightly-3").await;
    assert_eq!(n3["verdict"], "fail", "{n3}");
    let blockers: Vec<(String, String)> = n3["blockers"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|b| {
                    (
                        b["slot"].as_str().unwrap_or("").to_string(),
                        b["kind"]["kind"].as_str().unwrap_or("").to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let mut blockers = blockers;
    blockers.sort();
    let s = |a: &str, b: &str| (a.to_string(), b.to_string());
    assert_eq!(
        blockers,
        [
            s("dma_burst", "blocked"),
            s("dma_chain", "blocked"),
            s("irq_storm", "failed"),
            s("spi_basic", "missing"),
            s("uart_rx", "failed"),
        ],
        "{n3}"
    );
    let sig_of = |slot: &str| {
        n3["blockers"]
            .as_array()
            .and_then(|a| a.iter().find(|b| b["slot"] == slot))
            .and_then(|b| b["signatures"][0].as_i64())
            .unwrap_or_else(|| panic!("{slot}: {n3}"))
    };
    // The repeated signature occurs in nightly-2 and nightly-3 and has its triage case.
    let rep = app
        .signature_detail(&v, "demo", sig_of("uart_rx"))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let regs: std::collections::BTreeSet<&str> = rep["occurrences"]
        .as_array()
        .map(|a| a.iter().filter_map(|o| o["regression"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(
        regs,
        ["nightly-2", "nightly-3"].into_iter().collect(),
        "{rep}"
    );
    assert!(rep["triage"].to_string().contains("DEMO-1"), "{rep}");
    // The other failure's exception expired: it covers nothing now, but did while live.
    let exp = app
        .signature_detail(&v, "demo", sig_of("irq_storm"))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        exp["exceptions"][0]["expired"], true,
        "shown as expired: {exp}"
    );
    assert_eq!(rep["exceptions"], json!([]), "{rep}");
    let expired: (OffsetDateTime,) =
        sqlx::query_as("SELECT expires_at FROM exceptions ORDER BY expires_at LIMIT 1")
            .fetch_one(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    assert!(expired.0 < now, "{expired:?}");
    let earlier = app
        .read_readiness(
            &v,
            "demo",
            "nightly-3",
            None,
            None,
            now - time::Duration::days(10),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        !earlier["blockers"].to_string().contains("irq_storm"),
        "covered while the exception was live: {earlier}"
    );
    // No usable credential is left; a second run refuses the existing project.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_tokens WHERE revoked_at IS NULL AND expires_at > now()",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(live, 0);
    assert!(
        dviscope_server::demo::generate(&t.pool, "demo", now)
            .await
            .is_err()
    );
    // Invented records only: no path or host of this machine in them.
    let dump: String =
        sqlx::query_scalar("SELECT string_agg(payload::text, '') FROM attempt_reports")
            .fetch_one(&t.pool)
            .await
            .unwrap_or_default();
    assert!(
        !dump.contains("/home/") && !dump.contains(":\\\\"),
        "{dump}"
    );
    t.drop().await;
}

/// Maintenance is a fence: every write path of the app refuses in it, even
/// without the HTTP layer; `maintenance on` waits for a write that already passed the gate
/// and every later write is refused; retention's real run is refused (its preview is not);
/// the admin CLI runs only credential recovery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn maintenance_fences_every_write() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;

    // A write that passed the gate holds `maintenance on` back until it commits.
    let mut inflight = dviscope_server::app::begin_write(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let pool = t.pool.clone();
    let on =
        tokio::spawn(
            async move { dviscope_server::backup::set_maintenance(&pool, true, "test").await },
        );
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        !on.is_finished(),
        "maintenance waited for the in-flight write"
    );
    sqlx::query("INSERT INTO audit (actor, action, object) VALUES ('t', 'inflight', 'x')")
        .execute(&mut *inflight)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    inflight.commit().await.unwrap_or_else(|e| panic!("{e}"));
    tokio::time::timeout(std::time::Duration::from_secs(10), on)
        .await
        .unwrap_or_else(|_| panic!("maintenance on after the commit"))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e:#}"));

    // Every later write is refused at the app layer.
    let unavailable =
        |r: Result<dviscope_server::app::Receipt, dviscope_server::error::AppError>| {
            assert_eq!(
                r.err().map(|e| e.code),
                Some(dviscope_model::errors::ErrorCode::Unavailable)
            );
        };
    unavailable(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    unavailable(app.create_regression(&c, &regression("r2")).await);
    unavailable(
        app.finish(&c, "r1", &json!({"kind": "finish", "regression_ref": "r1"}))
            .await,
    );
    assert!(
        dviscope_server::app::begin_write(&t.pool).await.is_err(),
        "the gate itself"
    );
    // Retention: the preview runs, the real run is refused.
    let later = OffsetDateTime::now_utc() + time::Duration::days(1000);
    let policy = dviscope_server::retention::Policy::default();
    assert!(
        dviscope_server::retention::preview(&t.pool, later, policy, Some(pid))
            .await
            .is_ok()
    );
    assert!(
        dviscope_server::retention::run(&t.pool, later, policy, false)
            .await
            .is_err()
    );
    // The demo writes through the app: refused.
    assert!(
        dviscope_server::demo::generate(&t.pool, "demo", OffsetDateTime::now_utc())
            .await
            .is_err()
    );
    let regressions: i64 = sqlx::query_scalar("SELECT count(*) FROM regressions")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(regressions, 1, "nothing written in maintenance");
    // The admin functions themselves are gated (not only the CLI's early check): only
    // credential recovery writes.
    use dviscope_server::admin as ad;
    assert!(
        ad::create_project(&t.pool, "frozen", "strict")
            .await
            .is_err()
    );
    assert!(ad::create_producer(&t.pool, "p1", "frozen").await.is_err());
    assert!(
        ad::set_pipeline(
            &t.pool,
            "p1",
            passing().pipeline_digest.as_str(),
            "withdrawn"
        )
        .await
        .is_err()
    );
    assert!(
        ad::create_user(&t.pool, "frozen", "correct horse battery")
            .await
            .is_err()
    );
    assert!(
        ad::set_member(&t.pool, "p1", "frozen", "viewer")
            .await
            .is_err()
    );
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert!(
        ad::issue_token(&t.pool, "p1", "pilot", &scopes, 1, "recovery")
            .await
            .is_ok()
    );
    // Publication retirement is a write (gated before it looks for the receipt); the rules
    // views are reads (available).
    let admin_user = dviscope_server::auth::Actor::User {
        user_id: 0,
        token_id: None,
        roles: vec![(pid, dviscope_server::auth::Role::Admin)],
    };
    let e = app
        .retire_publication(
            &admin_user,
            "p1",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            &dviscope_server::app::publications::Retire {
                reason: "superseded".into(),
            },
            OffsetDateTime::now_utc(),
        )
        .await;
    assert_eq!(
        e.err().map(|e| e.code),
        Some(dviscope_model::errors::ErrorCode::Unavailable)
    );
    assert!(app.rules_status(&admin_user, "p1").await.is_ok());
    assert!(app.rules_definition(&admin_user, "p1").await.is_ok());

    // The admin CLI: credential recovery only.
    let dir = std::env::temp_dir().join(format!("dviscope-maint-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();
    let cfg = dir.join("server.toml");
    std::fs::write(
        &cfg,
        "listen = \"127.0.0.1:0\"\npublic_origin = \"https://127.0.0.1:8443\"\n\
         [tls]\ncert_file = \"x.pem\"\nkey_file = \"x.key\"\n[database]\n",
    )
    .ok();
    let admin = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_dviscope-server"))
            .arg("--config")
            .arg(&cfg)
            .arg("admin")
            .args(args)
            .env("DVISCOPE_SERVER_DATABASE_URL", t.url())
            .output()
            .unwrap_or_else(|e| panic!("{e}"))
    };
    let o = admin(&["create-project", "--name", "frozen"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("maintenance"));
    let token_file = dir.join("replacement.token");
    let o = admin(&[
        "issue-token",
        "--project",
        "p1",
        "--producer",
        "pilot",
        "--label",
        "replacement",
        "--out",
        token_file.to_str().unwrap_or_default(),
    ]);
    if cfg!(windows) {
        // Owner-only modes are Unix: a token file is refused on Windows, before issuing.
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("Linux host"));
        assert!(!token_file.exists());
        let _ = std::fs::remove_dir_all(&dir);
        t.drop().await;
        return;
    }
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // The token is in the new file, never on standard output.
    let token = std::fs::read_to_string(&token_file).unwrap_or_default();
    assert!(token.trim().starts_with("dvis_"), "a token in the file");
    let stdout = String::from_utf8_lossy(&o.stdout);
    assert!(!stdout.contains(token.trim()), "the token is never printed");
    assert!(stdout.contains("token_file"), "{stdout}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&token_file)
            .map(|m| m.permissions().mode())
            .unwrap_or(0);
        assert_eq!(mode & 0o077, 0, "owner-only");
    }
    // A Windows drive seen from WSL cannot make it owner-only: refused before issuing.
    if Path::new("/mnt/c").is_dir() {
        let drv = format!("/mnt/c/dviscope-token-{}.token", std::process::id());
        let o = admin(&[
            "issue-token",
            "--project",
            "p1",
            "--producer",
            "pilot",
            "--out",
            &drv,
        ]);
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("Windows drive"));
        assert!(!Path::new(&drv).exists());
    }
    // An existing file is never overwritten.
    let again = admin(&[
        "issue-token",
        "--project",
        "p1",
        "--producer",
        "pilot",
        "--out",
        token_file.to_str().unwrap_or_default(),
    ]);
    assert!(!again.status.success());
    assert_eq!(
        std::fs::read_to_string(&token_file).unwrap_or_default(),
        token
    );
    let _ = std::fs::remove_dir_all(&dir);
    t.drop().await;
}

/// A database URL backup cannot use is refused before anything
/// is read or written: no archive, no manifest (a retry with the corrected URL can use the
/// same name).
#[tokio::test]
async fn backup_refuses_an_unusable_url_before_writing() {
    let Some(t) = TestDb::new().await else {
        return;
    };
    let d = std::env::temp_dir().join(format!("dviscope-badurl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    let out = d.join("b.dump");
    let url = format!("{}?dbname=other", t.url());
    let e = dviscope_server::backup::backup(&t.pool, &url, &out, OffsetDateTime::now_utc()).await;
    assert!(
        e.as_ref()
            .is_err_and(|e| format!("{e:#}").contains("not supported")),
        "{e:?}"
    );
    assert!(!out.exists(), "no archive");
    assert!(
        std::fs::read_dir(&d).is_ok_and(|mut r| r.next().is_none()),
        "no manifest"
    );
    let _ = std::fs::remove_dir_all(&d);
    t.drop().await;
}

/// A backup of a database before the safe-restore schema is refused before anything is
/// written: `restore` could not take it (the documented pre-upgrade procedure is pg_dump).
#[tokio::test]
async fn backup_refuses_a_schema_restore_cannot_take() {
    let Some(t) = TestDb::new_at(18).await else {
        return;
    };
    let d = std::env::temp_dir().join(format!("dviscope-old-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    let out = d.join("old.dump");
    let e =
        dviscope_server::backup::backup(&t.pool, &t.url(), &out, OffsetDateTime::now_utc()).await;
    assert!(
        e.as_ref()
            .is_err_and(|e| format!("{e:#}").contains("schema 18")),
        "{e:?}"
    );
    assert!(!out.exists(), "nothing written");
    let _ = std::fs::remove_dir_all(&d);
    t.drop().await;
}

/// Rolling an upgrade back (operate.md): a backup of a real schema-19 database restores into
/// a new, empty database (no `schema_migrations` there yet).
#[tokio::test]
async fn rollback_restores_a_schema_19_backup_into_an_empty_database() {
    if !tools() {
        eprintln!("skipped: pg_dump not on PATH");
        return;
    }
    let Some(a) = TestDb::new_at(19).await else {
        return;
    };
    let app = a.app();
    let _pid = project(&a.pool).await;
    let (c, _) = collector(&a.pool).await;
    accept_pipeline(&a.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &passing(), &[])).await);
    finish(&app, &c, "r1").await;
    let d = std::env::temp_dir().join(format!("dviscope-rollback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    let archive = d.join("pre-upgrade.dump");
    let m = match dviscope_server::backup::backup(
        &a.pool,
        &a.url(),
        &archive,
        OffsetDateTime::now_utc(),
    )
    .await
    {
        Ok(m) => m,
        Err(e) if format!("{e:#}").contains("cannot back up PostgreSQL") => {
            eprintln!("backup refused as documented: {e:#}");
            let _ = std::fs::remove_dir_all(&d);
            a.drop().await;
            return;
        }
        Err(e) => panic!("{e:#}"),
    };
    assert_eq!(m.schema_version, 19);
    // A truly empty database: not even the migrations table.
    let Some(b) = TestDb::new_at(0).await else {
        return;
    };
    sqlx::query("DROP TABLE IF EXISTS schema_migrations")
        .execute(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let out = dviscope_server::backup::restore(&b.url(), &archive)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(out["maintenance"], true, "{out}");
    let v = dviscope_server::backup::verify(&b.pool, &archive)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(v["ok"], true, "{v}");
    let schema: i32 = sqlx::query_scalar("SELECT max(version) FROM schema_migrations")
        .fetch_one(&b.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(schema, 19, "the database is at the backup's schema");
    assert_eq!(b.count("regressions").await, 1);
    let _ = std::fs::remove_dir_all(&d);
    a.drop().await;
    b.drop().await;
}
