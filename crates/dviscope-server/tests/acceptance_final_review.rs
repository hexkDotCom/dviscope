//! Server regression tests, each one
//! tries to turn a failure green.

mod common;

use common::*;
use serde_json::json;
use time::OffsetDateTime;

/// S1: a regression finished without its seal (its manifest may be partial) never passes,
/// even when every declared slot passed.
#[tokio::test]
async fn s1_an_unsealed_finished_regression_never_passes() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let ev = passing();
    accept_pipeline(&t.pool, &ev).await;
    let now = OffsetDateTime::now_utc();
    let verdict = |r: &'static str| {
        let app = &app;
        async move {
            app.read_readiness(&viewer(pid), "p1", r, None, None, now)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"))["verdict"]
                .clone()
        }
    };
    // Sealed and finished with a passing slot: pass (the control).
    sealed(&app, &c, "ok", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("ok", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("ok", "s1", "a1", 1, 1, &ev, &[])).await);
    finish(&app, &c, "ok").await;
    assert_eq!(verdict("ok").await, json!("pass"));
    // The same, its manifest declared but never sealed: never a pass.
    ok(app.create_regression(&c, &regression("part")).await);
    ok(app
        .manifest_chunk(&c, "part", 1, &chunk(&[slot("s1")]))
        .await);
    ok(ingest(&app, &c, &started("part", "s1", "b1", 1, &[])).await);
    ok(ingest(&app, &c, &report("part", "s1", "b1", 1, 1, &ev, &[])).await);
    finish(&app, &c, "part").await;
    assert_ne!(verdict("part").await, json!("pass"));
    // Nothing declared at all: never a pass.
    ok(app.create_regression(&c, &regression("empty")).await);
    finish(&app, &c, "empty").await;
    assert_ne!(verdict("empty").await, json!("pass"));
    t.drop().await;
}

/// S2: `repository/branch` keys triage cases, exceptions and feature candidates, so a
/// repository name may not contain `/` (two branches would be one); branch names may.
#[tokio::test]
async fn s2_a_repository_name_never_contains_a_slash() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let _ = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    let with = |r: &str, repo: &str, name: &str| {
        let mut v = regression(r);
        v["branch"] = json!({"repository": repo, "name": name});
        v
    };
    ok(app
        .create_regression(&c, &with("r1", "rtl", "feature/x"))
        .await);
    for (r, repo, name) in [
        ("r2", "rtl/feature", "x"),
        ("r3", "", "main"),
        ("r4", "rtl", ""),
    ] {
        let e = app
            .create_regression(&c, &with(r, repo, name))
            .await
            .err()
            .unwrap_or_else(|| panic!("{repo:?} {name:?} must be refused"));
        assert_eq!(e.code, dviscope_model::errors::ErrorCode::Invalid, "{e:?}");
    }
    t.drop().await;
}

/// S3: creating a regression advances the change feed (a dashboard showing the previous
/// run as latest learns of the new one before any chunk arrives).
#[tokio::test]
async fn s3_creating_a_regression_is_a_change() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    let seq = |v: serde_json::Value| v["change_seq"].as_i64().unwrap_or(0);
    let before = seq(app
        .changes_since(&viewer(pid), "p1", 0)
        .await
        .unwrap_or_else(|e| panic!("{e:?}")));
    ok(app.create_regression(&c, &regression("r1")).await);
    let after = app
        .changes_since(&viewer(pid), "p1", before)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(seq(after.clone()) > before, "{after}");
    assert!(after.to_string().contains("regression:r1"), "{after}");
    t.drop().await;
}

/// S4: replacing an unused manifest chunk before the seal also replaces its feature
/// candidates: the regression is never selected for a test it no longer declares.
#[tokio::test]
async fn s4_a_replaced_chunk_leaves_no_phantom_candidate() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    ok(app.create_regression(&c, &regression("r1")).await);
    let tests = || async {
        sqlx::query_scalar::<_, String>(
            "SELECT test FROM candidate_index WHERE project_id = $1 ORDER BY test",
        )
        .bind(pid)
        .fetch_all(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
    };
    ok(app
        .manifest_chunk(&c, "r1", 1, &chunk(&[slot("s1"), slot("s2")]))
        .await);
    assert_eq!(tests().await, ["t_s1", "t_s2"]);
    // Replaced (no attempts yet): s1 stays, s2 becomes s3.
    ok(app
        .manifest_chunk(&c, "r1", 1, &chunk(&[slot("s1"), slot("s3")]))
        .await);
    assert_eq!(tests().await, ["t_s1", "t_s3"]);
    t.drop().await;
}

/// S2 and S4 on data written before the fixes (migration 0023): a phantom candidate left by
/// an earlier chunk replacement is removed; a stored repository name with '/' stops the
/// upgrade (a decision could otherwise cross branches).
#[tokio::test]
async fn s2_s4_the_upgrade_repairs_or_refuses_earlier_data() {
    let Some(t) = TestDb::new_at(22).await else {
        return;
    };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    ok(app.create_regression(&c, &regression("r1")).await);
    ok(app
        .manifest_chunk(&c, "r1", 1, &chunk(&[slot("s1"), slot("s2")]))
        .await);
    // An earlier replacement removed s2's slot and left its candidate.
    sqlx::query("DELETE FROM slots WHERE project_id = $1 AND slot_ref = 's2'")
        .bind(pid)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    dviscope_server::db::migrate(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let tests: Vec<String> =
        sqlx::query_scalar("SELECT test FROM candidate_index WHERE project_id = $1 ORDER BY test")
            .bind(pid)
            .fetch_all(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tests, ["t_s1"]);
    t.drop().await;

    let Some(t) = TestDb::new_at(22).await else {
        return;
    };
    let app = t.app();
    let _ = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    ok(app.create_regression(&c, &regression("r1")).await);
    sqlx::query("UPDATE regressions SET branch_repository = 'rtl/feature'")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let e = dviscope_server::db::migrate(&t.pool)
        .await
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(e.contains("repository names"), "{e}");
    t.drop().await;

    // A decision on a branch key with two '/' is refused even when a surviving regression's
    // `repository/name` matches it (it may have been made for repository `rtl/feature`, branch
    // `x`, whose regressions retention removed); a key with one '/' upgrades.
    for (key, refused) in [("rtl/feature/x", true), ("rtl/main", false)] {
        let Some(t) = TestDb::new_at(22).await else {
            return;
        };
        let app = t.app();
        let pid = project(&t.pool).await;
        let (c, _) = collector(&t.pool).await;
        let _ = app.create_source_manifest(&c, &source_manifest()).await;
        ok(app.create_regression(&c, &regression("r0")).await);
        let mut reg = regression("r1");
        reg["branch"] = json!({"repository": "rtl", "name": "feature/x"});
        ok(app.create_regression(&c, &reg).await);
        sqlx::query(
            "INSERT INTO signatures (project_id, fingerprint, family_kind, diag_id, identity_template)
             VALUES ($1, 'sha256:fp', 'uvm', 'uvm:X', 't')",
        )
        .bind(pid)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        sqlx::query(
            "INSERT INTO triage_cases (project_id, signature_id, branch, revision)
             SELECT $1, id, $2, 1 FROM signatures WHERE project_id = $1",
        )
        .bind(pid)
        .bind(key)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        let r = dviscope_server::db::migrate(&t.pool).await;
        if refused {
            let e = r.err().map(|e| format!("{e:#}")).unwrap_or_default();
            assert!(e.contains("cannot be attributed") && e.contains(key), "{e}");
        } else {
            r.unwrap_or_else(|e| panic!("{e:#}"));
        }
        t.drop().await;
    }
}
