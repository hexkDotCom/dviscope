//! Regression tests.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use serde_json::json;

/// R1-2: bindings outlive receipts and are claimed atomically.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r2_2_bindings_are_permanent_and_atomic() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    sealed(&app, &c, "r2", &[slot("s1")]).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &pass, &[])).await);
    // Receipts gone (past the horizon): the binding still holds.
    sqlx::query("DELETE FROM receipts")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut moved = report("r1", "s2", "a9", 1, 5, &pass, &[]);
    moved["report_id"] = json!("a1:r1");
    assert_eq!(
        code(ingest(&app, &c, &moved).await),
        ErrorCode::RevisionConflict
    );
    // Two regressions claiming one attempt reference at once: exactly one wins.
    for i in 0..5 {
        let a = format!("race{i}");
        let (x, y) = (
            started("r1", "s2", &a, 1 + i, &[]),
            started("r2", "s1", &a, 1 + i, &[]),
        );
        let (rx, ry) = tokio::join!(ingest(&app, &c, &x), ingest(&app, &c, &y));
        assert!(rx.is_ok() ^ ry.is_ok(), "{rx:?} {ry:?}");
    }
    t.drop().await;
}

/// R1-3: a simulator pack the server cannot resolve exactly keeps the exit-code check on.
#[tokio::test]
async fn r2_3_unresolved_simulator_packs_never_pass_a_failing_exit() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let mut rec = report("r1", "s1", "a1", 1, 1, &pass, &[]);
    // A customized simulator pack: same profile, another digest.
    for p in rec["evidence"]["packs"]
        .as_array_mut()
        .into_iter()
        .flatten()
    {
        p["digest"] = json!(format!("sha256:{}", "ab".repeat(32)));
    }
    rec["result"]["runner"]["termination"]["exit_code"] = json!(1);
    ok(ingest(&app, &c, &rec).await);
    assert_ne!(state(&read(&app, pid, "r1").await, "s1")["state"], "passed");
    t.drop().await;
}

/// R1-5: a build log's failure count, failing verdict or excess counted failures deny a
/// claimed pass.
#[tokio::test]
async fn r2_5_build_failure_indications_deny_a_pass() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    sealed(&app, &c, "r1", &[built_slot("s1")]).await;
    ok(ingest(&app, &c, &build_started("b1")).await);
    let mut rec = build_report("b1", "pass");
    let span = json!({"line_start": 1, "line_end": 1, "byte_start": 0, "byte_end": 10});
    rec["evidence"]["counters"]
        .as_array_mut()
        .unwrap_or_else(|| panic!("counters"))
        .push(json!({"domain": "sim_tool", "key": "errors", "value": "1",
                     "role": "failure_count", "protected": true, "span": span}));
    ok(ingest(&app, &c, &rec).await);
    let stored: String = sqlx::query_scalar("SELECT outcome FROM build_facts")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stored, "error");
    t.drop().await;
}

/// New in r2: the comparison configuration ignores seed-like arguments and the source.
#[tokio::test]
async fn r2_config_digest_is_logical() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let mut sm2 = source_manifest();
    sm2["source_manifest_ref"] = json!("sm2");
    sm2["repositories"][0]["revision"] = json!("def456");
    ok(app.create_source_manifest(&c, &source_manifest()).await);
    ok(app.create_source_manifest(&c, &sm2).await);
    let mk = |seed: &str, sm: &str| {
        let mut s = built_slot("s1");
        s["exec_inputs"]["plusargs"] = json!([format!("+seed={seed}"), "+mode=a"]);
        s["build_reqs"][0]["source_manifest_ref"] = json!(sm);
        s
    };
    for (r, seed, sm) in [("a", "1", "sm1"), ("b", "2", "sm2")] {
        let mut reg = regression(r);
        reg["source_manifest_ref"] = json!(sm);
        ok(app.create_regression(&c, &reg).await);
        let s = [mk(seed, sm)];
        ok(app.manifest_chunk(&c, r, 1, &chunk(&s)).await);
    }
    let digests: Vec<String> = sqlx::query_scalar("SELECT DISTINCT config_digest FROM slots")
        .fetch_all(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(digests.len(), 1, "{digests:?}");
    t.drop().await;
}
