//! Regression tests.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_server::retention::{self, Policy};
use serde_json::json;

/// 1: two identical creates in flight: one commits, the other answers its receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_1_concurrent_identical_writes_are_duplicates() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    ok(app.create_source_manifest(&c, &source_manifest()).await);
    for i in 0..5 {
        let r = regression(&format!("r{i}"));
        let (a, b) = tokio::join!(app.create_regression(&c, &r), app.create_regression(&c, &r));
        let (a, b) = (ok(a), ok(b));
        assert!(a.duplicate ^ b.duplicate);
        assert_eq!(a.body["server_ids"], b.body["server_ids"]);
    }
    t.drop().await;
}

/// 2: a report ID and an attempt reference each belong to one attempt, in one slot.
#[tokio::test]
async fn r1_2_identities_are_bound_to_their_parents() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &pass, &[])).await);
    // Revision 2 of the same report naming another slot (and attempt).
    let mut moved = report("r1", "s2", "a9", 1, 2, &pass, &[]);
    moved["report_id"] = json!("a1:r1");
    assert_eq!(
        code(ingest(&app, &c, &moved).await),
        ErrorCode::RevisionConflict
    );
    // The attempt reference reused in another slot.
    assert_eq!(
        code(ingest(&app, &c, &started("r1", "s2", "a1", 1, &[])).await),
        ErrorCode::RevisionConflict
    );
    assert_eq!(t.count("attempts").await, 1);
    t.drop().await;
}

/// 4: a report must run exactly the slot's declared inputs.
#[tokio::test]
async fn r1_4_other_execution_inputs_are_refused() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let mut other = report("r1", "s1", "a1", 1, 1, &pass, &[]);
    other["execution"]["seed"] = json!("2");
    assert_eq!(
        code(ingest(&app, &c, &other).await),
        ErrorCode::RetryInputsDiffer
    );
    other["execution"]["seed"] = json!("1");
    other["execution"]["plusargs"] = json!(["+no_asserts"]);
    assert_eq!(
        code(ingest(&app, &c, &other).await),
        ErrorCode::RetryInputsDiffer
    );
    t.drop().await;
}

/// 5 and 6: a build's pass must be supported by its runner facts, and a build proves only
/// the producer's own requirements.
#[tokio::test]
async fn r1_5_6_build_proof() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    sealed(&app, &c, "r1", &[built_slot("s1")]).await;
    // A claimed pass with a crashed runner is an error: it proves nothing.
    ok(ingest(&app, &c, &build_started("b1")).await);
    let mut crashed = build_report("b1", "pass");
    crashed["runner"]["termination"] = json!({"kind": "crash", "posix_signal": 11});
    ok(ingest(&app, &c, &crashed).await);
    let stored: String = sqlx::query_scalar("SELECT outcome FROM build_facts")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stored, "error");
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &["b1"])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &pass, &["b1"])).await);
    assert_ne!(state(&read(&app, pid, "r1").await, "s1")["state"], "passed");

    // Another producer with the same source manifest and build references.
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
    let mut sm = source_manifest();
    sm["producer_id"] = json!("other");
    ok(app.create_source_manifest(&o, &sm).await);
    let mut bs = build_started("b2");
    bs["producer_id"] = json!("other");
    ok(ingest(&app, &o, &bs).await);
    let mut br = build_report("b2", "pass");
    br["producer_id"] = json!("other");
    ok(ingest(&app, &o, &br).await);
    // pilot's attempt names "b2": the other producer's pass does not prove it.
    ok(ingest(&app, &c, &started("r1", "s1", "a2", 2, &["b2"])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a2", 2, 1, &pass, &["b2"])).await);
    assert_ne!(state(&read(&app, pid, "r1").await, "s1")["state"], "passed");
    t.drop().await;
}

/// 7: a quarantined revision keeps its barrier under a clean correction.
#[tokio::test]
async fn r1_7_corrections_keep_quarantine_barriers() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (clean, _) = collector(&t.pool).await;
    let (bad, bad_id) = collector(&t.pool).await;
    sealed(&app, &clean, "r1", &[slot("s1")]).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &bad, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &bad, &report("r1", "s1", "a1", 1, 1, &pass, &[])).await);
    let mut corr = report("r1", "s1", "a1", 1, 2, &pass, &[]);
    corr["result"]["outcome_reported"] = json!("pass");
    ok(ingest(&app, &clean, &corr).await);
    dviscope_server::admin::quarantine_token(&t.pool, bad_id, "2000-01-01T00:00:00Z")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        state(&read(&app, pid, "r1").await, "s1"),
        json!({"state": "failed", "detail": "insufficient"})
    );
    t.drop().await;
}

/// 11 and 13: a regression whose pass is now quarantined stays in the long-lived cohort;
/// a build a remaining slot requires is kept; an expired build's identity is never reused.
#[tokio::test]
async fn r1_11_13_retention_cohorts_and_builds() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, cid) = collector(&t.pool).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    sealed(&app, &c, "q", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("q", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("q", "s1", "a1", 1, 1, &pass, &[])).await);
    sealed(&app, &c, "b", &[built_slot("s1")]).await;
    ok(ingest(&app, &c, &build_started("b1")).await);
    ok(ingest(&app, &c, &build_report("b1", "pass")).await);
    let origin = time::OffsetDateTime::now_utc();
    sqlx::query("UPDATE regressions SET finished_at = $1")
        .bind(origin)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("UPDATE build_attempts SET started_at = $1")
        .bind(origin)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    dviscope_server::admin::quarantine_token(&t.pool, cid, "2000-01-01T00:00:00Z")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    // Day 100: "q" now settles insufficient: the long-lived cohort keeps it. "b" has no
    // result (missing): also kept. The build its slot requires is kept.
    let r = retention::run(
        &t.pool,
        origin + time::Duration::days(100),
        Policy::default(),
        false,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((r.regressions, r.builds), (0, 0), "{r:?}");
    // Day 800: both expire; the build goes with its last obligation, and is tombstoned.
    let r = retention::run(
        &t.pool,
        origin + time::Duration::days(800),
        Policy::default(),
        false,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((r.regressions, r.builds), (2, 1), "{r:?}");
    dviscope_server::admin::release_token(&t.pool, cid)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (c2, _) = collector(&t.pool).await;
    let mut again = build_report("b1", "pass");
    again["report_revision"] = json!(2);
    assert_eq!(code(ingest(&app, &c2, &again).await), ErrorCode::Expired);
    t.drop().await;
}
