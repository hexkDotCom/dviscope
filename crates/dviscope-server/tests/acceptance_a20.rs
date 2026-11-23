//! A20: a failure after the evidence insert, before the head and the receipt, leaves no
//! partial revision; the retry succeeds once. (Its own test binary: the fail point is
//! process-global.)

mod common;

use common::*;
use dviscope_server::app::fail;

#[tokio::test]
async fn a20_transaction_failure_injection() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let before = (
        t.count("attempt_facts").await,
        t.count("attempt_reports").await,
        t.count("buckets").await,
        t.count("receipts").await,
    );
    let rec = report("r1", "s1", "a1", 1, 1, &pass, &[]);
    fail::arm(Some("after_evidence"));
    let e = ingest(&app, &c, &rec).await.err().map(|e| e.code);
    fail::arm(None);
    assert_eq!(e, Some(dviscope_model::errors::ErrorCode::Internal));
    let after = (
        t.count("attempt_facts").await,
        t.count("attempt_reports").await,
        t.count("buckets").await,
        t.count("receipts").await,
    );
    assert_eq!(before, after, "no partial revision");
    let head: Option<i32> = sqlx::query_scalar("SELECT head_revision FROM attempts")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(head, None);
    // The retry commits once; a further retry is a duplicate.
    assert!(!ok(ingest(&app, &c, &rec).await).duplicate);
    assert!(ok(ingest(&app, &c, &rec).await).duplicate);
    assert_eq!(t.count("attempt_facts").await, before.0 + 1);
    assert_eq!(state(&read(&app, pid, "r1").await, "s1")["state"], "passed");
    t.drop().await;
}
