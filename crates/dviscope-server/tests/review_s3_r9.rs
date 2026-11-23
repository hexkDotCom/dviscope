//! Regression tests.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_server::retention::{self, Policy};

/// Every receipt retention deletes leaves a tombstone, and an expired regression is never
/// created again, even when no receipt or receipt tombstone remembers it.
#[tokio::test]
async fn r9_expired_regressions_are_never_recreated() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    let receipts = t.count("receipts").await;
    let far = time::OffsetDateTime::now_utc() + time::Duration::days(3 * 365);
    let rep = retention::run(&t.pool, far, Policy::default(), false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rep.receipts, u64::try_from(receipts).unwrap_or(0));
    assert_eq!(t.count("receipts").await, 0);
    assert_eq!(
        t.count("expired_receipts").await,
        receipts,
        "one tombstone per identity deleted"
    );
    // The worst case of the race: the receipt and its tombstone are both gone.
    sqlx::raw_sql("DELETE FROM expired_receipts")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        code(app.create_regression(&c, &regression("r1")).await),
        ErrorCode::Expired
    );
    assert_eq!(t.count("regressions").await, 0);
    t.drop().await;
}

/// Creation is serialized with retention. A live regression whose receipt
/// history is missing (old receipt race); retention holds the gate and removes it while a
/// creation of the same name is in flight: the creation waits, then sees the tombstone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r10_creation_waits_for_retention() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    ok(app.create_source_manifest(&c, &source_manifest()).await);
    ok(app.create_regression(&c, &regression("r1")).await);
    sqlx::raw_sql("DELETE FROM receipts WHERE identity = 'regression:r1'")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // "Retention" takes the gate exclusively first.
    let mut ret = t.pool.begin().await.unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(dviscope_server::app::TRUST_GATE)
        .execute(&mut *ret)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let app2 = app.clone();
    let c2 = c.clone();
    let creation =
        tokio::spawn(async move { app2.create_regression(&c2, &regression("r1")).await });
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(!creation.is_finished(), "the creation waits for retention");
    sqlx::raw_sql(
        "DELETE FROM regressions WHERE ref = 'r1';
         INSERT INTO expired_regressions (project_id, producer_id, ref, expired_at)
         SELECT project_id, id, 'r1', now() FROM producers WHERE name = 'pilot'",
    )
    .execute(&mut *ret)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    ret.commit().await.unwrap_or_else(|e| panic!("{e}"));
    let r = creation.await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(code(r), ErrorCode::Expired);
    assert_eq!(t.count("regressions").await, 0, "never resurrected");
    t.drop().await;
}
