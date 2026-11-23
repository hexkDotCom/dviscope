//! Regression tests.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_server::retention::{self, Policy};
use serde_json::json;

/// R1-2: parents whose joined references collide are told apart.
#[tokio::test]
async fn r3_2_parent_pairs_are_unambiguous() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r/a", &[slot("b")]).await;
    sealed(&app, &c, "r", &[slot("a/b")]).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &c, &started("r/a", "b", "x1", 1, &[])).await);
    assert_eq!(
        code(ingest(&app, &c, &started("r", "a/b", "x1", 1, &[])).await),
        ErrorCode::RevisionConflict
    );
    t.drop().await;
}

/// R1-3: a profile named `unknown` (customized pack) keeps the exit-code check.
#[tokio::test]
async fn r3_3_reserved_looking_profiles_keep_the_exit_check() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let mut rec = report("r1", "s1", "a1", 1, 1, &pass, &[]);
    rec["evidence"]["completion"]["profile"] = json!("unknown");
    rec["result"]["runner"]["termination"]["exit_code"] = json!(1);
    ok(ingest(&app, &c, &rec).await);
    assert_ne!(state(&read(&app, pid, "r1").await, "s1")["state"], "passed");
    t.drop().await;
}

/// New in r3: retention and manifest writes that need the trust gate never deadlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r3_retention_and_manifest_writes_share_one_lock_order() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    for i in 0..6 {
        let r = format!("live{i}");
        ok(app.create_regression(&c, &regression(&r)).await);
    }
    let later = time::OffsetDateTime::now_utc() + time::Duration::days(1);
    for i in 0..6 {
        let r = format!("live{i}");
        let ch = chunk(&[built_slot("s1"), built_slot("s2")]);
        let (w, ret) = tokio::join!(
            app.manifest_chunk(&c, &r, 1, &ch),
            retention::run(&t.pool, later, Policy::default(), false)
        );
        ok(w);
        assert!(ret.is_ok(), "{ret:?}");
        ok(app
            .manifest_seal(&c, &r, &seal(&[built_slot("s1"), built_slot("s2")]))
            .await);
        let amend = json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2,
                           "add": [built_slot("s3")]});
        let (w, ret) = tokio::join!(
            app.manifest_amend(&c, &r, &amend),
            retention::run(&t.pool, later, Policy::default(), false)
        );
        ok(w);
        assert!(ret.is_ok(), "{ret:?}");
    }
    t.drop().await;
}
