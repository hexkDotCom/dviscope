//! Regression test: upgrading a database whose
//! receipts and payloads retention already thinned keeps every known identity bound.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_server::db::MIGRATIONS;
use serde_json::json;

#[tokio::test]
async fn r4_upgrade_binds_historical_identities() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2"), slot("s3")]).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    for (s, a, ev) in [("s1", "a1", &fail), ("s2", "a2", &pass)] {
        ok(ingest(&app, &c, &started("r1", s, a, 1, &[])).await);
        ok(ingest(&app, &c, &report("r1", s, a, 1, 1, ev, &[])).await);
    }
    // The state of a database from before the bindings, after retention thinned it:
    // a1's receipts expired and its payload expired; a2's receipts expired, payload kept.
    let exec = |sql: &'static str| {
        let pool = t.pool.clone();
        async move {
            sqlx::raw_sql(sql)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
    };
    exec("DELETE FROM report_bindings").await;
    exec("DELETE FROM attempt_bindings").await;
    exec(
        "INSERT INTO expired_receipts (project_id, producer_id, identity, max_revision, expired_at)
         SELECT project_id, producer_id, identity, max(revision), now() FROM receipts
          WHERE identity LIKE '%a1%' OR identity LIKE '%a2%' GROUP BY 1, 2, 3",
    )
    .await;
    exec("DELETE FROM receipts WHERE identity LIKE '%a1%' OR identity LIKE '%a2%'").await;
    exec(
        "DELETE FROM attempt_reports p USING attempts a
          WHERE a.id = p.attempt_id AND a.attempt_ref = 'a1'",
    )
    .await;
    // The upgrade.
    for (_, _, sql) in MIGRATIONS.iter().filter(|(v, _, _)| (6..=7).contains(v)) {
        sqlx::raw_sql(*sql)
            .execute(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    // a1's report, whose parent cannot be recovered, is refused for good (any parent).
    ok(ingest(&app, &c, &started("r1", "s3", "a9", 1, &[])).await);
    let mut moved = report("r1", "s3", "a9", 1, 2, &pass, &[]);
    moved["report_id"] = json!("a1:r1");
    assert_eq!(
        code(ingest(&app, &c, &moved).await),
        ErrorCode::RevisionConflict
    );
    // a2's report was recovered from its payload: a correction of the same attempt is
    // accepted, the same report naming another attempt is not.
    let mut other = report("r1", "s3", "a9", 1, 2, &pass, &[]);
    other["report_id"] = json!("a2:r1");
    assert_eq!(
        code(ingest(&app, &c, &other).await),
        ErrorCode::RevisionConflict
    );
    let mut corr = report("r1", "s2", "a2", 1, 2, &pass, &[]);
    corr["result"]["outcome_reported"] = json!("pass");
    ok(ingest(&app, &c, &corr).await);
    t.drop().await;
}

/// Rounds 5 to 7: a producer that lost regressions to retention before the binding
/// backfill completed (after 0004, before 0006) is retired — also for a database already
/// upgraded with the first version of the boundary (migration 0008), through the normal
/// migration runner. Other producers stay usable.
#[tokio::test]
async fn r5_upgrade_retires_namespaces_with_unrecoverable_identities() {
    let Some(t) = TestDb::new_at(8).await else {
        return;
    };
    let app = t.app();
    project(&t.pool).await;
    dviscope_server::admin::create_producer(&t.pool, "p1", "fresh")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (c, _) = collector(&t.pool).await;
    // The staged history: 0004 applied, retention removed a regression of `pilot`, the
    // backfill (0006) ran later. Migration 0008 (as released) did not retire `pilot`.
    sqlx::raw_sql(
        "UPDATE schema_migrations SET applied_at = applied_at + interval '1 hour' WHERE version >= 6;
         INSERT INTO expired_regressions (project_id, producer_id, ref, expired_at)
         SELECT p.project_id, p.id, 'gone', m.applied_at + interval '1 minute'
           FROM producers p, schema_migrations m WHERE p.name = 'pilot' AND m.version = 4",
    )
    .execute(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let retired = |name: &'static str| {
        let pool = t.pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT retired_at IS NOT NULL FROM producers WHERE name = $1",
            )
            .bind(name)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
        }
    };
    assert!(!retired("pilot").await, "the round-6 state");
    assert!(
        !dviscope_server::db::schema_ready(&t.pool)
            .await
            .unwrap_or(true)
    );
    // The upgrade, through the runner (0008's checksum is unchanged; 0009 applies).
    let applied = dviscope_server::db::migrate(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(applied.contains(&9), "{applied:?}");
    assert!(
        dviscope_server::db::schema_ready(&t.pool)
            .await
            .unwrap_or(false)
    );
    assert!(retired("pilot").await);
    assert!(!retired("fresh").await);
    assert_eq!(
        code(app.create_source_manifest(&c, &source_manifest()).await),
        ErrorCode::Expired
    );
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let tok = dviscope_server::admin::issue_token(&t.pool, "p1", "fresh", &scopes, 1, "f")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let f = dviscope_server::auth::actor_from_token(&t.pool, tok["token"].as_str().unwrap_or(""))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut sm = source_manifest();
    sm["producer_id"] = json!("fresh");
    ok(app.create_source_manifest(&f, &sm).await);
    t.drop().await;
}

/// A legacy tombstone carrying retention's evaluation clock (here in the future)
/// cannot be ordered against the backfill: its producer is retired at the upgrade. From
/// then on, tombstones record the database time of the deletion.
#[tokio::test]
async fn r8_ambiguous_legacy_tombstones_retire_their_producer() {
    let Some(t) = TestDb::new_at(9).await else {
        return;
    };
    let app = t.app();
    project(&t.pool).await;
    dviscope_server::admin::create_producer(&t.pool, "p1", "fresh")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let (c, _) = collector(&t.pool).await;
    sqlx::raw_sql(
        "INSERT INTO expired_regressions (project_id, producer_id, ref, expired_at)
         SELECT project_id, id, 'gone', '2030-01-01T00:00:00Z' FROM producers WHERE name = 'pilot'",
    )
    .execute(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let applied = dviscope_server::db::migrate(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(applied.contains(&10), "{applied:?}");
    assert_eq!(
        code(app.create_source_manifest(&c, &source_manifest()).await),
        ErrorCode::Expired
    );
    // A retention run with a far clock records the real deletion time.
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let tok = dviscope_server::admin::issue_token(&t.pool, "p1", "fresh", &scopes, 1, "f")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let f = dviscope_server::auth::actor_from_token(&t.pool, tok["token"].as_str().unwrap_or(""))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut sm = source_manifest();
    sm["producer_id"] = json!("fresh");
    ok(app.create_source_manifest(&f, &sm).await);
    let mut reg = regression("old");
    reg["producer_id"] = json!("fresh");
    ok(app.create_regression(&f, &reg).await);
    let far = time::OffsetDateTime::now_utc() + time::Duration::days(3 * 365);
    dviscope_server::retention::run(
        &t.pool,
        far,
        dviscope_server::retention::Policy::default(),
        false,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let recent: bool = sqlx::query_scalar(
        "SELECT expired_at < now() + interval '1 minute' FROM expired_regressions WHERE ref = 'old'",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        recent,
        "the tombstone records the database time, not the evaluation clock"
    );
    t.drop().await;
}
