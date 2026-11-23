//! Demo generators under injected failure (its own test binary: the fail point is
//! process-wide, so no other demo test may run beside it) and under maintenance.

mod common;

use common::*;
use time::OffsetDateTime;

/// A failure right after the token is issued (before the generator's identity is resolved)
/// still revokes it; under maintenance no demo is written.
#[tokio::test]
async fn demo_generation_failing_early_or_in_maintenance() {
    let Some(t) = TestDb::new().await else { return };
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    dviscope_server::app::fail::arm(Some("demo_generator"));
    let r = dviscope_server::demo_soc::generate(&t.pool, "early-soc", now).await;
    dviscope_server::app::fail::arm(None);
    assert!(r.is_err());
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_tokens WHERE revoked_at IS NULL AND expires_at > now()",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap_or(-1);
    assert_eq!(
        live, 0,
        "revoked although generation failed before resolving its identity"
    );
    dviscope_server::backup::set_maintenance(&t.pool, true, "test")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        dviscope_server::demo_soc::generate(&t.pool, "maint-soc", now)
            .await
            .is_err()
    );
    let made: i64 = sqlx::query_scalar("SELECT count(*) FROM projects WHERE name = 'maint-soc'")
        .fetch_one(&t.pool)
        .await
        .unwrap_or(-1);
    assert_eq!(made, 0);
    t.drop().await;
}
