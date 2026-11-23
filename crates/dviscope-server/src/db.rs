//! Database access: connection pool and forward-only migrations applied under
//! an exclusive advisory lock with immutable checksums. Queries take the caller's
//! transaction and never commit on their own.

use anyhow::{Context as _, Result, bail};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row as _};

/// Embedded migrations: (version, name, SQL).
pub const MIGRATIONS: &[(i32, &str, &str)] = &[
    (1, "init", include_str!("../migrations/0001_init.sql")),
    (
        2,
        "retention",
        include_str!("../migrations/0002_retention.sql"),
    ),
    (
        3,
        "build_pipeline",
        include_str!("../migrations/0003_build_pipeline.sql"),
    ),
    (
        4,
        "bindings",
        include_str!("../migrations/0004_bindings.sql"),
    ),
    (
        5,
        "decisions",
        include_str!("../migrations/0005_decisions.sql"),
    ),
    (
        6,
        "backfill_bindings",
        include_str!("../migrations/0006_backfill_bindings.sql"),
    ),
    (
        7,
        "backfill_history",
        include_str!("../migrations/0007_backfill_history.sql"),
    ),
    (
        8,
        "retire_unbindable",
        include_str!("../migrations/0008_retire_unbindable.sql"),
    ),
    (
        9,
        "retire_boundary",
        include_str!("../migrations/0009_retire_boundary.sql"),
    ),
    (
        10,
        "retire_ambiguous",
        include_str!("../migrations/0010_retire_ambiguous.sql"),
    ),
    (
        11,
        "publications",
        include_str!("../migrations/0011_publications.sql"),
    ),
    (
        12,
        "checklists",
        include_str!("../migrations/0012_checklists.sql"),
    ),
    (
        13,
        "removal_credentials",
        include_str!("../migrations/0013_removal_credentials.sql"),
    ),
    (
        14,
        "trusted_receipt_times",
        include_str!("../migrations/0014_trusted_receipt_times.sql"),
    ),
    (
        15,
        "rebuild_candidates",
        include_str!("../migrations/0015_rebuild_candidates.sql"),
    ),
    (
        16,
        "index_receipt_bound",
        include_str!("../migrations/0016_index_receipt_bound.sql"),
    ),
    (
        17,
        "index_removals",
        include_str!("../migrations/0017_index_removals.sql"),
    ),
    (18, "rules", include_str!("../migrations/0018_rules.sql")),
    (
        19,
        "maintenance",
        include_str!("../migrations/0019_maintenance.sql"),
    ),
    (20, "health", include_str!("../migrations/0020_health.sql")),
    (
        21,
        "growth_index",
        include_str!("../migrations/0021_growth_index.sql"),
    ),
    (
        22,
        "receipt_aliases",
        include_str!("../migrations/0022_receipt_aliases.sql"),
    ),
    (
        23,
        "final_review_repairs",
        include_str!("../migrations/0023_final_review_repairs.sql"),
    ),
];

/// Advisory lock key of the migration runner.
const MIGRATION_LOCK: i64 = 0x4456_4953_434f_5045; // "DVISCOPE"

/// Opens a pool. `statement_timeout` applies to every connection.
///
/// # Errors
/// Invalid URL or connection failure.
pub async fn connect(url: &str, max: u32, statement_timeout_ms: u64) -> Result<PgPool> {
    let opts: PgConnectOptions = url.parse().context("database URL")?;
    let timeout = statement_timeout_ms.to_string();
    let opts = opts.options([("statement_timeout", timeout.as_str())]);
    PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect_with(opts)
        .await
        .context("connecting to PostgreSQL")
}

fn checksum(sql: &str) -> String {
    hex::encode(Sha256::digest(sql.as_bytes()))
}

/// Applies pending migrations (idempotent). A changed checksum of an applied migration is
/// an error (migrations are immutable).
///
/// # Errors
/// Database errors or a checksum mismatch.
pub async fn migrate(pool: &PgPool) -> Result<Vec<i32>> {
    migrate_to(pool, i32::MAX).await
}

/// Applies pending migrations up to `upto` (inclusive): upgrade tests stage a database at
/// an earlier release this way.
///
/// # Errors
/// Database errors or a checksum mismatch.
pub async fn migrate_to(pool: &PgPool, upto: i32) -> Result<Vec<i32>> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(MIGRATION_LOCK)
        .execute(&mut *conn)
        .await?;
    let result = async {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        )
        .execute(&mut *conn)
        .await?;
        let mut applied = vec![];
        for (version, name, sql) in MIGRATIONS.iter().filter(|m| m.0 <= upto) {
            let row = sqlx::query("SELECT checksum FROM schema_migrations WHERE version = $1")
                .bind(version)
                .fetch_optional(&mut *conn)
                .await?;
            match row {
                Some(r) => {
                    let stored: String = r.get(0);
                    if stored != checksum(sql) {
                        bail!("migration {version} ({name}) changed after it was applied");
                    }
                }
                None => {
                    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
                    sqlx::raw_sql(*sql).execute(&mut *tx).await.with_context(|| format!("migration {version} ({name})"))?;
                    sqlx::query("INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)")
                        .bind(version)
                        .bind(*name)
                        .bind(checksum(sql))
                        .execute(&mut *tx)
                        .await?;
                    tx.commit().await?;
                    applied.push(*version);
                }
            }
        }
        Ok::<_, anyhow::Error>(applied)
    }
    .await;
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_LOCK)
        .execute(&mut *conn)
        .await?;
    result
}

/// Whether the schema is at the version this binary expects (readiness).
///
/// # Errors
/// Database errors.
pub async fn schema_ready(pool: &PgPool) -> Result<bool> {
    // Every migration of this binary applied, each with its own checksum (not merely the
    // highest version: a changed or skipped migration is not this schema).
    let Ok(rows) = sqlx::query("SELECT version, checksum FROM schema_migrations ORDER BY version")
        .fetch_all(pool)
        .await
    else {
        return Ok(false);
    };
    let applied: Vec<(i32, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    let expected: Vec<(i32, String)> = MIGRATIONS
        .iter()
        .map(|(v, _, sql)| (*v, checksum(sql)))
        .collect();
    Ok(applied == expected)
}
