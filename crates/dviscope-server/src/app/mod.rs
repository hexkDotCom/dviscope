//! Application operations: every operation authorizes, runs in one
//! transaction, serializes on the subject head (`SELECT … FOR UPDATE`), answers a replay
//! with the original receipt, and writes its receipt in the same transaction as its
//! effect. Derived slot states are computed at read time, never stored (B.7.4).

pub mod browse;
pub mod checklists;
pub mod decisions;
pub mod fail;
pub mod health;
pub mod ingest;
pub mod ledger;
pub mod publications;
pub mod read;
pub mod readiness;
pub mod reconcile;
pub mod regression;
pub mod rules;

use dviscope_model::canonical::canonical_json;
use dviscope_model::errors::ErrorCode;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row as _, Transaction};

use crate::auth::{Action, Actor, authorize};
use crate::error::AppError;

/// The application: a database pool. Handlers call one operation per request (per record
/// for ingest).
#[derive(Debug, Clone)]
pub struct App {
    /// Pool.
    pub db: PgPool,
}

/// A collector acting for one producer of one project.
#[derive(Debug, Clone)]
pub struct Producer {
    /// Project.
    pub project_id: i64,
    /// Producer row.
    pub producer_id: i64,
    /// Producer name (the `producer_id` of records).
    pub name: String,
    /// Credential recorded with every effect (quarantine, B.17).
    pub credential_id: i64,
}

/// The answer of a write: the receipt, and whether it was a replay.
#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    /// Receipt body (`docs/journal.md`): identity, revision, digest, result, server IDs.
    pub body: Value,
    /// `true` for a replay of an earlier effect.
    pub duplicate: bool,
}

/// A producer-supplied value made safe to interpolate into text people copy (a terminal,
/// a ticket): control characters (line breaks, escapes) and Unicode direction controls
/// become U+FFFD, so a value can neither start a new line nor reorder or recolor the text.
#[must_use]
pub fn plain_text(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control()
                || matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
            {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// SHA-256 (hex) of the canonical JSON of a record as received: the payload digest the
/// client computed (`docs/journal.md`).
///
/// # Errors
/// A value that has no canonical form.
pub fn payload_digest(v: &Value) -> Result<String, AppError> {
    let c = canonical_json(v)
        .map_err(|e| AppError::new(ErrorCode::Invalid, format!("not canonicalizable: {e}")))?;
    Ok(hex::encode(Sha256::digest(c.as_bytes())))
}

/// Parses a record body into its type (unknown members rejected).
///
/// # Errors
/// 400 naming the first problem.
pub fn parse<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, AppError> {
    serde_json::from_value(v.clone()).map_err(|e| {
        AppError::new(
            ErrorCode::Invalid,
            format!(
                "invalid record: {}",
                e.to_string().lines().next().unwrap_or_default()
            ),
        )
    })
}

/// Checks the record's schema identifier against the families this server accepts.
///
/// # Errors
/// 400 `E_SCHEMA_VERSION`.
pub fn check_schema(schema: &str, family: &str) -> Result<(), AppError> {
    if dviscope_model::schema::ALL.contains(&schema) && schema.starts_with(family) {
        Ok(())
    } else {
        Err(AppError::field(
            ErrorCode::SchemaVersion,
            format!("schema {schema} is not accepted here"),
            "schema",
        ))
    }
}

impl App {
    /// Resolves the collector behind `actor` for `action`, and checks the record's producer
    /// namespace (when the record names one) is the token's.
    ///
    /// # Errors
    /// 403 for users, other projects, missing scopes or another producer's records.
    pub async fn producer(
        &self,
        actor: &Actor,
        action: Action,
        record_producer: Option<&str>,
    ) -> Result<Producer, AppError> {
        let Actor::Collector {
            project_id,
            producer_id,
            ..
        } = actor
        else {
            return Err(AppError::new(
                ErrorCode::Forbidden,
                "only collector tokens submit records",
            ));
        };
        authorize(actor, action, *project_id)?;
        let row = sqlx::query(
            "SELECT name, retired_at IS NOT NULL FROM producers WHERE project_id = $1 AND id = $2",
        )
        .bind(project_id)
        .bind(producer_id)
        .fetch_one(&self.db)
        .await?;
        let name: String = row.get(0);
        if row.get::<bool, _>(1) {
            // Its identities could not all be bound at the upgrade: never reused.
            return Err(AppError::new(
                ErrorCode::Expired,
                "this producer namespace is retired: create a new producer and token",
            ));
        }
        if record_producer.is_some_and(|r| r != name) {
            return Err(AppError::field(
                ErrorCode::Forbidden,
                "the record names another producer than the token's",
                "producer_id",
            ));
        }
        Ok(Producer {
            project_id: *project_id,
            producer_id: *producer_id,
            name,
            credential_id: actor.credential_id(),
        })
    }
}

/// Earlier development revisions in which a source manifest meant exactly what it means in
/// this build (its wire type unchanged; reviewed per revision).
pub const SOURCE_MANIFEST_COMPATIBLE: &[u32] = &[2];

/// The digests a source manifest body had under [`SOURCE_MANIFEST_COMPATIBLE`] revisions:
/// only its root `schema` label (`dviscope.ingest/1.0-dev.N`) set back. A nightly that
/// declares the same manifest by reference before and after a coordinated upgrade sends
/// the same content: a duplicate, not a conflict. No other record type is compared across
/// revisions.
#[must_use]
pub fn source_manifest_compat_digests(body: &Value) -> Vec<String> {
    use dviscope_model::schema::{DEV_REVISION, INGEST};
    if body.get("schema").and_then(Value::as_str) != Some(INGEST) {
        return vec![];
    }
    let base = INGEST.trim_end_matches(&format!("/1.0-dev.{DEV_REVISION}"));
    SOURCE_MANIFEST_COMPATIBLE
        .iter()
        .filter(|k| **k < DEV_REVISION)
        .filter_map(|k| {
            let mut v = body.clone();
            v["schema"] = json!(format!("{base}/1.0-dev.{k}"));
            payload_digest(&v).ok()
        })
        .collect()
}

/// The replay check of B.3, in order: identical identity + revision + digest (or one of
/// `also`, the digests the caller declares equivalent: [`source_manifest_compat_digests`]
/// only) → the original receipt (`duplicate`); same revision, other digest → 409
/// `E_REVISION_CONFLICT`; a revision below the newest seen that was never seen → 409
/// `E_STALE_REVISION`.
///
/// # Errors
/// The two conflicts above, or a database error.
pub async fn replay(
    tx: &mut Transaction<'_, Postgres>,
    p: &Producer,
    identity: &str,
    revision: i32,
    digest: &str,
    also: &[String],
) -> Result<Option<Receipt>, AppError> {
    lock_identity(tx, p, identity).await?;
    let row = sqlx::query(
        "SELECT digest, receipt FROM receipts
          WHERE project_id = $1 AND producer_id = $2 AND identity = $3 AND revision = $4",
    )
    .bind(p.project_id)
    .bind(p.producer_id)
    .bind(identity)
    .bind(revision)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(r) = row {
        let stored: String = r.get(0);
        if stored == digest || also.contains(&stored) {
            let mut body: Value = r.get(1);
            body["result"] = json!("duplicate");
            // An equivalent body (an earlier compatible label) is acknowledged with the
            // digest of the body sent: the collector checks the receipt names its record.
            body["digest"] = json!(digest);
            return Ok(Some(Receipt {
                body,
                duplicate: true,
            }));
        }
        return Err(AppError::new(
            ErrorCode::RevisionConflict,
            format!("{identity} revision {revision} was received with other content"),
        ));
    }
    let newest: Option<i32> = sqlx::query(
        "SELECT max(revision) FROM receipts
          WHERE project_id = $1 AND producer_id = $2 AND identity = $3",
    )
    .bind(p.project_id)
    .bind(p.producer_id)
    .bind(identity)
    .fetch_one(&mut **tx)
    .await?
    .get(0);
    if newest.is_some_and(|n| revision < n) {
        return Err(AppError::new(
            ErrorCode::StaleRevision,
            format!("{identity}: a newer revision than {revision} exists"),
        ));
    }
    replay_expired(tx, p, identity, revision).await?;
    Ok(None)
}

/// A record whose receipt passed the deduplication horizon (a tombstone remembers it) can
/// no longer be told from a new one: 410 `E_REPLAY_EXPIRED`. A newer revision is new.
///
/// # Errors
/// The expired replay, or a database error.
pub async fn replay_expired(
    tx: &mut Transaction<'_, Postgres>,
    p: &Producer,
    identity: &str,
    revision: i32,
) -> Result<(), AppError> {
    let max: Option<i32> = sqlx::query(
        "SELECT max_revision FROM expired_receipts
          WHERE project_id = $1 AND producer_id = $2 AND identity = $3",
    )
    .bind(p.project_id)
    .bind(p.producer_id)
    .bind(identity)
    .fetch_optional(&mut **tx)
    .await?
    .map(|r| r.get(0));
    if max.is_some_and(|m| revision <= m) {
        return Err(AppError::new(
            ErrorCode::ReplayExpired,
            format!("{identity} revision {revision} is older than the deduplication horizon"),
        ));
    }
    Ok(())
}

/// Serializes every write of one record identity (transaction-scoped advisory lock), so
/// two identical deliveries in flight never both miss the receipt: the second one waits
/// and then answers the first one's receipt.
///
/// # Errors
/// Database errors.
pub async fn lock_identity(
    tx: &mut Transaction<'_, Postgres>,
    p: &Producer,
    identity: &str,
) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7))")
        .bind(format!("{}/{}/{identity}", p.project_id, p.producer_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// The trust gate: retention decides and deletes holding it exclusively; every write that
/// can change what retention reads across regressions (build records, build references,
/// slots requiring builds, quarantine, pipeline acceptance) holds it shared. Shared holders
/// never wait for each other.
pub const TRUST_GATE: i64 = 0x4456_4953_4741_5445; // "DVISGATE"

/// The maintenance gate: every write transaction holds it shared and then reads
/// the maintenance flag; turning maintenance on takes it exclusively. When `maintenance on`
/// returns, every write that passed the check has committed, and every later one sees the
/// flag and is refused: a maintenance window is a fence, not a hint.
pub const MAINTENANCE_GATE: i64 = 0x4456_4953_4d41_494e; // "DVISMAIN"

/// Passes the maintenance gate inside a write transaction (refused in maintenance). A
/// database before migration 0019 has no maintenance: the gate is open.
///
/// # Errors
/// Maintenance (`E_UNAVAILABLE`), database errors.
pub async fn write_gate(tx: &mut Transaction<'_, Postgres>) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(MAINTENANCE_GATE)
        .execute(&mut **tx)
        .await?;
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('maintenance') IS NOT NULL")
        .fetch_one(&mut **tx)
        .await?;
    if !exists {
        return Ok(());
    }
    let active: Option<bool> = sqlx::query_scalar("SELECT active FROM maintenance")
        .fetch_optional(&mut **tx)
        .await?;
    if active == Some(true) {
        return Err(AppError::new(
            ErrorCode::Unavailable,
            "the server is in maintenance: writes are refused (retry later)",
        ));
    }
    Ok(())
}

/// A write transaction past the maintenance gate.
///
/// # Errors
/// Maintenance (`E_UNAVAILABLE`), database errors.
pub async fn begin_write(db: &PgPool) -> Result<Transaction<'static, Postgres>, AppError> {
    let mut tx = db.begin().await?;
    write_gate(&mut tx).await?;
    Ok(tx)
}

/// Takes the trust gate shared (transaction-scoped).
///
/// # Errors
/// Database errors.
pub async fn gate_shared(tx: &mut Transaction<'_, Postgres>) -> Result<(), AppError> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(TRUST_GATE)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Writes the receipt of a committed effect (same transaction) and returns it.
///
/// # Errors
/// Database errors.
pub async fn commit_receipt(
    tx: &mut Transaction<'_, Postgres>,
    p: &Producer,
    identity: &str,
    revision: i32,
    digest: &str,
    server_ids: Value,
) -> Result<Receipt, AppError> {
    let body = json!({
        "identity": identity,
        "revision": revision,
        "digest": digest,
        "result": "committed",
        "server_ids": server_ids,
    });
    sqlx::query(
        "INSERT INTO receipts (project_id, producer_id, identity, revision, digest, receipt)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(p.project_id)
    .bind(p.producer_id)
    .bind(identity)
    .bind(revision)
    .bind(digest)
    .bind(&body)
    .execute(&mut **tx)
    .await?;
    Ok(Receipt {
        body,
        duplicate: false,
    })
}

/// Bumps the regression's change sequence (cache keys of reads).
///
/// # Errors
/// Database errors.
pub async fn bump(
    tx: &mut Transaction<'_, Postgres>,
    project_id: i64,
    regression_id: i64,
) -> Result<(), AppError> {
    let r: Option<String> = sqlx::query_scalar(
        "UPDATE regressions SET change_seq = change_seq + 1 WHERE project_id = $1 AND id = $2
         RETURNING ref",
    )
    .bind(project_id)
    .bind(regression_id)
    .fetch_optional(&mut **tx)
    .await?;
    // Every evidence change also advances the project watermark that evaluations record.
    decisions::bump_project(
        tx,
        project_id,
        "regression",
        &format!("regression:{}", r.unwrap_or_default()),
    )
    .await?;
    Ok(())
}

/// Appends an audit row.
///
/// # Errors
/// Database errors.
pub async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    actor: &str,
    action: &str,
    object: &str,
    detail: Value,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO audit (actor, action, object, detail) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(action)
        .bind(object)
        .bind(detail)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
