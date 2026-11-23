//! Provisioning (`dviscope-server admin …`, documented in `docs/operate.md`): run on the
//! server host against the database, audited. Secrets are shown once (tokens) or read
//! from a file or standard input (passwords), never taken from the command line.

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};
use sqlx::{PgPool, Row as _};

use crate::auth;

async fn audit_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    action: &str,
    object: &str,
    detail: Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit (actor, action, object, detail) VALUES ('admin-cli', $1, $2, $3)",
    )
    .bind(action)
    .bind(object)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A data-changing admin transaction: past the maintenance gate (refused in maintenance;
/// only credential recovery runs then), so a command that passed an earlier check cannot
/// write after `maintenance on` returned.
async fn write_tx(db: &PgPool) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    crate::app::begin_write(db)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message))
}

/// A transaction holding the trust gate shared: trust-state changes (quarantine, pipelines)
/// never land in the middle of a retention decision.
async fn gated(db: &PgPool) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(crate::app::TRUST_GATE)
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn project_id(db: &PgPool, project: &str) -> Result<i64> {
    Ok(sqlx::query("SELECT id FROM projects WHERE name = $1")
        .bind(project)
        .fetch_optional(db)
        .await?
        .with_context(|| format!("no project {project}"))?
        .get(0))
}

/// Creates a project.
///
/// # Errors
/// Invalid name, duplicate, database errors.
pub async fn create_project(db: &PgPool, name: &str, policy: &str) -> Result<Value> {
    if !["strict", "retry-pass-accepted"].contains(&policy) {
        bail!("policy is strict or retry-pass-accepted");
    }
    let mut tx = write_tx(db).await?;
    let id: i64 = sqlx::query("INSERT INTO projects (name, policy) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(policy)
        .fetch_one(&mut *tx)
        .await
        .context("creating the project (names: lower-case letters, digits, '-', '_')")?
        .get(0);
    sqlx::query("INSERT INTO project_heads (project_id) VALUES ($1)")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit_tx(&mut tx, "project.create", name, json!({"policy": policy})).await?;
    tx.commit().await?;
    Ok(json!({"project": name, "id": id}))
}

/// Creates a producer namespace in a project.
///
/// # Errors
/// Unknown project, duplicate, database errors.
pub async fn create_producer(db: &PgPool, project: &str, name: &str) -> Result<Value> {
    let pid = project_id(db, project).await?;
    dviscope_model::ids::ExternalKey::try_from(name.to_string())
        .map_err(|e| anyhow::anyhow!("producer name: {e:?}"))?;
    let mut tx = write_tx(db).await?;
    sqlx::query("INSERT INTO producers (project_id, name) VALUES ($1, $2)")
        .bind(pid)
        .bind(name)
        .execute(&mut *tx)
        .await
        .context("creating the producer")?;
    audit_tx(
        &mut tx,
        "producer.create",
        &format!("{project}/{name}"),
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"project": project, "producer": name}))
}

/// Issues a collector token (shown once).
///
/// # Errors
/// Unknown project or producer, unknown scope, expiry beyond a year, database errors.
pub async fn issue_token(
    db: &PgPool,
    project: &str,
    producer: &str,
    scopes: &[String],
    days: u32,
    label: &str,
) -> Result<Value> {
    if !(1..=366).contains(&days) {
        bail!("a token expires within a year (1..=366 days)");
    }
    if let Some(s) = scopes.iter().find(|s| !auth::SCOPES.contains(&s.as_str())) {
        bail!("unknown scope {s} (known: {})", auth::SCOPES.join(", "));
    }
    let pid = project_id(db, project).await?;
    let prod: i64 = sqlx::query("SELECT id FROM producers WHERE project_id = $1 AND name = $2")
        .bind(pid)
        .bind(producer)
        .fetch_optional(db)
        .await?
        .with_context(|| format!("no producer {producer} in {project}"))?
        .get(0);
    let token = auth::new_token().map_err(|e| anyhow::anyhow!("{}", e.message))?;
    // The credential and its audit record commit together (B.17).
    let mut tx = db.begin().await?;
    let id: i64 = sqlx::query(
        "INSERT INTO api_tokens (hash, kind, project_id, producer_id, scopes, label, expires_at)
         VALUES ($1, 'collector', $2, $3, $4, $5, now() + make_interval(days => $6)) RETURNING id",
    )
    .bind(auth::token_hash(&token))
    .bind(pid)
    .bind(prod)
    .bind(scopes)
    .bind(label)
    .bind(i32::try_from(days)?)
    .fetch_one(&mut *tx)
    .await?
    .get(0);
    audit_tx(
        &mut tx,
        "token.issue",
        &format!("token:{id}"),
        json!({"project": project, "producer": producer, "scopes": scopes, "days": days}),
    )
    .await?;
    tx.commit().await?;
    Ok(
        json!({"token_id": id, "token": token, "note": "shown once: store it in the collector's token_file"}),
    )
}

/// Issues a personal token for a user (printed once). It acts with the user's current
/// roles on every request, so a role change applies at once.
///
/// # Errors
/// Unknown user, expiry beyond a year, database errors.
pub async fn issue_personal_token(
    db: &PgPool,
    username: &str,
    days: u32,
    label: &str,
) -> Result<Value> {
    if !(1..=366).contains(&days) {
        bail!("a token expires within a year (1..=366 days)");
    }
    let uid: i64 = sqlx::query("SELECT id FROM users WHERE username = $1 AND NOT disabled")
        .bind(username)
        .fetch_optional(db)
        .await?
        .with_context(|| format!("no active user {username}"))?
        .get(0);
    let token = auth::new_token().map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let mut tx = db.begin().await?;
    let id: i64 = sqlx::query(
        "INSERT INTO api_tokens (hash, kind, user_id, label, expires_at)
         VALUES ($1, 'personal', $2, $3, now() + make_interval(days => $4)) RETURNING id",
    )
    .bind(auth::token_hash(&token))
    .bind(uid)
    .bind(label)
    .bind(i32::try_from(days)?)
    .fetch_one(&mut *tx)
    .await?
    .get(0);
    audit_tx(
        &mut tx,
        "token.issue_personal",
        &format!("token:{id}"),
        json!({"user": username, "days": days}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"token_id": id, "token": token, "note": "shown once"}))
}

/// Revokes a token.
///
/// # Errors
/// Unknown token, database errors.
pub async fn revoke_token(db: &PgPool, id: i64) -> Result<Value> {
    let mut tx = db.begin().await?;
    let n = sqlx::query(
        "UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 0 {
        bail!("no active token {id}");
    }
    audit_tx(&mut tx, "token.revoke", &format!("token:{id}"), json!({})).await?;
    tx.commit().await?;
    Ok(json!({"revoked": id}))
}

/// Quarantines a token from a receipt time on: every revision it delivered
/// since then is a settlement barrier (never a pass) until released. The token is also
/// revoked, so it delivers nothing more.
///
/// # Errors
/// Unknown token, an unparseable time, database errors.
pub async fn quarantine_token(db: &PgPool, id: i64, since: &str) -> Result<Value> {
    let t = time::OffsetDateTime::parse(since, &time::format_description::well_known::Rfc3339)
        .context("--since is an RFC 3339 time, e.g. 2026-11-08T00:00:00Z")?;
    let mut tx = gated(db).await?;
    let n = sqlx::query(
        "UPDATE api_tokens SET quarantined_since = $2, revoked_at = coalesce(revoked_at, now())
          WHERE id = $1",
    )
    .bind(id)
    .bind(t)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 0 {
        bail!("no token {id}");
    }
    bump_token_project(&mut tx, id, "quarantine").await?;
    audit_tx(
        &mut tx,
        "token.quarantine",
        &format!("token:{id}"),
        json!({"since": since}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"quarantined": id, "since": since}))
}

/// Advances the watermark of a token's project (quarantine changes eligibility).
async fn bump_token_project(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: i64,
    kind: &str,
) -> Result<()> {
    let pid: Option<i64> = sqlx::query_scalar("SELECT project_id FROM api_tokens WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .flatten();
    if let Some(pid) = pid {
        crate::app::decisions::bump_project(tx, pid, kind, &format!("token:{id}"))
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.message))?;
    }
    Ok(())
}

/// Releases a quarantine: the token's revisions count again (the token stays revoked).
///
/// # Errors
/// Unknown token, database errors.
pub async fn release_token(db: &PgPool, id: i64) -> Result<Value> {
    let mut tx = gated(db).await?;
    let n = sqlx::query(
        "UPDATE api_tokens SET quarantined_since = NULL WHERE id = $1 AND quarantined_since IS NOT NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 0 {
        bail!("token {id} is not quarantined");
    }
    bump_token_project(&mut tx, id, "release").await?;
    audit_tx(&mut tx, "token.release", &format!("token:{id}"), json!({})).await?;
    tx.commit().await?;
    Ok(json!({"released": id}))
}

/// Accepts (or withdraws) a pipeline digest for a project.
///
/// # Errors
/// Unknown project, malformed digest, database errors.
pub async fn set_pipeline(db: &PgPool, project: &str, digest: &str, state: &str) -> Result<Value> {
    let pid = project_id(db, project).await?;
    serde_json::from_value::<dviscope_model::canonical::Digest>(json!(digest))
        .map_err(|_| anyhow::anyhow!("a pipeline digest is sha256:<64 hex>"))?;
    // Maintenance gate first, then the trust gate (the order of every app write).
    let mut tx = write_tx(db).await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(crate::app::TRUST_GATE)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO pipelines (project_id, digest, state) VALUES ($1, $2, $3)
         ON CONFLICT (project_id, digest) DO UPDATE SET state = EXCLUDED.state, changed_at = now()",
    )
    .bind(pid)
    .bind(digest)
    .bind(state)
    .execute(&mut *tx)
    .await?;
    crate::app::decisions::bump_project(&mut tx, pid, "pipeline", &format!("pipeline:{digest}"))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message))?;
    audit_tx(
        &mut tx,
        &format!("pipeline.{state}"),
        &format!("{project}/{digest}"),
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"project": project, "pipeline": digest, "state": state}))
}

/// Creates a local user with a password (read by the caller from a file or stdin).
///
/// # Errors
/// Password too short, duplicate user, database errors.
pub async fn create_user(db: &PgPool, username: &str, password: &str) -> Result<Value> {
    let phc = auth::hash_password(password).map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let mut tx = write_tx(db).await?;
    let id: i64 = sqlx::query("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(username)
        .fetch_one(&mut *tx)
        .await
        .context("creating the user")?
        .get(0);
    sqlx::query("INSERT INTO local_credentials (user_id, phc) VALUES ($1, $2)")
        .bind(id)
        .bind(phc)
        .execute(&mut *tx)
        .await?;
    audit_tx(&mut tx, "user.create", username, json!({})).await?;
    tx.commit().await?;
    Ok(json!({"user": username, "id": id}))
}

/// Sets a user's role in a project.
///
/// # Errors
/// Unknown project, user or role, database errors.
pub async fn set_member(db: &PgPool, project: &str, username: &str, role: &str) -> Result<Value> {
    if !["viewer", "triager", "admin"].contains(&role) {
        bail!("role is viewer, triager or admin");
    }
    let pid = project_id(db, project).await?;
    let uid: i64 = sqlx::query("SELECT id FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await?
        .with_context(|| format!("no user {username}"))?
        .get(0);
    let mut tx = write_tx(db).await?;
    sqlx::query(
        "INSERT INTO memberships (project_id, user_id, role) VALUES ($1, $2, $3)
         ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(pid)
    .bind(uid)
    .bind(role)
    .execute(&mut *tx)
    .await?;
    audit_tx(
        &mut tx,
        "member.set",
        &format!("{project}/{username}"),
        json!({"role": role}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"project": project, "user": username, "role": role}))
}
