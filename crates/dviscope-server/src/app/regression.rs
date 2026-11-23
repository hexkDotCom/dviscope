//! Regression operations: source manifest
//! and regression creation, manifest chunks, seal, amendments, slot marks and finish. Each
//! runs in one transaction serialized on the regression head (`FOR UPDATE`) and is
//! idempotent by its identity and payload digest.

use std::collections::BTreeSet;

use dviscope_model::canonical::digest_of;
use dviscope_model::errors::ErrorCode;
use dviscope_model::wire::manifest::{
    ManifestAmend, ManifestChunk, ManifestSeal, SlotDecl, SlotMark,
};
use dviscope_model::wire::regression::{RegressionCreate, SourceManifest};
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};

use super::{
    App, Producer, Receipt, bump, check_schema, commit_receipt, parse, payload_digest, replay,
};
use crate::auth::{Action, Actor};
use crate::error::AppError;

/// The regression head, locked for the operation.
#[derive(Debug, Clone)]
pub struct Head {
    /// Row ID.
    pub id: i64,
    /// `unsealed`, `sealed` or `finished`.
    pub state: String,
    /// Whether the manifest was sealed (stays true once finished).
    pub sealed: bool,
    /// Current manifest revision (0 before the seal).
    pub manifest_revision: i32,
    /// The regression's source manifest.
    pub source_manifest_ref: String,
}

/// Locks and returns the regression head of `p`'s producer.
///
/// # Errors
/// 404 when the regression does not exist.
pub async fn lock_head(
    tx: &mut Transaction<'_, Postgres>,
    p: &Producer,
    regression_ref: &str,
) -> Result<Head, AppError> {
    let row = sqlx::query(
        "SELECT id, state, sealed, manifest_revision, source_manifest_ref FROM regressions
          WHERE project_id = $1 AND producer_id = $2 AND ref = $3 FOR UPDATE",
    )
    .bind(p.project_id)
    .bind(p.producer_id)
    .bind(regression_ref)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        let expired = sqlx::query(
            "SELECT 1 FROM expired_regressions WHERE project_id = $1 AND producer_id = $2 AND ref = $3",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(regression_ref)
        .fetch_optional(&mut **tx)
        .await?;
        return Err(if expired.is_some() {
            AppError::field(
                ErrorCode::Expired,
                format!("regression {regression_ref} is past retention"),
                "regression_ref",
            )
        } else {
            AppError::field(
                ErrorCode::NotFound,
                format!("no regression {regression_ref}"),
                "regression_ref",
            )
        });
    };
    Ok(Head {
        id: row.get(0),
        state: row.get(1),
        sealed: row.get(2),
        manifest_revision: row.get(3),
        source_manifest_ref: row.get(4),
    })
}

fn conflict(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::RevisionConflict, msg)
}

fn invalid(msg: impl Into<String>, field: &str) -> AppError {
    AppError::field(ErrorCode::Invalid, msg, field)
}

fn digest_str<T: serde::Serialize>(v: &T) -> Result<String, AppError> {
    digest_of(v)
        .map(|d| d.as_str().to_string())
        .map_err(|e| AppError::new(ErrorCode::Invalid, format!("not canonicalizable: {e}")))
}

/// The build requirement key: digest of the canonical `BuildReqRef`.
///
/// # Errors
/// A value without canonical form.
pub fn build_req_key(r: &dviscope_model::wire::manifest::BuildReqRef) -> Result<String, AppError> {
    digest_str(r)
}

/// Digests of a declared slot: exact execution inputs, and the logical comparison
/// configuration (B.1, `core::execution::config_digest`): the inputs without seed-like
/// arguments, and the build configurations without their source identity.
fn slot_digests(d: &SlotDecl) -> Result<(String, String), AppError> {
    let exec = digest_str(&d.exec_inputs)?;
    let configs = d
        .build_reqs
        .iter()
        .map(|r| dviscope_core::execution::build_config_digest(&r.build_config))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::new(ErrorCode::Invalid, format!("build configuration: {e}")))?;
    let config = dviscope_core::execution::config_digest(
        &d.exec_inputs,
        &configs,
        dviscope_core::execution::DEFAULT_SEED_LIKE,
    )
    .map_err(|e| AppError::new(ErrorCode::Invalid, format!("configuration: {e}")))?;
    Ok((exec, config.as_str().to_string()))
}

async fn insert_slot(
    tx: &mut Transaction<'_, Postgres>,
    project_id: i64,
    regression_id: i64,
    chunk_n: Option<i32>,
    revision: i32,
    d: &SlotDecl,
) -> Result<(), AppError> {
    let (exec, config) = slot_digests(d)?;
    // The caller holds the trust gate (taken before the head lock) when a slot requires
    // builds.
    let reqs: Vec<String> = d
        .build_reqs
        .iter()
        .map(build_req_key)
        .collect::<Result<_, _>>()?;
    let expected = d.expected.as_ref().map(serde_json::to_value).transpose()?;
    let done = sqlx::query(
        "INSERT INTO slots (project_id, regression_id, slot_ref, chunk_n, added_revision, required,
                            test, exec_digest, config_digest, build_reqs, expected, decl)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT (project_id, regression_id, slot_ref) DO NOTHING",
    )
    .bind(project_id)
    .bind(regression_id)
    .bind(d.slot_ref.as_str())
    .bind(chunk_n)
    .bind(revision)
    .bind(d.required)
    .bind(&d.exec_inputs.test)
    .bind(exec)
    .bind(&config)
    .bind(json!(reqs))
    .bind(expected)
    .bind(serde_json::to_value(d)?)
    .execute(&mut **tx)
    .await?;
    if done.rows_affected() == 0 {
        return Err(invalid(
            format!(
                "slot {} is already declared in this regression",
                d.slot_ref.as_str()
            ),
            "slot_ref",
        ));
    }
    // The permanent candidate index of feature mode.
    let decl = serde_json::to_value(d)?;
    let simulator = decl
        .pointer("/build_reqs/0/build_config/simulator/vendor")
        .or_else(|| decl.pointer("/exec_inputs/extra/tool/simulator"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    sqlx::query(
        "INSERT INTO candidate_index (project_id, branch, test, config_digest, simulator,
                                      regression_id, regression_ref, producer_id, started_at,
                                      received_at)
         SELECT r.project_id, r.branch_repository || '/' || r.branch_name, $3, $4, $5, r.id,
                r.ref, r.producer_id, r.started_at, r.received_at
           FROM regressions r WHERE r.project_id = $1 AND r.id = $2
         ON CONFLICT DO NOTHING",
    )
    .bind(project_id)
    .bind(regression_id)
    .bind(&d.exec_inputs.test)
    .bind(&config)
    .bind(simulator)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The manifest digest: SHA-256 of the canonical JSON array of the live slots, sorted by
/// `slot_ref` (`docs/api.md`).
async fn manifest_digest(
    tx: &mut Transaction<'_, Postgres>,
    project_id: i64,
    regression_id: i64,
) -> Result<(i64, String), AppError> {
    let rows = sqlx::query(
        "SELECT decl FROM slots WHERE project_id = $1 AND regression_id = $2
            AND removed_revision IS NULL ORDER BY slot_ref COLLATE \"C\"",
    )
    .bind(project_id)
    .bind(regression_id)
    .fetch_all(&mut **tx)
    .await?;
    let decls: Vec<Value> = rows.iter().map(|r| r.get(0)).collect();
    Ok((decls.len() as i64, digest_str(&decls)?))
}

fn ids(head: &Head) -> Value {
    json!({"regression": head.id})
}

impl App {
    /// `POST /api/v1/source-manifests`.
    ///
    /// # Errors
    /// Authorization, validation, a conflicting replay, database errors.
    pub async fn create_source_manifest(
        &self,
        actor: &Actor,
        body: &Value,
    ) -> Result<Receipt, AppError> {
        let m: SourceManifest = parse(body)?;
        check_schema(&m.schema, "dviscope.ingest/")?;
        let p = self
            .producer(
                actor,
                Action::SourceManifestCreate,
                Some(m.producer_id.as_str()),
            )
            .await?;
        let identity = format!("source_manifest:{}", m.source_manifest_ref.as_str());
        let digest = payload_digest(body)?;
        let also = super::source_manifest_compat_digests(body);
        let mut tx = super::begin_write(&self.db).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, 1, &digest, &also).await? {
            // An equivalent manifest received under an earlier compatible label: the
            // receipt keeps its digest, and the digest sent becomes its alias, so collectors
            // of either label reconcile (the original is listed first).
            let moved = sqlx::query(
                "INSERT INTO receipt_aliases (project_id, producer_id, identity, revision, digest)
                 SELECT project_id, producer_id, identity, revision, $4 FROM receipts
                  WHERE project_id = $1 AND producer_id = $2 AND identity = $3 AND revision = 1
                    AND digest = ANY($5)
                 ON CONFLICT DO NOTHING",
            )
            .bind(p.project_id)
            .bind(p.producer_id)
            .bind(&identity)
            .bind(&digest)
            .bind(&also)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if moved > 0 {
                tx.commit().await?;
            }
            return Ok(r);
        }
        let mut repos = BTreeSet::new();
        for e in &m.repositories {
            if !repos.insert(&e.repository) {
                return Err(invalid(
                    format!("repository {} is listed twice", e.repository),
                    "repositories",
                ));
            }
        }
        let id: i64 = sqlx::query(
            "INSERT INTO source_manifests (project_id, producer_id, ref, digest, body)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (project_id, producer_id, ref) DO NOTHING RETURNING id",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(m.source_manifest_ref.as_str())
        .bind(&digest)
        .bind(body)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| conflict(format!("{identity} exists with other content")))?
        .get(0);
        let r = commit_receipt(
            &mut tx,
            &p,
            &identity,
            1,
            &digest,
            json!({"source_manifest": id}),
        )
        .await?;
        tx.commit().await?;
        Ok(r)
    }

    /// `POST /api/v1/regressions`.
    ///
    /// # Errors
    /// Authorization, validation (unknown source manifest), a conflicting replay, database
    /// errors.
    pub async fn create_regression(
        &self,
        actor: &Actor,
        body: &Value,
    ) -> Result<Receipt, AppError> {
        let c: RegressionCreate = parse(body)?;
        check_schema(&c.schema, "dviscope.ingest/")?;
        let p = self
            .producer(
                actor,
                Action::RegressionCreate,
                Some(c.producer_id.as_str()),
            )
            .await?;
        let identity = format!("regression:{}", c.regression_ref.as_str());
        let digest = payload_digest(body)?;
        let mut tx = super::begin_write(&self.db).await?;
        // Held to commit: retention (exclusive) cannot remove a regression of this name
        // between the tombstone check and the insert.
        super::gate_shared(&mut tx).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, 1, &digest, &[]).await? {
            return Ok(r);
        }
        // A regression removed by retention is never created again.
        let expired = sqlx::query(
            "SELECT 1 FROM expired_regressions WHERE project_id = $1 AND producer_id = $2 AND ref = $3",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(c.regression_ref.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if expired.is_some() {
            return Err(AppError::field(
                ErrorCode::Expired,
                format!("regression {} is past retention", c.regression_ref.as_str()),
                "regression_ref",
            ));
        }
        let known = sqlx::query(
            "SELECT 1 FROM source_manifests WHERE project_id = $1 AND producer_id = $2 AND ref = $3",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(c.source_manifest_ref.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if known.is_none() {
            return Err(invalid(
                format!("unknown source manifest {}", c.source_manifest_ref.as_str()),
                "source_manifest_ref",
            ));
        }
        // A branch is named `repository/branch` wherever it keys decisions (triage cases,
        // exceptions, feature candidates): a repository name with `/` would make two branches
        // one (`rtl` + `feature/x` and `rtl/feature` + `x`), so it is refused. Branch names may contain `/`.
        if c.branch.repository.is_empty() || c.branch.repository.contains('/') {
            return Err(invalid(
                "a repository name is not empty and has no '/'",
                "branch.repository",
            ));
        }
        if c.branch.name.is_empty() {
            return Err(invalid("a branch name is not empty", "branch.name"));
        }
        let id: i64 = sqlx::query(
            "INSERT INTO regressions (project_id, producer_id, ref, digest, body, suite,
                                      branch_repository, branch_name, source_manifest_ref, started_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (project_id, producer_id, ref) DO NOTHING RETURNING id",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(c.regression_ref.as_str())
        .bind(&digest)
        .bind(body)
        .bind(&c.suite)
        .bind(&c.branch.repository)
        .bind(&c.branch.name)
        .bind(c.source_manifest_ref.as_str())
        .bind(c.started_at.get())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| conflict(format!("{identity} exists with other content")))?
        .get(0);
        // A new regression is news for the dashboard (its stream's latest run changed):
        // the project watermark and change feed advance with it.
        bump(&mut tx, p.project_id, id).await?;
        let r = commit_receipt(
            &mut tx,
            &p,
            &identity,
            1,
            &digest,
            json!({"regression": id}),
        )
        .await?;
        tx.commit().await?;
        Ok(r)
    }

    /// `PUT /api/v1/regressions/{ref}/manifest/chunks/{n}`.
    ///
    /// # Errors
    /// See the manifest state table.
    pub async fn manifest_chunk(
        &self,
        actor: &Actor,
        regression_ref: &str,
        n: i32,
        body: &Value,
    ) -> Result<Receipt, AppError> {
        let c: ManifestChunk = parse(body)?;
        check_schema(&c.schema, "dviscope.manifest/")?;
        if n < 1 {
            return Err(invalid("chunk numbers start at 1", "n"));
        }
        let p = self.producer(actor, Action::ManifestChunk, None).await?;
        let identity = format!("manifest_chunk:{regression_ref}/{n}");
        let digest = payload_digest(body)?;
        let mut tx = super::begin_write(&self.db).await?;
        // Lock order: trust gate, then the regression head (as retention).
        if c.slots.iter().any(|d| !d.build_reqs.is_empty()) {
            super::gate_shared(&mut tx).await?;
        }
        let head = lock_head(&mut tx, &p, regression_ref).await?;
        super::lock_identity(&mut tx, &p, &identity).await?;
        let prior: Option<(String, Value)> = sqlx::query(
            "SELECT digest, receipt FROM receipts
              WHERE project_id = $1 AND producer_id = $2 AND identity = $3 AND revision = 1",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(&identity)
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| (r.get(0), r.get(1)));
        if prior.is_none() {
            super::replay_expired(&mut tx, &p, &identity, 1).await?;
        }
        if let Some((d, mut receipt)) = prior.clone()
            && d == digest
        {
            receipt["result"] = json!("duplicate");
            return Ok(Receipt {
                body: receipt,
                duplicate: true,
            });
        }
        if head.state != "unsealed" {
            return Err(conflict(format!(
                "regression {regression_ref} is {}: chunks are closed",
                head.state
            )));
        }
        let mut seen = BTreeSet::new();
        for s in &c.slots {
            if !seen.insert(s.slot_ref.as_str()) {
                return Err(invalid(
                    format!(
                        "slot {} is declared twice in chunk {n}",
                        s.slot_ref.as_str()
                    ),
                    "slot_ref",
                ));
            }
        }
        if prior.is_some() {
            // A different chunk n replaces the old one (its slots), unless one already ran.
            let used: Option<String> = sqlx::query(
                "SELECT s.slot_ref FROM slots s JOIN attempts a
                   ON a.project_id = s.project_id AND a.slot_id = s.id
                  WHERE s.project_id = $1 AND s.regression_id = $2 AND s.chunk_n = $3 LIMIT 1",
            )
            .bind(p.project_id)
            .bind(head.id)
            .bind(n)
            .fetch_optional(&mut *tx)
            .await?
            .map(|r| r.get(0));
            if let Some(s) = used {
                return Err(conflict(format!(
                    "chunk {n} cannot be replaced: slot {s} has attempts"
                )));
            }
            sqlx::query(
                "DELETE FROM slots WHERE project_id = $1 AND regression_id = $2 AND chunk_n = $3",
            )
            .bind(p.project_id)
            .bind(head.id)
            .bind(n)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "DELETE FROM receipts WHERE project_id = $1 AND producer_id = $2 AND identity = $3",
            )
            .bind(p.project_id)
            .bind(p.producer_id)
            .bind(&identity)
            .execute(&mut *tx)
            .await?;
        }
        for s in &c.slots {
            insert_slot(&mut tx, p.project_id, head.id, Some(n), 0, s).await?;
        }
        // A replaced chunk's slots are gone: so are the feature candidates of this (unsealed,
        // live) regression that no slot declares any more, else feature selection would
        // pick it for a test it no longer runs.
        sqlx::query(
            "DELETE FROM candidate_index ci
              WHERE ci.project_id = $1 AND ci.regression_id = $2 AND ci.state = 'live'
                AND NOT EXISTS (SELECT 1 FROM slots s
                                 WHERE s.project_id = ci.project_id
                                   AND s.regression_id = ci.regression_id
                                   AND s.test = ci.test AND s.config_digest = ci.config_digest)",
        )
        .bind(p.project_id)
        .bind(head.id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO manifest_chunks (project_id, regression_id, n, digest, credential_id)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (project_id, regression_id, n)
             DO UPDATE SET digest = EXCLUDED.digest, credential_id = EXCLUDED.credential_id",
        )
        .bind(p.project_id)
        .bind(head.id)
        .bind(n)
        .bind(&digest)
        .bind(p.credential_id)
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, p.project_id, head.id).await?;
        let r = commit_receipt(&mut tx, &p, &identity, 1, &digest, ids(&head)).await?;
        tx.commit().await?;
        Ok(r)
    }

    /// `POST /api/v1/regressions/{ref}/manifest/seal`.
    ///
    /// # Errors
    /// See the manifest state table.
    pub async fn manifest_seal(
        &self,
        actor: &Actor,
        regression_ref: &str,
        body: &Value,
    ) -> Result<Receipt, AppError> {
        let s: ManifestSeal = parse(body)?;
        check_schema(&s.schema, "dviscope.manifest/")?;
        let p = self.producer(actor, Action::ManifestSeal, None).await?;
        let identity = format!("manifest_seal:{regression_ref}");
        let digest = payload_digest(body)?;
        let mut tx = super::begin_write(&self.db).await?;
        let head = lock_head(&mut tx, &p, regression_ref).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, 1, &digest, &[]).await? {
            return Ok(r);
        }
        if head.state != "unsealed" {
            return Err(conflict(format!(
                "regression {regression_ref} is {}",
                head.state
            )));
        }
        if s.revision != 1 {
            return Err(invalid("the first seal is revision 1", "revision"));
        }
        let chunks: Vec<i32> = sqlx::query(
            "SELECT n FROM manifest_chunks WHERE project_id = $1 AND regression_id = $2 ORDER BY n",
        )
        .bind(p.project_id)
        .bind(head.id)
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
        if chunks.iter().zip(1..).any(|(n, want)| *n != want) {
            return Err(invalid(
                "chunk numbers are not contiguous from 1",
                "manifest_digest",
            ));
        }
        let (count, md) = manifest_digest(&mut tx, p.project_id, head.id).await?;
        if count != i64::from(s.slot_count) {
            return Err(invalid(
                format!(
                    "the chunks declare {count} slots, the seal {}",
                    s.slot_count
                ),
                "slot_count",
            ));
        }
        if md != s.manifest_digest.as_str() {
            return Err(invalid(
                "the manifest digest does not match the chunks",
                "manifest_digest",
            ));
        }
        sqlx::query(
            "UPDATE regressions SET state = 'sealed', sealed = true, manifest_revision = 1,
                    manifest_digest = $3 WHERE project_id = $1 AND id = $2",
        )
        .bind(p.project_id)
        .bind(head.id)
        .bind(&md)
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, p.project_id, head.id).await?;
        let r = commit_receipt(&mut tx, &p, &identity, 1, &digest, ids(&head)).await?;
        tx.commit().await?;
        Ok(r)
    }

    /// `POST /api/v1/regressions/{ref}/manifest/amend`.
    ///
    /// # Errors
    /// See the manifest state table.
    pub async fn manifest_amend(
        &self,
        actor: &Actor,
        regression_ref: &str,
        body: &Value,
    ) -> Result<Receipt, AppError> {
        let a: ManifestAmend = parse(body)?;
        check_schema(&a.schema, "dviscope.manifest/")?;
        let p = self.producer(actor, Action::ManifestAmend, None).await?;
        let identity = format!("manifest_amend:{regression_ref}/{}", a.revision);
        let digest = payload_digest(body)?;
        let mut tx = super::begin_write(&self.db).await?;
        // Lock order: trust gate, then the regression head (as retention).
        if a.add.iter().any(|d| !d.build_reqs.is_empty()) {
            super::gate_shared(&mut tx).await?;
        }
        let head = lock_head(&mut tx, &p, regression_ref).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, 1, &digest, &[]).await? {
            return Ok(r);
        }
        if head.state != "sealed" {
            return Err(conflict(format!(
                "regression {regression_ref} is {}: amendments need a sealed, unfinished manifest",
                head.state
            )));
        }
        let rev =
            i32::try_from(a.revision).map_err(|_| invalid("revision too large", "revision"))?;
        if rev <= head.manifest_revision {
            return Err(AppError::new(
                ErrorCode::StaleRevision,
                format!(
                    "manifest revision {rev} is not newer than {}",
                    head.manifest_revision
                ),
            ));
        }
        if rev != head.manifest_revision + 1 {
            return Err(invalid(
                format!(
                    "the next manifest revision is {}",
                    head.manifest_revision + 1
                ),
                "revision",
            ));
        }
        for r in &a.remove {
            let row = sqlx::query(
                concat!(
                    "SELECT s.id, EXISTS (SELECT 1 FROM attempts t WHERE t.project_id = s.project_id AND t.slot_id = s.id)
                       FROM slots s WHERE s.project_id = $1 AND s.regression_id = $2 AND s.slot_ref = $3
                        AND (s.removed_revision IS NULL OR ",
                    // re-making a removal that does not count
                    removal_untrusted!(),
                    ")"
                ),
            )
            .bind(p.project_id)
            .bind(head.id)
            .bind(r.slot_ref.as_str())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| invalid(format!("no live slot {}", r.slot_ref.as_str()), "remove"))?;
            if row.get::<bool, _>(1) {
                return Err(conflict(format!(
                    "slot {} has attempts and cannot be removed",
                    r.slot_ref.as_str()
                )));
            }
            sqlx::query(
                "UPDATE slots SET removed_revision = $3, removed_by = $4, removed_at = now()
                  WHERE project_id = $1 AND id = $2",
            )
            .bind(p.project_id)
            .bind(row.get::<i64, _>(0))
            .bind(rev)
            .bind(p.credential_id)
            .execute(&mut *tx)
            .await?;
            // The candidate index keeps the row: feature selection excludes validly
            // removed slots at evaluation time (a quarantined removal must not count).
        }
        for d in &a.add {
            insert_slot(&mut tx, p.project_id, head.id, None, rev, d).await?;
        }
        let (_, md) = manifest_digest(&mut tx, p.project_id, head.id).await?;
        sqlx::query(
            "UPDATE regressions SET manifest_revision = $3, manifest_digest = $4
              WHERE project_id = $1 AND id = $2",
        )
        .bind(p.project_id)
        .bind(head.id)
        .bind(rev)
        .bind(&md)
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, p.project_id, head.id).await?;
        let r = commit_receipt(&mut tx, &p, &identity, 1, &digest, ids(&head)).await?;
        tx.commit().await?;
        Ok(r)
    }

    /// `POST /api/v1/regressions/{ref}/slots/mark`.
    ///
    /// # Errors
    /// See the manifest state table.
    pub async fn slot_mark(
        &self,
        actor: &Actor,
        regression_ref: &str,
        body: &Value,
    ) -> Result<Receipt, AppError> {
        let m: SlotMark = parse(body)?;
        check_schema(&m.schema, "dviscope.manifest/")?;
        let p = self.producer(actor, Action::SlotMark, None).await?;
        let digest = payload_digest(body)?;
        let identity = format!("slot_mark:{regression_ref}/{digest}");
        let mut tx = super::begin_write(&self.db).await?;
        let head = lock_head(&mut tx, &p, regression_ref).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, 1, &digest, &[]).await? {
            return Ok(r);
        }
        if !head.sealed {
            return Err(conflict(format!(
                "regression {regression_ref} is not sealed"
            )));
        }
        let state = serde_json::to_value(m.state)?;
        for s in &m.slot_refs {
            let id: i64 = sqlx::query(
                "SELECT id FROM slots WHERE project_id = $1 AND regression_id = $2 AND slot_ref = $3
                    AND removed_revision IS NULL",
            )
            .bind(p.project_id)
            .bind(head.id)
            .bind(s.as_str())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| invalid(format!("no live slot {}", s.as_str()), "slot_refs"))?
            .get(0);
            sqlx::query(
                "INSERT INTO slot_marks (project_id, slot_id, state, reason, credential_id)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (project_id, slot_id) DO NOTHING",
            )
            .bind(p.project_id)
            .bind(id)
            .bind(state.as_str().unwrap_or("cancelled"))
            .bind(&m.reason)
            .bind(p.credential_id)
            .execute(&mut *tx)
            .await?;
        }
        bump(&mut tx, p.project_id, head.id).await?;
        let r = commit_receipt(&mut tx, &p, &identity, 1, &digest, ids(&head)).await?;
        tx.commit().await?;
        Ok(r)
    }

    /// `POST /api/v1/regressions/{ref}/finish`.
    ///
    /// # Errors
    /// Authorization, unknown regression, a conflicting replay, database errors.
    pub async fn finish(
        &self,
        actor: &Actor,
        regression_ref: &str,
        body: &Value,
    ) -> Result<Receipt, AppError> {
        let p = self.producer(actor, Action::RegressionFinish, None).await?;
        let identity = format!("finish:{regression_ref}");
        let digest = payload_digest(body)?;
        let mut tx = super::begin_write(&self.db).await?;
        let head = lock_head(&mut tx, &p, regression_ref).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, 1, &digest, &[]).await? {
            return Ok(r);
        }
        if head.state == "finished" {
            return Err(conflict(format!(
                "regression {regression_ref} is already finished"
            )));
        }
        sqlx::query(
            "UPDATE regressions SET state = 'finished', finished_at = now()
              WHERE project_id = $1 AND id = $2",
        )
        .bind(p.project_id)
        .bind(head.id)
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, p.project_id, head.id).await?;
        let r = commit_receipt(&mut tx, &p, &identity, 1, &digest, ids(&head)).await?;
        tx.commit().await?;
        Ok(r)
    }
}
