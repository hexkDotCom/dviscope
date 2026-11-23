//! Project rules and activation: pipeline definitions, the activation sample
//! (uploaded in chunks, resumable by file digest), and activation, which re-runs the same
//! `core::rule_check` as the client over the stored sample and refuses a stale, failing or
//! different result. An activation accepts the new pipeline digest; evidence is never
//! relabelled (B.9.5).

use dviscope_core::packs::Pipeline;
use dviscope_core::rule_check::{self, SampleManifest, Structural};
use dviscope_model::canonical::Digest;
use dviscope_model::errors::ErrorCode;
use serde_json::{Value, json};
use sqlx::Row as _;

use super::App;
use super::decisions::bump_project;
use crate::auth::{Action, Actor};
use crate::error::AppError;

/// A sample file chunk is at most 4 MiB.
pub const MAX_CHUNK: usize = 4 * 1024 * 1024;
/// Activations listed in the status.
const HISTORY: i64 = 20;

pub use dviscope_core::rule_check::{DEFINITION_FORMAT, PackText, PipelineDefinition};

/// Compiles a definition, mapping its problems to API errors.
fn compile(def: &PipelineDefinition) -> Result<Pipeline, AppError> {
    def.compile().map_err(|e| {
        if e.contains("4 MiB") {
            AppError::new(ErrorCode::TooLarge, e)
        } else {
            AppError::field(ErrorCode::Invalid, e, "definition")
        }
    })
}

fn user_id(actor: &Actor) -> Result<i64, AppError> {
    match actor {
        Actor::User { user_id, .. } => Ok(*user_id),
        Actor::Collector { .. } => Err(AppError::new(ErrorCode::Forbidden, "people only")),
    }
}

fn hex_digest(s: &str) -> Result<(), AppError> {
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(AppError::field(
            ErrorCode::Invalid,
            "a file digest is 64 lowercase hex digits (SHA-256)",
            "sha256",
        ))
    }
}

fn file_status(sha256: &str, size: i64, received: i64, complete: bool) -> Value {
    json!({"sha256": sha256, "size": size, "received": received, "complete": complete})
}

/// The project's active definition (the shipped default when none was activated) and the
/// current sample digest.
async fn current(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pid: i64,
) -> Result<(PipelineDefinition, Option<String>), AppError> {
    let row = sqlx::query(
        "SELECT r.sample_digest, d.definition FROM project_rules r
           LEFT JOIN pipeline_definitions d
             ON d.project_id = r.project_id AND d.digest = r.active_pipeline
          WHERE r.project_id = $1",
    )
    .bind(pid)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok((PipelineDefinition::shipped(), None));
    };
    let def = match row.get::<Option<Value>, _>(1) {
        Some(v) => serde_json::from_value(v).map_err(|_| AppError::internal("definition"))?,
        None => PipelineDefinition::shipped(),
    };
    Ok((def, row.get(0)))
}

/// Compiles on a blocking thread (pack compilation and sample extraction are CPU work).
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| AppError::internal("rules worker"))?
}

impl App {
    /// The project's rules status: active pipeline (packs named, no text), the current
    /// sample (cases, bytes) and the latest activations.
    ///
    /// # Errors
    /// Not found or forbidden.
    pub async fn rules_status(&self, actor: &Actor, project: &str) -> Result<Value, AppError> {
        let (pid, _) = self.read_project(actor, project, Action::RulesRead).await?;
        // A read: a snapshot, available in maintenance.
        let mut tx = self.snapshot().await?;
        let (def, sample) = current(&mut tx, pid).await?;
        let digest = blocking({
            let def = def.clone();
            move || compile(&def).map(|p| p.digest)
        })
        .await?;
        let sample_info = match &sample {
            Some(d) => {
                let m: Option<Value> = sqlx::query_scalar(
                    "SELECT manifest FROM activation_samples WHERE project_id = $1 AND digest = $2",
                )
                .bind(pid)
                .bind(d)
                .fetch_optional(&mut *tx)
                .await?;
                let m: Option<SampleManifest> = m.and_then(|v| serde_json::from_value(v).ok());
                m.map(|m| {
                    json!({"digest": d, "cases": m.cases.len(),
                           "bytes": m.cases.iter().map(|c| c.bytes).sum::<u64>()})
                })
            }
            None => None,
        };
        let history: Vec<Value> = sqlx::query(
            "SELECT id, old_pipeline, new_pipeline, sample_digest, actor_user, activated_at,
                    jsonb_array_length(result -> 'cases')
               FROM activations WHERE project_id = $1 ORDER BY id DESC LIMIT $2",
        )
        .bind(pid)
        .bind(HISTORY)
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>(0).to_string(),
                "old_pipeline": r.get::<String, _>(1),
                "new_pipeline": r.get::<String, _>(2),
                "sample": r.get::<String, _>(3),
                "actor": r.get::<i64, _>(4).to_string(),
                "activated_at": r.get::<time::OffsetDateTime, _>(5)
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                "cases": r.get::<Option<i32>, _>(6),
            })
        })
        .collect();
        Ok(json!({
            "active_pipeline": digest.as_str(),
            "default_packs": def.default_packs,
            "packs": def.packs.iter().map(|p| p.name.clone()).collect::<Vec<_>>(),
            "sample": sample_info,
            "activations": history,
        }))
    }

    /// The active definition with its pack texts, for a client building the old pipeline.
    ///
    /// # Errors
    /// Not found or forbidden.
    pub async fn rules_definition(&self, actor: &Actor, project: &str) -> Result<Value, AppError> {
        let (pid, _) = self.read_project(actor, project, Action::RulesRead).await?;
        // A read: a snapshot, available in maintenance.
        let mut tx = self.snapshot().await?;
        let (def, sample) = current(&mut tx, pid).await?;
        let digest = blocking({
            let def = def.clone();
            move || compile(&def).map(|p| p.digest)
        })
        .await?;
        Ok(json!({"digest": digest.as_str(), "definition": def, "sample": sample}))
    }

    /// The upload state of a sample file (resume by its digest).
    ///
    /// # Errors
    /// Not found or forbidden; an invalid digest.
    pub async fn sample_file(
        &self,
        actor: &Actor,
        project: &str,
        sha256: &str,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::RulesWrite)
            .await?;
        hex_digest(sha256)?;
        let row = sqlx::query(
            "SELECT size, length(content), complete FROM sample_files
              WHERE project_id = $1 AND sha256 = $2",
        )
        .bind(pid)
        .bind(sha256)
        .fetch_optional(&self.db)
        .await?;
        Ok(match row {
            Some(r) => file_status(sha256, r.get(0), i64::from(r.get::<i32, _>(1)), r.get(2)),
            None => json!({"sha256": sha256, "received": 0, "complete": false}),
        })
    }

    /// Appends one chunk (≤ 4 MiB) of a sample file at `offset`; the last chunk verifies
    /// the file's digest (a mismatch discards the file).
    ///
    /// # Errors
    /// Forbidden; an invalid digest, size, offset or chunk; a digest mismatch.
    pub async fn sample_chunk(
        &self,
        actor: &Actor,
        project: &str,
        sha256: &str,
        size: i64,
        offset: i64,
        chunk: &[u8],
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::RulesWrite)
            .await?;
        hex_digest(sha256)?;
        let max = i64::try_from(rule_check::MAX_SAMPLE_BYTES).unwrap_or(i64::MAX);
        if !(0..=max).contains(&size) {
            return Err(AppError::field(
                ErrorCode::Invalid,
                "a sample file is at most 64 MiB",
                "size",
            ));
        }
        if chunk.len() > MAX_CHUNK {
            return Err(AppError::new(
                ErrorCode::TooLarge,
                "a chunk is at most 4 MiB",
            ));
        }
        let mut tx = super::begin_write(&self.db).await?;
        sqlx::query(
            "INSERT INTO sample_files (project_id, sha256, size) VALUES ($1, $2, $3)
             ON CONFLICT (project_id, sha256) DO NOTHING",
        )
        .bind(pid)
        .bind(sha256)
        .bind(size)
        .execute(&mut *tx)
        .await?;
        let r = sqlx::query(
            "SELECT size, length(content), complete FROM sample_files
              WHERE project_id = $1 AND sha256 = $2 FOR UPDATE",
        )
        .bind(pid)
        .bind(sha256)
        .fetch_one(&mut *tx)
        .await?;
        let (stored_size, received, complete): (i64, i64, bool) =
            (r.get(0), i64::from(r.get::<i32, _>(1)), r.get(2));
        if complete {
            return Ok(file_status(sha256, stored_size, received, true));
        }
        if stored_size != size {
            return Err(AppError::field(
                ErrorCode::Invalid,
                format!("this file was started with size {stored_size}"),
                "size",
            ));
        }
        if offset != received {
            return Err(AppError::field(
                ErrorCode::Invalid,
                format!("resume at offset {received}"),
                "offset",
            ));
        }
        let len = i64::try_from(chunk.len()).unwrap_or(i64::MAX);
        if received + len > size {
            return Err(AppError::field(
                ErrorCode::Invalid,
                "the chunk passes the file's size",
                "offset",
            ));
        }
        sqlx::query(
            "UPDATE sample_files SET content = content || $3 WHERE project_id = $1 AND sha256 = $2",
        )
        .bind(pid)
        .bind(sha256)
        .bind(chunk)
        .execute(&mut *tx)
        .await?;
        let now_received = received + len;
        if now_received == size {
            let content: Vec<u8> = sqlx::query_scalar(
                "SELECT content FROM sample_files WHERE project_id = $1 AND sha256 = $2",
            )
            .bind(pid)
            .bind(sha256)
            .fetch_one(&mut *tx)
            .await?;
            if Digest::of_bytes(&content).as_str() != format!("sha256:{sha256}") {
                sqlx::query("DELETE FROM sample_files WHERE project_id = $1 AND sha256 = $2")
                    .bind(pid)
                    .bind(sha256)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                return Err(AppError::new(
                    ErrorCode::Unprocessable,
                    "the file does not match its digest; it was discarded (upload it again)",
                ));
            }
            sqlx::query(
                "UPDATE sample_files SET complete = true WHERE project_id = $1 AND sha256 = $2",
            )
            .bind(pid)
            .bind(sha256)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(file_status(
            sha256,
            size,
            now_received,
            now_received == size,
        ))
    }

    /// Registers the project's activation sample (every log uploaded and complete); it
    /// becomes the sample activations are checked against.
    ///
    /// # Errors
    /// Forbidden; an invalid manifest; a log not uploaded.
    pub async fn register_sample(
        &self,
        actor: &Actor,
        project: &str,
        manifest: &SampleManifest,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::RulesWrite)
            .await?;
        let author = user_id(actor)?;
        manifest
            .validate()
            .map_err(|e| AppError::field(ErrorCode::Invalid, e, "sample"))?;
        let digest = manifest.digest();
        // Stored in canonical order (by case name), as its digest is computed.
        let mut manifest = manifest.clone();
        manifest.cases.sort_by(|a, b| a.case.cmp(&b.case));
        let manifest = &manifest;
        let mut tx = super::begin_write(&self.db).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 13))")
            .bind(format!("{pid}|rules"))
            .execute(&mut *tx)
            .await?;
        for c in &manifest.cases {
            let ok: Option<bool> = sqlx::query_scalar(
                "SELECT complete AND size = $3 FROM sample_files WHERE project_id = $1 AND sha256 = $2",
            )
            .bind(pid)
            .bind(&c.log_sha256)
            .bind(i64::try_from(c.bytes).unwrap_or(-1))
            .fetch_optional(&mut *tx)
            .await?;
            if ok != Some(true) {
                return Err(AppError::field(
                    ErrorCode::Invalid,
                    format!(
                        "case {}: its log is not uploaded (or differs in size)",
                        c.case
                    ),
                    "sample",
                ));
            }
        }
        sqlx::query(
            "INSERT INTO activation_samples (project_id, digest, manifest, uploaded_by)
             VALUES ($1, $2, $3, $4) ON CONFLICT (project_id, digest) DO NOTHING",
        )
        .bind(pid)
        .bind(digest.as_str())
        .bind(serde_json::to_value(manifest)?)
        .bind(author)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO project_rules (project_id, sample_digest) VALUES ($1, $2)
             ON CONFLICT (project_id) DO UPDATE SET sample_digest = EXCLUDED.sample_digest,
                                                    changed_at = now()",
        )
        .bind(pid)
        .bind(digest.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO audit (actor, action, object, detail) VALUES ($1, $2, $3, $4)")
            .bind(format!("user:{author}"))
            .bind("rules.sample")
            .bind(format!("{project}/{}", digest.as_str()))
            .bind(json!({"cases": manifest.cases.len()}))
            .execute(&mut *tx)
            .await?;
        bump_project(
            &mut tx,
            pid,
            "rules",
            &format!("sample:{}", digest.as_str()),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({"digest": digest.as_str(), "cases": manifest.cases.len()}))
    }

    /// Activates a pipeline definition (B.9.4): the client's check must be bound to the
    /// project's active pipeline, this definition and the current sample (else stale), the
    /// server's own check over the stored sample must be identical, and it must pass. The
    /// new digest is accepted (earlier ones stay as they are).
    ///
    /// # Errors
    /// Forbidden; no sample; a stale, different or failing check; invalid packs.
    #[allow(clippy::too_many_lines)] // one locked transition: verify, then record
    pub async fn activate_rules(
        &self,
        actor: &Actor,
        project: &str,
        definition: &PipelineDefinition,
        check: &Structural,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::RulesWrite)
            .await?;
        let author = user_id(actor)?;
        let mut tx = super::begin_write(&self.db).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 13))")
            .bind(format!("{pid}|rules"))
            .execute(&mut *tx)
            .await?;
        let (old_def, sample) = current(&mut tx, pid).await?;
        let Some(sample) = sample else {
            return Err(AppError::field(
                ErrorCode::Invalid,
                "no activation sample: upload one first (dviscope sample upload)",
                "sample",
            ));
        };
        let manifest: Value = sqlx::query_scalar(
            "SELECT manifest FROM activation_samples WHERE project_id = $1 AND digest = $2",
        )
        .bind(pid)
        .bind(&sample)
        .fetch_one(&mut *tx)
        .await?;
        let manifest: SampleManifest =
            serde_json::from_value(manifest).map_err(|_| AppError::internal("sample"))?;
        let mut logs: Vec<Vec<u8>> = vec![];
        for c in &manifest.cases {
            logs.push(
                sqlx::query_scalar(
                    "SELECT content FROM sample_files WHERE project_id = $1 AND sha256 = $2",
                )
                .bind(pid)
                .bind(&c.log_sha256)
                .fetch_one(&mut *tx)
                .await?,
            );
        }
        let new_def = definition.clone();
        let (old_digest, new_digest, server) = blocking(move || {
            let old = compile(&old_def)?;
            let new = compile(&new_def)?;
            let refs: Vec<&[u8]> = logs.iter().map(Vec::as_slice).collect();
            let s = rule_check::check(&old, &new, &manifest, &refs)
                .map_err(|e| AppError::new(ErrorCode::Unprocessable, e))?;
            Ok((old.digest, new.digest, s))
        })
        .await?;
        if check.old_pipeline != old_digest
            || check.new_pipeline != new_digest
            || check.sample.as_str() != sample
        {
            return Err(AppError::new(
                ErrorCode::StaleRevision,
                "the check is stale: the active pipeline, the definition or the sample changed \
                 since it ran; run it again",
            ));
        }
        if *check != server {
            let differ: Vec<&str> = server
                .cases
                .iter()
                .zip(&check.cases)
                .filter(|(a, b)| a != b)
                .map(|(a, _)| a.case.as_str())
                .collect();
            return Err(AppError::new(
                ErrorCode::Unprocessable,
                format!(
                    "the server's check differs from yours (cases: {}); use the same \
                     dviscope version",
                    differ.join(", ")
                ),
            ));
        }
        if !server.pass {
            let failing: Vec<&str> = server
                .cases
                .iter()
                .filter(|c| !c.ok)
                .map(|c| c.case.as_str())
                .collect();
            return Err(AppError::new(
                ErrorCode::Unprocessable,
                format!("the check fails (cases: {})", failing.join(", ")),
            ));
        }
        sqlx::query(
            "INSERT INTO pipeline_definitions (project_id, digest, definition) VALUES ($1, $2, $3)
             ON CONFLICT (project_id, digest) DO NOTHING",
        )
        .bind(pid)
        .bind(new_digest.as_str())
        .bind(serde_json::to_value(definition)?)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO pipelines (project_id, digest, state) VALUES ($1, $2, 'accepted')
             ON CONFLICT (project_id, digest) DO UPDATE SET state = 'accepted', changed_at = now()",
        )
        .bind(pid)
        .bind(new_digest.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO project_rules (project_id, active_pipeline) VALUES ($1, $2)
             ON CONFLICT (project_id) DO UPDATE SET active_pipeline = EXCLUDED.active_pipeline,
                                                    changed_at = now()",
        )
        .bind(pid)
        .bind(new_digest.as_str())
        .execute(&mut *tx)
        .await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO activations (project_id, old_pipeline, new_pipeline, sample_digest,
                                      result, actor_user)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(pid)
        .bind(old_digest.as_str())
        .bind(new_digest.as_str())
        .bind(&sample)
        .bind(serde_json::to_value(&server)?)
        .bind(author)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO audit (actor, action, object, detail) VALUES ($1, $2, $3, $4)")
            .bind(format!("user:{author}"))
            .bind("rules.activate")
            .bind(format!("{project}/{}", new_digest.as_str()))
            .bind(json!({"old": old_digest.as_str(), "sample": sample}))
            .execute(&mut *tx)
            .await?;
        bump_project(
            &mut tx,
            pid,
            "pipeline",
            &format!("pipeline:{}", new_digest.as_str()),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({
            "activation": id.to_string(),
            "old_pipeline": old_digest.as_str(),
            "new_pipeline": new_digest.as_str(),
            "sample": sample,
            "pass": true,
            "cases": server.cases.len(),
        }))
    }
}
