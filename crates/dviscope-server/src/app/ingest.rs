//! Ingest: each record is its own transaction. Attempt records serialize on the
//! regression head, build records on the build attempt (and its requirement, for the
//! server-assigned `build_order`). A report revision derives the outcome, expectation and
//! classification from the reported evidence on the server, stores the retained facts and
//! buckets (signatures by family fingerprint), and keeps the payload separately.

use dviscope_core::outcome::{self, Derived, Input};
use dviscope_model::canonical::digest_of;
use dviscope_model::errors::ErrorCode;
use dviscope_model::wire::evidence::{CompletionState, CounterRole, Evidence, VerdictValue};
use dviscope_model::wire::ingest::{
    AttemptStarted, BuildAttempt, BuildOutcome, BuildStarted, IngestRecord, Purpose,
    SimulationAttempt, TerminationKind,
};
use dviscope_model::wire::manifest::Expected;
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};

use super::regression::{build_req_key, lock_head};
use super::{
    App, Producer, Receipt, bump, check_schema, commit_receipt, parse, payload_digest, replay,
};
use crate::auth::{Action, Actor};
use crate::error::AppError;

fn invalid(msg: impl Into<String>, field: &str) -> AppError {
    AppError::field(ErrorCode::Invalid, msg, field)
}

fn text<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The simulator pack selected during extraction (shared with activation).
fn simulator_pack(ev: &Evidence) -> Option<&'static dviscope_core::packs::CompiledPack> {
    dviscope_core::packs::shipped::simulator_pack_of(ev)
}

/// The signature fingerprint of a synthetic bucket (`fp/1` over its diagnostic ID).
///
/// # Errors
/// Never in practice (the value is canonicalizable).
pub fn synthetic_fingerprint(diag_id: &str) -> Result<String, AppError> {
    digest_of(&json!({"schema": "fp/1", "key": {"synthetic": diag_id}}))
        .map(|d| d.as_str().to_string())
        .map_err(|_| AppError::internal("fingerprint"))
}

/// One result line of a batch.
#[derive(Debug, Clone)]
pub enum LineResult {
    /// Committed or replayed.
    Ok(Receipt),
    /// Rejected alone.
    Rejected(AppError),
}

struct Attempt {
    id: i64,
    head_revision: Option<i32>,
}

/// Finds or creates the attempt of a slot (`attempt_seq` must agree), locked.
#[allow(clippy::too_many_arguments)] // the attempt's identity, parents and start facts
async fn attempt_row(
    tx: &mut Transaction<'_, Postgres>,
    p: &Producer,
    regression_ref: &str,
    slot_ref: &str,
    slot_id: i64,
    attempt_ref: &str,
    attempt_seq: u32,
    build_refs: &[String],
    started_at: time::OffsetDateTime,
) -> Result<Attempt, AppError> {
    let project_id = p.project_id;
    let seq =
        i32::try_from(attempt_seq).map_err(|_| invalid("attempt_seq too large", "attempt_seq"))?;
    if seq < 1 {
        return Err(invalid("attempt_seq starts at 1", "attempt_seq"));
    }
    // An attempt reference names one slot of one regression of the producer, for good: the
    // binding is claimed atomically (unique key) and outlives receipts and facts.
    claim(
        tx,
        "INSERT INTO attempt_bindings (project_id, producer_id, attempt_ref, regression_ref, slot_ref)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        "SELECT regression_ref || '|' || slot_ref FROM attempt_bindings
          WHERE project_id = $1 AND producer_id = $2 AND attempt_ref = $3",
        p,
        &[attempt_ref, regression_ref, slot_ref],
        &format!("{regression_ref}|{slot_ref}"),
    )
    .await
    .map_err(|e| e.unwrap_or_else(|| {
        AppError::field(
            ErrorCode::RevisionConflict,
            format!("attempt {attempt_ref} belongs to another slot"),
            "attempt_ref",
        )
    }))?;
    let row = sqlx::query(
        "SELECT id, attempt_seq, head_revision FROM attempts
          WHERE project_id = $1 AND slot_id = $2 AND attempt_ref = $3 FOR UPDATE",
    )
    .bind(project_id)
    .bind(slot_id)
    .bind(attempt_ref)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(r) = row {
        if r.get::<i32, _>(1) != seq {
            return Err(AppError::field(
                ErrorCode::RevisionConflict,
                format!("attempt {attempt_ref} has another attempt_seq"),
                "attempt_seq",
            ));
        }
        return Ok(Attempt {
            id: r.get(0),
            head_revision: r.get(2),
        });
    }
    let taken: Option<String> = sqlx::query(
        "SELECT attempt_ref FROM attempts WHERE project_id = $1 AND slot_id = $2 AND attempt_seq = $3",
    )
    .bind(project_id)
    .bind(slot_id)
    .bind(seq)
    .fetch_optional(&mut **tx)
    .await?
    .map(|r| r.get(0));
    if let Some(other) = taken {
        return Err(AppError::field(
            ErrorCode::RevisionConflict,
            format!("attempt_seq {seq} of this slot belongs to attempt {other}"),
            "attempt_seq",
        ));
    }
    let id: i64 = sqlx::query(
        "INSERT INTO attempts (project_id, slot_id, attempt_ref, attempt_seq, build_refs, started_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(project_id)
    .bind(slot_id)
    .bind(attempt_ref)
    .bind(seq)
    .bind(json!(build_refs))
    .bind(started_at)
    .fetch_one(&mut **tx)
    .await?
    .get(0);
    Ok(Attempt {
        id,
        head_revision: None,
    })
}

/// Claims a permanent binding: inserts it unless it exists, then reads it back; `Err(None)`
/// when it is bound to something else. Concurrent claims serialize on the unique key.
async fn claim(
    tx: &mut Transaction<'_, Postgres>,
    insert: &'static str,
    select: &'static str,
    p: &Producer,
    values: &[&str],
    expected: &str,
) -> Result<(), Option<AppError>> {
    let mut q = sqlx::query(insert).bind(p.project_id).bind(p.producer_id);
    for v in values {
        q = q.bind(*v);
    }
    q.execute(&mut **tx)
        .await
        .map_err(|e| Some(AppError::from(e)))?;
    let bound: String = sqlx::query(select)
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(values[0])
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| Some(AppError::from(e)))?
        .get(0);
    if bound == expected { Ok(()) } else { Err(None) }
}

struct Slot {
    id: i64,
    build_reqs: usize,
    expected: Option<Value>,
    exec_digest: String,
}

async fn live_slot(
    tx: &mut Transaction<'_, Postgres>,
    project_id: i64,
    regression_id: i64,
    slot_ref: &str,
) -> Result<Slot, AppError> {
    let r = sqlx::query(
        "SELECT id, jsonb_array_length(build_reqs), expected, exec_digest FROM slots
          WHERE project_id = $1 AND regression_id = $2 AND slot_ref = $3 AND removed_revision IS NULL",
    )
    .bind(project_id)
    .bind(regression_id)
    .bind(slot_ref)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| invalid(format!("slot {slot_ref} is not declared"), "slot_ref"))?;
    Ok(Slot {
        id: r.get(0),
        build_reqs: usize::try_from(r.get::<i32, _>(1)).unwrap_or(0),
        expected: r.get(2),
        exec_digest: r.get(3),
    })
}

fn revision_of(n: u32) -> Result<i32, AppError> {
    i32::try_from(n)
        .ok()
        .filter(|r| *r > 0)
        .ok_or_else(|| invalid("report_revision starts at 1", "report_revision"))
}

/// Revision order against the subject head: an unseen revision at or below the head is
/// stale (or conflicting, at the head itself).
fn check_head(head: Option<i32>, rev: i32, what: &str) -> Result<(), AppError> {
    match head {
        Some(h) if rev == h => Err(AppError::new(
            ErrorCode::RevisionConflict,
            format!("{what} revision {rev} was received with other content"),
        )),
        Some(h) if rev < h => Err(AppError::new(
            ErrorCode::StaleRevision,
            format!("{what}: a newer revision than {rev} exists"),
        )),
        _ => Ok(()),
    }
}

impl App {
    /// Ingests one NDJSON line. Never fails as a whole: every problem is this line's.
    pub async fn ingest_line(&self, actor: &Actor, body: &Value) -> LineResult {
        let r = match parse::<IngestRecord>(body) {
            Ok(IngestRecord::AttemptStarted(s)) => self.attempt_started(actor, body, &s).await,
            Ok(IngestRecord::SimulationAttempt(s)) => {
                self.simulation_attempt(actor, body, &s).await
            }
            Ok(IngestRecord::BuildStarted(b)) => self.build_started(actor, body, &b).await,
            Ok(IngestRecord::BuildAttempt(b)) => self.build_attempt(actor, body, &b).await,
            Err(e) => Err(e),
        };
        match r {
            Ok(r) => LineResult::Ok(r),
            Err(e) => LineResult::Rejected(e),
        }
    }

    async fn attempt_started(
        &self,
        actor: &Actor,
        body: &Value,
        s: &AttemptStarted,
    ) -> Result<Receipt, AppError> {
        check_schema(&s.schema, "dviscope.ingest/")?;
        let p = self
            .producer(actor, Action::IngestSubmit, Some(s.producer_id.as_str()))
            .await?;
        let identity = format!("attempt_started:{}", s.attempt_ref.as_str());
        let digest = payload_digest(body)?;
        let mut tx = super::begin_write(&self.db).await?;
        // Lock order: trust gate, then the regression head (as retention).
        if !s.build_refs.is_empty() {
            super::gate_shared(&mut tx).await?;
        }
        let head = lock_head(&mut tx, &p, s.regression_ref.as_str()).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, 1, &digest, &[]).await? {
            return Ok(r);
        }
        let slot = live_slot(&mut tx, p.project_id, head.id, s.slot_ref.as_str()).await?;
        if s.build_refs.len() != slot.build_reqs {
            return Err(invalid(
                format!("the slot has {} build requirements", slot.build_reqs),
                "build_refs",
            ));
        }
        let refs: Vec<String> = s
            .build_refs
            .iter()
            .map(|b| b.as_str().to_string())
            .collect();
        let a = attempt_row(
            &mut tx,
            &p,
            s.regression_ref.as_str(),
            s.slot_ref.as_str(),
            slot.id,
            s.attempt_ref.as_str(),
            s.attempt_seq,
            &refs,
            s.started_at.get(),
        )
        .await?;
        sqlx::query(
            "UPDATE attempts SET started_at = $3, start_credential_id = $4, build_refs = $5
              WHERE project_id = $1 AND id = $2",
        )
        .bind(p.project_id)
        .bind(a.id)
        .bind(s.started_at.get())
        .bind(p.credential_id)
        .bind(json!(refs))
        .execute(&mut *tx)
        .await?;
        bump(&mut tx, p.project_id, head.id).await?;
        let ids = json!({"regression": head.id, "slot": slot.id, "attempt": a.id});
        let r = commit_receipt(&mut tx, &p, &identity, 1, &digest, ids).await?;
        tx.commit().await?;
        Ok(r)
    }

    #[allow(clippy::too_many_lines)] // one transaction, step by step (B.15)
    async fn simulation_attempt(
        &self,
        actor: &Actor,
        body: &Value,
        s: &SimulationAttempt,
    ) -> Result<Receipt, AppError> {
        check_schema(&s.schema, "dviscope.ingest/")?;
        check_schema(&s.evidence.schema, "dviscope.evidence/")?;
        let p = self
            .producer(actor, Action::IngestSubmit, Some(s.producer_id.as_str()))
            .await?;
        let rev = revision_of(s.report_revision)?;
        let identity = format!("simulation_attempt:{}", s.report_id.as_str());
        let digest = payload_digest(body)?;
        let mut tx = super::begin_write(&self.db).await?;
        // Lock order: trust gate, then the regression head (as retention).
        if !s.build_refs.is_empty() {
            super::gate_shared(&mut tx).await?;
        }
        let head = lock_head(&mut tx, &p, s.regression_ref.as_str()).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, rev, &digest, &[]).await? {
            return Ok(r);
        }
        let slot = live_slot(&mut tx, p.project_id, head.id, s.slot_ref.as_str()).await?;
        if s.build_refs.len() != slot.build_reqs {
            return Err(invalid(
                format!("the slot has {} build requirements", slot.build_reqs),
                "build_refs",
            ));
        }
        let refs: Vec<String> = s
            .build_refs
            .iter()
            .map(|b| b.as_str().to_string())
            .collect();
        let a = attempt_row(
            &mut tx,
            &p,
            s.regression_ref.as_str(),
            s.slot_ref.as_str(),
            slot.id,
            s.attempt_ref.as_str(),
            s.attempt_seq,
            &refs,
            s.result.runner.started_at.get(),
        )
        .await?;
        check_head(a.head_revision, rev, &identity)?;
        // A report ID belongs to one attempt for good (every revision), claimed atomically.
        claim(
            &mut tx,
            "INSERT INTO report_bindings (project_id, producer_id, report_id, attempt_ref)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            "SELECT attempt_ref FROM report_bindings
              WHERE project_id = $1 AND producer_id = $2 AND report_id = $3",
            &p,
            &[s.report_id.as_str(), s.attempt_ref.as_str()],
            s.attempt_ref.as_str(),
        )
        .await
        .map_err(|e| {
            e.unwrap_or_else(|| {
                AppError::field(
                    ErrorCode::RevisionConflict,
                    format!("{identity} belongs to another attempt"),
                    "report_id",
                )
            })
        })?;
        // The report must run exactly the slot's declared inputs.
        let exec = dviscope_model::canonical::digest_of(&s.execution)
            .map_err(|_| AppError::internal("execution digest"))?;
        if exec.as_str() != slot.exec_digest {
            return Err(AppError::field(
                ErrorCode::RetryInputsDiffer,
                "the execution inputs differ from the slot's declaration",
                "execution",
            ));
        }
        // A model with its own main (plan F2): the evidence's profile and segments agree
        // with the slot's declaration (the inputs above are the slot's).
        dviscope_core::model_main::declares(&s.execution)
            .and_then(|declared| dviscope_core::model_main::check_simulation(declared, &s.evidence))
            .map_err(|m| invalid(m, "evidence"))?;
        let expected: Option<Expected> = slot
            .expected
            .as_ref()
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|_| AppError::internal("stored expectation"))?;
        let sim = simulator_pack(&s.evidence);
        let d: Derived = outcome::derive(&Input {
            evidence: Some(&s.evidence),
            runner: &s.result.runner,
            producer: s.result.outcome_reported,
            has_build_requirement: slot.build_reqs > 0,
            // A simulator pack this server cannot resolve exactly (e.g. a customized
            // one) keeps the exit-code check on: never a pass by default.
            exit_code_meaningful: dviscope_core::packs::shipped::exit_code_meaningful(&s.evidence),
            expected: expected.as_ref(),
        });
        let pipeline_digest = s.evidence.pipeline_digest.as_str().to_string();
        // A correction keeps its attempt's generation (B.9.5): its evidence names the
        // pipeline of the attempt's first revision. Other evidence would be a re-extraction,
        // which 0.1 does not support; it is refused, never relabelled.
        if a.head_revision.is_some() {
            let first: Option<String> = sqlx::query_scalar(
                "SELECT pipeline_digest FROM attempt_facts
                  WHERE project_id = $1 AND attempt_id = $2
                  ORDER BY report_revision LIMIT 1",
            )
            .bind(p.project_id)
            .bind(a.id)
            .fetch_optional(&mut *tx)
            .await?;
            if first.is_some_and(|f| f != pipeline_digest) {
                return Err(AppError::field(
                    ErrorCode::NotSupported,
                    "a correction keeps its attempt's pipeline: re-extraction under another pipeline is not supported in 0.1 (run a new attempt instead)",
                    "evidence.pipeline_digest",
                ));
            }
        }
        let pipeline_status: String =
            sqlx::query("SELECT state FROM pipelines WHERE project_id = $1 AND digest = $2")
                .bind(p.project_id)
                .bind(&pipeline_digest)
                .fetch_optional(&mut *tx)
                .await?
                .map_or_else(|| "unknown".to_string(), |r| r.get(0));
        let received_at = time::OffsetDateTime::now_utc();
        sqlx::query(
            "INSERT INTO attempt_facts (project_id, attempt_id, report_revision, report_digest, outcome,
                 blocking_phase, effective, assessment, completion, termination, design_loaded,
                 pipeline_digest, pipeline_status, purpose, source_matches, build_refs, simulator,
                 contradiction, primary_diag, credential_id, producer_id, received_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                     $18, $19, $20, $21, $22)",
        )
        .bind(p.project_id)
        .bind(a.id)
        .bind(rev)
        .bind(&digest)
        .bind(text(&d.outcome))
        .bind(d.blocking_phase.map(|b| text(&b)))
        .bind(text(&d.effective))
        .bind(text(&d.assessment))
        .bind(if d.completion_complete { "complete" } else { "incomplete" })
        .bind(text(&s.result.runner.termination.kind))
        .bind(text(&s.evidence.design_loaded))
        .bind(&pipeline_digest)
        .bind(&pipeline_status)
        .bind(text(&s.purpose))
        .bind(s.source_manifest_ref.as_str() == head.source_manifest_ref)
        .bind(json!(refs))
        .bind(sim.and_then(|c| c.simulator.clone()).unwrap_or_else(|| {
            // The profile names the simulator (`questa-run` → `questa`).
            let p = &s.evidence.completion.profile;
            p.split_once('-').map_or(String::new(), |(sim, _)| sim.to_string())
        }))
        .bind(d.contradictions.iter().any(|c| !c.explained))
        .bind(d.primary.as_deref())
        .bind(p.credential_id)
        .bind(p.producer_id)
        .bind(received_at)
        .execute(&mut *tx)
        .await?;
        // Runner metrics as retained facts (health dashboard): NULL when not measured;
        // written once migration 0020 created their table.
        let runner = &s.result.runner;
        let has_metrics: bool =
            sqlx::query_scalar("SELECT to_regclass('attempt_metrics') IS NOT NULL")
                .fetch_one(&mut *tx)
                .await?;
        if has_metrics {
            sqlx::query(
                "INSERT INTO attempt_metrics (project_id, attempt_id, report_revision, wall_s,
                        cpu_s, cpu_scope, run_finished_at)
                 VALUES ($1, $2, $3, $4::numeric, $5::numeric, $6, $7)",
            )
            .bind(p.project_id)
            .bind(a.id)
            .bind(rev)
            .bind(runner.wall_s.clone().map(String::from))
            .bind(runner.cpu_s.clone().map(String::from))
            .bind(runner.cpu_scope.as_ref().map(text))
            .bind(runner.finished_at.map(dviscope_model::values::UtcTime::get))
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO attempt_reports (project_id, attempt_id, report_revision, payload)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(p.project_id)
        .bind(a.id)
        .bind(rev)
        .bind(body)
        .execute(&mut *tx)
        .await?;
        self.classify(&mut tx, p.project_id, a.id, rev, &s.evidence, &d)
            .await?;
        super::fail::point("after_evidence")?;
        sqlx::query("UPDATE attempts SET head_revision = $3 WHERE project_id = $1 AND id = $2")
            .bind(p.project_id)
            .bind(a.id)
            .bind(rev)
            .execute(&mut *tx)
            .await?;
        bump(&mut tx, p.project_id, head.id).await?;
        let ids = json!({"regression": head.id, "slot": slot.id, "attempt": a.id});
        let r = commit_receipt(&mut tx, &p, &identity, rev, &digest, ids).await?;
        tx.commit().await?;
        Ok(r)
    }

    /// Buckets of one report revision, each attached to its signature (one per family
    /// fingerprint, created on first sight), then the synthetic buckets of the derivation.
    async fn classify(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        project_id: i64,
        attempt_id: i64,
        rev: i32,
        ev: &Evidence,
        d: &Derived,
    ) -> Result<(), AppError> {
        struct Row {
            diag: String,
            site: Option<String>,
            observed: String,
            effective: String,
            framework: String,
            provenance: &'static str,
            fails: bool,
            count: String,
            fingerprint: String,
            family_kind: String,
            identity: String,
        }
        let mut rows = vec![];
        for b in &ev.buckets {
            let fam = ev.families.iter().find(|f| f.fingerprint == b.family);
            rows.push(Row {
                diag: b.diag_id.clone(),
                site: b.site.clone(),
                observed: text(&b.observed_severity),
                effective: text(&b.effective_severity),
                framework: text(&b.framework),
                provenance: "observed",
                fails: b.fails_run,
                count: b.count.as_str().to_string(),
                fingerprint: b.family.as_str().to_string(),
                family_kind: fam.map(|f| f.family_kind.clone()).unwrap_or_default(),
                identity: fam.map_or_else(|| b.diag_id.clone(), |f| f.identity_template.clone()),
            });
        }
        for sb in &d.synthetic {
            rows.push(Row {
                diag: sb.diag_id.clone(),
                site: None,
                observed: "error".into(),
                effective: "error".into(),
                framework: "runner".into(),
                provenance: "synthetic",
                fails: true,
                count: "1".into(),
                fingerprint: synthetic_fingerprint(&sb.diag_id)?,
                family_kind: "synthetic".into(),
                identity: sb.diag_id.clone(),
            });
        }
        for (idx, r) in rows.iter().enumerate() {
            sqlx::query(
                "INSERT INTO signatures (project_id, fingerprint, family_kind, diag_id, identity_template)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (project_id, fingerprint) DO NOTHING",
            )
            .bind(project_id)
            .bind(&r.fingerprint)
            .bind(&r.family_kind)
            .bind(&r.diag)
            .bind(&r.identity)
            .execute(&mut **tx)
            .await?;
            sqlx::query(
                "INSERT INTO buckets (project_id, attempt_id, report_revision, idx, diag_id, site,
                     observed_severity, effective_severity, framework, provenance, fails_run, count,
                     signature_id)
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::text::numeric, id
                   FROM signatures WHERE project_id = $1 AND fingerprint = $13",
            )
            .bind(project_id)
            .bind(attempt_id)
            .bind(rev)
            .bind(i32::try_from(idx).unwrap_or(i32::MAX))
            .bind(&r.diag)
            .bind(r.site.as_deref())
            .bind(&r.observed)
            .bind(&r.effective)
            .bind(&r.framework)
            .bind(r.provenance)
            .bind(r.fails)
            .bind(&r.count)
            .bind(&r.fingerprint)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    /// A build requirement names a source manifest of the producer (a foreign-source build
    /// is refused).
    async fn check_build_source(
        tx: &mut Transaction<'_, Postgres>,
        p: &Producer,
        req: &dviscope_model::wire::manifest::BuildReqRef,
    ) -> Result<(), AppError> {
        let known = sqlx::query(
            "SELECT 1 FROM source_manifests WHERE project_id = $1 AND producer_id = $2 AND ref = $3",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(req.source_manifest_ref.as_str())
        .fetch_optional(&mut **tx)
        .await?;
        if known.is_none() {
            return Err(invalid(
                format!(
                    "unknown source manifest {}",
                    req.source_manifest_ref.as_str()
                ),
                "build_req",
            ));
        }
        Ok(())
    }

    /// Locks (creating on first sight) a build attempt; `build_order` is assigned by the
    /// server per requirement, under a transaction-scoped lock on the requirement.
    async fn build_row(
        tx: &mut Transaction<'_, Postgres>,
        p: &Producer,
        build_ref: &str,
        req: &str,
        started_at: time::OffsetDateTime,
    ) -> Result<(i64, Option<i32>), AppError> {
        super::gate_shared(tx).await?;
        // Builds settle the slots that require them: evaluations become stale.
        super::decisions::bump_project(tx, p.project_id, "build", &format!("build:{build_ref}"))
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, $2))")
            .bind(req)
            .bind(p.project_id)
            .execute(&mut **tx)
            .await?;
        let expired = sqlx::query(
            "SELECT 1 FROM expired_builds WHERE project_id = $1 AND producer_id = $2 AND build_ref = $3",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(build_ref)
        .fetch_optional(&mut **tx)
        .await?;
        if expired.is_some() {
            return Err(AppError::field(
                ErrorCode::Expired,
                format!("build {build_ref} is past retention"),
                "build_ref",
            ));
        }
        if let Some(r) = sqlx::query(
            "SELECT id, build_req, head_revision FROM build_attempts
              WHERE project_id = $1 AND producer_id = $2 AND build_ref = $3 FOR UPDATE",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(build_ref)
        .fetch_optional(&mut **tx)
        .await?
        {
            if r.get::<String, _>(1) != req {
                return Err(AppError::field(
                    ErrorCode::RevisionConflict,
                    format!("build {build_ref} builds another requirement"),
                    "build_req",
                ));
            }
            return Ok((r.get(0), r.get(2)));
        }
        let id: i64 = sqlx::query(
            "INSERT INTO build_attempts (project_id, producer_id, build_ref, build_req, build_order,
                                         started_at, credential_id)
             SELECT $1, $2, $3, $4, coalesce(max(build_order), 0) + 1, $5, $6
               FROM build_attempts WHERE project_id = $1 AND build_req = $4
             RETURNING id",
        )
        .bind(p.project_id)
        .bind(p.producer_id)
        .bind(build_ref)
        .bind(req)
        .bind(started_at)
        .bind(p.credential_id)
        .fetch_one(&mut **tx)
        .await?
        .get(0);
        Ok((id, None))
    }

    async fn build_started(
        &self,
        actor: &Actor,
        body: &Value,
        b: &BuildStarted,
    ) -> Result<Receipt, AppError> {
        check_schema(&b.schema, "dviscope.ingest/")?;
        let p = self
            .producer(actor, Action::IngestSubmit, Some(b.producer_id.as_str()))
            .await?;
        let identity = format!("build_started:{}", b.build_ref.as_str());
        let digest = payload_digest(body)?;
        let req = build_req_key(&b.build_req)?;
        let mut tx = super::begin_write(&self.db).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, 1, &digest, &[]).await? {
            return Ok(r);
        }
        Self::check_build_source(&mut tx, &p, &b.build_req).await?;
        let (id, _) =
            Self::build_row(&mut tx, &p, b.build_ref.as_str(), &req, b.started_at.get()).await?;
        let r = commit_receipt(
            &mut tx,
            &p,
            &identity,
            1,
            &digest,
            json!({"build_attempt": id}),
        )
        .await?;
        tx.commit().await?;
        Ok(r)
    }

    async fn build_attempt(
        &self,
        actor: &Actor,
        body: &Value,
        b: &BuildAttempt,
    ) -> Result<Receipt, AppError> {
        check_schema(&b.schema, "dviscope.ingest/")?;
        check_schema(&b.evidence.schema, "dviscope.evidence/")?;
        dviscope_core::model_main::check_build(&b.evidence).map_err(|m| invalid(m, "evidence"))?;
        let p = self
            .producer(actor, Action::IngestSubmit, Some(b.producer_id.as_str()))
            .await?;
        let rev = revision_of(b.report_revision)?;
        let identity = format!("build_attempt:{}", b.build_ref.as_str());
        let digest = payload_digest(body)?;
        let req = build_req_key(&b.build_req)?;
        let mut tx = super::begin_write(&self.db).await?;
        if let Some(r) = replay(&mut tx, &p, &identity, rev, &digest, &[]).await? {
            return Ok(r);
        }
        Self::check_build_source(&mut tx, &p, &b.build_req).await?;
        let (id, head) = Self::build_row(
            &mut tx,
            &p,
            b.build_ref.as_str(),
            &req,
            b.runner.started_at.get(),
        )
        .await?;
        check_head(head, rev, &identity)?;
        let purpose = if b.purpose == Purpose::Experiment {
            "experiment"
        } else {
            "production"
        };
        // A claimed pass counts only when the runner and the evidence support it: exited 0,
        // complete evidence, no failing diagnostic. Otherwise the build is an error.
        let supported = b.runner.termination.kind == TerminationKind::Exited
            && b.runner.termination.exit_code == Some(0)
            && b.evidence.completion.state == CompletionState::Complete
            && !b.evidence.buckets.iter().any(|x| x.fails_run)
            && !b.evidence.overflow.iter().any(|x| x.fails_run)
            && !b
                .evidence
                .counters
                .iter()
                .any(|c| c.role == CounterRole::FailureCount && c.value.as_str() != "0")
            && !b
                .evidence
                .verdict_sources
                .iter()
                .any(|v| v.value == VerdictValue::Fail)
            && b.evidence
                .reconciliation
                .iter()
                .all(|r| r.holds && r.counted == r.extracted);
        let outcome = match b.outcome {
            BuildOutcome::Pass if !supported => "error".to_string(),
            o => text(&o),
        };
        // A build correction keeps its attempt's generation (B.9.5), as a simulation one:
        // its evidence names the pipeline of the first revision (an unknown one included);
        // anything else would be a re-extraction, refused in 0.1.
        let first: Option<String> = sqlx::query_scalar(
            "SELECT pipeline_digest FROM build_facts
              WHERE project_id = $1 AND build_attempt_id = $2
              ORDER BY report_revision LIMIT 1",
        )
        .bind(p.project_id)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        if first.is_some_and(|f| f != b.evidence.pipeline_digest.as_str()) {
            return Err(AppError::field(
                ErrorCode::NotSupported,
                "a correction keeps its build's pipeline: re-extraction under another pipeline is not supported in 0.1 (run a new build instead)",
                "evidence.pipeline_digest",
            ));
        }
        sqlx::query(
            "INSERT INTO build_facts (project_id, build_attempt_id, report_revision, report_digest,
                 outcome, phase_reached, purpose, credential_id, received_at, pipeline_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9)",
        )
        .bind(p.project_id)
        .bind(id)
        .bind(rev)
        .bind(&digest)
        .bind(&outcome)
        .bind(text(&b.phase_reached))
        .bind(purpose)
        .bind(p.credential_id)
        .bind(b.evidence.pipeline_digest.as_str())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE build_attempts SET head_revision = $3 WHERE project_id = $1 AND id = $2",
        )
        .bind(p.project_id)
        .bind(id)
        .bind(rev)
        .execute(&mut *tx)
        .await?;
        let r = commit_receipt(
            &mut tx,
            &p,
            &identity,
            rev,
            &digest,
            json!({"build_attempt": id}),
        )
        .await?;
        tx.commit().await?;
        Ok(r)
    }
}
