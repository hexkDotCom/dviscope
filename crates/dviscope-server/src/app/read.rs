//! Reads: slot states are settled at query time from the retained facts
//! (never payloads, never stored states), with eligibility and barriers evaluated against
//! the current quarantine and pipeline state. Comparison reads both regressions the same
//! way and joins them in core.

use std::collections::BTreeMap;

use dviscope_core::compare::{self, Comparison, Header, SignatureCounts, SlotView};
use dviscope_core::eligibility::{self, Eligibility, PipelineStatus};
use dviscope_core::outcome::{BlockingPhase, Effective, Outcome};
use dviscope_core::readiness::AttemptView;
use dviscope_core::settlement::{
    self, AttemptFacts, Barrier, BuildFacts, BuildResult, Mark, Policy, Settled, SlotFacts,
    SlotState, Terminal,
};
use dviscope_model::canonical::Digest;
use dviscope_model::errors::ErrorCode;
use serde::Serialize;
use serde_json::Value;
use sqlx::{Postgres, Row as _, Transaction};

use super::App;
use crate::auth::{Action, Actor, authorize};
use crate::error::AppError;

/// A slot with its settled state.
#[derive(Debug, Clone, Serialize)]
pub struct SlotRead {
    /// Producer slot key.
    pub slot_ref: String,
    /// Test name.
    pub test: String,
    /// Required for readiness.
    pub required: bool,
    /// Settled state (`state`, and `detail` for failed and blocked).
    #[serde(flatten)]
    pub state: SlotState,
    /// Explanation shown with the state.
    pub note: Option<String>,
    /// `attempt_seq` of the deciding attempt.
    pub deciding: Option<u32>,
    /// Attempts received (started or reported).
    pub attempts: usize,
}

/// `GET /api/v1/projects/{p}/regressions/{ref}`.
#[derive(Debug, Clone, Serialize)]
pub struct RegressionRead {
    /// Regression header as received, plus the server's state.
    pub regression: Value,
    /// Header counts.
    pub header: Header,
    /// Slots in `slot_ref` order.
    pub slots: Vec<SlotRead>,
}

/// `GET …/comparison`: the comparison with each row's decisions and the finish card.
#[derive(Debug, Clone)]
pub struct ComparisonRead {
    /// Regression header.
    pub regression: Value,
    /// Header counts and rows (rows in display order).
    pub comparison: Comparison,
    /// Per signature fingerprint: number, triage, exception, disposition.
    pub decisions: BTreeMap<String, RowDecision>,
    /// Finish card counts.
    pub finish: Value,
    /// The baseline used and why (`{ref, reason, simulators, simulators_differ}`; `ref` null
    /// without a baseline).
    pub baseline: Value,
}

/// A comparison row's decisions for the regression's branch and suite.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RowDecision {
    /// Project signature number.
    pub number: Option<i64>,
    /// Diagnostic ID of the signature (e.g. `uvm:ID`).
    pub diag_id: Option<String>,
    /// Identity template of the signature (variable parts as placeholders).
    pub identity_template: Option<String>,
    /// `open` or `closed`, if triaged on this branch.
    pub triage_state: Option<String>,
    /// Head revision of the branch's triage case (the base of an edit), if any.
    pub triage_revision: Option<i32>,
    /// Owner.
    pub owner: Option<String>,
    /// First non-empty line of the notes (at most 200 characters).
    pub latest_note: Option<String>,
    /// First bug URL.
    pub bug_url: Option<String>,
    /// Active exception for this branch and suite.
    pub exception: Option<RowException>,
    /// `needs_decision`, `assigned` or `covered`.
    pub disposition: &'static str,
    /// The one next action.
    pub next_action: &'static str,
}

/// An active exception of a row.
#[derive(Debug, Clone, Serialize)]
pub struct RowException {
    /// ID.
    pub id: i64,
    /// Expiry (RFC 3339).
    pub expires_at: String,
}

/// One regression's settled slots, for reads and comparison.
pub(crate) struct Loaded {
    pub(crate) header: Value,
    pub(crate) slots: Vec<(SlotRead, SlotView)>,
    /// Per slot (same order): its attempts as readiness reads them.
    pub(crate) attempts: Vec<Vec<AttemptView>>,
    /// Regression row facts readiness needs.
    pub(crate) facts: RegressionFacts,
    /// Per slot (same order): what the proof card and the repair list show.
    pub(crate) extra: Vec<SlotExtra>,
}

/// Per-slot facts beyond settlement: the deciding attempt's builds and expectation, and why
/// received reports were not eligible.
#[derive(Debug, Clone, Default)]
pub(crate) struct SlotExtra {
    pub(crate) deciding_builds: Vec<String>,
    pub(crate) expectation_met: bool,
    pub(crate) ineligible: Vec<&'static str>,
    /// A received report says the attempt was interrupted (termination unknown).
    pub(crate) interrupted: bool,
}

fn ineligible_label(r: eligibility::IneligibleReason) -> &'static str {
    match r {
        eligibility::IneligibleReason::SourceMismatch => "source",
        eligibility::IneligibleReason::PipelineMismatch => "pipeline",
        eligibility::IneligibleReason::Quarantined => "quarantine",
        eligibility::IneligibleReason::PurposeExperiment => "experiment",
    }
}

/// Regression facts for readiness.
#[derive(Debug, Clone, Default)]
pub(crate) struct RegressionFacts {
    pub(crate) state: String,
    pub(crate) sealed: bool,
    pub(crate) suite: String,
    pub(crate) branch: String,
    pub(crate) source_manifest_ref: String,
    pub(crate) producer_id: i64,
    pub(crate) manifest_revision: i32,
    /// An expected-set removal by a quarantined credential is pending.
    pub(crate) quarantined_removal: bool,
}

fn outcome_of(s: &str) -> Outcome {
    match s {
        "pass" => Outcome::Pass,
        "fail" => Outcome::Fail,
        "timeout" => Outcome::Timeout,
        "killed" => Outcome::Killed,
        "blocked" => Outcome::Blocked,
        _ => Outcome::Error,
    }
}

fn digest(s: &str) -> Result<Digest, AppError> {
    serde_json::from_value(Value::String(s.to_string()))
        .map_err(|_| AppError::internal("stored digest"))
}

impl App {
    /// Resolves a project by name for a reading user (role `viewer` or more).
    /// A read-only, repeatable-read transaction: one snapshot for every query of a read.
    pub(crate) async fn snapshot(&self) -> Result<Transaction<'static, Postgres>, AppError> {
        let mut tx = self.db.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    pub(crate) async fn read_project(
        &self,
        actor: &Actor,
        project: &str,
        action: Action,
    ) -> Result<(i64, Policy), AppError> {
        let row = sqlx::query("SELECT id, policy FROM projects WHERE name = $1")
            .bind(project)
            .fetch_optional(&self.db)
            .await?
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, format!("no project {project}")))?;
        let id: i64 = row.get(0);
        // Not-found and forbidden look alike to outsiders: a user without a role here gets
        // 403 only after the project exists, which names nothing they could not guess.
        authorize(actor, action, id)?;
        let policy = if row.get::<String, _>(1) == "retry-pass-accepted" {
            Policy::RetryPassAccepted
        } else {
            Policy::Strict
        };
        Ok((id, policy))
    }

    #[allow(clippy::too_many_lines)] // a fixed number of bulk queries, then core settlement
    /// Loads and settles one regression inside the caller's read snapshot.
    pub(crate) async fn load(
        tx: &mut Transaction<'_, Postgres>,
        project_id: i64,
        policy: Policy,
        regression_ref: &str,
        producer: Option<&str>,
    ) -> Result<Loaded, AppError> {
        let regs = sqlx::query(
            "SELECT r.id, r.ref, p.name, r.suite, r.branch_repository, r.branch_name, r.state,
                    r.manifest_revision, r.manifest_digest, r.started_at, r.finished_at,
                    r.change_seq, r.source_manifest_ref, r.producer_id, r.sealed
               FROM regressions r JOIN producers p ON p.project_id = r.project_id AND p.id = r.producer_id
              WHERE r.project_id = $1 AND r.ref = $2 AND ($3::text IS NULL OR p.name = $3)",
        )
        .bind(project_id)
        .bind(regression_ref)
        .bind(producer)
        .fetch_all(&mut **tx)
        .await?;
        let reg = match regs.as_slice() {
            [r] => r,
            [] => {
                // A regression retention removed answers as such (410), as its late records
                // do, not as one that never existed.
                let expired = sqlx::query(
                    "SELECT 1 FROM expired_regressions e
                       JOIN producers p ON p.project_id = e.project_id AND p.id = e.producer_id
                      WHERE e.project_id = $1 AND e.ref = $2 AND ($3::text IS NULL OR p.name = $3)
                      LIMIT 1",
                )
                .bind(project_id)
                .bind(regression_ref)
                .bind(producer)
                .fetch_optional(&mut **tx)
                .await?;
                return Err(if expired.is_some() {
                    AppError::new(
                        ErrorCode::Expired,
                        format!("regression {regression_ref} is past retention"),
                    )
                } else {
                    AppError::new(
                        ErrorCode::NotFound,
                        format!("no regression {regression_ref}"),
                    )
                });
            }
            _ => {
                return Err(AppError::field(
                    ErrorCode::Invalid,
                    "several producers use this regression reference: name the producer",
                    "producer",
                ));
            }
        };
        let rid: i64 = reg.get(0);
        let producer_id: i64 = reg.get(13);
        let header = serde_json::json!({
            "ref": reg.get::<String, _>(1),
            "producer": reg.get::<String, _>(2),
            "suite": reg.get::<String, _>(3),
            "branch": {"repository": reg.get::<String, _>(4), "name": reg.get::<String, _>(5)},
            "state": reg.get::<String, _>(6),
            "manifest_revision": reg.get::<i32, _>(7),
            "manifest_digest": reg.get::<Option<String>, _>(8),
            "started_at": reg.get::<time::OffsetDateTime, _>(9).format(&time::format_description::well_known::Rfc3339).ok(),
            "finished_at": reg.get::<Option<time::OffsetDateTime>, _>(10).and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok()),
            "change_seq": reg.get::<i64, _>(11),
            "source_manifest_ref": reg.get::<String, _>(12),
        });

        // Slots and marks.
        let slot_rows = sqlx::query(
            concat!(
                "SELECT s.id, s.slot_ref, s.test, s.required, s.config_digest, s.build_reqs, m.state,
                        coalesce(s.decl #>> '{build_reqs,0,build_config,simulator,vendor}',
                                 s.decl #>> '{exec_inputs,extra,tool,simulator}'),
                        s.removed_revision IS NOT NULL
                   FROM slots s LEFT JOIN slot_marks m ON m.project_id = s.project_id AND m.slot_id = s.id
                  WHERE s.project_id = $1 AND s.regression_id = $2
                    AND (s.removed_revision IS NULL OR ",
                // A removal that does not count does not shrink the expected set.
                removal_untrusted!(),
                ") ORDER BY s.slot_ref COLLATE \"C\""
            ),
        )
        .bind(project_id)
        .bind(rid)
        .fetch_all(&mut **tx)
        .await?;

        // Head facts of every attempt, with current quarantine and pipeline state.
        let att_rows = sqlx::query(
            "SELECT a.slot_id, a.attempt_seq, f.outcome, f.blocking_phase, f.effective,
                    f.assessment, f.termination, f.purpose, f.source_matches, f.build_refs,
                    pl.state,
                    EXISTS (SELECT 1 FROM attempt_facts f2
                              JOIN api_tokens q ON q.id = f2.credential_id
                             WHERE f2.project_id = a.project_id AND f2.attempt_id = a.id
                               AND f2.received_at >= q.quarantined_since),
                    f.simulator, a.id, f.report_revision, f.completion, f.contradiction
               FROM attempts a
               JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
               LEFT JOIN attempt_facts f ON f.project_id = a.project_id AND f.attempt_id = a.id
                                        AND f.report_revision = a.head_revision
               LEFT JOIN pipelines pl ON pl.project_id = a.project_id AND pl.digest = f.pipeline_digest
              WHERE a.project_id = $1 AND s.regression_id = $2",
        )
        .bind(project_id)
        .bind(rid)
        .fetch_all(&mut **tx)
        .await?;

        // Failing buckets of head revisions, per attempt and signature.
        let sig_rows = sqlx::query(
            "SELECT b.attempt_id, g.fingerprint, sum(b.count)::text, g.diag_id
               FROM buckets b
               JOIN attempts a ON a.project_id = b.project_id AND a.id = b.attempt_id
                              AND a.head_revision = b.report_revision
               JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
               JOIN signatures g ON g.project_id = b.project_id AND g.id = b.signature_id
              WHERE b.project_id = $1 AND s.regression_id = $2 AND b.fails_run
              GROUP BY b.attempt_id, g.fingerprint, g.diag_id",
        )
        .bind(project_id)
        .bind(rid)
        .fetch_all(&mut **tx)
        .await?;
        // Attempts failing only by the synthetic "unexplained" diagnostic (never exceptable).
        let unexplained: std::collections::BTreeSet<i64> = sig_rows
            .iter()
            .filter(|r| {
                r.get::<String, _>(3) == dviscope_core::outcome::synthetic::UNEXPLAINED_FAILURE
            })
            .map(|r| r.get::<i64, _>(0))
            .collect();
        let mut sigs: BTreeMap<i64, Vec<(String, u64)>> = BTreeMap::new();
        for r in &sig_rows {
            let n: String = r.get(2);
            sigs.entry(r.get(0))
                .or_default()
                .push((r.get(1), n.parse().unwrap_or(u64::MAX)));
        }

        // Builds of every requirement the slots name (latest facts per build attempt).
        let build_rows = sqlx::query(
            "SELECT b.build_ref, b.build_req, b.build_order, f.outcome, f.purpose,
                    EXISTS (SELECT 1 FROM build_facts f2
                              JOIN api_tokens q ON q.id = f2.credential_id
                             WHERE f2.project_id = b.project_id AND f2.build_attempt_id = b.id
                               AND f2.received_at >= q.quarantined_since),
                    pl.state
               FROM build_attempts b
               LEFT JOIN build_facts f ON f.project_id = b.project_id AND f.build_attempt_id = b.id
                                      AND f.report_revision = b.head_revision
               LEFT JOIN pipelines pl ON pl.project_id = b.project_id AND pl.digest = f.pipeline_digest
              WHERE b.project_id = $1 AND b.producer_id = $3 AND b.build_req IN (
                    SELECT jsonb_array_elements_text(s.build_reqs) FROM slots s
                     WHERE s.project_id = $1 AND s.regression_id = $2)",
        )
        .bind(project_id)
        .bind(rid)
        .bind(producer_id)
        .fetch_all(&mut **tx)
        .await?;
        let builds: Vec<BuildFacts> = build_rows
            .iter()
            .map(|r| {
                let quarantined = r.get::<Option<bool>, _>(5).unwrap_or(false);
                let purpose: Option<String> = r.get(4);
                // A reported build proves something only under an accepted pipeline.
                let reported = r.get::<Option<String>, _>(3).is_some();
                let accepted = r.get::<Option<String>, _>(6).as_deref() == Some("accepted");
                BuildFacts {
                    build_ref: r.get(0),
                    requirement: r.get(1),
                    build_order: u64::try_from(r.get::<i64, _>(2)).unwrap_or(0),
                    eligible: !quarantined
                        && purpose.as_deref() != Some("experiment")
                        && (!reported || accepted),
                    result: r.get::<Option<String>, _>(3).map(|o| match o.as_str() {
                        "pass" => BuildResult::Pass,
                        "fail" => BuildResult::Fail,
                        _ => BuildResult::Error,
                    }),
                }
            })
            .collect();
        let quarantined_builds: std::collections::BTreeSet<String> = build_rows
            .iter()
            .filter(|r| r.get::<Option<bool>, _>(5).unwrap_or(false))
            .map(|r| r.get(0))
            .collect();
        // Build history indexed by requirement once; slots with the same requirements share
        // one list (no per-slot scan or copy of the history).
        let mut by_req: BTreeMap<&str, Vec<&BuildFacts>> = BTreeMap::new();
        for b in &builds {
            by_req.entry(b.requirement.as_str()).or_default().push(b);
        }
        let mut shared: BTreeMap<Vec<String>, settlement::SharedBuilds> = BTreeMap::new();
        let mut builds_of = |reqs: &Vec<String>| -> settlement::SharedBuilds {
            let mut key = reqs.clone();
            key.sort();
            key.dedup();
            shared
                .entry(key)
                .or_insert_with_key(|k| {
                    k.iter()
                        .flat_map(|r| by_req.get(r.as_str()).into_iter().flatten())
                        .map(|b| (*b).clone())
                        .collect()
                })
                .clone()
        };

        // Attempts grouped by slot once (a scan per slot is quadratic in big regressions).
        let mut att_by_slot: BTreeMap<i64, Vec<&sqlx::postgres::PgRow>> = BTreeMap::new();
        for a in &att_rows {
            att_by_slot.entry(a.get::<i64, _>(0)).or_default().push(a);
        }
        let mut slots = vec![];
        let mut all_views: Vec<Vec<AttemptView>> = vec![];
        let mut extras: Vec<SlotExtra> = vec![];
        for s in &slot_rows {
            let sid: i64 = s.get(0);
            let reqs: Vec<String> =
                serde_json::from_value(s.get::<Value, _>(5)).unwrap_or_default();
            let mut attempts = vec![];
            let mut views_r: Vec<AttemptView> = vec![];
            let mut views: BTreeMap<Digest, SignatureCounts> = BTreeMap::new();
            let mut simulator = String::new();
            let mut per_attempt: BTreeMap<u32, (Vec<String>, bool)> = BTreeMap::new();
            let mut ineligible: Vec<&'static str> = vec![];
            let mut interrupted = false;
            for &a in att_by_slot.get(&sid).into_iter().flatten() {
                let seq = u32::try_from(a.get::<i32, _>(1)).unwrap_or(0);
                let has_report = a.get::<Option<i32>, _>(14).is_some();
                let build_refs: Vec<String> = a
                    .get::<Option<Value>, _>(9)
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_default();
                let pipeline = a.get::<Option<String>, _>(10);
                let pipeline = has_report.then_some(match pipeline.as_deref() {
                    Some("accepted") => PipelineStatus::Accepted,
                    Some("withdrawn") => PipelineStatus::Withdrawn,
                    _ => PipelineStatus::Unknown,
                });
                let quarantined = a.get::<Option<bool>, _>(11).unwrap_or(false);
                let elig = eligibility::eligibility(&eligibility::Facts {
                    quarantined,
                    experiment: a.get::<Option<String>, _>(7).as_deref() == Some("experiment"),
                    source_matches: a.get::<Option<bool>, _>(8).unwrap_or(true),
                    pipeline,
                });
                interrupted |=
                    has_report && a.get::<Option<String>, _>(6).as_deref() == Some("unknown");
                if let (true, Eligibility::Ineligible(r)) = (has_report, elig) {
                    let label = ineligible_label(r);
                    if !ineligible.contains(&label) {
                        ineligible.push(label);
                    }
                }
                per_attempt.insert(
                    seq,
                    (
                        build_refs.clone(),
                        a.get::<Option<String>, _>(5).as_deref() == Some("met"),
                    ),
                );
                let terminal = if has_report {
                    let effective = if a.get::<Option<String>, _>(4).as_deref() == Some("passed") {
                        Effective::Passed
                    } else {
                        Effective::Failed
                    };
                    if effective == Effective::Failed && elig == Eligibility::Eligible {
                        for (fp, n) in sigs.get(&a.get::<i64, _>(13)).into_iter().flatten() {
                            let c = views.entry(digest(fp)?).or_default();
                            c.attempts += 1;
                            c.diagnostics = c.diagnostics.saturating_add(*n);
                        }
                    }
                    let sim: Option<String> = a.get(12);
                    if let Some(sim) = sim.filter(|x| !x.is_empty()) {
                        simulator = sim;
                    }
                    Some(Terminal {
                        outcome: outcome_of(&a.get::<Option<String>, _>(2).unwrap_or_default()),
                        blocking_phase: a.get::<Option<String>, _>(3).map(|b| {
                            if b == "compile" {
                                BlockingPhase::Compile
                            } else {
                                BlockingPhase::Elaborate
                            }
                        }),
                        effective,
                        expectation_not_met: a.get::<Option<String>, _>(5).as_deref()
                            == Some("not_met"),
                        termination_unknown: a.get::<Option<String>, _>(6).as_deref()
                            == Some("unknown"),
                        build_refs: build_refs.clone(),
                    })
                } else {
                    None
                };
                views_r.push(AttemptView {
                    attempt_seq: seq,
                    eligible: elig == Eligibility::Eligible,
                    terminal: has_report,
                    failed: a.get::<Option<String>, _>(4).as_deref() == Some("failed"),
                    complete: !has_report
                        || a.get::<Option<String>, _>(15).as_deref() == Some("complete"),
                    contradiction: a.get::<Option<bool>, _>(16).unwrap_or(false),
                    unexplained: unexplained.contains(&a.get::<i64, _>(13)),
                    build_proven: true, // set below, once the slot's builds are known
                    fail_reason: terminal
                        .as_ref()
                        .filter(|t| t.effective == Effective::Failed)
                        .and_then(|t| settlement::attempt_failure(t).ok()),
                    blocked: terminal
                        .as_ref()
                        .filter(|t| t.effective == Effective::Failed)
                        .and_then(|t| settlement::attempt_failure(t).err()),
                    signatures: sigs
                        .get(&a.get::<i64, _>(13))
                        .into_iter()
                        .flatten()
                        .map(|(fp, _)| fp.clone())
                        .collect(),
                });
                attempts.push(AttemptFacts {
                    attempt_seq: seq,
                    eligibility: elig,
                    barrier: Barrier {
                        quarantined_credential: quarantined,
                        withdrawn_pipeline: pipeline == Some(PipelineStatus::Withdrawn),
                        quarantined_build: build_refs
                            .iter()
                            .any(|b| quarantined_builds.contains(b)),
                    },
                    terminal,
                });
            }
            if simulator.is_empty() {
                // The declared build configuration (or, without a build requirement, the
                // execution inputs' `extra.tool.simulator`) names the simulator before any
                // report.
                // (Projected in the query: only those two fields of the declaration.)
                simulator = s.get::<Option<String>, _>(7).unwrap_or_default();
            }
            let facts = SlotFacts {
                attempts,
                build_requirements: reqs.clone(),
                builds: builds_of(&reqs),
                mark: s.get::<Option<String>, _>(6).map(|m| {
                    if m == "skipped" {
                        Mark::Skipped
                    } else {
                        Mark::Cancelled
                    }
                }),
            };
            // Each terminal attempt's own build proof (readiness checks every authoritative
            // attempt, not only the deciding one).
            for (view, fact) in views_r.iter_mut().zip(&facts.attempts) {
                if let Some(t) = &fact.terminal {
                    view.build_proven = settlement::build_proven(&facts, t);
                }
            }
            let Settled {
                state,
                note,
                deciding,
            } = settlement::settle(&facts, policy);
            all_views.push(views_r);
            let (deciding_builds, expectation_met) = deciding
                .and_then(|d| per_attempt.remove(&d))
                .unwrap_or_default();
            extras.push(SlotExtra {
                deciding_builds,
                expectation_met,
                ineligible,
                interrupted,
            });
            slots.push((
                SlotRead {
                    slot_ref: s.get(1),
                    test: s.get(2),
                    required: s.get(3),
                    state,
                    note,
                    deciding,
                    attempts: facts.attempts.len(),
                },
                SlotView {
                    slot: s.get(1),
                    config: digest(&s.get::<String, _>(4))?,
                    simulator,
                    state,
                    signatures: views,
                },
            ));
        }
        Ok(Loaded {
            header,
            slots,
            attempts: all_views,
            extra: extras,
            facts: RegressionFacts {
                state: reg.get(6),
                // The stored flag: a regression finished without its seal stays unsealed
                // (its manifest may be partial), never "closed".
                sealed: reg.get(14),
                suite: reg.get(3),
                branch: format!("{}/{}", reg.get::<String, _>(4), reg.get::<String, _>(5)),
                source_manifest_ref: reg.get(12),
                producer_id,
                manifest_revision: reg.get(7),
                quarantined_removal: slot_rows.iter().any(|s| s.get::<bool, _>(8)),
            },
        })
    }

    /// A regression with its settled slots.
    ///
    /// # Errors
    /// Authorization, unknown project or regression, database errors.
    pub async fn read_regression(
        &self,
        actor: &Actor,
        project: &str,
        regression_ref: &str,
        producer: Option<&str>,
    ) -> Result<RegressionRead, AppError> {
        let (pid, policy) = self
            .read_project(actor, project, Action::RegressionRead)
            .await?;
        let mut tx = self.snapshot().await?;
        let l = Self::load(&mut tx, pid, policy, regression_ref, producer).await?;
        tx.commit().await?;
        let views: Vec<SlotView> = l.slots.iter().map(|(_, v)| v.clone()).collect();
        Ok(RegressionRead {
            regression: l.header,
            header: compare::compare(&views, None).header,
            slots: l.slots.into_iter().map(|(s, _)| s).collect(),
        })
    }

    /// The comparison of a regression with an optional baseline of the same project, with
    /// each signature's triage and exception state for the regression's branch and suite,
    /// its disposition, and the finish card. One snapshot.
    ///
    /// # Errors
    /// Authorization, unknown project or regressions, database errors.
    #[allow(clippy::too_many_lines)] // one snapshot: rows, decisions, finish card
    pub async fn read_comparison(
        &self,
        actor: &Actor,
        project: &str,
        regression_ref: &str,
        baseline: Option<&str>,
        producer: Option<&str>,
    ) -> Result<ComparisonRead, AppError> {
        let (pid, policy) = self
            .read_project(actor, project, Action::ComparisonRead)
            .await?;
        let mut tx = self.snapshot().await?;
        let cur = Self::load(&mut tx, pid, policy, regression_ref, producer).await?;
        // Baseline: the one named, none, or by default the most recent earlier
        // finished regression of the same producer, suite and repository-qualified branch.
        let (base_ref, reason) = match baseline {
            Some("none") => (None, "none requested".to_string()),
            Some(b) => (Some(b.to_string()), "selected".to_string()),
            None => {
                let r: Option<String> = sqlx::query_scalar(
                    "SELECT b.ref FROM regressions c
                       JOIN regressions b ON b.project_id = c.project_id
                        AND b.producer_id = c.producer_id AND b.suite = c.suite
                        AND b.branch_repository = c.branch_repository
                        AND b.branch_name = c.branch_name AND b.state = 'finished'
                        AND (b.started_at, b.id) < (c.started_at, c.id)
                      WHERE c.project_id = $1 AND c.producer_id = $2 AND c.ref = $3
                      ORDER BY b.started_at DESC, b.id DESC LIMIT 1",
                )
                .bind(pid)
                .bind(cur.facts.producer_id)
                .bind(regression_ref)
                .fetch_optional(&mut *tx)
                .await?;
                let why = if r.is_some() {
                    format!(
                        "most recent earlier finished regression of suite {} on {}",
                        cur.facts.suite, cur.facts.branch
                    )
                } else {
                    format!(
                        "none: no earlier finished regression of suite {} on {}",
                        cur.facts.suite, cur.facts.branch
                    )
                };
                (r, why)
            }
        };
        let base = match &base_ref {
            Some(b) => Some(Self::load(&mut tx, pid, policy, b, producer).await?),
            None => None,
        };
        let now = time::OffsetDateTime::now_utc();
        let out = Self::comparison_of(
            &mut tx,
            pid,
            policy,
            &cur,
            base.as_ref(),
            base_ref,
            reason,
            now,
        )
        .await?;
        tx.commit().await?;
        Ok(out)
    }

    /// The comparison of a loaded regression with its loaded baseline, decisions as of
    /// `now` (one snapshot and one clock for the caller: the comparison page, the health
    /// dashboard).
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)] // one snapshot: rows, decisions, finish card
    pub(crate) async fn comparison_of(
        tx: &mut Transaction<'_, Postgres>,
        pid: i64,
        policy: Policy,
        cur: &Loaded,
        base: Option<&Loaded>,
        base_ref: Option<String>,
        reason: String,
        now: time::OffsetDateTime,
    ) -> Result<ComparisonRead, AppError> {
        let cv: Vec<SlotView> = cur.slots.iter().map(|(_, v)| v.clone()).collect();
        let bv: Option<Vec<SlotView>> =
            base.map(|b| b.slots.iter().map(|(_, v)| v.clone()).collect());
        let mut cmp = compare::compare(&cv, bv.as_deref());
        let fingerprints: Vec<String> = cmp.rows.iter().map(|r| r.signature.to_string()).collect();
        // Signature numbers and the triage head of the regression's branch.
        let tri = sqlx::query(
            "SELECT g.fingerprint, g.number, r.state, r.owner, r.notes, r.bug_urls,
                    g.diag_id, g.identity_template, c.revision
               FROM signatures g
               LEFT JOIN triage_cases c ON c.project_id = g.project_id AND c.signature_id = g.id
                                       AND c.branch = $3
               LEFT JOIN triage_revisions r ON r.project_id = c.project_id AND r.case_id = c.id
                                           AND r.revision = c.revision
              WHERE g.project_id = $1 AND g.fingerprint = ANY($2)",
        )
        .bind(pid)
        .bind(&fingerprints)
        .bind(&cur.facts.branch)
        .fetch_all(&mut **tx)
        .await?;
        // Active exceptions of the branch and suite (snapshot time).
        let exc = sqlx::query(
            "SELECT g.fingerprint, e.id, e.expires_at, e.revision
               FROM exceptions e
               JOIN signatures g ON g.project_id = e.project_id AND g.id = e.signature_id
              WHERE e.project_id = $1 AND e.branch = $2 AND e.suite = $3
                AND e.revoked_at IS NULL AND e.superseded_by IS NULL AND e.expires_at > $5
                AND g.fingerprint = ANY($4)",
        )
        .bind(pid)
        .bind(&cur.facts.branch)
        .bind(&cur.facts.suite)
        .bind(&fingerprints)
        .bind(now)
        .fetch_all(&mut **tx)
        .await?;
        let mut decisions: BTreeMap<String, RowDecision> = BTreeMap::new();
        for r in &tri {
            let notes: Option<String> = r.get(4);
            decisions.insert(
                r.get(0),
                RowDecision {
                    number: Some(r.get(1)),
                    diag_id: Some(r.get(6)),
                    identity_template: Some(r.get(7)),
                    triage_state: r.get(2),
                    triage_revision: r.get(8),
                    owner: r.get(3),
                    latest_note: notes
                        .as_deref()
                        .and_then(|n| n.lines().find(|l| !l.trim().is_empty()))
                        .map(|l| l.chars().take(200).collect()),
                    bug_url: r
                        .get::<Option<Vec<String>>, _>(5)
                        .and_then(|v| v.into_iter().next()),
                    ..RowDecision::default()
                },
            );
        }
        for r in &exc {
            let d = decisions.entry(r.get(0)).or_default();
            d.exception = Some(RowException {
                id: r.get(1),
                expires_at: r
                    .get::<time::OffsetDateTime, _>(2)
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            });
        }
        // Coverage as readiness adjudicates it: an exception covers a group only when it
        // actually accepts every failed slot carrying the signature (never a contradiction,
        // an unexplained failure or incomplete evidence).
        let adjudicated_exceptions: Vec<dviscope_core::readiness::ExceptionView> = exc
            .iter()
            .map(|r| dviscope_core::readiness::ExceptionView {
                id: r.get::<i64, _>(1).to_string(),
                revision: u32::try_from(r.get::<i32, _>(3)).unwrap_or(0),
                signature: r.get(0),
                expires_at: r
                    .get::<time::OffsetDateTime, _>(2)
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            })
            .collect();
        let adjudicated =
            dviscope_core::readiness::evaluate(&dviscope_core::readiness::MergeInput {
                candidate: dviscope_core::readiness::Candidate {
                    source_matches: true,
                    collection_closed: true,
                },
                policy,
                slots: cur
                    .slots
                    .iter()
                    .zip(&cur.attempts)
                    .map(|((s, _), a)| dviscope_core::readiness::SlotInput {
                        slot: s.slot_ref.clone(),
                        // Optional slots are judged too: coverage is about the group.
                        required: true,
                        state: s.state,
                        attempts: a.clone(),
                    })
                    .collect(),
                exceptions: adjudicated_exceptions.clone(),
            });
        let still_blocked: std::collections::BTreeSet<&str> = adjudicated
            .blockers
            .iter()
            .filter_map(|b| b.slot.as_deref())
            .collect();
        // Signatures carried by a slot that stays blocked, computed once (not per row).
        let blocked_sigs: std::collections::BTreeSet<&Digest> = cur
            .slots
            .iter()
            .filter(|(s, _)| still_blocked.contains(s.slot_ref.as_str()))
            .flat_map(|(_, v)| v.signatures.keys())
            .collect();
        for row in &cmp.rows {
            let row_blocked = blocked_sigs.contains(&row.signature);
            let d = decisions.entry(row.signature.to_string()).or_default();
            let (disposition, next_action) = if let Some(group) = row.group {
                // Blocked without a diagnostic: nothing to triage, the cause is upstream.
                (
                    "needs_decision",
                    if group == "build" {
                        "fix the build and rebuild, then run its tests"
                    } else {
                        "fix the elaboration failure, then run its tests"
                    },
                )
            } else if d.exception.is_some() && !row_blocked {
                (
                    "covered",
                    "none: covered by an exception for this branch and suite",
                )
            } else if d.exception.is_some() {
                (
                    "needs_decision",
                    "the exception cannot accept these slots (contradiction, unexplained failure, incomplete evidence or another uncovered group): investigate",
                )
            } else if d.triage_state.as_deref() == Some("closed") {
                // A closed case observed again needs a fresh decision.
                (
                    "needs_decision",
                    "closed triage; observed in this run: reopen or except",
                )
            } else if d.owner.is_some() {
                ("assigned", "owner investigates")
            } else {
                ("needs_decision", "assign an owner")
            };
            d.disposition = disposition;
            d.next_action = next_action;
        }
        // Order: new and undecided, other new, the rest (stable: then the core order).
        let rank = |r: &compare::Row| -> u8 {
            let new = r.baseline == compare::BaselineStatus::AbsentFromBaseline;
            let undecided = decisions
                .get(r.signature.as_str())
                .is_some_and(|d| d.disposition == "needs_decision");
            match (new, undecided) {
                (true, true) => 0,
                (true, false) => 1,
                _ => 2,
            }
        };
        cmp.rows.sort_by_key(|r| rank(r));
        // Finish card: group dispositions; blocking groups and missing results.
        let count = |k: &str| {
            cmp.rows
                .iter()
                .filter(|r| {
                    decisions
                        .get(r.signature.as_str())
                        .is_some_and(|d| d.disposition == k)
                })
                .count()
        };
        let (need, assigned, covered) =
            (count("needs_decision"), count("assigned"), count("covered"));
        // Group coverage is not slot acceptance: a failed slot with a covered group and an
        // uncovered one stays blocked.
        let partly_covered = cur.slots.iter().any(|(_, v)| {
            let covered: Vec<bool> = v
                .signatures
                .keys()
                .map(|g| {
                    decisions
                        .get(g.as_str())
                        .is_some_and(|d| d.disposition == "covered")
                })
                .collect();
            covered.contains(&true) && covered.contains(&false)
        });
        // The merge line of the card comes from readiness itself (real required flags and
        // collection closure; the candidate binding is checked on the readiness page).
        let merge = dviscope_core::readiness::evaluate(&dviscope_core::readiness::MergeInput {
            candidate: dviscope_core::readiness::Candidate {
                source_matches: true,
                collection_closed: cur.facts.state == "finished"
                    && cur.facts.sealed
                    && !cur.facts.quarantined_removal,
            },
            policy,
            slots: cur
                .slots
                .iter()
                .zip(&cur.attempts)
                .map(|((s, _), a)| dviscope_core::readiness::SlotInput {
                    slot: s.slot_ref.clone(),
                    required: s.required,
                    state: s.state,
                    attempts: a.clone(),
                })
                .collect(),
            exceptions: adjudicated_exceptions,
        });
        let mut merge_kinds: BTreeMap<String, u64> = BTreeMap::new();
        for b in &merge.blockers {
            let k = serde_json::to_value(&b.kind)
                .ok()
                .and_then(|v| v["kind"].as_str().map(str::to_string))
                .unwrap_or_default();
            *merge_kinds.entry(k).or_default() += 1;
        }
        let finish = serde_json::json!({
            "merge_blockers": merge.blockers.len(),
            "merge_blocker_kinds": merge_kinds,
            "merge_verdict": merge.verdict,
            "groups": cmp.rows.len(),
            "needs_decision": need,
            "assigned": assigned,
            "covered": covered,
            "blocking_groups": need + assigned,
            "missing_results": cmp.header.missing + cmp.header.running,
            "partly_covered_slots": partly_covered,
        });
        Ok(ComparisonRead {
            regression: cur.header.clone(),
            comparison: cmp,
            decisions,
            finish,
            baseline: baseline_json(base_ref, reason, cur, base),
        })
    }
}

/// The simulators a loaded regression's slots name (declared or reported), without blanks.
fn simulators_of(l: &Loaded) -> std::collections::BTreeSet<String> {
    l.slots
        .iter()
        .map(|(_, v)| v.simulator.clone())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The comparison's `baseline`: the regression used and why, and each side's simulators.
/// `simulators_differ` is true when both sides name simulators and the sets differ: "new"
/// and "also in baseline" then mix simulators (run each simulator in its own suite).
fn baseline_json(
    base_ref: Option<String>,
    reason: String,
    cur: &Loaded,
    base: Option<&Loaded>,
) -> Value {
    let current = simulators_of(cur);
    let baseline = base.map(simulators_of);
    let differ = baseline
        .as_ref()
        .is_some_and(|b| !b.is_empty() && !current.is_empty() && *b != current);
    serde_json::json!({
        "ref": base_ref,
        "reason": reason,
        "simulators": {"current": current, "baseline": baseline},
        "simulators_differ": differ,
    })
}
