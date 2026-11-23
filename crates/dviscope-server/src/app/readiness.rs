//! Readiness, merge mode, server side: the inputs are assembled in one
//! repeatable-read snapshot, the core decides, and the result carries the change sequence
//! it saw, `valid_until`, the decision-input digest (`dig/2`) and the log-free summary.

use std::collections::BTreeMap;

use dviscope_core::readiness::{
    self, BlockerKind, Candidate, ExceptionView, MergeInput, SlotInput,
};
use dviscope_model::canonical::digest_of;
use dviscope_model::wire::regression::SourceManifest;
use serde_json::{Value, json};
use sqlx::Row as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::App;
use crate::auth::{Action, Actor};
use crate::error::AppError;

/// Schema of the result.
pub const VERDICT_SCHEMA: &str = "dviscope.verdict/1.0-dev";

fn rfc(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// A blocker group: kind, slots, signature numbers, owner, exceptable, clearing action.
type Group = (Value, u64, Vec<i64>, Option<String>, bool, &'static str);

/// The clearing action of a blocker (the log-free summary's `clearing_action`): an
/// exception is offered only where one can clear it.
fn clearing_action(kind: &BlockerKind, exceptable: bool) -> &'static str {
    match kind {
        BlockerKind::SourceMismatch => "evaluate the regression of this candidate",
        BlockerKind::CollectionOpen => "seal the manifest and finish the regression",
        BlockerKind::Missing | BlockerKind::RequiredNotRun => "run the slot",
        BlockerKind::Running => "wait for the attempt to end",
        BlockerKind::Blocked { .. } => "fix and rebuild the configuration, then run its tests",
        BlockerKind::Failed { .. } if exceptable => "fix the failure or add an exception",
        BlockerKind::Failed { .. } => "fix the failure (no exception can cover it)",
        BlockerKind::InsufficientEvidence { .. } => "re-run with eligible evidence",
        BlockerKind::Contradiction => "investigate the contradiction",
        BlockerKind::IncompleteEvidence => "re-run to get complete evidence",
        BlockerKind::Unexplained => {
            "investigate: the run failed without a failure diagnostic (no exception can cover it)"
        }
    }
}

/// A hypothetical exception whose impact is previewed (never stored).
#[derive(Debug, Clone)]
pub struct ExceptionPreview {
    /// Signature number.
    pub signature: i64,
    /// Expiry (RFC 3339), as it would be requested.
    pub expires_at: String,
}

impl App {
    /// Evaluates merge readiness of a regression at `now`.
    ///
    /// # Errors
    /// Authorization, unknown project or regression, database errors.
    pub async fn read_readiness(
        &self,
        actor: &Actor,
        project: &str,
        regression_ref: &str,
        expect_source: Option<&str>,
        producer: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        self.readiness(
            actor,
            project,
            regression_ref,
            expect_source,
            producer,
            now,
            None,
        )
        .await
        .map(|(v, _)| v)
    }

    /// The impact of a hypothetical exception for the regression's branch and suite: which
    /// failing slots it would cover, which stay blocked by other groups, the simulators, the
    /// scope and the verdict before and after. Nothing is stored.
    ///
    /// # Errors
    /// Authorization, unknown project, regression or signature, database errors.
    pub async fn preview_exception(
        &self,
        actor: &Actor,
        project: &str,
        regression_ref: &str,
        producer: Option<&str>,
        preview: ExceptionPreview,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        super::decisions::check_expiry(&preview.expires_at, now)?;
        let (_, impact) = self
            .readiness(
                actor,
                project,
                regression_ref,
                None,
                producer,
                now,
                Some(preview),
            )
            .await?;
        impact.ok_or_else(|| AppError::internal("preview"))
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)] // one snapshot
    async fn readiness(
        &self,
        actor: &Actor,
        project: &str,
        regression_ref: &str,
        expect_source: Option<&str>,
        producer: Option<&str>,
        now: OffsetDateTime,
        preview: Option<ExceptionPreview>,
    ) -> Result<(Value, Option<Value>), AppError> {
        let (pid, policy) = self
            .read_project(actor, project, Action::ReadinessRead)
            .await?;
        let mut tx = self.snapshot().await?;
        let out = Self::readiness_in(
            &mut tx,
            pid,
            policy,
            regression_ref,
            expect_source,
            producer,
            now,
            preview,
        )
        .await?;
        tx.commit().await?;
        Ok(out)
    }

    /// [`Self::readiness`] inside the caller's snapshot (a backup evaluates readiness in the
    /// snapshot it dumps). No authorization: the caller has done it.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)] // one snapshot
    pub(crate) async fn readiness_in(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        pid: i64,
        policy: dviscope_core::settlement::Policy,
        regression_ref: &str,
        expect_source: Option<&str>,
        producer: Option<&str>,
        now: OffsetDateTime,
        preview: Option<ExceptionPreview>,
    ) -> Result<(Value, Option<Value>), AppError> {
        let change_seq: i64 = sqlx::query(
            "SELECT coalesce(max(change_seq), 0) FROM project_heads WHERE project_id = $1",
        )
        .bind(pid)
        .fetch_one(&mut **tx)
        .await?
        .get(0);
        let l = Self::load(tx, pid, policy, regression_ref, producer).await?;
        let f = &l.facts;
        // Candidate binding: the regression's source digest.
        let body: Value = sqlx::query(
            "SELECT body FROM source_manifests WHERE project_id = $1 AND producer_id = $2 AND ref = $3",
        )
        .bind(pid)
        .bind(f.producer_id)
        .bind(&f.source_manifest_ref)
        .fetch_one(&mut **tx)
        .await?
        .get(0);
        let sm: SourceManifest = serde_json::from_value(body)
            .map_err(|_| AppError::internal("stored source manifest"))?;
        let source_digest = dviscope_core::execution::source_digest(&sm.repositories)
            .map_err(|_| AppError::internal("source digest"))?;
        let mut warnings = vec![];
        if f.quarantined_removal {
            warnings.push(
                "an expected-set removal by a quarantined credential is pending: re-make it with a valid credential or release the quarantine",
            );
        }
        let source_matches = match expect_source {
            Some(d) => d == source_digest.as_str(),
            None => {
                warnings.push("candidate not bound: no expected source digest given");
                true
            }
        };
        // Active exceptions of the branch and suite.
        let exc_rows = sqlx::query(
            "SELECT e.id, e.revision, g.fingerprint, e.expires_at, g.number
               FROM exceptions e JOIN signatures g ON g.project_id = e.project_id AND g.id = e.signature_id
              WHERE e.project_id = $1 AND e.branch = $2 AND e.suite = $3
                AND e.revoked_at IS NULL AND e.superseded_by IS NULL AND e.expires_at > $4",
        )
        .bind(pid)
        .bind(&f.branch)
        .bind(&f.suite)
        .bind(now)
        .fetch_all(&mut **tx)
        .await?;
        let exceptions: Vec<ExceptionView> = exc_rows
            .iter()
            .map(|r| ExceptionView {
                id: r.get::<i64, _>(0).to_string(),
                revision: u32::try_from(r.get::<i32, _>(1)).unwrap_or(0),
                signature: r.get(2),
                expires_at: rfc(r.get(3)),
            })
            .collect();
        // Signature numbers and triage owners (log-free summary).
        let sig_rows = sqlx::query(
            "SELECT g.fingerprint, g.number, (SELECT r.owner FROM triage_cases c
                      JOIN triage_revisions r ON r.project_id = c.project_id AND r.case_id = c.id
                                             AND r.revision = c.revision
                     WHERE c.project_id = g.project_id AND c.signature_id = g.id AND c.branch = $2)
               FROM signatures g WHERE g.project_id = $1",
        )
        .bind(pid)
        .bind(&f.branch)
        .fetch_all(&mut **tx)
        .await?;
        // The previewed signature, resolved in the same snapshot.
        let preview_fp: Option<(ExceptionPreview, String)> = match preview {
            Some(pv) => {
                let fp: Option<String> = sqlx::query_scalar(
                    "SELECT fingerprint FROM signatures WHERE project_id = $1 AND number = $2",
                )
                .bind(pid)
                .bind(pv.signature)
                .fetch_optional(&mut **tx)
                .await?;
                let fp = fp.ok_or_else(|| {
                    AppError::new(
                        dviscope_model::errors::ErrorCode::NotFound,
                        format!("no signature {}", pv.signature),
                    )
                })?;
                Some((pv, fp))
            }
            None => None,
        };
        let numbers: BTreeMap<String, (i64, Option<String>)> = sig_rows
            .iter()
            .map(|r| {
                (
                    r.get::<String, _>(0),
                    (r.get::<i64, _>(1), r.get::<Option<String>, _>(2)),
                )
            })
            .collect();

        let input = MergeInput {
            candidate: Candidate {
                source_matches,
                collection_closed: f.state == "finished" && f.sealed && !f.quarantined_removal,
            },
            policy,
            slots: l
                .slots
                .iter()
                .zip(&l.attempts)
                .map(|((s, _), a)| SlotInput {
                    slot: s.slot_ref.clone(),
                    required: s.required,
                    state: s.state,
                    attempts: a.clone(),
                })
                .collect(),
            exceptions,
        };
        let d = readiness::evaluate(&input);
        // Exception impact preview: the same inputs with the hypothetical exception added.
        let impact = preview_fp.map(|(pv, fp)| {
            let mut with = input.clone();
            with.exceptions.retain(|e| e.signature != fp);
            with.exceptions.push(ExceptionView {
                id: "preview".into(),
                revision: 0,
                signature: fp.clone(),
                expires_at: pv.expires_at.clone(),
            });
            let after = readiness::evaluate(&with);
            let blocked = |dd: &readiness::MergeDecision| -> std::collections::BTreeSet<String> {
                dd.blockers.iter().filter_map(|b| b.slot.clone()).collect()
            };
            let affected: std::collections::BTreeSet<String> = d
                .blockers
                .iter()
                .filter(|b| b.signatures.contains(&fp))
                .filter_map(|b| b.slot.clone())
                .collect();
            let not_exceptable = d
                .blockers
                .iter()
                .any(|b| b.signatures.contains(&fp) && !b.exceptable);
            let still = blocked(&after);
            let covers: Vec<&String> = affected.iter().filter(|s| !still.contains(*s)).collect();
            let stay: Vec<&String> = affected.iter().filter(|s| still.contains(*s)).collect();
            let simulators: std::collections::BTreeSet<&str> = l
                .slots
                .iter()
                .filter(|(s, _)| affected.contains(&s.slot_ref))
                .map(|(_, v)| v.simulator.as_str())
                .filter(|x| !x.is_empty())
                .collect();
            json!({
                "signature": pv.signature,
                "scope": {"branch": f.branch, "suite": f.suite},
                "expires_at": pv.expires_at,
                "covers_slots": covers,
                "stay_blocked_slots": stay,
                "not_exceptable": not_exceptable,
                "simulators": simulators,
                "verdict_before": d.verdict,
                "verdict_after": after.verdict,
            })
        });
        let policy_name = serde_json::to_value(policy)?;
        // Decision-input digest (dig/2), deterministically ordered.
        let digest = digest_of(&json!({
            "schema": "dig/2",
            "evaluator_version": env!("CARGO_PKG_VERSION"),
            "mode": "merge",
            "evaluated_at": rfc(now),
            "valid_until": d.valid_until,
            "candidate": {"regression": regression_ref, "source_digest": source_digest.as_str(),
                          "expect_source": expect_source},
            "manifest_revision": f.manifest_revision,
            "policy": policy_name,
            "change_seq": change_seq,
            "slots": input.slots.iter().map(|s| json!({
                "slot": s.slot,
                "state": serde_json::to_value(s.state).unwrap_or(Value::Null),
                "contributing": s.attempts.iter().map(|a| json!([
                    a.attempt_seq, a.eligible, a.terminal, a.failed, a.complete, a.contradiction,
                    a.signatures,
                ])).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "exceptions": d.exceptions_used.iter().map(|e| json!([e.id, e.revision])).collect::<Vec<_>>(),
        }))
        .map_err(|_| AppError::internal("decision digest"))?;
        // Blockers grouped by clearing action (and kind), with slot counts and signatures.
        let mut groups: BTreeMap<String, Group> = BTreeMap::new();
        for b in &d.blockers {
            let kind = serde_json::to_value(&b.kind)?;
            // Exceptability is part of the group: its clearing action differs.
            let key = format!("{kind}|{}", b.exceptable);
            let e = groups.entry(key).or_insert_with(|| {
                (
                    kind.clone(),
                    0,
                    vec![],
                    None,
                    b.exceptable,
                    clearing_action(&b.kind, b.exceptable),
                )
            });
            e.1 += u64::from(b.slot.is_some());
            for g in &b.signatures {
                if let Some((n, owner)) = numbers.get(g) {
                    if !e.2.contains(n) {
                        e.2.push(*n);
                    }
                    if e.3.is_none() {
                        e.3.clone_from(owner);
                    }
                }
            }
        }
        let blockers: Vec<Value> = d
            .blockers
            .iter()
            .map(|b| {
                json!({
                    "kind": serde_json::to_value(&b.kind).unwrap_or(Value::Null),
                    "slot": b.slot,
                    "signatures": b.signatures.iter()
                        .filter_map(|g| numbers.get(g).map(|(n, _)| *n)).collect::<Vec<_>>(),
                    "exceptable": b.exceptable,
                    "clearing_action": clearing_action(&b.kind, b.exceptable),
                })
            })
            .collect();
        let summary_blockers: Vec<Value> = groups
            .values()
            .map(|(kind, slots, sigs, owner, exceptable, action)| {
                json!({
                    "kind": kind,
                    "slots": slots,
                    "signatures": sigs,
                    "owner": owner.clone().unwrap_or_else(|| "Unassigned".into()),
                    "clearing_action": action,
                    "exceptable": exceptable,
                })
            })
            .collect();
        let exceptions_used: Vec<Value> = d
            .exceptions_used
            .iter()
            .map(|e| {
                json!({
                    "signature": numbers.get(&e.signature).map(|(n, _)| *n),
                    "expires_at": e.expires_at,
                })
            })
            .collect();
        // Green proof card: for every required slot that is not blocked, the accepting
        // attempt, its build attempts, and any expectation, retry or exception that
        // contributed.
        let blocked_slots: std::collections::BTreeSet<&str> = d
            .blockers
            .iter()
            .filter_map(|b| b.slot.as_deref())
            .collect();
        let proof: Vec<Value> = l
            .slots
            .iter()
            .zip(&l.attempts)
            .zip(&l.extra)
            .filter(|(((s, _), _), _)| s.required && !blocked_slots.contains(s.slot_ref.as_str()))
            .map(|(((s, _), atts), x)| {
                let deciding = atts.iter().find(|a| Some(a.attempt_seq) == s.deciding);
                let covered_by: Vec<i64> = d
                    .exceptions_used
                    .iter()
                    .filter(|e| deciding.is_some_and(|a| a.signatures.contains(&e.signature)))
                    .filter_map(|e| numbers.get(&e.signature).map(|(n, _)| *n))
                    .collect();
                json!({
                    "slot": s.slot_ref,
                    "state": serde_json::to_value(s.state).unwrap_or(Value::Null),
                    "attempt_seq": s.deciding,
                    "builds": x.deciding_builds,
                    "retry": s.deciding.is_some_and(|n| n > 1),
                    "expectation_met": x.expectation_met,
                    "exceptions": covered_by,
                })
            })
            .collect();
        let repo = sm.repositories.first();
        let summary = json!({
            "candidate": {
                "bound": expect_source.is_some(),
                "repository": repo.map(|r| r.repository.clone()),
                "revision": repo.map(|r| r.revision.clone()),
                "source_digest": source_digest.as_str(),
            },
            "regression": regression_ref,
            "suite": f.suite,
            "policy": policy_name,
            "verdict": d.verdict,
            "evaluated_at": rfc(now),
            "valid_until": d.valid_until,
            "digest": digest.as_str(),
            "counts": d.counts,
            "blockers": summary_blockers,
            "exceptions_used": exceptions_used,
        });
        Ok((
            json!({
                "schema": VERDICT_SCHEMA,
                "verdict": d.verdict,
                "digest": digest.as_str(),
                "evaluated_at": rfc(now),
                "valid_until": d.valid_until,
                "change_seq": change_seq,
                "regression": l.header,
                "blockers": blockers,
                "exceptions_used": d.exceptions_used,
                "warnings": warnings,
                "proof": proof,
                "summary": summary,
            }),
            impact,
        ))
    }
}
