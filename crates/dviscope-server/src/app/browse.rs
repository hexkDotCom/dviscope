//! Browse reads for the pages: projects, the regression list (cursor-paginated,
//! default 100, at most 500 rows), signature detail and attempt detail. Every list is
//! bounded and ordered with stable tie-breakers; payloads are read only for an attempt's
//! detail, and an expired payload says so.

use dviscope_model::errors::ErrorCode;
use serde_json::{Value, json};
use sqlx::Row as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::App;
use crate::auth::{Action, Actor};
use crate::error::AppError;

/// Default page size.
pub const PAGE: i64 = 100;
/// Largest page.
pub const MAX_PAGE: i64 = 500;

fn rfc(t: Option<OffsetDateTime>) -> Option<String> {
    t.and_then(|t| t.format(&Rfc3339).ok())
}

impl App {
    /// The projects the user has a role in.
    ///
    /// # Errors
    /// A collector token (403), database errors.
    pub async fn list_projects(&self, actor: &Actor) -> Result<Value, AppError> {
        let Actor::User { roles, .. } = actor else {
            return Err(AppError::new(
                ErrorCode::Forbidden,
                "projects are listed for people",
            ));
        };
        let ids: Vec<i64> = roles.iter().map(|(p, _)| *p).collect();
        let rows =
            sqlx::query("SELECT id, name, policy FROM projects WHERE id = ANY($1) ORDER BY name")
                .bind(&ids)
                .fetch_all(&self.db)
                .await?;
        Ok(json!({"projects": rows.iter().map(|r| {
            let id: i64 = r.get(0);
            json!({
                "name": r.get::<String, _>(1),
                "policy": r.get::<String, _>(2),
                "role": roles.iter().find(|(p, _)| *p == id).map(|(_, r)| format!("{r:?}").to_lowercase()),
            })
        }).collect::<Vec<_>>()}))
    }

    /// Regressions of a project, newest first; `before` is the cursor (a regression ID).
    ///
    /// # Errors
    /// Authorization, unknown project, database errors.
    pub async fn list_regressions(
        &self,
        actor: &Actor,
        project: &str,
        before: Option<&str>,
        limit: Option<i64>,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::RegressionRead)
            .await?;
        let limit = limit.unwrap_or(PAGE).clamp(1, MAX_PAGE);
        // The cursor is the full ordering key (start, id): an older regression delivered
        // late (a larger id) is neither skipped nor repeated.
        let cursor: Option<(OffsetDateTime, i64)> = match before {
            None => None,
            Some(c) => {
                let bad = || {
                    AppError::field(
                        ErrorCode::Invalid,
                        "before is a cursor from `next`",
                        "before",
                    )
                };
                let (t, id) = c.split_once('.').ok_or_else(bad)?;
                let micros: i128 = t.parse().map_err(|_| bad())?;
                let at =
                    OffsetDateTime::from_unix_timestamp_nanos(micros * 1000).map_err(|_| bad())?;
                Some((at, id.parse().map_err(|_| bad())?))
            }
        };
        let rows = sqlx::query(
            "SELECT r.id, r.ref, p.name, r.suite, r.branch_repository, r.branch_name, r.state,
                    r.started_at, r.finished_at, r.change_seq,
                    (SELECT count(*) FROM slots s WHERE s.project_id = r.project_id
                        AND s.regression_id = r.id AND s.removed_revision IS NULL)
               FROM regressions r JOIN producers p ON p.project_id = r.project_id AND p.id = r.producer_id
              WHERE r.project_id = $1
                AND ($2::timestamptz IS NULL OR (r.started_at, r.id) < ($2, $3))
              ORDER BY r.started_at DESC, r.id DESC LIMIT $4",
        )
        .bind(pid)
        .bind(cursor.map(|c| c.0))
        .bind(cursor.map_or(0, |c| c.1))
        .bind(limit + 1)
        .fetch_all(&self.db)
        .await?;
        let more = i64::try_from(rows.len()).unwrap_or(0) > limit;
        let page: Vec<_> = rows
            .iter()
            .take(usize::try_from(limit).unwrap_or(0))
            .collect();
        Ok(json!({
            "regressions": page.iter().map(|r| json!({
                "ref": r.get::<String, _>(1),
                "producer": r.get::<String, _>(2),
                "suite": r.get::<String, _>(3),
                "branch": format!("{}/{}", r.get::<String, _>(4), r.get::<String, _>(5)),
                "state": r.get::<String, _>(6),
                "started_at": rfc(Some(r.get(7))),
                "finished_at": rfc(r.get(8)),
                "change_seq": r.get::<i64, _>(9),
                "planned": r.get::<i64, _>(10),
            })).collect::<Vec<_>>(),
            "next": if more {
                page.last().map(|r| {
                    let at: OffsetDateTime = r.get(7);
                    format!("{}.{}", at.unix_timestamp_nanos() / 1000, r.get::<i64, _>(0))
                })
            } else {
                None
            },
        }))
    }

    /// A signature: its identity, where it occurs (newest first, bounded), its triage
    /// cases and current exceptions (not revoked or superseded; each says whether it has
    /// expired, so an expired one is seen as such rather than taken for cover).
    ///
    /// # Errors
    /// Authorization, unknown project or signature, database errors.
    pub async fn signature_detail(
        &self,
        actor: &Actor,
        project: &str,
        number: i64,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::RegressionRead)
            .await?;
        let sig = sqlx::query(
            "SELECT id, fingerprint, family_kind, diag_id, identity_template FROM signatures
              WHERE project_id = $1 AND number = $2",
        )
        .bind(pid)
        .bind(number)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, format!("no signature {number}")))?;
        let sid: i64 = sig.get(0);
        let occ = sqlx::query(
            "SELECT r.ref, s.slot_ref, a.attempt_seq, b.report_revision, b.count::text,
                    b.observed_severity, f.simulator, f.effective, r.started_at, pr.name
               FROM buckets b
               JOIN attempts a ON a.project_id = b.project_id AND a.id = b.attempt_id
                              AND a.head_revision = b.report_revision
               JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
               JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
               JOIN producers pr ON pr.project_id = r.project_id AND pr.id = r.producer_id
               JOIN attempt_facts f ON f.project_id = a.project_id AND f.attempt_id = a.id
                                   AND f.report_revision = a.head_revision
              WHERE b.project_id = $1 AND b.signature_id = $2
              ORDER BY r.started_at DESC, r.id DESC, s.slot_ref, a.attempt_seq LIMIT $3",
        )
        .bind(pid)
        .bind(sid)
        .bind(MAX_PAGE)
        .fetch_all(&self.db)
        .await?;
        let triage = sqlx::query(
            "SELECT c.id, c.branch, c.revision, r.state, r.owner, r.notes, r.bug_urls, u.username, r.at
               FROM triage_cases c
               JOIN triage_revisions r ON r.project_id = c.project_id AND r.case_id = c.id
                                      AND r.revision = c.revision
               JOIN users u ON u.id = r.author
              WHERE c.project_id = $1 AND c.signature_id = $2 ORDER BY c.branch",
        )
        .bind(pid)
        .bind(sid)
        .fetch_all(&self.db)
        .await?;
        let exceptions = sqlx::query(
            "SELECT e.id, e.revision, e.branch, e.suite, e.reason, e.expires_at, u.username,
                    e.expires_at <= now()
               FROM exceptions e JOIN users u ON u.id = e.author
              WHERE e.project_id = $1 AND e.signature_id = $2
                AND e.revoked_at IS NULL AND e.superseded_by IS NULL
              ORDER BY e.branch, e.suite",
        )
        .bind(pid)
        .bind(sid)
        .fetch_all(&self.db)
        .await?;
        Ok(json!({
            "number": number,
            "fingerprint": sig.get::<String, _>(1),
            "family_kind": sig.get::<String, _>(2),
            "diag_id": sig.get::<String, _>(3),
            "identity_template": sig.get::<String, _>(4),
            "note": "Same diagnostic pattern; common root cause not established.",
            "occurrences": occ.iter().map(|r| json!({
                "regression": r.get::<String, _>(0),
                // Regression references are per producer: links carry it.
                "producer": r.get::<String, _>(9),
                "slot": r.get::<String, _>(1),
                "attempt_seq": r.get::<i32, _>(2),
                "report_revision": r.get::<i32, _>(3),
                "count": r.get::<String, _>(4),
                "severity": r.get::<String, _>(5),
                "simulator": r.get::<String, _>(6),
                "effective": r.get::<String, _>(7),
            })).collect::<Vec<_>>(),
            "triage": triage.iter().map(|r| json!({
                "id": r.get::<i64, _>(0),
                "branch": r.get::<String, _>(1),
                "revision": r.get::<i32, _>(2),
                "state": r.get::<String, _>(3),
                "owner": r.get::<Option<String>, _>(4),
                "notes": r.get::<String, _>(5),
                "bug_urls": r.get::<Vec<String>, _>(6),
                "by": r.get::<String, _>(7),
                "at": rfc(Some(r.get(8))),
            })).collect::<Vec<_>>(),
            "exceptions": exceptions.iter().map(|r| json!({
                "id": r.get::<i64, _>(0),
                "revision": r.get::<i32, _>(1),
                "branch": r.get::<String, _>(2),
                "suite": r.get::<String, _>(3),
                "reason": r.get::<String, _>(4),
                "expires_at": rfc(Some(r.get(5))),
                "by": r.get::<String, _>(6),
                "expired": r.get::<bool, _>(7),
            })).collect::<Vec<_>>(),
        }))
    }

    /// An attempt: its facts per report revision, the buckets of its head revision with
    /// their signatures, and its representative evidence while the payload is retained.
    ///
    /// # Errors
    /// Authorization, unknown project, regression, slot or attempt, database errors.
    pub async fn attempt_detail(
        &self,
        actor: &Actor,
        project: &str,
        regression_ref: &str,
        slot_ref: &str,
        attempt_seq: i32,
        producer: Option<&str>,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::RegressionRead)
            .await?;
        let found = sqlx::query(
            "SELECT a.id, a.attempt_ref, a.head_revision, a.build_refs, a.started_at
               FROM attempts a
               JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
               JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
               JOIN producers p ON p.project_id = r.project_id AND p.id = r.producer_id
              WHERE a.project_id = $1 AND r.ref = $2 AND s.slot_ref = $3 AND a.attempt_seq = $4
                AND ($5::text IS NULL OR p.name = $5)
              LIMIT 2",
        )
        .bind(pid)
        .bind(regression_ref)
        .bind(slot_ref)
        .bind(attempt_seq)
        .bind(producer)
        .fetch_all(&self.db)
        .await?;
        // Two producers using the same names: never guess (as regression reads).
        let a = match found.as_slice() {
            [a] => a,
            [] => return Err(AppError::new(ErrorCode::NotFound, "no such attempt")),
            _ => {
                return Err(AppError::field(
                    ErrorCode::Invalid,
                    "several producers use this regression reference: name the producer",
                    "producer",
                ));
            }
        };
        let aid: i64 = a.get(0);
        let head: Option<i32> = a.get(2);
        let revs = sqlx::query(
            "SELECT report_revision, outcome, blocking_phase, effective, assessment, completion,
                    termination, design_loaded, pipeline_status, purpose, source_matches,
                    contradiction, primary_diag, simulator, received_at
               FROM attempt_facts WHERE project_id = $1 AND attempt_id = $2 ORDER BY report_revision",
        )
        .bind(pid)
        .bind(aid)
        .fetch_all(&self.db)
        .await?;
        let buckets = sqlx::query(
            "SELECT b.idx, b.diag_id, b.site, b.observed_severity, b.effective_severity,
                    b.framework, b.provenance, b.fails_run, b.count::text, g.number
               FROM buckets b JOIN signatures g ON g.project_id = b.project_id AND g.id = b.signature_id
              WHERE b.project_id = $1 AND b.attempt_id = $2 AND b.report_revision = $3
              ORDER BY b.idx",
        )
        .bind(pid)
        .bind(aid)
        .bind(head)
        .fetch_all(&self.db)
        .await?;
        let payload: Option<Value> = sqlx::query(
            "SELECT payload FROM attempt_reports
              WHERE project_id = $1 AND attempt_id = $2 AND report_revision = $3",
        )
        .bind(pid)
        .bind(aid)
        .bind(head)
        .fetch_optional(&self.db)
        .await?
        .map(|r| r.get(0));
        let evidence = payload.as_ref().map(|p| {
            let ev = &p["evidence"];
            json!({
                "completion": ev["completion"],
                "verdict_sources": ev["verdict_sources"],
                "counters": ev["counters"],
                "reconciliation": ev["reconciliation"],
                "excerpt": ev["excerpt"],
                "coverage": ev["coverage"],
                "runner": p["result"]["runner"],
            })
        });
        Ok(json!({
            "regression": regression_ref,
            "slot": slot_ref,
            "attempt_seq": attempt_seq,
            "attempt_ref": a.get::<String, _>(1),
            "head_revision": head,
            "build_refs": a.get::<Value, _>(3),
            "started_at": rfc(Some(a.get(4))),
            "revisions": revs.iter().map(|r| json!({
                "report_revision": r.get::<i32, _>(0),
                "outcome": r.get::<String, _>(1),
                "blocking_phase": r.get::<Option<String>, _>(2),
                "effective": r.get::<String, _>(3),
                "assessment": r.get::<String, _>(4),
                "completion": r.get::<String, _>(5),
                "termination": r.get::<String, _>(6),
                "design_loaded": r.get::<String, _>(7),
                "pipeline_status": r.get::<String, _>(8),
                "purpose": r.get::<String, _>(9),
                "source_matches": r.get::<bool, _>(10),
                "contradiction": r.get::<bool, _>(11),
                "primary": r.get::<Option<String>, _>(12),
                "simulator": r.get::<String, _>(13),
                "received_at": rfc(Some(r.get(14))),
            })).collect::<Vec<_>>(),
            "buckets": buckets.iter().map(|r| json!({
                "idx": r.get::<i32, _>(0),
                "diag_id": r.get::<String, _>(1),
                "site": r.get::<Option<String>, _>(2),
                "observed_severity": r.get::<String, _>(3),
                "effective_severity": r.get::<String, _>(4),
                "framework": r.get::<String, _>(5),
                "provenance": r.get::<String, _>(6),
                "fails_run": r.get::<bool, _>(7),
                "count": r.get::<String, _>(8),
                "signature": r.get::<i64, _>(9),
            })).collect::<Vec<_>>(),
            "evidence": evidence,
            "evidence_note": if payload.is_none() { Some("Excerpt expired; triage history retained") } else { None },
        }))
    }

    /// The collection repair list: slots without an eligible result, each with
    /// why (*"No report received"* or *"Report received; not eligible: …"*) and its recovery
    /// action, grouped by producer, plus a copyable text with no paths, hosts or tokens.
    ///
    /// # Errors
    /// Authorization, unknown project or regression, database errors.
    pub async fn repair_list(
        &self,
        actor: &Actor,
        project: &str,
        regression_ref: &str,
        producer: Option<&str>,
    ) -> Result<Value, AppError> {
        let (pid, policy) = self
            .read_project(actor, project, Action::RegressionRead)
            .await?;
        let mut tx = self.snapshot().await?;
        let l = Self::load(&mut tx, pid, policy, regression_ref, producer).await?;
        tx.commit().await?;
        let producer_id = l.header["producer"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let mut items = vec![];
        for ((s, _), x) in l.slots.iter().zip(&l.extra) {
            use dviscope_core::settlement::{FailReason, SlotState};
            // Missing slots, and slots whose reports were rejected (a settlement barrier:
            // quarantined credential, withdrawn pipeline, quarantined build).
            let rejected = matches!(s.state, SlotState::Failed(FailReason::Insufficient))
                && s.note
                    .as_deref()
                    .is_some_and(|n| n.starts_with("evidence from") || n.starts_with("built by"));
            // A running slot may be a collector that stopped: listed, with that hedge.
            let running = s.state == SlotState::Running;
            if s.state != SlotState::Missing && !rejected && !running {
                continue;
            }
            let (reason, action) = if running {
                (
                    "Attempt started; no report yet".to_string(),
                    "if its collector stopped, re-run the slot (re-running the same regression reference resumes it); otherwise wait"
                        .to_string(),
                )
            } else if rejected {
                (
                    format!(
                        "Report received; rejected: {}",
                        s.note.as_deref().unwrap_or_default()
                    ),
                    "release the quarantine or re-accept the pipeline, or re-run the slot"
                        .to_string(),
                )
            } else if s.note.as_deref() == Some("waiting for build") {
                (
                    "Waiting for build".to_string(),
                    "deliver the build's report, or re-run the build".to_string(),
                )
            } else if x.interrupted {
                // An interrupted attempt has no log, so also no accepted pipeline: the
                // remedy is a new run, not a pipeline decision.
                (
                    "Attempt interrupted; no result (termination unknown)".to_string(),
                    "re-run the slot (re-running the same regression reference runs it again)"
                        .to_string(),
                )
            } else if let Some(why) = x.ineligible.first() {
                let action = match *why {
                    "pipeline" => {
                        "accept the rules pipeline that produced it, or re-run with the accepted one"
                    }
                    "source" => "re-run on the regression's sources",
                    "quarantine" => "re-run with a valid collector token",
                    _ => "re-run without the experiment purpose",
                };
                (
                    format!("Report received; not eligible: {}", x.ineligible.join(", ")),
                    action.to_string(),
                )
            } else if s.attempts > 0 {
                (
                    "Attempt started; no report received".to_string(),
                    "flush the collector's journal; if nothing is pending, re-run the slot"
                        .to_string(),
                )
            } else {
                (
                    "No report received".to_string(),
                    "re-run the slot (re-running the same regression reference resumes it)"
                        .to_string(),
                )
            };
            items.push(json!({
                "slot": s.slot_ref,
                "test": s.test,
                "required": s.required,
                "reason": reason,
                "action": action,
            }));
        }
        // Every interpolated value is plain: a hostile test name cannot add a line (a
        // command, when pasted into a terminal) or an escape sequence.
        let p = |v: &Value| super::plain_text(v.as_str().unwrap_or_default());
        let mut text = format!(
            "Collection repair list: regression {} (producer {}), {} slot{}\n",
            super::plain_text(regression_ref),
            super::plain_text(&producer_id),
            items.len(),
            if items.len() == 1 { "" } else { "s" }
        );
        for i in &items {
            text.push_str(&format!(
                "- {} ({}){}: {}; {}\n",
                p(&i["slot"]),
                p(&i["test"]),
                if i["required"].as_bool().unwrap_or(false) {
                    ", required"
                } else {
                    ""
                },
                p(&i["reason"]),
                p(&i["action"]),
            ));
        }
        if !items.is_empty() {
            text.push_str(
                "First, on each collector host: dviscope spool flush --dir <journal directory>\n",
            );
        }
        Ok(json!({
            "regression": regression_ref,
            "groups": [{"producer": producer_id, "slots": items}],
            "text": text,
        }))
    }

    /// What retention would expire in this project now: each regression with
    /// its cohort and action, plus build and receipt counts. Read-only; admin role.
    ///
    /// # Errors
    /// Authorization (admin role), unknown project, database errors.
    pub async fn retention_preview(&self, actor: &Actor, project: &str) -> Result<Value, AppError> {
        let (pid, _) = self.read_project(actor, project, Action::AdminRead).await?;
        let now: OffsetDateTime = sqlx::query_scalar("SELECT now()")
            .fetch_one(&self.db)
            .await?;
        let policy = crate::retention::Policy::default();
        let rep = crate::retention::preview(&self.db, now, policy, Some(pid)).await?;
        let days = |d: time::Duration| d.whole_days();
        Ok(json!({
            "project": project,
            "as_of": rfc(Some(now)),
            "policy_days": {
                "pass_payload": days(policy.pass_payload),
                "pass_facts": days(policy.pass_facts),
                "fail_payload": days(policy.fail_payload),
                "fail_facts": days(policy.fail_facts),
                "receipts": days(policy.receipts),
            },
            "report": serde_json::to_value(&rep)?,
        }))
    }

    /// The project's administration overview:
    /// members, collector-token metadata (never secrets), producers with their integration
    /// assurance profile, and pipelines. Changes stay in `dviscope-server admin`.
    ///
    /// # Errors
    /// Authorization (admin role), unknown project, database errors.
    pub async fn admin_overview(&self, actor: &Actor, project: &str) -> Result<Value, AppError> {
        let (pid, policy) = self.read_project(actor, project, Action::AdminRead).await?;
        let mut tx = self.snapshot().await?;
        let members = sqlx::query(
            "SELECT u.username, m.role, u.disabled FROM memberships m
               JOIN users u ON u.id = m.user_id
              WHERE m.project_id = $1 ORDER BY u.username",
        )
        .bind(pid)
        .fetch_all(&mut *tx)
        .await?;
        let tokens = sqlx::query(
            "SELECT t.id, p.name, t.label, t.scopes, t.created_at, t.expires_at, t.revoked_at,
                    t.quarantined_since, t.expires_at <= now(),
                    EXISTS (SELECT 1 FROM restore_disabled_tokens d WHERE d.token_id = t.id)
               FROM api_tokens t JOIN producers p ON p.id = t.producer_id
              WHERE t.project_id = $1 AND t.kind = 'collector' ORDER BY t.id",
        )
        .bind(pid)
        .fetch_all(&mut *tx)
        .await?;
        let producers = sqlx::query(
            "SELECT p.name, p.retired_at, p.retired_reason,
                    EXISTS (SELECT 1 FROM regressions r WHERE r.project_id = p.project_id
                              AND r.producer_id = p.id AND r.state <> 'unsealed'),
                    EXISTS (SELECT 1 FROM build_attempts b WHERE b.project_id = p.project_id
                              AND b.producer_id = p.id),
                    EXISTS (SELECT 1 FROM source_manifests s WHERE s.project_id = p.project_id
                              AND s.producer_id = p.id
                              AND jsonb_array_length(s.body -> 'repositories') > 0)
               FROM producers p WHERE p.project_id = $1 ORDER BY p.name",
        )
        .bind(pid)
        .fetch_all(&mut *tx)
        .await?;
        let pipelines = sqlx::query(
            "SELECT digest, state, changed_at FROM pipelines WHERE project_id = $1
              ORDER BY changed_at DESC, digest",
        )
        .bind(pid)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(json!({
            "project": project,
            "policy": serde_json::to_value(policy)?,
            "members": members.iter().map(|r| json!({
                "username": r.get::<String, _>(0),
                "role": r.get::<String, _>(1),
                "disabled": r.get::<bool, _>(2),
            })).collect::<Vec<_>>(),
            "tokens": tokens.iter().map(|r| {
                let state = if r.get::<Option<OffsetDateTime>, _>(7).is_some() {
                    "quarantined"
                } else if r.get::<Option<OffsetDateTime>, _>(6).is_some() {
                    "revoked"
                } else if r.get::<bool, _>(9) {
                    "restore_disabled"
                } else if r.get::<bool, _>(8) {
                    "expired"
                } else {
                    "active"
                };
                json!({
                    "id": r.get::<i64, _>(0),
                    "producer": r.get::<String, _>(1),
                    "label": r.get::<String, _>(2),
                    "scopes": r.get::<Vec<String>, _>(3),
                    "created_at": rfc(Some(r.get(4))),
                    "expires_at": rfc(Some(r.get(5))),
                    "revoked_at": rfc(r.get(6)),
                    "quarantined_since": rfc(r.get(7)),
                    "state": state,
                })
            }).collect::<Vec<_>>(),
            "producers": producers.iter().map(|r| {
                let (sealed, builds, sources) =
                    (r.get::<bool, _>(3), r.get::<bool, _>(4), r.get::<bool, _>(5));
                json!({
                    "name": r.get::<String, _>(0),
                    "retired_at": rfc(r.get(1)),
                    "retired_reason": r.get::<Option<String>, _>(2),
                    // What its data supports, from what it has sent.
                    "assurance": [
                        if sealed { "Counting available (sealed expected sets)" }
                        else { "Counting unavailable (no sealed expected set yet)" },
                        if builds { "Build provenance available (build attempts)" }
                        else { "Build provenance missing (no build attempts)" },
                        // A source manifest without a repository revision carries no
                        // source identity: nothing to bind a merge verdict to.
                        if sources { "Merge gating available (source manifests)" }
                        else { "Merge gating unavailable (no source manifests)" },
                    ],
                })
            }).collect::<Vec<_>>(),
            "pipelines": pipelines.iter().map(|r| json!({
                "digest": r.get::<String, _>(0),
                "state": r.get::<String, _>(1),
                "changed_at": rfc(Some(r.get(2))),
            })).collect::<Vec<_>>(),
        }))
    }
}
