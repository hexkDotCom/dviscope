//! Ledger export and import (`dviscope.ledger/1.0`): the project's decisions —
//! triage owners, notes, bug URLs and states, and live exceptions — keyed by signature
//! fingerprint, so they can move to another project or installation. An import maps each
//! record by fingerprint (or a mapping file), applies it through the ordinary triage and
//! exception paths (so it applies only what the importer may do, validated the same way),
//! records the importer as the actor with the original author as attribution, keeps every
//! existing local decision, and lists what did not apply.

use std::collections::BTreeMap;

use dviscope_model::errors::ErrorCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::App;
use super::decisions::{ExceptionRequest, TriageEdit, validate_exception, validate_triage};
use crate::auth::{Action, Actor};
use crate::error::AppError;

/// Ledger format.
pub const LEDGER_FORMAT: &str = "dviscope.ledger/1.0";
/// At most this many records per kind in one import.
pub const MAX_RECORDS: usize = 10_000;

/// A triage record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageRecord {
    /// Signature fingerprint.
    pub fingerprint: String,
    /// Diagnostic ID (shown when unmatched).
    pub diag_id: String,
    /// Repository-qualified branch.
    pub branch: String,
    /// `open` or `closed`.
    pub state: String,
    /// Owner.
    #[serde(default)]
    pub owner: Option<String>,
    /// Notes.
    #[serde(default)]
    pub notes: String,
    /// Bug URLs.
    #[serde(default)]
    pub bug_urls: Vec<String>,
    /// Original author (user name).
    pub author: String,
    /// When the original revision was written.
    pub at: String,
}

/// An exception record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionRecord {
    /// Signature fingerprint.
    pub fingerprint: String,
    /// Diagnostic ID (shown when unmatched).
    pub diag_id: String,
    /// Repository-qualified branch.
    pub branch: String,
    /// Suite.
    pub suite: String,
    /// Reason.
    pub reason: String,
    /// Original author (user name).
    pub author: String,
    /// Created.
    pub created_at: String,
    /// Expiry.
    pub expires_at: String,
}

/// A ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    /// Always `dviscope.ledger/1.0`.
    pub format: String,
    /// The exporting project.
    pub project: String,
    /// Export time.
    pub exported_at: String,
    /// Current triage cases.
    pub triage: Vec<TriageRecord>,
    /// Live exceptions (not revoked, not superseded, not expired at export).
    pub exceptions: Vec<ExceptionRecord>,
}

fn rfc(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

impl App {
    /// Exports the project's decisions (project admins: notes may name people).
    ///
    /// # Errors
    /// Not found or forbidden.
    pub async fn export_ledger(
        &self,
        actor: &Actor,
        project: &str,
        now: OffsetDateTime,
    ) -> Result<Ledger, AppError> {
        let (pid, _) = self.read_project(actor, project, Action::AdminRead).await?;
        let triage = sqlx::query(
            "SELECT s.fingerprint, s.diag_id, c.branch, r.state, r.owner, r.notes, r.bug_urls,
                    u.username, r.at
               FROM triage_cases c
               JOIN triage_revisions r ON r.project_id = c.project_id AND r.case_id = c.id
                                      AND r.revision = c.revision
               JOIN signatures s ON s.project_id = c.project_id AND s.id = c.signature_id
               JOIN users u ON u.id = r.author
              WHERE c.project_id = $1
              ORDER BY s.fingerprint, c.branch",
        )
        .bind(pid)
        .fetch_all(&self.db)
        .await?
        .iter()
        .map(|r| TriageRecord {
            fingerprint: r.get(0),
            diag_id: r.get(1),
            branch: r.get(2),
            state: r.get(3),
            owner: r.get(4),
            notes: r.get(5),
            bug_urls: r.get(6),
            author: r.get(7),
            at: rfc(r.get(8)),
        })
        .collect();
        let exceptions = sqlx::query(
            "SELECT s.fingerprint, s.diag_id, e.branch, e.suite, e.reason, u.username,
                    e.created_at, e.expires_at
               FROM exceptions e
               JOIN signatures s ON s.project_id = e.project_id AND s.id = e.signature_id
               JOIN users u ON u.id = e.author
              WHERE e.project_id = $1 AND e.revoked_at IS NULL AND e.superseded_by IS NULL
                AND e.expires_at > $2
              ORDER BY s.fingerprint, e.branch, e.suite",
        )
        .bind(pid)
        .bind(now)
        .fetch_all(&self.db)
        .await?
        .iter()
        .map(|r| ExceptionRecord {
            fingerprint: r.get(0),
            diag_id: r.get(1),
            branch: r.get(2),
            suite: r.get(3),
            reason: r.get(4),
            author: r.get(5),
            created_at: rfc(r.get(6)),
            expires_at: rfc(r.get(7)),
        })
        .collect();
        Ok(Ledger {
            format: LEDGER_FORMAT.into(),
            project: project.into(),
            exported_at: rfc(now),
            triage,
            exceptions,
        })
    }

    /// Imports a ledger. `mapping` maps exported fingerprints to this project's (records
    /// without an entry keep their fingerprint). With `dry_run`, nothing is written and each
    /// record reports what would happen.
    ///
    /// # Errors
    /// Not found or forbidden (the importer needs at least triage rights); an invalid
    /// ledger. Per-record problems are outcomes, not errors.
    #[allow(clippy::too_many_lines)] // one pass per record kind
    pub async fn import_ledger(
        &self,
        actor: &Actor,
        project: &str,
        ledger: &Ledger,
        mapping: &BTreeMap<String, String>,
        dry_run: bool,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::TriageWrite)
            .await?;
        let Actor::User { .. } = actor else {
            return Err(AppError::new(ErrorCode::Forbidden, "people only"));
        };
        if ledger.format != LEDGER_FORMAT {
            return Err(AppError::field(
                ErrorCode::Invalid,
                format!("format must be {LEDGER_FORMAT}"),
                "format",
            ));
        }
        if ledger.triage.len() > MAX_RECORDS || ledger.exceptions.len() > MAX_RECORDS {
            return Err(AppError::new(
                ErrorCode::TooLarge,
                format!("at most {MAX_RECORDS} records of each kind"),
            ));
        }
        let may_except = crate::auth::authorize(actor, Action::ExceptionWrite, pid).is_ok();
        let mut records: Vec<Value> = vec![];
        let (mut applied_triage, mut applied_exceptions) = (0u32, 0u32);
        for t in &ledger.triage {
            let fp = mapping.get(&t.fingerprint).unwrap_or(&t.fingerprint);
            let base = json!({"kind": "triage", "fingerprint": fp, "diag_id": t.diag_id,
                              "branch": t.branch, "author": t.author});
            let outcome = match self.signature_number(pid, fp).await? {
                None => "unmatched".to_string(),
                Some(number) => {
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM triage_cases c JOIN signatures s
                                          ON s.project_id = c.project_id AND s.id = c.signature_id
                                         WHERE c.project_id = $1 AND s.number = $2 AND c.branch = $3)",
                    )
                    .bind(pid)
                    .bind(number)
                    .bind(&t.branch)
                    .fetch_one(&self.db)
                    .await?;
                    let edit = TriageEdit {
                        state: t.state.clone(),
                        owner: t.owner.clone(),
                        notes: t.notes.clone(),
                        bug_urls: t.bug_urls.clone(),
                    };
                    if exists {
                        "exists".to_string()
                    } else if let Err(e) = validate_triage(&t.branch, &edit) {
                        outcome_of(&e)
                    } else if dry_run {
                        "would_apply".to_string()
                    } else {
                        let attribution = json!({"original_author": t.author,
                                                 "original_at": t.at,
                                                 "ledger_project": ledger.project});
                        match self
                            .set_triage_attributed(
                                actor,
                                project,
                                number,
                                &t.branch,
                                None,
                                &edit,
                                Some(&attribution),
                            )
                            .await
                        {
                            Ok(_) => {
                                applied_triage += 1;
                                "applied".to_string()
                            }
                            Err(e) => outcome_of(&e),
                        }
                    }
                }
            };
            records.push(with_outcome(base, &outcome));
        }
        for x in &ledger.exceptions {
            let fp = mapping.get(&x.fingerprint).unwrap_or(&x.fingerprint);
            let base = json!({"kind": "exception", "fingerprint": fp, "diag_id": x.diag_id,
                              "branch": x.branch, "suite": x.suite, "author": x.author});
            let expired = OffsetDateTime::parse(&x.expires_at, &Rfc3339).map_or(true, |e| e <= now);
            let outcome = if !may_except {
                "not_permitted".to_string()
            } else if expired {
                "expired".to_string()
            } else {
                match self.signature_number(pid, fp).await? {
                    None => "unmatched".to_string(),
                    Some(number) => {
                        let exists: bool = sqlx::query_scalar(
                            "SELECT EXISTS (SELECT 1 FROM exceptions e JOIN signatures s
                                              ON s.project_id = e.project_id AND s.id = e.signature_id
                                             WHERE e.project_id = $1 AND s.number = $2
                                               AND e.branch = $3 AND e.suite = $4)",
                        )
                        .bind(pid)
                        .bind(number)
                        .bind(&x.branch)
                        .bind(&x.suite)
                        .fetch_one(&self.db)
                        .await?;
                        let req = ExceptionRequest {
                            signature: number,
                            branch: x.branch.clone(),
                            suite: x.suite.clone(),
                            reason: x.reason.clone(),
                            expires_at: x.expires_at.clone(),
                        };
                        if exists {
                            "exists".to_string()
                        } else if let Err(e) = validate_exception(&req, now) {
                            outcome_of(&e)
                        } else if dry_run {
                            "would_apply".to_string()
                        } else {
                            let attribution = json!({"original_author": x.author,
                                                     "original_at": x.created_at,
                                                     "ledger_project": ledger.project});
                            match self
                                .create_exception_attributed(
                                    actor,
                                    project,
                                    &req,
                                    None,
                                    now,
                                    Some(&attribution),
                                )
                                .await
                            {
                                Ok(_) => {
                                    applied_exceptions += 1;
                                    "applied".to_string()
                                }
                                Err(e) => outcome_of(&e),
                            }
                        }
                    }
                }
            };
            records.push(with_outcome(base, &outcome));
        }
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for r in &records {
            *counts
                .entry(r["outcome"].as_str().unwrap_or("?").to_string())
                .or_default() += 1;
        }
        Ok(json!({
            "format": "dviscope.ledger-import/1",
            "dry_run": dry_run,
            "from_project": ledger.project,
            "applied": {"triage": applied_triage, "exceptions": applied_exceptions},
            "outcomes": counts,
            "records": records,
        }))
    }

    async fn signature_number(&self, pid: i64, fingerprint: &str) -> Result<Option<i64>, AppError> {
        Ok(sqlx::query_scalar(
            "SELECT number FROM signatures WHERE project_id = $1 AND fingerprint = $2",
        )
        .bind(pid)
        .bind(fingerprint)
        .fetch_optional(&self.db)
        .await?)
    }
}

/// A per-record outcome of an error: `not_permitted`, or `invalid: <message>`.
fn outcome_of(e: &AppError) -> String {
    match e.code {
        ErrorCode::Forbidden => "not_permitted".to_string(),
        // A local decision appeared meanwhile (checked again inside the write).
        ErrorCode::StaleRevision | ErrorCode::PreconditionFailed => "exists".to_string(),
        _ => format!("invalid: {}", e.message),
    }
}

fn with_outcome(mut base: Value, outcome: &str) -> Value {
    base["outcome"] = json!(outcome);
    base
}
