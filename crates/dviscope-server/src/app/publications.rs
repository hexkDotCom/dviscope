//! Publication receipts and published statuses.
//!
//! Publishing evaluates readiness, compares the result with the status currently posted
//! for the same target (repository, commit, context), and either records a refresh (same
//! basis: verdict, validity, counts, blockers, exceptions, candidate) or stores a new
//! immutable receipt for the publisher to post. The code host's acceptance is recorded
//! afterwards (`posted`), which retires the receipts it replaced; a receipt whose
//! monitoring ended is retired only after the host accepted its final update. Statuses are
//! advisory snapshots: the description always carries the evaluation time and validity.

use dviscope_model::errors::ErrorCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row as _;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use super::App;
use crate::auth::{Action, Actor};
use crate::error::AppError;

/// Page size of the open-publications inventory.
pub const OPEN_PAGE: usize = 500;

/// How long a status without `valid_until` is monitored.
pub const MONITOR_DAYS: i64 = 14;

/// Where a status is published.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// `owner/name`.
    pub repository: String,
    /// Commit SHA (40 or 64 hex digits).
    pub commit: String,
    /// Status context, e.g. `dviscope/merge`.
    pub context: String,
}

/// `POST …/readiness/publications`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    /// Regression reference.
    pub regression: String,
    /// Producer, when the reference is ambiguous.
    #[serde(default)]
    pub producer: Option<String>,
    /// The candidate's source digest (required: a published status is always bound).
    pub expect_source: String,
    /// Status target.
    pub target: Target,
}

/// `POST …/publications/{digest}/posted`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Posted {
    /// The state the code host accepted.
    pub state: String,
}

/// `POST …/publications/{digest}/retire`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retire {
    /// `monitoring_ended` or `superseded`.
    pub reason: String,
}

fn rfc(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

fn invalid(msg: &str, field: &str) -> AppError {
    AppError::field(ErrorCode::Invalid, msg, field)
}

fn check_target(t: &Target) -> Result<(), AppError> {
    let part = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    };
    match t.repository.split_once('/') {
        Some((o, n)) if part(o) && part(n) => {}
        _ => return Err(invalid("repository is owner/name", "target.repository")),
    }
    if !matches!(t.commit.len(), 40 | 64) || !t.commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid("commit is a full hex SHA", "target.commit"));
    }
    if t.context.is_empty()
        || t.context.len() > 100
        || !t.context.chars().all(|c| c.is_ascii_graphic() || c == ' ')
    {
        return Err(invalid(
            "context is 1 to 100 printable characters",
            "target.context",
        ));
    }
    Ok(())
}

/// The commit-status state of a verdict: never `success` unless the verdict passes.
#[must_use]
pub fn status_state(verdict: &str) -> &'static str {
    match verdict {
        "pass" | "accepted_with_exceptions" => "success",
        "fail" => "failure",
        "insufficient_evidence" => "pending",
        _ => "error",
    }
}

/// The status description (at most 140 characters): verdict, evaluation time, validity
/// and digest prefix — an advisory snapshot that says when it was true.
#[must_use]
pub fn description(
    verdict: &str,
    evaluated_at: &str,
    valid_until: Option<&str>,
    digest: &str,
) -> String {
    let label = match verdict {
        "pass" => "Pass",
        "accepted_with_exceptions" => "Accepted with exceptions",
        "fail" => "Fail",
        "insufficient_evidence" => "Insufficient evidence",
        _ => "No verdict",
    };
    let short = |t: &str| t.get(..16).unwrap_or(t).replace('T', " ");
    let mut d = format!("{label} as of {}Z", short(evaluated_at));
    if let Some(v) = valid_until {
        d.push_str(&format!(", valid until {}Z", short(v)));
    }
    let dig = digest.strip_prefix("sha256:").unwrap_or(digest);
    d.push_str(&format!("; dig {}", dig.get(..12).unwrap_or(dig)));
    d.chars().take(140).collect()
}

/// The parts of a summary that make up a status's basis (not its time or digest).
fn basis(summary: &Value) -> Value {
    json!({
        "verdict": summary["verdict"],
        "valid_until": summary["valid_until"],
        "counts": summary["counts"],
        "blockers": summary["blockers"],
        "exceptions_used": summary["exceptions_used"],
        "candidate": summary["candidate"],
    })
}

fn receipt_json(project: &str, r: &sqlx::postgres::PgRow) -> Value {
    let summary: Value = r.get("summary");
    let digest: String = r.get("digest");
    let opt = |c: &str| r.get::<Option<OffsetDateTime>, _>(c).map(rfc);
    json!({
        "digest": digest,
        "summary": summary,
        "regression": r.get::<Option<String>, _>("regression_ref"),
        // The producer whose regression was evaluated (refreshes evaluate the same one).
        "producer": r.get::<Option<String>, _>("producer"),
        "expect_source": r.get::<Option<String>, _>("expect_source"),
        "target": {
            "repository": r.get::<Option<String>, _>("target_repository"),
            "commit": r.get::<Option<String>, _>("target_commit"),
            "context": r.get::<Option<String>, _>("target_context"),
        },
        "status": {
            "state": r.get::<Option<String>, _>("status_state"),
            "description": description(
                summary["verdict"].as_str().unwrap_or_default(),
                summary["evaluated_at"].as_str().unwrap_or_default(),
                summary["valid_until"].as_str(),
                &digest,
            ),
        },
        "published_at": rfc(r.get("published_at")),
        "valid_until": opt("valid_until"),
        "monitor_until": opt("monitor_until"),
        "posted_at": opt("posted_at"),
        "last_refresh_at": opt("last_refresh_at"),
        "retired_at": opt("retired_at"),
        "retired_reason": r.get::<Option<String>, _>("retired_reason"),
        "receipt_path": format!("/p/{}/receipts/{}", urlish(project), urlish(&digest)),
    })
}

/// Percent-encodes what is not unreserved (for the receipt page path).
fn urlish(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

const COLS: &str =
    "digest, summary, regression_ref, expect_source, target_repository, target_commit,
    target_context, status_state, published_at, valid_until, monitor_until, posted_at,
    last_refresh_at, retired_at, retired_reason,
    (SELECT p.name FROM producers p WHERE p.id = publication_receipts.producer_id) AS producer";

impl App {
    /// Evaluates and either refreshes the posted status of the target (same basis) or
    /// stores a new receipt to post (`action`: `unchanged` or `post`).
    ///
    /// # Errors
    /// Authorization (triager), invalid target, unknown regression, database errors.
    pub async fn publish(
        &self,
        actor: &Actor,
        project: &str,
        req: &PublishRequest,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::PublicationWrite)
            .await?;
        check_target(&req.target)?;
        let v = self
            .read_readiness(
                actor,
                project,
                &req.regression,
                Some(&req.expect_source),
                req.producer.as_deref(),
                now,
            )
            .await?;
        let summary = v["summary"].clone();
        let digest = v["digest"].as_str().unwrap_or_default().to_string();
        let verdict = v["verdict"].as_str().unwrap_or_default().to_string();
        let valid_until = v["valid_until"]
            .as_str()
            .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok());
        let t = &req.target;
        let mut tx = super::begin_write(&self.db).await?;
        // One publisher decision per target at a time. GitHub compares repositories,
        // commits and contexts without case, so does every target comparison here.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7))")
            .bind(format!(
                "{pid}|{}|{}|{}",
                t.repository.to_lowercase(),
                t.commit.to_lowercase(),
                t.context.to_lowercase()
            ))
            .execute(&mut *tx)
            .await?;
        let current = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS} FROM publication_receipts
              WHERE project_id = $1 AND lower(target_repository) = lower($2)
                AND lower(target_commit) = lower($3) AND lower(target_context) = lower($4)
                AND retired_at IS NULL AND posted_at IS NOT NULL
              ORDER BY published_at DESC LIMIT 1"
        )))
        .bind(pid)
        .bind(&t.repository)
        .bind(&t.commit)
        .bind(&t.context)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(c) = &current {
            let same_request = c.get::<Option<String>, _>("regression_ref").as_deref()
                == Some(req.regression.as_str())
                && c.get::<Option<String>, _>("producer").as_deref()
                    == v["regression"]["producer"].as_str()
                && c.get::<Option<String>, _>("expect_source").as_deref()
                    == Some(req.expect_source.as_str());
            if same_request && basis(&c.get::<Value, _>("summary")) == basis(&summary) {
                let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "UPDATE publication_receipts SET last_refresh_at = $3
                      WHERE project_id = $1 AND digest = $2 RETURNING {COLS}"
                )))
                .bind(pid)
                .bind(c.get::<String, _>("digest"))
                .bind(now)
                .fetch_one(&mut *tx)
                .await?;
                tx.commit().await?;
                return Ok(json!({"action": "unchanged", "receipt": receipt_json(project, &row)}));
            }
        }
        let producer_id: Option<i64> =
            sqlx::query_scalar("SELECT id FROM producers WHERE project_id = $1 AND name = $2")
                .bind(pid)
                .bind(v["regression"]["producer"].as_str().unwrap_or_default())
                .fetch_optional(&mut *tx)
                .await?;
        let monitor_until = valid_until.unwrap_or(now + Duration::days(MONITOR_DAYS));
        sqlx::query(
            "INSERT INTO publication_receipts
                (project_id, digest, summary, published_at, monitor_until, regression_ref,
                 producer_id, expect_source, target_repository, target_commit, target_context,
                 valid_until, status_state)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (project_id, digest) DO NOTHING",
        )
        .bind(pid)
        .bind(&digest)
        .bind(&summary)
        .bind(now)
        .bind(monitor_until)
        .bind(&req.regression)
        .bind(producer_id)
        .bind(&req.expect_source)
        .bind(&t.repository)
        .bind(&t.commit)
        .bind(&t.context)
        .bind(valid_until)
        .bind(status_state(&verdict))
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS} FROM publication_receipts WHERE project_id = $1 AND digest = $2"
        )))
        .bind(pid)
        .bind(&digest)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(json!({"action": "post", "receipt": receipt_json(project, &row)}))
    }

    /// Records that the code host accepted a receipt's status; retires the older receipts
    /// of the same target (superseded).
    ///
    /// # Errors
    /// Authorization, unknown receipt, a state other than the receipt's own.
    pub async fn mark_posted(
        &self,
        actor: &Actor,
        project: &str,
        digest: &str,
        p: &Posted,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::PublicationWrite)
            .await?;
        let mut tx = super::begin_write(&self.db).await?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS} FROM publication_receipts WHERE project_id = $1 AND digest = $2 FOR UPDATE")))
        .bind(pid)
        .bind(digest)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "no such receipt"))?;
        if row.get::<Option<String>, _>("status_state").as_deref() != Some(p.state.as_str()) {
            return Err(invalid("state is the receipt's own status state", "state"));
        }
        // Fence: an obsolete receipt (retired, or older than one already posted for the
        // target) is never recorded as the host's state; the publisher re-posts the newest.
        let newer_posted: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM publication_receipts n
                             WHERE n.project_id = $1 AND lower(n.target_repository) = lower($2)
                               AND lower(n.target_commit) = lower($3)
                               AND lower(n.target_context) = lower($4)
                               AND n.digest <> $5 AND n.posted_at IS NOT NULL
                               AND n.published_at > (SELECT published_at FROM publication_receipts
                                                      WHERE project_id = $1 AND digest = $5))",
        )
        .bind(pid)
        .bind(row.get::<Option<String>, _>("target_repository"))
        .bind(row.get::<Option<String>, _>("target_commit"))
        .bind(row.get::<Option<String>, _>("target_context"))
        .bind(digest)
        .fetch_one(&mut *tx)
        .await?;
        if newer_posted || row.get::<Option<OffsetDateTime>, _>("retired_at").is_some() {
            return Err(AppError::new(
                ErrorCode::StaleRevision,
                "a newer status of this target exists: post the newest receipt",
            ));
        }
        sqlx::query(
            "UPDATE publication_receipts SET posted_at = coalesce(posted_at, $3),
                    last_refresh_at = coalesce(last_refresh_at, $3)
              WHERE project_id = $1 AND digest = $2",
        )
        .bind(pid)
        .bind(digest)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE publication_receipts SET retired_at = $6, retired_reason = 'superseded'
              WHERE project_id = $1 AND lower(target_repository) = lower($2)
                AND lower(target_commit) = lower($3) AND lower(target_context) = lower($4)
                AND digest <> $5 AND retired_at IS NULL
                AND published_at <= (SELECT published_at FROM publication_receipts
                                      WHERE project_id = $1 AND digest = $5)",
        )
        .bind(pid)
        .bind(row.get::<Option<String>, _>("target_repository"))
        .bind(row.get::<Option<String>, _>("target_commit"))
        .bind(row.get::<Option<String>, _>("target_context"))
        .bind(digest)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS} FROM publication_receipts WHERE project_id = $1 AND digest = $2"
        )))
        .bind(pid)
        .bind(digest)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(receipt_json(project, &row))
    }

    /// Retires a receipt (after the code host accepted its final update).
    ///
    /// # Errors
    /// Authorization, unknown receipt, unknown reason.
    pub async fn retire_publication(
        &self,
        actor: &Actor,
        project: &str,
        digest: &str,
        r: &Retire,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::PublicationWrite)
            .await?;
        if !["monitoring_ended", "superseded"].contains(&r.reason.as_str()) {
            return Err(invalid(
                "reason is monitoring_ended or superseded",
                "reason",
            ));
        }
        // A write: past the maintenance gate, held to the commit.
        let mut tx = super::begin_write(&self.db).await?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE publication_receipts
                SET retired_at = coalesce(retired_at, $3),
                    retired_reason = coalesce(retired_reason, $4)
              WHERE project_id = $1 AND digest = $2 RETURNING {COLS}"
        )))
        .bind(pid)
        .bind(digest)
        .bind(now)
        .bind(&r.reason)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "no such receipt"))?;
        tx.commit().await?;
        Ok(receipt_json(project, &row))
    }

    /// Receipts not retired (what a restarting publisher resumes), oldest deadline first.
    ///
    /// # Errors
    /// Authorization, database errors.
    pub async fn open_publications(
        &self,
        actor: &Actor,
        project: &str,
        after: Option<&str>,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::PublicationWrite)
            .await?;
        // Every page of the inventory, by (monitoring deadline, digest): a publisher reads
        // them all.
        let cursor: Option<(OffsetDateTime, String)> = match after {
            None => None,
            Some(c) => {
                let bad = || invalid("after is a cursor from `next`", "after");
                let (t, d) = c.split_once('.').ok_or_else(bad)?;
                let micros: i128 = t.parse().map_err(|_| bad())?;
                let at =
                    OffsetDateTime::from_unix_timestamp_nanos(micros * 1000).map_err(|_| bad())?;
                Some((at, d.to_string()))
            }
        };
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS} FROM publication_receipts
              WHERE project_id = $1 AND retired_at IS NULL AND target_repository IS NOT NULL
                AND ($2::timestamptz IS NULL OR (monitor_until, digest) > ($2, $3))
              ORDER BY monitor_until, digest LIMIT {}",
            OPEN_PAGE + 1
        )))
        .bind(pid)
        .bind(cursor.as_ref().map(|c| c.0))
        .bind(cursor.as_ref().map_or("", |c| c.1.as_str()))
        .fetch_all(&self.db)
        .await?;
        let more = rows.len() > OPEN_PAGE;
        let page = &rows[..rows.len().min(OPEN_PAGE)];
        let next = if more {
            page.last().map(|r| {
                let at: OffsetDateTime = r.get("monitor_until");
                format!(
                    "{}.{}",
                    at.unix_timestamp_nanos() / 1000,
                    r.get::<String, _>("digest")
                )
            })
        } else {
            None
        };
        Ok(json!({
            "publications": page.iter().map(|r| receipt_json(project, r)).collect::<Vec<_>>(),
            "next": next,
        }))
    }

    /// A published receipt next to a current evaluation of the same regression and
    /// candidate (the status link's page).
    ///
    /// # Errors
    /// Authorization, unknown receipt, database errors.
    pub async fn read_receipt(
        &self,
        actor: &Actor,
        project: &str,
        digest: &str,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::ReadinessRead)
            .await?;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLS} FROM publication_receipts WHERE project_id = $1 AND digest = $2"
        )))
        .bind(pid)
        .bind(digest)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "no such receipt"))?;
        let receipt = receipt_json(project, &row);
        let current = match row.get::<Option<String>, _>("regression_ref") {
            Some(reg) => match self
                .read_readiness(
                    actor,
                    project,
                    &reg,
                    row.get::<Option<String>, _>("expect_source").as_deref(),
                    row.get::<Option<String>, _>("producer").as_deref(),
                    now,
                )
                .await
            {
                Ok(v) => json!({"summary": v["summary"], "digest": v["digest"]}),
                Err(e) => json!({"error": {"code": e.code.as_str(), "message": e.message}}),
            },
            None => Value::Null,
        };
        Ok(json!({"receipt": receipt, "current": current}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_never_turn_green_without_a_passing_verdict() {
        assert_eq!(status_state("pass"), "success");
        assert_eq!(status_state("accepted_with_exceptions"), "success");
        assert_eq!(status_state("fail"), "failure");
        assert_eq!(status_state("insufficient_evidence"), "pending");
        assert_eq!(status_state(""), "error");
        assert_eq!(status_state("PASS"), "error");
    }

    #[test]
    fn descriptions_carry_time_validity_and_digest() {
        let d = description(
            "accepted_with_exceptions",
            "2026-11-08T07:05:31Z",
            Some("2026-12-08T23:59:59Z"),
            "sha256:0123456789abcdef0123",
        );
        assert_eq!(
            d,
            "Accepted with exceptions as of 2026-11-08 07:05Z, valid until 2026-12-08 23:59Z; dig 0123456789ab"
        );
        assert!(d.len() <= 140);
    }

    #[test]
    fn targets_are_validated() {
        let ok = Target {
            repository: "hexkDotCom/dviscope-dev".into(),
            commit: "a".repeat(40),
            context: "dviscope/merge".into(),
        };
        assert!(check_target(&ok).is_ok());
        for bad in [
            Target {
                repository: "x".into(),
                ..ok.clone()
            },
            Target {
                repository: "a/b/c".into(),
                ..ok.clone()
            },
            Target {
                commit: "abc".into(),
                ..ok.clone()
            },
            Target {
                commit: "g".repeat(40),
                ..ok.clone()
            },
            Target {
                context: String::new(),
                ..ok.clone()
            },
            Target {
                context: "a\nb".into(),
                ..ok.clone()
            },
        ] {
            assert!(check_target(&bad).is_err(), "{bad:?}");
        }
    }
}
