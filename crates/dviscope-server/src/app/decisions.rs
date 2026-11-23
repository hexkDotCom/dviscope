//! Decisions: triage cases and exceptions, each a head with immutable
//! revisions; `If-Match` on the head revision (412 names the conflicting change); history
//! in the same transaction; every decision-affecting write advances the project's change
//! sequence (the readiness watermark, B.11).

use dviscope_model::errors::ErrorCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::App;
use crate::auth::{Action, Actor, authorize};
use crate::error::AppError;

/// Notes bound (B.10).
pub const MAX_NOTES_BYTES: usize = 64 * 1024;
/// Bug URLs per case.
pub const MAX_BUG_URLS: usize = 20;
/// Longest exception lifetime.
pub const MAX_EXCEPTION_DAYS: i64 = 180;

/// A triage edit (the whole new state; a revision is a full snapshot).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriageEdit {
    /// `open` or `closed` (closing does not certify a fix).
    pub state: String,
    /// Owner (free text, ≤ 64 characters).
    #[serde(default)]
    pub owner: Option<String>,
    /// Notes (Markdown, sanitized when rendered).
    #[serde(default)]
    pub notes: String,
    /// Bug URLs (http/https, never fetched).
    #[serde(default)]
    pub bug_urls: Vec<String>,
}

/// Most signatures one bulk triage request may decide.
pub const MAX_BULK_TRIAGE: usize = 500;

/// One signature of a bulk triage request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BulkTriageItem {
    /// Project signature number.
    pub number: i64,
    /// The case head revision the decision is based on (absent or 0: no case yet).
    #[serde(default)]
    pub if_match: Option<i32>,
}

/// The new head of one case of a bulk triage request.
#[derive(Debug, Clone, Serialize)]
pub struct BulkTriageHead {
    /// Project signature number.
    pub signature: i64,
    /// Case ID.
    pub id: i64,
    /// New revision.
    pub revision: i32,
}

/// An exception request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionRequest {
    /// Signature number.
    pub signature: i64,
    /// Repository-qualified branch, `repo/name`.
    pub branch: String,
    /// Suite.
    pub suite: String,
    /// Why.
    pub reason: String,
    /// Expiry (RFC 3339), at most 180 days ahead.
    pub expires_at: String,
}

/// Checks an exception expiry: RFC 3339, in the future, at most 180 days ahead of `now`
/// (also for previews, so a preview never promises what creation refuses).
///
/// # Errors
/// Not RFC 3339, not in the future, or too far.
pub fn check_expiry(expires_at: &str, now: OffsetDateTime) -> Result<OffsetDateTime, AppError> {
    let expires = OffsetDateTime::parse(expires_at, &Rfc3339)
        .map_err(|_| invalid("expires_at is an RFC 3339 time", "expires_at"))?;
    if expires <= now || expires > now + time::Duration::days(MAX_EXCEPTION_DAYS) {
        return Err(invalid(
            "an exception expires within 180 days",
            "expires_at",
        ));
    }
    Ok(expires)
}

/// A decision head as answered.
#[derive(Debug, Clone, Serialize)]
pub struct Head {
    /// ID.
    pub id: i64,
    /// Current revision (the `ETag`).
    pub revision: i32,
}

fn invalid(msg: impl Into<String>, field: &str) -> AppError {
    AppError::field(ErrorCode::Invalid, msg, field)
}

fn user_id(actor: &Actor) -> Result<i64, AppError> {
    match actor {
        Actor::User { user_id, .. } => Ok(*user_id),
        Actor::Collector { .. } => Err(AppError::new(
            ErrorCode::Forbidden,
            "decisions are made by people, not collector tokens",
        )),
    }
}

/// Advances the project's change sequence and records the change (same transaction).
///
/// # Errors
/// Database errors.
pub async fn bump_project(
    tx: &mut Transaction<'_, Postgres>,
    project_id: i64,
    kind: &str,
    object: &str,
) -> Result<i64, AppError> {
    let seq: i64 = sqlx::query(
        "INSERT INTO project_heads (project_id, change_seq) VALUES ($1, 1)
         ON CONFLICT (project_id) DO UPDATE SET change_seq = project_heads.change_seq + 1
         RETURNING change_seq",
    )
    .bind(project_id)
    .fetch_one(&mut **tx)
    .await?
    .get(0);
    sqlx::query("INSERT INTO changes (project_id, seq, kind, object) VALUES ($1, $2, $3, $4)")
        .bind(project_id)
        .bind(seq)
        .bind(kind)
        .bind(object)
        .execute(&mut **tx)
        .await?;
    Ok(seq)
}

/// Adds an imported record's attribution to a history detail.
fn with_attribution(mut detail: Value, attribution: Option<&Value>) -> Value {
    if let Some(a) = attribution {
        detail["imported"] = a.clone();
    }
    detail
}

async fn history(
    tx: &mut Transaction<'_, Postgres>,
    project_id: i64,
    actor: i64,
    object: &str,
    action: &str,
    detail: Value,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO history (project_id, actor, object, action, detail) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(project_id)
    .bind(actor)
    .bind(object)
    .bind(action)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Validates a triage edit (the same checks for an edit, an import and its dry run).
///
/// # Errors
/// The first invalid field.
pub fn validate_triage(branch: &str, edit: &TriageEdit) -> Result<(), AppError> {
    check_branch(branch)?;
    if !matches!(edit.state.as_str(), "open" | "closed") {
        return Err(invalid("state is open or closed", "state"));
    }
    if edit.owner.as_ref().is_some_and(|o| o.chars().count() > 64) {
        return Err(invalid("an owner is at most 64 characters", "owner"));
    }
    if edit.notes.len() > MAX_NOTES_BYTES {
        return Err(invalid("notes are at most 64 KiB", "notes"));
    }
    if edit.bug_urls.len() > MAX_BUG_URLS
        || edit
            .bug_urls
            .iter()
            .any(|u| !(u.starts_with("https://") || u.starts_with("http://")) || u.len() > 2048)
    {
        return Err(invalid("at most 20 http(s) bug URLs", "bug_urls"));
    }
    Ok(())
}

/// Validates an exception request at `now`; returns its expiry.
///
/// # Errors
/// The first invalid field.
pub fn validate_exception(
    req: &ExceptionRequest,
    now: OffsetDateTime,
) -> Result<OffsetDateTime, AppError> {
    check_branch(&req.branch)?;
    if req.suite.is_empty() || req.suite.len() > 200 {
        return Err(invalid("a suite is required", "suite"));
    }
    if req.reason.trim().is_empty() || req.reason.len() > 4096 {
        return Err(invalid("a reason is required (≤ 4 KiB)", "reason"));
    }
    check_expiry(&req.expires_at, now)
}

fn check_branch(b: &str) -> Result<(), AppError> {
    if b.split_once('/')
        .is_some_and(|(r, n)| !r.is_empty() && !n.is_empty())
        && b.len() <= 300
    {
        Ok(())
    } else {
        Err(invalid("a branch is repository/name", "branch"))
    }
}

impl App {
    async fn project_for(
        &self,
        actor: &Actor,
        project: &str,
        action: Action,
    ) -> Result<i64, AppError> {
        let id: i64 = sqlx::query("SELECT id FROM projects WHERE name = $1")
            .bind(project)
            .fetch_optional(&self.db)
            .await?
            .ok_or_else(|| AppError::new(ErrorCode::NotFound, format!("no project {project}")))?
            .get(0);
        authorize(actor, action, id)?;
        Ok(id)
    }

    async fn signature_id(
        tx: &mut Transaction<'_, Postgres>,
        project_id: i64,
        number: i64,
    ) -> Result<i64, AppError> {
        Ok(
            sqlx::query("SELECT id FROM signatures WHERE project_id = $1 AND number = $2")
                .bind(project_id)
                .bind(number)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| invalid(format!("no signature {number}"), "signature"))?
                .get(0),
        )
    }

    /// Creates or edits the triage case of a signature on a branch. `if_match` is the head
    /// revision the edit was based on (`None` for a new case).
    ///
    /// # Errors
    /// Authorization, validation, 412 on a stale base (naming the change), database errors.
    #[allow(clippy::too_many_lines)] // validation, head, revision, history, change feed
    pub async fn set_triage(
        &self,
        actor: &Actor,
        project: &str,
        signature: i64,
        branch: &str,
        if_match: Option<i32>,
        edit: &TriageEdit,
    ) -> Result<Head, AppError> {
        self.set_triage_attributed(actor, project, signature, branch, if_match, edit, None)
            .await
    }

    /// [`Self::set_triage`], recording `attribution` (an imported record's original author
    /// and time) in the same transaction as the revision.
    ///
    /// # Errors
    /// As [`Self::set_triage`].
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub async fn set_triage_attributed(
        &self,
        actor: &Actor,
        project: &str,
        signature: i64,
        branch: &str,
        if_match: Option<i32>,
        edit: &TriageEdit,
        attribution: Option<&Value>,
    ) -> Result<Head, AppError> {
        let pid = self
            .project_for(actor, project, Action::TriageWrite)
            .await?;
        let uid = user_id(actor)?;
        validate_triage(branch, edit)?;
        let mut tx = super::begin_write(&self.db).await?;
        let sid = Self::signature_id(&mut tx, pid, signature).await?;
        let head =
            Self::triage_in(&mut tx, pid, uid, sid, branch, if_match, edit, attribution).await?;
        bump_project(&mut tx, pid, "triage", &format!("triage:{}", head.id)).await?;
        tx.commit().await?;
        Ok(head)
    }

    /// Applies one triage decision to several signatures of a branch in one transaction:
    /// every signature gets a new revision of its case, or nothing is written. Each item
    /// carries the head revision it was based on (absent or 0 for a signature without a case
    /// on the branch); a stale base fails the whole request with 412 naming the signature.
    ///
    /// # Errors
    /// Authorization, validation (1 to [`MAX_BULK_TRIAGE`] distinct signatures), an unknown
    /// signature, 412 on a stale base, database errors.
    pub async fn set_triage_bulk(
        &self,
        actor: &Actor,
        project: &str,
        branch: &str,
        items: &[BulkTriageItem],
        edit: &TriageEdit,
    ) -> Result<Vec<BulkTriageHead>, AppError> {
        let pid = self
            .project_for(actor, project, Action::TriageWrite)
            .await?;
        let uid = user_id(actor)?;
        validate_triage(branch, edit)?;
        if items.is_empty() || items.len() > MAX_BULK_TRIAGE {
            return Err(invalid(
                format!("between 1 and {MAX_BULK_TRIAGE} signatures"),
                "signatures",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        if let Some(d) = items.iter().find(|i| !seen.insert(i.number)) {
            return Err(invalid(
                format!("signature {} is listed twice", d.number),
                "signatures",
            ));
        }
        let mut tx = super::begin_write(&self.db).await?;
        let mut resolved = Vec::with_capacity(items.len());
        for i in items {
            resolved.push((Self::signature_id(&mut tx, pid, i.number).await?, i));
        }
        // One lock order for every writer: the case scopes by signature id, then the project
        // counter last (as the single path does), so overlapping bulk and single edits never
        // wait on each other in a cycle.
        resolved.sort_by_key(|(sid, _)| *sid);
        let mut out = Vec::with_capacity(items.len());
        for (sid, i) in resolved {
            let head = Self::triage_in(&mut tx, pid, uid, sid, branch, i.if_match, edit, None)
                .await
                .map_err(|mut e| {
                    if e.code == ErrorCode::PreconditionFailed {
                        e.message = format!("signature #{}: {}", i.number, e.message);
                    }
                    e
                })?;
            out.push(BulkTriageHead {
                signature: i.number,
                id: head.id,
                revision: head.revision,
            });
        }
        // The change feed names every case, as for single edits; written after every case
        // lock is held, so the project counter is always taken last.
        for h in &out {
            bump_project(&mut tx, pid, "triage", &format!("triage:{}", h.id)).await?;
        }
        tx.commit().await?;
        out.sort_by_key(|h| h.signature);
        Ok(out)
    }

    /// One triage revision of signature `sid` on `branch` inside `tx` (the scope lock, the
    /// 412 check, the revision and its history entry).
    #[allow(clippy::too_many_arguments)]
    async fn triage_in(
        tx: &mut Transaction<'_, Postgres>,
        pid: i64,
        uid: i64,
        sid: i64,
        branch: &str,
        if_match: Option<i32>,
        edit: &TriageEdit,
        attribution: Option<&Value>,
    ) -> Result<Head, AppError> {
        // Serialize first creations of one scope.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 11))")
            .bind(format!("triage/{pid}/{sid}/{branch}"))
            .execute(&mut **tx)
            .await?;
        let head = sqlx::query(
            "SELECT id, revision FROM triage_cases
              WHERE project_id = $1 AND signature_id = $2 AND branch = $3 FOR UPDATE",
        )
        .bind(pid)
        .bind(sid)
        .bind(branch)
        .fetch_optional(&mut **tx)
        .await?;
        let (id, rev) = match head {
            Some(h) => {
                let (id, rev): (i64, i32) = (h.get(0), h.get(1));
                if if_match != Some(rev) {
                    let last = sqlx::query(
                        "SELECT r.revision, u.username, r.at, r.owner, r.state
                           FROM triage_revisions r JOIN users u ON u.id = r.author
                          WHERE r.project_id = $1 AND r.case_id = $2 AND r.revision = $3",
                    )
                    .bind(pid)
                    .bind(id)
                    .bind(rev)
                    .fetch_one(&mut **tx)
                    .await?;
                    let at: OffsetDateTime = last.get(2);
                    let mut e = AppError::new(
                        ErrorCode::PreconditionFailed,
                        format!(
                            "revision {rev} by {} at {} (owner {}, {}) is newer than your base",
                            last.get::<String, _>(1),
                            at.format(&Rfc3339).unwrap_or_default(),
                            last.get::<Option<String>, _>(3)
                                .unwrap_or_else(|| "none".into()),
                            last.get::<String, _>(4),
                        ),
                    );
                    e.field = Some("if_match".into());
                    return Err(e);
                }
                sqlx::query(
                    "UPDATE triage_cases SET revision = $3 WHERE project_id = $1 AND id = $2",
                )
                .bind(pid)
                .bind(id)
                .bind(rev + 1)
                .execute(&mut **tx)
                .await?;
                (id, rev + 1)
            }
            None => {
                if if_match.is_some_and(|r| r != 0) {
                    return Err(AppError::new(
                        ErrorCode::PreconditionFailed,
                        "the case does not exist any more at that revision",
                    ));
                }
                let id: i64 = sqlx::query(
                    "INSERT INTO triage_cases (project_id, signature_id, branch, revision)
                     VALUES ($1, $2, $3, 1) RETURNING id",
                )
                .bind(pid)
                .bind(sid)
                .bind(branch)
                .fetch_one(&mut **tx)
                .await?
                .get(0);
                (id, 1)
            }
        };
        sqlx::query(
            "INSERT INTO triage_revisions (project_id, case_id, revision, state, owner, notes, bug_urls, author)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(pid)
        .bind(id)
        .bind(rev)
        .bind(&edit.state)
        .bind(edit.owner.as_deref())
        .bind(&edit.notes)
        .bind(&edit.bug_urls)
        .bind(uid)
        .execute(&mut **tx)
        .await?;
        let object = format!("triage:{id}");
        history(
            tx,
            pid,
            uid,
            &object,
            "triage.revise",
            with_attribution(json!({"revision": rev, "state": edit.state}), attribution),
        )
        .await?;
        Ok(Head { id, revision: rev })
    }

    /// Creates an exception, superseding the scope's live one in the same transaction.
    ///
    /// # Errors
    /// Authorization (project admin), validation, database errors.
    pub async fn create_exception(
        &self,
        actor: &Actor,
        project: &str,
        req: &ExceptionRequest,
        if_match: Option<i32>,
        now: OffsetDateTime,
    ) -> Result<Head, AppError> {
        self.create_exception_attributed(actor, project, req, if_match, now, None)
            .await
    }

    /// [`Self::create_exception`], recording `attribution` in the same transaction.
    ///
    /// # Errors
    /// As [`Self::create_exception`].
    #[allow(clippy::too_many_lines)]
    pub async fn create_exception_attributed(
        &self,
        actor: &Actor,
        project: &str,
        req: &ExceptionRequest,
        if_match: Option<i32>,
        now: OffsetDateTime,
        attribution: Option<&Value>,
    ) -> Result<Head, AppError> {
        let pid = self
            .project_for(actor, project, Action::ExceptionWrite)
            .await?;
        let uid = user_id(actor)?;
        let expires = validate_exception(req, now)?;
        let mut tx = super::begin_write(&self.db).await?;
        let sid = Self::signature_id(&mut tx, pid, req.signature).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 12))")
            .bind(format!(
                "exception/{pid}/{sid}/{}/{}",
                req.branch, req.suite
            ))
            .execute(&mut *tx)
            .await?;
        // An imported exception never reopens a scope with local history (a revoked or
        // superseded exception is a local decision), checked under the scope lock so a
        // concurrent create-and-revoke cannot slip between check and insert.
        if attribution.is_some() {
            let decided: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM exceptions WHERE project_id = $1
                                  AND signature_id = $2 AND branch = $3 AND suite = $4)",
            )
            .bind(pid)
            .bind(sid)
            .bind(&req.branch)
            .bind(&req.suite)
            .fetch_one(&mut *tx)
            .await?;
            if decided {
                return Err(AppError::new(
                    ErrorCode::StaleRevision,
                    "the scope has local exception history: an import never reopens it",
                ));
            }
        }
        let live = sqlx::query(
            "SELECT id, revision FROM exceptions
              WHERE project_id = $1 AND signature_id = $2 AND branch = $3 AND suite = $4
                AND revoked_at IS NULL AND superseded_by IS NULL FOR UPDATE",
        )
        .bind(pid)
        .bind(sid)
        .bind(&req.branch)
        .bind(&req.suite)
        .fetch_optional(&mut *tx)
        .await?;
        let new_id: i64 = sqlx::query("SELECT nextval(pg_get_serial_sequence('exceptions', 'id'))")
            .fetch_one(&mut *tx)
            .await?
            .get(0);
        // Optimistic concurrency: a change to a live exception names the revision its
        // author reviewed (If-Match); a new scope names none.
        let head = live.as_ref().map(|r| r.get::<i32, _>(1));
        if head != if_match {
            return Err(AppError::new(
                ErrorCode::PreconditionFailed,
                match head {
                    Some(h) => format!(
                        "the exception of this scope is at revision {h}: review it and send If-Match: \"{h}\""
                    ),
                    None => "no live exception in this scope: send no If-Match".to_string(),
                },
            ));
        }
        // Revisions grow across the scope's whole history (revoked and superseded rows
        // included), so a revision is never reused and a stale If-Match never matches a
        // recreated exception.
        let last: i32 = sqlx::query_scalar(
            "SELECT coalesce(max(revision), 0) FROM exceptions
              WHERE project_id = $1 AND signature_id = $2 AND branch = $3 AND suite = $4",
        )
        .bind(pid)
        .bind(sid)
        .bind(&req.branch)
        .bind(&req.suite)
        .fetch_one(&mut *tx)
        .await?;
        let revision = last + 1;
        if let Some(old) = &live {
            sqlx::query(
                "UPDATE exceptions SET superseded_by = $3 WHERE project_id = $1 AND id = $2",
            )
            .bind(pid)
            .bind(old.get::<i64, _>(0))
            .bind(new_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO exceptions (project_id, id, signature_id, branch, suite, revision, reason,
                                     author, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(pid)
        .bind(new_id)
        .bind(sid)
        .bind(&req.branch)
        .bind(&req.suite)
        .bind(revision)
        .bind(&req.reason)
        .bind(uid)
        .bind(now)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
        let object = format!("exception:{new_id}");
        history(
            &mut tx,
            pid,
            uid,
            &object,
            "exception.create",
            with_attribution(
                json!({"signature": req.signature, "branch": req.branch, "suite": req.suite,
                       "expires_at": req.expires_at,
                       "supersedes": live.map(|r| r.get::<i64, _>(0))}),
                attribution,
            ),
        )
        .await?;
        bump_project(&mut tx, pid, "exception", &object).await?;
        tx.commit().await?;
        Ok(Head {
            id: new_id,
            revision,
        })
    }

    /// Revokes an exception.
    ///
    /// # Errors
    /// Authorization, unknown or inactive exception, database errors.
    pub async fn revoke_exception(
        &self,
        actor: &Actor,
        project: &str,
        id: i64,
    ) -> Result<(), AppError> {
        let pid = self
            .project_for(actor, project, Action::ExceptionWrite)
            .await?;
        let uid = user_id(actor)?;
        let mut tx = super::begin_write(&self.db).await?;
        let n = sqlx::query(
            "UPDATE exceptions SET revoked_at = now()
              WHERE project_id = $1 AND id = $2 AND revoked_at IS NULL AND superseded_by IS NULL",
        )
        .bind(pid)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(AppError::new(
                ErrorCode::NotFound,
                format!("no live exception {id}"),
            ));
        }
        let object = format!("exception:{id}");
        history(&mut tx, pid, uid, &object, "exception.revoke", json!({})).await?;
        bump_project(&mut tx, pid, "exception", &object).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Changes after `since` (the readiness watermark feed).
    ///
    /// # Errors
    /// Authorization, database errors.
    pub async fn changes_since(
        &self,
        actor: &Actor,
        project: &str,
        since: i64,
    ) -> Result<Value, AppError> {
        let pid = self
            .project_for(actor, project, Action::ChangesRead)
            .await?;
        let rows = sqlx::query(
            "SELECT seq, at, kind, object FROM changes WHERE project_id = $1 AND seq > $2
              ORDER BY seq LIMIT 500",
        )
        .bind(pid)
        .bind(since)
        .fetch_all(&self.db)
        .await?;
        let head: i64 = sqlx::query(
            "SELECT coalesce(max(change_seq), 0) FROM project_heads WHERE project_id = $1",
        )
        .bind(pid)
        .fetch_one(&self.db)
        .await?
        .get(0);
        Ok(json!({
            "change_seq": head,
            "changes": rows.iter().map(|r| json!({
                "seq": r.get::<i64, _>(0),
                "at": r.get::<OffsetDateTime, _>(1).format(&Rfc3339).ok(),
                "kind": r.get::<String, _>(2),
                "object": r.get::<String, _>(3),
            })).collect::<Vec<_>>(),
        }))
    }
}
