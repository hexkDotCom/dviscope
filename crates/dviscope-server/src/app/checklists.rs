//! Checklists and feature mode.
//!
//! Import creates an immutable checklist version; items are matched across versions by
//! `item_id`, and a changed `requires` or evidence digest is a new item revision (which
//! invalidates its attestations). Attestations are bound to (version, item revision,
//! evidence digest). Feature evaluation runs in one snapshot: the candidate index selects
//! one candidate regression per test and configuration (core `feature::select`), the
//! candidates' slots are settled at read time, and core `feature::judge` decides each item.

use std::collections::BTreeMap;

use dviscope_core::feature::{self, CandidateFacts, IndexEntry, ItemState, SelectError, Selection};
use dviscope_core::readiness::{self, SlotInput};
use dviscope_core::settlement::{FailReason, SlotState};
use dviscope_model::canonical::digest_of;
use dviscope_model::errors::ErrorCode;
use dviscope_model::wire::checklist::{CHECKLIST, Checklist, ChecklistItem};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::App;
use super::decisions::bump_project;
use crate::auth::{Action, Actor};
use crate::error::AppError;

/// An item of the evaluated version: item, revision, evidence digest, valid attestation,
/// and its selection (`None`: not applicable to the branch).
type Selected = (
    ChecklistItem,
    i32,
    Option<String>,
    Option<i64>,
    Option<Result<Vec<Selection>, SelectError>>,
);

/// Most items per checklist version.
pub const MAX_ITEMS: usize = 500;

/// `POST …/checklists/{checklist}/attestations`: exactly what the reviewer saw.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestRequest {
    /// Checklist version.
    pub version: String,
    /// Item.
    pub item_id: String,
    /// Item revision.
    pub item_revision: i32,
    /// Evidence digest shown.
    pub evidence_digest: String,
}

fn invalid(msg: impl Into<String>, field: &str) -> AppError {
    AppError::field(ErrorCode::Invalid, msg, field)
}

/// Unix microseconds (feature evaluation keeps full precision).
fn micros(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1000).unwrap_or(i64::MAX)
}

fn from_micros(t: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(t) * 1000).ok()
}

fn rfc(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

fn user_id(actor: &Actor) -> Result<i64, AppError> {
    match actor {
        Actor::User { user_id, .. } => Ok(*user_id),
        Actor::Collector { .. } => Err(AppError::new(ErrorCode::Forbidden, "people only")),
    }
}

fn validate(c: &Checklist) -> Result<(), AppError> {
    if let Some(s) = &c.schema
        && s != CHECKLIST
    {
        return Err(invalid(format!("schema is {CHECKLIST}"), "schema"));
    }
    let ok_id = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch))
    };
    if !ok_id(&c.checklist_id) {
        return Err(invalid(
            "checklist_id is 1-128 of [A-Za-z0-9._-]",
            "checklist_id",
        ));
    }
    if c.version.is_empty() || c.version.len() > 64 {
        return Err(invalid("version is 1-64 characters", "version"));
    }
    if c.items.is_empty() || c.items.len() > MAX_ITEMS {
        return Err(invalid(format!("1 to {MAX_ITEMS} items"), "items"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, it) in c.items.iter().enumerate() {
        let f = |name: &str| format!("items[{i}].{name}");
        if !ok_id(&it.item_id) || !seen.insert(it.item_id.as_str()) {
            return Err(invalid(
                "item_id is unique, 1-128 of [A-Za-z0-9._-]",
                &f("item_id"),
            ));
        }
        if it.requires.tests.is_empty() || it.requires.tests.len() > 100 {
            return Err(invalid("1 to 100 test globs", &f("requires.tests")));
        }
        if it.freshness_days == 0 || it.freshness_days > 3650 {
            return Err(invalid("freshness_days is 1 to 3650", &f("freshness_days")));
        }
        if it.requires.min_passing_seeds == Some(0) {
            return Err(invalid(
                "min_passing_seeds is at least 1",
                &f("requires.min_passing_seeds"),
            ));
        }
    }
    Ok(())
}

/// The evidence digest of an item (none without external evidence).
fn evidence_digest(it: &ChecklistItem) -> Result<Option<String>, AppError> {
    if it.evidence.is_empty() {
        return Ok(None);
    }
    let mut ev: Vec<(&str, &str)> = it
        .evidence
        .iter()
        .map(|e| (e.name.as_str(), e.digest.as_str()))
        .collect();
    ev.sort_unstable();
    digest_of(&json!({"evidence": ev}))
        .map(|d| Some(d.as_str().to_string()))
        .map_err(|_| AppError::internal("evidence digest"))
}

/// What makes an item revision: its requirement and evidence.
fn content_digest(it: &ChecklistItem) -> Result<String, AppError> {
    digest_of(&json!({"requires": it.requires, "evidence": evidence_digest(it)?}))
        .map(|d| d.as_str().to_string())
        .map_err(|_| AppError::internal("item digest"))
}

impl App {
    /// Imports a checklist version (idempotent for the same content; another content
    /// under an existing version is a conflict).
    ///
    /// # Errors
    /// Authorization (admin), invalid checklist, version conflict, database errors.
    pub async fn import_checklist(
        &self,
        actor: &Actor,
        project: &str,
        c: &Checklist,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::ChecklistWrite)
            .await?;
        let author = user_id(actor)?;
        validate(c)?;
        let digest = digest_of(&serde_json::to_value(c)?)
            .map_err(|_| AppError::internal("checklist digest"))?;
        let mut tx = super::begin_write(&self.db).await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 11))")
            .bind(format!("{pid}|checklist|{}", c.checklist_id))
            .execute(&mut *tx)
            .await?;
        let cl: i64 = sqlx::query_scalar(
            "INSERT INTO checklists (project_id, checklist_id) VALUES ($1, $2)
             ON CONFLICT (project_id, checklist_id) DO UPDATE SET checklist_id = EXCLUDED.checklist_id
             RETURNING id",
        )
        .bind(pid)
        .bind(&c.checklist_id)
        .fetch_one(&mut *tx)
        .await?;
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT digest FROM checklist_versions WHERE project_id = $1 AND checklist = $2 AND version = $3",
        )
        .bind(pid)
        .bind(cl)
        .bind(&c.version)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(d) = existing {
            tx.commit().await?;
            if d == digest.as_str() {
                return Ok(
                    json!({"checklist_id": c.checklist_id, "version": c.version, "result": "duplicate"}),
                );
            }
            return Err(AppError::field(
                ErrorCode::RevisionConflict,
                "this version was imported with other content: give it a new version",
                "version",
            ));
        }
        sqlx::query(
            "INSERT INTO checklist_versions (project_id, checklist, version, digest, body, imported_by)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(pid)
        .bind(cl)
        .bind(&c.version)
        .bind(digest.as_str())
        .bind(serde_json::to_value(c)?)
        .bind(author)
        .execute(&mut *tx)
        .await?;
        let mut revisions = vec![];
        for (pos, it) in c.items.iter().enumerate() {
            let cd = content_digest(it)?;
            let latest = sqlx::query(
                "SELECT revision, content_digest FROM checklist_items
                  WHERE project_id = $1 AND checklist = $2 AND item_id = $3
                  ORDER BY revision DESC LIMIT 1",
            )
            .bind(pid)
            .bind(cl)
            .bind(&it.item_id)
            .fetch_optional(&mut *tx)
            .await?;
            let revision: i32 = match latest {
                Some(r) if r.get::<String, _>(1) == cd => r.get(0),
                Some(r) => r.get::<i32, _>(0) + 1,
                None => 1,
            };
            sqlx::query(
                "INSERT INTO checklist_items (project_id, checklist, item_id, revision, content_digest, evidence_digest)
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
            )
            .bind(pid)
            .bind(cl)
            .bind(&it.item_id)
            .bind(revision)
            .bind(&cd)
            .bind(evidence_digest(it)?)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO checklist_version_items (project_id, checklist, version, item_id, revision, position, item)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(pid)
            .bind(cl)
            .bind(&c.version)
            .bind(&it.item_id)
            .bind(revision)
            .bind(i32::try_from(pos).unwrap_or(i32::MAX))
            .bind(serde_json::to_value(it)?)
            .execute(&mut *tx)
            .await?;
            revisions.push(json!({"item_id": it.item_id, "revision": revision}));
        }
        bump_project(
            &mut tx,
            pid,
            "checklist",
            &format!("{}@{}", c.checklist_id, c.version),
        )
        .await?;
        tx.commit().await?;
        Ok(
            json!({"checklist_id": c.checklist_id, "version": c.version, "result": "imported", "items": revisions}),
        )
    }

    /// Attests an item exactly as shown (version, item revision, evidence digest).
    ///
    /// # Errors
    /// Authorization (admin), unknown checklist/version/item, a stale view (412).
    pub async fn attest(
        &self,
        actor: &Actor,
        project: &str,
        checklist_id: &str,
        r: &AttestRequest,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::ChecklistWrite)
            .await?;
        let author = user_id(actor)?;
        let mut tx = super::begin_write(&self.db).await?;
        let row = sqlx::query(
            "SELECT c.id, v.revision, i.evidence_digest
               FROM checklists c
               JOIN checklist_version_items v ON v.project_id = c.project_id AND v.checklist = c.id
               JOIN checklist_items i ON i.project_id = v.project_id AND i.checklist = v.checklist
                                     AND i.item_id = v.item_id AND i.revision = v.revision
              WHERE c.project_id = $1 AND c.checklist_id = $2 AND v.version = $3 AND v.item_id = $4",
        )
        .bind(pid)
        .bind(checklist_id)
        .bind(&r.version)
        .bind(&r.item_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "no such checklist item"))?;
        let evidence: Option<String> = row.get(2);
        let Some(evidence) = evidence else {
            return Err(invalid(
                "this item declares no external evidence",
                "item_id",
            ));
        };
        if row.get::<i32, _>(1) != r.item_revision || evidence != r.evidence_digest {
            return Err(AppError::new(
                ErrorCode::PreconditionFailed,
                "the item changed since it was shown: review the current revision",
            ));
        }
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO attestations (project_id, checklist, version, item_id, item_revision, evidence_digest, author)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(pid)
        .bind(row.get::<i64, _>(0))
        .bind(&r.version)
        .bind(&r.item_id)
        .bind(r.item_revision)
        .bind(&evidence)
        .bind(author)
        .fetch_one(&mut *tx)
        .await?;
        bump_project(
            &mut tx,
            pid,
            "attestation",
            &format!("{checklist_id}/{}", r.item_id),
        )
        .await?;
        tx.commit().await?;
        Ok(json!({"id": id}))
    }

    /// Revokes an attestation.
    ///
    /// # Errors
    /// Authorization (admin), unknown attestation.
    pub async fn revoke_attestation(
        &self,
        actor: &Actor,
        project: &str,
        checklist_id: &str,
        id: i64,
    ) -> Result<(), AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::ChecklistWrite)
            .await?;
        let mut tx = super::begin_write(&self.db).await?;
        let done = sqlx::query(
            "UPDATE attestations a SET revoked_at = now()
               FROM checklists c
              WHERE a.project_id = $1 AND a.id = $2 AND c.project_id = a.project_id
                AND c.id = a.checklist AND c.checklist_id = $3 AND a.revoked_at IS NULL",
        )
        .bind(pid)
        .bind(id)
        .bind(checklist_id)
        .execute(&mut *tx)
        .await?;
        if done.rows_affected() == 0 {
            return Err(AppError::new(ErrorCode::NotFound, "no active attestation"));
        }
        bump_project(&mut tx, pid, "attestation", &format!("{checklist_id}/{id}")).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The project's checklists with their latest version.
    ///
    /// # Errors
    /// Authorization, database errors.
    pub async fn list_checklists(&self, actor: &Actor, project: &str) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::ChecklistRead)
            .await?;
        let rows = sqlx::query(
            "SELECT c.checklist_id, v.version, v.body->>'title', v.body->>'feature', v.imported_at,
                    (SELECT count(*) FROM checklist_versions w WHERE w.project_id = c.project_id AND w.checklist = c.id)
               FROM checklists c
               JOIN LATERAL (SELECT * FROM checklist_versions w
                              WHERE w.project_id = c.project_id AND w.checklist = c.id
                              ORDER BY w.imported_at DESC, w.version DESC LIMIT 1) v ON true
              WHERE c.project_id = $1 ORDER BY c.checklist_id",
        )
        .bind(pid)
        .fetch_all(&self.db)
        .await?;
        Ok(json!({"checklists": rows.iter().map(|r| json!({
            "checklist_id": r.get::<String, _>(0),
            "latest_version": r.get::<String, _>(1),
            "title": r.get::<Option<String>, _>(2),
            "feature": r.get::<Option<String>, _>(3),
            "imported_at": rfc(r.get(4)),
            "versions": r.get::<i64, _>(5),
        })).collect::<Vec<_>>()}))
    }

    /// Feature mode: evaluates a checklist version (default: the latest) for a branch at
    /// `now`, in one snapshot.
    ///
    /// # Errors
    /// Authorization, unknown checklist or version, database errors.
    #[allow(clippy::too_many_lines)] // one snapshot: items, index, candidates, judgement
    pub async fn evaluate_feature(
        &self,
        actor: &Actor,
        project: &str,
        checklist_id: &str,
        version: Option<&str>,
        branch: &str,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        let (pid, policy) = self
            .read_project(actor, project, Action::ChecklistRead)
            .await?;
        if branch
            .split_once('/')
            .is_none_or(|(r, n)| r.is_empty() || n.is_empty())
        {
            return Err(invalid("branch is repo/name", "branch"));
        }
        let mut tx = self.snapshot().await?;
        let change_seq: i64 = sqlx::query_scalar(
            "SELECT coalesce(max(change_seq), 0) FROM project_heads WHERE project_id = $1",
        )
        .bind(pid)
        .fetch_one(&mut *tx)
        .await?;
        let head = sqlx::query(
            "SELECT c.id, v.version, v.body FROM checklists c
               JOIN checklist_versions v ON v.project_id = c.project_id AND v.checklist = c.id
              WHERE c.project_id = $1 AND c.checklist_id = $2 AND ($3::text IS NULL OR v.version = $3)
              ORDER BY v.imported_at DESC, v.version DESC LIMIT 1",
        )
        .bind(pid)
        .bind(checklist_id)
        .bind(version)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::new(ErrorCode::NotFound, "no such checklist or version"))?;
        let cl: i64 = head.get(0);
        let ver: String = head.get(1);
        let body: Checklist = serde_json::from_value(head.get(2))
            .map_err(|_| AppError::internal("stored checklist"))?;
        let items = sqlx::query(
            "SELECT v.item_id, v.revision, v.item, i.evidence_digest,
                    (SELECT a.id FROM attestations a
                      WHERE a.project_id = v.project_id AND a.checklist = v.checklist
                        AND a.item_id = v.item_id AND a.item_revision = v.revision
                        AND a.evidence_digest = i.evidence_digest AND a.revoked_at IS NULL
                      ORDER BY a.id DESC LIMIT 1)
               FROM checklist_version_items v
               JOIN checklist_items i ON i.project_id = v.project_id AND i.checklist = v.checklist
                                     AND i.item_id = v.item_id AND i.revision = v.revision
              WHERE v.project_id = $1 AND v.checklist = $2 AND v.version = $3
              ORDER BY v.position",
        )
        .bind(pid)
        .bind(cl)
        .bind(&ver)
        .fetch_all(&mut *tx)
        .await?;
        let (entries, producer_of) = feature_index(&mut tx, pid, branch).await?;
        // Select per item first (only the index), then load each candidate once.
        let mut selections: Vec<Selected> = vec![];
        for r in &items {
            let it: ChecklistItem =
                serde_json::from_value(r.get(2)).map_err(|_| AppError::internal("stored item"))?;
            let sel = feature::applies(&it, branch).then(|| feature::select(&it, &entries));
            selections.push((it, r.get(1), r.get(3), r.get(4), sel));
        }
        let mut facts: BTreeMap<i64, Option<Loaded2>> = BTreeMap::new();
        for (_, _, _, _, sel) in &selections {
            for s in sel.iter().flat_map(|x| x.iter().flatten()) {
                let rid = s.candidate.regression_id;
                if facts.contains_key(&rid) {
                    continue;
                }
                let loaded = if s.candidate.live {
                    load_candidate(&mut tx, pid, policy, rid, producer_of.get(&rid).copied())
                        .await?
                } else {
                    None
                };
                facts.insert(rid, loaded);
            }
        }
        tx.commit().await?;
        let now_s = micros(now);
        let mut out_items = vec![];
        let mut digest_items = vec![];
        let mut valid_until: Option<i64> = None;
        let mut ready = true;
        for (it, revision, evidence, attestation, sel) in &selections {
            let owner = it.owner.clone().unwrap_or_else(|| body.owner.clone());
            let Some(sel) = sel else {
                out_items.push(json!({
                    "item_id": it.item_id, "title": it.title, "revision": revision, "owner": owner,
                    "applicable": false, "state": "not_applicable",
                }));
                continue;
            };
            let with: Result<Vec<(Selection, Option<CandidateFacts>)>, &SelectError> = match sel {
                Ok(s) => Ok(s
                    .iter()
                    .map(|x| {
                        let f = facts
                            .get(&x.candidate.regression_id)
                            .cloned()
                            .flatten()
                            .map(|l| l.facts_for(&x.candidate.test, &x.candidate.config_digest));
                        (x.clone(), f)
                    })
                    .collect()),
                Err(e) => Err(e),
            };
            let unmatched = feature::unmatched(it, &entries);
            let res = feature::judge(
                it,
                with.as_ref().map(Vec::as_slice).map_err(|e| *e),
                &unmatched,
                attestation.is_some(),
                now_s,
            );
            ready &= res.state == ItemState::Satisfied;
            if let Some(v) = res.valid_until {
                valid_until = Some(valid_until.map_or(v, |w| w.min(v)));
            }
            // Per-simulator seeds: "questa 3/5 passing seeds".
            let mut sims: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
            for p in &res.pairs {
                let e = sims.entry(p.simulator.as_str()).or_default();
                e.0 += p.passing_seeds.min(p.required_seeds);
                e.1 += p.required_seeds;
            }
            let next_action = match res.state {
                ItemState::Satisfied => "none",
                ItemState::Failed => "fix the failing tests and run them again",
                ItemState::Insufficient => "re-run with eligible evidence",
                ItemState::Missing => "run the required tests and seeds on this branch",
                ItemState::Outdated => "run the required tests again (evidence too old)",
                ItemState::Unreviewed => "review the external evidence and attest it",
            };
            digest_items.push(json!([
                it.item_id,
                revision,
                attestation,
                res.pairs
                    .iter()
                    .map(|p| json!([p.test, p.config_digest, p.regression, p.state]))
                    .collect::<Vec<_>>()
            ]));
            out_items.push(json!({
                "item_id": it.item_id,
                "title": it.title,
                "revision": revision,
                "owner": owner,
                "applicable": true,
                "state": res.state,
                "reasons": res.reasons,
                "requires": it.requires,
                "freshness_days": it.freshness_days,
                "pairs": res.pairs,
                "seeds_by_simulator": sims.iter().map(|(s, (a, r))| json!({"simulator": s, "achieved": a, "required": r})).collect::<Vec<_>>(),
                "evidence": it.evidence,
                "evidence_digest": evidence,
                "attestation": attestation,
                "valid_until": res.valid_until.and_then(from_micros).map(rfc),
                "next_action": next_action,
            }));
        }
        let valid_until = valid_until.and_then(from_micros).map(rfc);
        let digest = digest_of(&json!({
            "schema": "dig/2",
            "mode": "feature",
            "evaluator_version": env!("CARGO_PKG_VERSION"),
            "evaluated_at": rfc(now),
            "valid_until": valid_until,
            "checklist": [checklist_id, ver],
            "branch": branch,
            "change_seq": change_seq,
            "items": digest_items,
        }))
        .map_err(|_| AppError::internal("decision digest"))?;
        Ok(json!({
            "schema": super::readiness::VERDICT_SCHEMA,
            "mode": "feature",
            "checklist": {"checklist_id": checklist_id, "version": ver, "title": body.title,
                          "feature": body.feature, "owner": body.owner},
            "branch": branch,
            "evaluated_at": rfc(now),
            "valid_until": valid_until,
            "change_seq": change_seq,
            "digest": digest.as_str(),
            "ready": ready,
            "result": if ready { "ready for sign-off review" } else { "not ready" },
            "items": out_items,
        }))
    }
}

/// A candidate regression's settled slots, with seeds, for feature judgement.
#[derive(Debug, Clone)]
struct Loaded2 {
    complete: bool,
    /// (test, config digest, seed, state)
    slots: Vec<(String, String, String, dviscope_core::settlement::SlotState)>,
}

impl Loaded2 {
    fn facts_for(&self, test: &str, config: &str) -> CandidateFacts {
        CandidateFacts {
            complete: self.complete,
            slots: self
                .slots
                .iter()
                .filter(|(t, c, _, _)| t == test && c == config)
                .map(|(_, _, seed, st)| (seed.clone(), *st))
                .collect(),
        }
    }
}

async fn load_candidate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pid: i64,
    policy: dviscope_core::settlement::Policy,
    regression_id: i64,
    producer_id: Option<i64>,
) -> Result<Option<Loaded2>, AppError> {
    let head = sqlx::query(
        "SELECT r.ref, p.name FROM regressions r JOIN producers p ON p.id = r.producer_id
          WHERE r.project_id = $1 AND r.id = $2 AND ($3::bigint IS NULL OR r.producer_id = $3)",
    )
    .bind(pid)
    .bind(regression_id)
    .bind(producer_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(head) = head else {
        return Ok(None);
    };
    let l = App::load(
        tx,
        pid,
        policy,
        &head.get::<String, _>(0),
        Some(&head.get::<String, _>(1)),
    )
    .await?;
    let seeds: BTreeMap<String, String> = sqlx::query(
        "SELECT slot_ref, coalesce(decl #>> '{exec_inputs,seed}', '') FROM slots
          WHERE project_id = $1 AND regression_id = $2 AND removed_revision IS NULL",
    )
    .bind(pid)
    .bind(regression_id)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(|r| (r.get(0), r.get(1)))
    .collect();
    Ok(Some(Loaded2 {
        complete: l.facts.state == "finished" && l.facts.sealed,
        slots: l
            .slots
            .iter()
            .zip(&l.attempts)
            .map(|((s, v), attempts)| {
                // The authoritative attempts are checked as merge readiness checks them: a result on unproven, contradictory or incomplete evidence
                // is insufficient evidence, never a passing seed.
                let input = SlotInput {
                    slot: s.slot_ref.clone(),
                    required: true,
                    state: s.state,
                    attempts: attempts.clone(),
                };
                let state = match s.state {
                    SlotState::Passed | SlotState::Failed(_)
                        if readiness::evidence_problem(&input, policy).is_some() =>
                    {
                        SlotState::Failed(FailReason::Insufficient)
                    }
                    st => st,
                };
                (
                    s.test.clone(),
                    v.config.as_str().to_string(),
                    seeds.get(&s.slot_ref).cloned().unwrap_or_default(),
                    state,
                )
            })
            .collect(),
    }))
}

/// The feature-readiness index of a branch exactly as evaluation sees it (validly removed
/// test/configurations left out, expired regressions kept), with each entry's producer.
///
/// # Errors
/// Database errors.
pub(crate) async fn feature_index(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pid: i64,
    branch: &str,
) -> Result<(Vec<IndexEntry>, BTreeMap<i64, i64>), AppError> {
    // Index rows, except a regression's test/configuration whose slots were all validly
    // removed (a removal by a quarantined credential does not count: R1 finding 6). An
    // expired regression keeps its rows (no slots left to judge).
    let index_rows = sqlx::query(
                "SELECT c.test, c.config_digest, c.simulator, c.regression_id, c.regression_ref,
                        c.started_at,
                        -- A row added after an upgrade (a late slot) takes the regression's
                        -- receipt time or bound.
                        coalesce(c.received_at, rr.received_at), c.state, c.producer_id,
                        CASE WHEN coalesce(c.received_at, rr.received_at) IS NULL
                             THEN coalesce(c.receipt_bound, rr.receipt_bound) END
                   FROM candidate_index c
                   LEFT JOIN regressions rr ON rr.project_id = c.project_id AND rr.id = c.regression_id
                  WHERE c.project_id = $1 AND c.branch = $2
                    -- A validly removed test/configuration is not a candidate; the removal
                    -- is kept in the permanent index (it outlives the slots).
                    -- Excluded only when every slot is removed and no removal is untrusted.
                    AND NOT (c.removed AND NOT EXISTS (
                        SELECT 1 FROM candidate_removals x
                         WHERE x.project_id = c.project_id AND x.regression_id = c.regression_id
                           AND x.test = c.test AND x.config_digest = c.config_digest
                           AND (EXISTS (SELECT 1 FROM api_tokens q WHERE q.id = x.removed_by
                                          AND q.quarantined_since IS NOT NULL
                                          AND x.removed_at >= q.quarantined_since)
                                OR (x.removed_by IS NULL AND EXISTS (
                                      SELECT 1 FROM api_tokens q
                                       WHERE q.producer_id = c.producer_id
                                         AND q.quarantined_since IS NOT NULL)))))",
        )
        .bind(pid)
        .bind(branch)
        .fetch_all(&mut **tx)
        .await?;
    let entries: Vec<IndexEntry> = index_rows
        .iter()
        .map(|r| IndexEntry {
            test: r.get(0),
            config_digest: r.get(1),
            simulator: r.get(2),
            regression_id: r.get(3),
            regression_ref: r.get(4),
            started_at: micros(r.get::<OffsetDateTime, _>(5)),
            received_at: r.get::<Option<OffsetDateTime>, _>(6).map(micros),
            live: r.get::<String, _>(7) == "live",
            receipt_bound: r.get::<Option<OffsetDateTime>, _>(9).map(micros),
        })
        .collect();
    let producer_of: BTreeMap<i64, i64> = index_rows
        .iter()
        .map(|r| (r.get::<i64, _>(3), r.get::<i64, _>(8)))
        .collect();
    Ok((entries, producer_of))
}

/// The feature-readiness selections whose candidate is regression `rid`, over every
/// version of every checklist of the project (evaluation may pin any version), on
/// `branch`: (checklist, version, item, test, configuration). The same index and core
/// selection as evaluation.
///
/// # Errors
/// Database errors, a stored item that does not parse.
pub(crate) async fn feature_selections_of(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pid: i64,
    branch: &str,
    rid: i64,
) -> Result<Vec<(String, String, String, String, String)>, AppError> {
    let (entries, _) = feature_index(tx, pid, branch).await?;
    if !entries.iter().any(|e| e.regression_id == rid) {
        return Ok(vec![]);
    }
    let items = sqlx::query(
        "SELECT c.checklist_id, v.version, v.item_id, v.item FROM checklists c
           JOIN checklist_version_items v ON v.project_id = c.project_id AND v.checklist = c.id
          WHERE c.project_id = $1
          ORDER BY c.checklist_id, v.version, v.position",
    )
    .bind(pid)
    .fetch_all(&mut **tx)
    .await?;
    let mut out = vec![];
    for r in items {
        let it: ChecklistItem =
            serde_json::from_value(r.get(3)).map_err(|_| AppError::internal("stored item"))?;
        if !feature::applies(&it, branch) {
            continue;
        }
        let Ok(sel) = feature::select(&it, &entries) else {
            continue;
        };
        for x in sel.iter().filter(|x| x.candidate.regression_id == rid) {
            out.push((
                r.get::<String, _>(0),
                r.get::<String, _>(1),
                r.get::<String, _>(2),
                x.candidate.test.clone(),
                x.candidate.config_digest.clone(),
            ));
        }
    }
    Ok(out)
}
