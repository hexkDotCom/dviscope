//! Retention: a regression's age is its end
//! (`finished_at`, else `started_at`) against a caller-given clock. Cohorts: *all-pass*
//! (no failing attempt) and *with failures*. Payloads expire first (the retained projection
//! keeps settlement and comparison answers); facts expire later (the regression is removed
//! and leaves a tombstone, so a late record is `E_EXPIRED`); receipts expire after the
//! deduplication horizon (a tombstone answers an older replay with `E_REPLAY_EXPIRED`).
//! Build attempts are kept while any remaining attempt references them. Every step is one
//! transaction per regression; a dry run reports what it would do. The clock decides what
//! expires; tombstones record the database time of the deletion (their order against
//! migrations must be provable).

use dviscope_core::settlement::{Policy as SettlePolicy, SlotState};
use serde::Serialize;

use crate::app::{App, TRUST_GATE};

async fn gate_exclusive(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(TRUST_GATE)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
use sqlx::{PgPool, Row as _};
use time::{Duration, OffsetDateTime};

/// Retention periods.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Payloads of all-pass regressions.
    pub pass_payload: Duration,
    /// Facts of all-pass regressions.
    pub pass_facts: Duration,
    /// Payloads of regressions with failures.
    pub fail_payload: Duration,
    /// Facts of regressions with failures.
    pub fail_facts: Duration,
    /// Receipts (the deduplication horizon).
    pub receipts: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            pass_payload: Duration::days(30),
            pass_facts: Duration::days(90),
            fail_payload: Duration::days(90),
            fail_facts: Duration::days(730),
            receipts: Duration::days(120),
        }
    }
}

/// The most regressions a report itemizes (the counts stay complete).
pub const MAX_ITEMS: usize = 500;

/// One regression a run expired (or, dry, would expire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Item {
    /// The project's name.
    pub project: String,
    /// The regression's reference.
    pub regression: String,
    /// `all_pass` or `with_failures` (which periods apply).
    pub cohort: &'static str,
    /// The regression's end (`finished_at`, else `started_at`), RFC 3339.
    pub ended_at: String,
    /// `remove` (facts expire: the regression is removed, tombstoned) or
    /// `expire_payloads` (report payloads removed; the projection stays).
    pub action: &'static str,
    /// Payload rows removed (for `expire_payloads`).
    pub payloads: u64,
}

/// A feature-readiness selection whose candidate a removal expires: a checklist item (of
/// any version) selects this regression's test and configuration on the branch, by the same
/// index and selection as evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateImpact {
    /// The project's name.
    pub project: String,
    /// Checklist.
    pub checklist: String,
    /// Checklist version (an evaluation may pin any version).
    pub version: String,
    /// Checklist item.
    pub item: String,
    /// Repository-qualified branch.
    pub branch: String,
    /// Test.
    pub test: String,
    /// Configuration digest.
    pub config_digest: String,
    /// The regression removed.
    pub regression: String,
    /// Its producer.
    pub producer: String,
}

/// A monitored (not retired) publication of a regression the run removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicationImpact {
    /// The project's name.
    pub project: String,
    /// The receipt's digest.
    pub digest: String,
    /// The regression removed.
    pub regression: String,
    /// `repository@commit` of the status, when it names one.
    pub target: Option<String>,
}

/// What a run did (or, dry, would do).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Payload rows removed.
    pub payloads: u64,
    /// Regressions removed (tombstoned).
    pub regressions: u64,
    /// Build attempts removed (no longer referenced and past the facts period).
    pub builds: u64,
    /// Receipts removed (tombstoned).
    pub receipts: u64,
    /// Whether nothing was changed.
    pub dry_run: bool,
    /// The regressions concerned, oldest decision first (at most [`MAX_ITEMS`]).
    pub items: Vec<Item>,
    /// Whether more regressions were concerned than itemized.
    pub items_truncated: bool,
    /// Feature-readiness candidates whose newest evidence is removed (at most
    /// [`MAX_ITEMS`]).
    pub candidates: Vec<CandidateImpact>,
    /// Monitored publications of removed regressions (at most [`MAX_ITEMS`]).
    pub publications: Vec<PublicationImpact>,
    /// Whether more candidates or publications were concerned than listed.
    pub impact_truncated: bool,
}

impl Report {
    fn item(&mut self, item: Item) {
        if self.items.len() < MAX_ITEMS {
            self.items.push(item);
        } else {
            self.items_truncated = true;
        }
    }
}

/// The readiness and publication impact of removing regression `rid`, recorded in `rep`.
/// Feature selection keeps an expired regression's index rows, so earlier removals of the
/// same run do not change what it selects: preview and run agree.
#[allow(clippy::too_many_arguments)]
async fn impact(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    rep: &mut Report,
    pid: i64,
    rid: i64,
    producer: i64,
    producer_name: &str,
    rref: &str,
    project_name: &str,
) -> Result<(), sqlx::Error> {
    let branches: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT branch FROM candidate_index
          WHERE project_id = $1 AND regression_id = $2 AND state = 'live' ORDER BY 1",
    )
    .bind(pid)
    .bind(rid)
    .fetch_all(&mut **tx)
    .await?;
    for branch in branches {
        let sel = crate::app::checklists::feature_selections_of(tx, pid, &branch, rid)
            .await
            .map_err(|e| sqlx::Error::Protocol(e.message))?;
        for (checklist, version, item, test, config_digest) in sel {
            if rep.candidates.len() < MAX_ITEMS {
                rep.candidates.push(CandidateImpact {
                    project: project_name.to_string(),
                    checklist,
                    version,
                    item,
                    branch: branch.clone(),
                    test,
                    config_digest,
                    regression: rref.to_string(),
                    producer: producer_name.to_string(),
                });
            } else {
                rep.impact_truncated = true;
            }
        }
    }
    let pubs = sqlx::query(
        "SELECT digest, target_repository, target_commit FROM publication_receipts
          WHERE project_id = $1 AND producer_id = $2 AND regression_ref = $3
            AND retired_at IS NULL ORDER BY digest",
    )
    .bind(pid)
    .bind(producer)
    .bind(rref)
    .fetch_all(&mut **tx)
    .await?;
    for r in pubs {
        if rep.publications.len() < MAX_ITEMS {
            let target = match (r.get::<Option<String>, _>(1), r.get::<Option<String>, _>(2)) {
                (Some(repo), Some(commit)) => Some(format!("{repo}@{commit}")),
                _ => None,
            };
            rep.publications.push(PublicationImpact {
                project: project_name.to_string(),
                digest: r.get(0),
                regression: rref.to_string(),
                target,
            });
        } else {
            rep.impact_truncated = true;
        }
    }
    Ok(())
}

/// Runs retention as of `now`.
///
/// # Errors
/// Database errors (each regression's step is its own transaction: work done before an
/// error stays done and is consistent).
pub async fn run(
    db: &PgPool,
    now: OffsetDateTime,
    policy: Policy,
    dry_run: bool,
) -> Result<Report, sqlx::Error> {
    run_in(db, now, policy, dry_run, None).await
}

/// What retention would do as of `now`, for one project or all: nothing is changed and
/// no lock blocks a writer (a preview is a read; the real run decides again under its
/// locks).
///
/// # Errors
/// Database errors.
pub async fn preview(
    db: &PgPool,
    now: OffsetDateTime,
    policy: Policy,
    project: Option<i64>,
) -> Result<Report, sqlx::Error> {
    run_in(db, now, policy, true, project).await
}

const HEAD: &str =
    "SELECT r.producer_id, r.ref, coalesce(r.finished_at, r.started_at), p.name, j.policy, j.name
   FROM regressions r
   JOIN producers p ON p.project_id = r.project_id AND p.id = r.producer_id
   JOIN projects j ON j.id = r.project_id
  WHERE r.project_id = $1 AND r.id = $2";

#[allow(clippy::too_many_lines)] // one pass per kind, in order
async fn run_in(
    db: &PgPool,
    now: OffsetDateTime,
    policy: Policy,
    dry_run: bool,
    project: Option<i64>,
) -> Result<Report, sqlx::Error> {
    let mut rep = Report {
        dry_run,
        ..Report::default()
    };
    // Regressions this run removes: a preview projects their removal onto the build
    // references below, as the real run (which deletes them first) sees them.
    let mut removed: Vec<i64> = vec![];
    let ids = sqlx::query(
        "SELECT project_id, id FROM regressions
          WHERE $1::bigint IS NULL OR project_id = $1 ORDER BY project_id, id",
    )
    .bind(project)
    .fetch_all(db)
    .await?;
    for r in ids {
        let (pid, rid): (i64, i64) = (r.get(0), r.get(1));
        // Decided under the regression's head lock, from its settled state: a late report
        // or a finish cannot slip between the decision and the deletion.
        let mut tx = db.begin().await?;
        if !dry_run {
            crate::app::write_gate(&mut tx)
                .await
                .map_err(|e| sqlx::Error::Protocol(e.message))?;
        }
        // No build, quarantine or pipeline change lands during the decision (they hold the
        // gate shared); the regression's own writes wait on its head lock. A dry run takes
        // neither: it changes nothing, and must not block writers.
        let head_sql = if dry_run {
            HEAD.to_string()
        } else {
            gate_exclusive(&mut tx).await?;
            format!("{HEAD} FOR UPDATE OF r")
        };
        let Some(head) = sqlx::query(sqlx::AssertSqlSafe(head_sql))
            .bind(pid)
            .bind(rid)
            .fetch_optional(&mut *tx)
            .await?
        else {
            continue;
        };
        let (producer, rref, end, producer_name, policy_name, project_name): (
            i64,
            String,
            OffsetDateTime,
            String,
            String,
            String,
        ) = (
            head.get(0),
            head.get(1),
            head.get(2),
            head.get(3),
            head.get(4),
            head.get(5),
        );
        let settle_policy = if policy_name == "retry-pass-accepted" {
            SettlePolicy::RetryPassAccepted
        } else {
            SettlePolicy::Strict
        };
        // All-pass only when every slot settles passed (or was skipped or cancelled):
        // failures, missing results, quarantine, withdrawn pipelines and failed builds all
        // keep the regression in the long-lived cohort.
        let loaded = App::load(&mut tx, pid, settle_policy, &rref, Some(&producer_name))
            .await
            .map_err(|e| sqlx::Error::Protocol(e.message))?;
        let all_pass = loaded.slots.iter().all(|(_, v)| {
            matches!(
                v.state,
                SlotState::Passed | SlotState::Skipped | SlotState::Cancelled
            )
        });
        let (payload, facts) = if all_pass {
            (policy.pass_payload, policy.pass_facts)
        } else {
            (policy.fail_payload, policy.fail_facts)
        };
        let age = now - end;
        let item = |action, payloads| Item {
            project: project_name.clone(),
            regression: rref.clone(),
            cohort: if all_pass {
                "all_pass"
            } else {
                "with_failures"
            },
            ended_at: end
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            action,
            payloads,
        };
        if age >= facts {
            rep.regressions += 1;
            rep.item(item("remove", 0));
            impact(
                &mut tx,
                &mut rep,
                pid,
                rid,
                producer,
                &producer_name,
                &rref,
                &project_name,
            )
            .await?;
            removed.push(rid);
            if dry_run {
                continue;
            }
            for sql in [
                "DELETE FROM buckets b USING attempts a, slots s
                  WHERE b.project_id = $1 AND a.project_id = b.project_id AND a.id = b.attempt_id
                    AND s.project_id = a.project_id AND s.id = a.slot_id AND s.regression_id = $2",
                "DELETE FROM attempt_reports p USING attempts a, slots s
                  WHERE p.project_id = $1 AND a.project_id = p.project_id AND a.id = p.attempt_id
                    AND s.project_id = a.project_id AND s.id = a.slot_id AND s.regression_id = $2",
                "DELETE FROM attempt_facts f USING attempts a, slots s
                  WHERE f.project_id = $1 AND a.project_id = f.project_id AND a.id = f.attempt_id
                    AND s.project_id = a.project_id AND s.id = a.slot_id AND s.regression_id = $2",
                "DELETE FROM attempts a USING slots s
                  WHERE a.project_id = $1 AND s.project_id = a.project_id AND s.id = a.slot_id
                    AND s.regression_id = $2",
                "DELETE FROM slot_marks m USING slots s
                  WHERE m.project_id = $1 AND s.project_id = m.project_id AND s.id = m.slot_id
                    AND s.regression_id = $2",
                "DELETE FROM slots WHERE project_id = $1 AND regression_id = $2",
                "DELETE FROM manifest_chunks WHERE project_id = $1 AND regression_id = $2",
                "DELETE FROM regressions WHERE project_id = $1 AND id = $2",
                // Feature selection keeps the regression as the candidate.
                "UPDATE candidate_index SET state = 'expired' WHERE project_id = $1 AND regression_id = $2",
            ] {
                sqlx::query(sql)
                    .bind(pid)
                    .bind(rid)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query(
                "INSERT INTO expired_regressions (project_id, producer_id, ref, expired_at)
                 VALUES ($1, $2, $3, now()) ON CONFLICT DO NOTHING",
            )
            .bind(pid)
            .bind(producer)
            .bind(&rref)
            .execute(&mut *tx)
            .await?;
            crate::app::decisions::bump_project(
                &mut tx,
                pid,
                "expired",
                &format!("regression:{rref}"),
            )
            .await
            .map_err(|e| sqlx::Error::Protocol(e.message))?;
            tx.commit().await?;
        } else if age >= payload {
            let q = if dry_run {
                "SELECT count(*) FROM attempt_reports p JOIN attempts a
                   ON a.project_id = p.project_id AND a.id = p.attempt_id
                   JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
                  WHERE p.project_id = $1 AND s.regression_id = $2"
            } else {
                "WITH d AS (DELETE FROM attempt_reports p USING attempts a, slots s
                  WHERE p.project_id = $1 AND a.project_id = p.project_id AND a.id = p.attempt_id
                    AND s.project_id = a.project_id AND s.id = a.slot_id AND s.regression_id = $2
                  RETURNING 1) SELECT count(*) FROM d"
            };
            let n: i64 = sqlx::query(q)
                .bind(pid)
                .bind(rid)
                .fetch_one(&mut *tx)
                .await?
                .get(0);
            let n_u = u64::try_from(n).unwrap_or(0);
            rep.payloads += n_u;
            if n_u > 0 {
                rep.item(item("expire_payloads", n_u));
            }
            if !dry_run && n > 0 {
                crate::app::decisions::bump_project(
                    &mut tx,
                    pid,
                    "payloads_expired",
                    &format!("regression_id:{rid}"),
                )
                .await
                .map_err(|e| sqlx::Error::Protocol(e.message))?;
            }
            tx.commit().await?;
        }
    }

    // Build attempts no remaining attempt references, past the all-pass facts period.
    // A build stays while anything retained needs it: an attempt's start or any report
    // revision naming it, or a remaining slot requiring its requirement.
    let old_builds = sqlx::query(
        "SELECT b.project_id, b.id, b.producer_id, b.build_ref FROM build_attempts b
          WHERE b.started_at < $1
            AND NOT EXISTS (SELECT 1 FROM attempts a
                              JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
                             WHERE a.project_id = b.project_id AND a.build_refs ? b.build_ref
                               AND s.regression_id <> ALL($3))
            AND NOT EXISTS (SELECT 1 FROM attempt_facts f
                              JOIN attempts a ON a.project_id = f.project_id AND a.id = f.attempt_id
                              JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
                             WHERE f.project_id = b.project_id AND f.build_refs ? b.build_ref
                               AND s.regression_id <> ALL($3))
            AND NOT EXISTS (SELECT 1 FROM slots s
                             WHERE s.project_id = b.project_id AND s.build_reqs ? b.build_req
                               AND s.regression_id <> ALL($3))
            AND ($2::bigint IS NULL OR b.project_id = $2)",
    )
    .bind(now - policy.pass_facts)
    .bind(project)
    .bind(&removed)
    .fetch_all(db)
    .await?;
    rep.builds = 0;
    for b in old_builds {
        if dry_run {
            rep.builds += 1;
            continue;
        }
        let mut tx = db.begin().await?;
        crate::app::write_gate(&mut tx)
            .await
            .map_err(|e| sqlx::Error::Protocol(e.message))?;
        gate_exclusive(&mut tx).await?;
        // Rechecked under the gate: a reference created meanwhile keeps the build.
        let still_unreferenced = sqlx::query(
            "SELECT 1 FROM build_attempts b
              WHERE b.project_id = $1 AND b.id = $2
                AND NOT EXISTS (SELECT 1 FROM attempts a
                                 WHERE a.project_id = b.project_id AND a.build_refs ? b.build_ref)
                AND NOT EXISTS (SELECT 1 FROM attempt_facts f
                                 WHERE f.project_id = b.project_id AND f.build_refs ? b.build_ref)
                AND NOT EXISTS (SELECT 1 FROM slots s
                                 WHERE s.project_id = b.project_id AND s.build_reqs ? b.build_req)",
        )
        .bind(b.get::<i64, _>(0))
        .bind(b.get::<i64, _>(1))
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !still_unreferenced {
            continue;
        }
        rep.builds += 1;
        if !dry_run {
            sqlx::query("DELETE FROM build_facts WHERE project_id = $1 AND build_attempt_id = $2")
                .bind(b.get::<i64, _>(0))
                .bind(b.get::<i64, _>(1))
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM build_attempts WHERE project_id = $1 AND id = $2")
                .bind(b.get::<i64, _>(0))
                .bind(b.get::<i64, _>(1))
                .execute(&mut *tx)
                .await?;
            // Its identity is never reused: a later record of it is 410.
            sqlx::query(
                "INSERT INTO expired_builds (project_id, producer_id, build_ref, expired_at)
                 VALUES ($1, $2, $3, now()) ON CONFLICT DO NOTHING",
            )
            .bind(b.get::<i64, _>(0))
            .bind(b.get::<i64, _>(2))
            .bind(b.get::<String, _>(3))
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }
    }

    // Receipts past the deduplication horizon, with tombstones.
    let horizon = now - policy.receipts;
    if dry_run {
        let n: i64 = sqlx::query(
            "SELECT count(*) FROM receipts
              WHERE received_at < $1 AND ($2::bigint IS NULL OR project_id = $2)",
        )
        .bind(horizon)
        .bind(project)
        .fetch_one(db)
        .await?
        .get(0);
        rep.receipts = u64::try_from(n).unwrap_or(0);
    } else {
        // One statement: the tombstones are made from exactly the rows deleted (a receipt
        // committed meanwhile is either both deleted and tombstoned, or neither).
        let mut tx = db.begin().await?;
        crate::app::write_gate(&mut tx)
            .await
            .map_err(|e| sqlx::Error::Protocol(e.message))?;
        let n: i64 = sqlx::query(
            "WITH gone AS (
                 DELETE FROM receipts WHERE received_at < $1
                 RETURNING project_id, producer_id, identity, revision),
             tomb AS (
                 INSERT INTO expired_receipts (project_id, producer_id, identity, max_revision, expired_at)
                 SELECT project_id, producer_id, identity, max(revision), now() FROM gone
                  GROUP BY project_id, producer_id, identity
                 ON CONFLICT (project_id, producer_id, identity)
                 DO UPDATE SET max_revision = greatest(expired_receipts.max_revision, EXCLUDED.max_revision)
                 RETURNING 1)
             SELECT count(*) FROM gone",
        )
        .bind(horizon)
        .fetch_one(&mut *tx)
        .await?
        .get(0);
        tx.commit().await?;
        let n = u64::try_from(n).unwrap_or(0);
        rep.receipts = n;
    }
    Ok(rep)
}
