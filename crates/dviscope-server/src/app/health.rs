//! Regression health dashboard (server part): the project hierarchy (versioned import and
//! read) and the health reads — a node's own streams and one roll-up per child, and one
//! stream's history. Every read is one repeatable-read snapshot with one clock; the work
//! is budgeted before anything is loaded (refused, never truncated) and bounded by a
//! deadline.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration as StdDuration;

use dviscope_core::compare;
use dviscope_core::health::{
    self, Colour, Cost, HealthSlot, Metrics, NodeHealth, RegInput, RegState, StreamHealth,
    StreamInput, Trend,
};
use dviscope_core::readiness::Verdict;
use dviscope_core::settlement::Policy;
use dviscope_model::canonical::{Digest, digest_of};
use dviscope_model::errors::ErrorCode;
use dviscope_model::wire::hierarchy::{self, Hierarchy, StreamRef};
use serde_json::{Value, json};
use sqlx::{Postgres, Row as _, Transaction};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::App;
use super::decisions::bump_project;
use super::read::Loaded;
use crate::auth::{Action, Actor};
use crate::error::AppError;

/// Work limits of one health read: counted before anything is loaded; above any of them
/// the read is refused (`E_TOO_LARGE`), never truncated. The deadline bounds the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Distinct streams one page evaluates.
    pub streams: i64,
    /// Slots over every regression the read loads.
    pub slots: i64,
    /// Attempts.
    pub attempts: i64,
    /// Report revisions of those attempts (quarantine probes read every revision).
    pub fact_revisions: i64,
    /// Head-revision bucket rows.
    pub buckets: i64,
    /// Distinct build attempts the slots' requirements match.
    pub builds: i64,
    /// (slot, matching build attempt) pairs settlement reads.
    pub build_pairs: i64,
    /// Build references in the head reports of the attempts (each is decoded and proven).
    pub build_refs: i64,
    /// Declared build requirements of the slots (each is decoded and settled).
    pub requirements: i64,
    /// Signature entries the roll-ups of one page combine (each child's subtree counted
    /// once per distinct set of streams).
    pub rollup_entries: i64,
    /// Regressions one growth read considers (the node's streams over the period).
    pub growth_regressions: i64,
    /// Slot rows the distinct-test counts of one growth read scan.
    pub growth_slots: i64,
    /// Deadline of the read.
    pub deadline: StdDuration,
}

impl Default for Limits {
    fn default() -> Self {
        // The scale the benchmark exercises (`health_benchmark`, numbers in the operations
        // guide): a read within these limits answers in about a second.
        Self {
            streams: 200,
            slots: 32_000,
            attempts: 40_000,
            fact_revisions: 80_000,
            buckets: 60_000,
            builds: 10_000,
            build_pairs: 200_000,
            build_refs: 80_000,
            requirements: 64_000,
            rollup_entries: 1_000_000,
            growth_regressions: 20_000,
            growth_slots: 2_000_000,
            deadline: StdDuration::from_secs(20),
        }
    }
}

/// Most history rows.
pub const MAX_HISTORY: i64 = 30;

/// Longest growth period, days.
pub const MAX_GROWTH_DAYS: i64 = 366;

/// The growth read's candidates: the streams' sealed regressions of the period (an index
/// range per stream) and each stream's last one before it (its value on the first day; a
/// top-1 index lookup per stream), both through `regressions_stream_sealed`.
/// Parameters: project, the streams as four arrays (producer id, suite, repository, branch),
/// the period's first instant, now.
macro_rules! growth_candidates {
    () => {
        "
            WITH st AS (SELECT * FROM unnest($2::bigint[], $3::text[], $4::text[], $5::text[])
                                   AS t(producer_id, suite, repository, branch))
            SELECT w.id, st.producer_id, st.suite, st.repository, st.branch, w.started_at
              FROM st CROSS JOIN LATERAL (
                   SELECT r.id, r.started_at FROM regressions r
                    WHERE r.project_id = $1 AND r.branch_repository = st.repository
                      AND r.branch_name = st.branch AND r.suite = st.suite
                      AND r.producer_id = st.producer_id AND r.sealed
                      AND r.started_at >= $6 AND r.started_at <= $7) w
            UNION ALL
            SELECT b.id, st.producer_id, st.suite, st.repository, st.branch, b.started_at
              FROM st CROSS JOIN LATERAL (
                   SELECT r.id, r.started_at FROM regressions r
                    WHERE r.project_id = $1 AND r.branch_repository = st.repository
                      AND r.branch_name = st.branch AND r.suite = st.suite
                      AND r.producer_id = st.producer_id AND r.sealed AND r.started_at < $6
                    ORDER BY r.started_at DESC, r.id DESC LIMIT 1) b"
    };
}

/// [`growth_candidates`] as text (the plan test inspects it).
#[doc(hidden)]
pub const GROWTH_CANDIDATES: &str = growth_candidates!();

/// Pseudo path of the streams not attached to the hierarchy.
pub const UNASSIGNED: &str = "~unassigned";

/// An instant as the core reads it (milliseconds since the Unix epoch).
fn ms(t: OffsetDateTime) -> i64 {
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX)
}

/// The core's milliseconds back as an instant.
fn from_ms(m: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(m) * 1_000_000).ok()
}

/// The core's milliseconds back as an RFC 3339 instant.
fn rfc_ms(m: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(m) * 1_000_000)
        .map(rfc)
        .unwrap_or_default()
}

fn rfc(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

fn invalid(msg: impl Into<String>, field: &str) -> AppError {
    AppError::field(ErrorCode::Invalid, msg, field)
}

/// One stream (resolved producer).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Stream {
    producer_id: i64,
    producer: String,
    suite: String,
    repository: String,
    branch: String,
}

impl Stream {
    fn json(&self) -> Value {
        json!({"producer": self.producer, "suite": self.suite,
               "branch": format!("{}/{}", self.repository, self.branch)})
    }
}

/// A stream shown at a node.
#[derive(Debug, Clone)]
struct Attachment {
    path: String,
    stream: Stream,
    home: bool,
    cadence_hours: Option<i32>,
}

/// What a health read shows: kind, path, title, breadcrumb, own attachments, children.
type NodeView = (
    &'static str,
    String,
    String,
    Vec<Value>,
    Vec<Attachment>,
    Vec<(String, String)>,
);

/// The current tree (or none).
struct Tree {
    revision: Option<i32>,
    /// path → (title, parent, ord)
    nodes: BTreeMap<String, (String, Option<String>, i32)>,
    attachments: Vec<Attachment>,
}

fn static_scope(s: &str) -> Option<&'static str> {
    match s {
        "process" => Some("process"),
        "process_and_waited_children" => Some("process_and_waited_children"),
        "job" => Some("job"),
        _ => None,
    }
}

fn verdict_of(v: &Value) -> Verdict {
    match v.as_str() {
        Some("pass") => Verdict::Pass,
        Some("accepted_with_exceptions") => Verdict::AcceptedWithExceptions,
        Some("fail") => Verdict::Fail,
        _ => Verdict::InsufficientEvidence,
    }
}

fn verdict_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "pass",
        Verdict::AcceptedWithExceptions => "accepted_with_exceptions",
        Verdict::Fail => "fail",
        Verdict::InsufficientEvidence => "insufficient_evidence",
    }
}

fn colour_name(c: Option<Colour>) -> Value {
    match c {
        None => Value::Null,
        Some(Colour::Grey) => json!("grey"),
        Some(Colour::Green) => json!("green"),
        Some(Colour::Yellow) => json!("yellow"),
        Some(Colour::Red) => json!("red"),
    }
}

fn trend_name(t: Trend) -> &'static str {
    match t {
        Trend::NoData => "no_data",
        Trend::Running => "running",
        Trend::NoBaseline => "no_baseline",
        Trend::NotComparable => "not_comparable",
        Trend::Green => "green",
        Trend::Yellow => "yellow",
        Trend::Red => "red",
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn cost_json(c: &Cost) -> Value {
    json!({
        "last_end": c.last_end.map(rfc_ms),
        "last_end_partial": c.last_end_partial,
        "times_inconsistent": c.times_inconsistent,
        "elapsed_s": c.elapsed_s.map(round1),
        "longest_run_s": c.longest_run_s.map(round1),
        "machine_s": c.machine_s.map(round1),
        "machine_partial": c.machine_partial,
        "cpu_s": c.cpu_s.map(round1),
        "cpu_slots": c.cpu_slots,
        "cpu_measured": c.cpu_measured,
        "cpu_scope": c.cpu_scope(),
    })
}

fn stream_json(h: &StreamHealth) -> Value {
    let rate = health::pass_rate(&h.counts);
    let base_rate = h.baseline_counts.as_ref().and_then(health::pass_rate);
    let deltas = h
        .baseline_cost
        .as_ref()
        .map(|b| health::cost_deltas(&h.cost, b));
    let s = &h.signatures;
    json!({
        "latest": h.latest.as_ref().map(|r| json!({
            "ref": r,
            "state": h.state.map(|s| match s {
                RegState::Unsealed => "unsealed",
                RegState::Sealed => "sealed",
                RegState::Finished => "finished",
            }),
            "started_at": h.started_at.map(rfc_ms),
        })),
        "baseline": h.baseline,
        "verdict": h.verdict.map(verdict_name),
        "baseline_verdict": h.baseline_verdict.map(verdict_name),
        "trend": trend_name(h.trend),
        "worse": h.worse,
        "counts": h.counts,
        "baseline_counts": h.baseline_counts,
        "pass_rate": rate.map(round1),
        "baseline_pass_rate": base_rate.map(round1),
        "pass_rate_delta_pts": rate.zip(base_rate).map(|(a, b)| round1(a - b)),
        "matched": h.matched,
        "matched_bad": h.matched_bad,
        "baseline_matched": h.baseline_matched,
        "baseline_matched_bad": h.baseline_matched_bad,
        "configs_added": h.configs_added,
        "configs_removed": h.configs_removed,
        "signatures": {
            "all": s.all.len(), "new": s.new.len(), "unknown": s.unknown.len(),
            "persistent": s.persistent.len(), "no_longer_observed": s.no_longer_observed.len(),
            "config_not_run": s.config_not_run.len(), "undecided": s.undecided.len(),
        },
        "cost": cost_json(&h.cost),
        "baseline_cost": h.baseline_cost.as_ref().map(cost_json),
        "deltas": deltas.map(|d| json!({
            "elapsed_s": d.elapsed_s.map(round1),
            "machine_s": d.machine_s.map(round1),
            "cpu_s": d.cpu_s.map(round1),
        })),
        "overdue": h.overdue,
        "overdue_at": h.overdue_at.map(rfc_ms),
    })
}

fn node_json(n: &NodeHealth) -> Value {
    let rate = health::pass_rate(&n.counts);
    let compared = health::pass_rate(&n.compared_counts);
    let compared_before = health::pass_rate(&n.compared_baseline_counts);
    json!({
        "streams": n.streams,
        "counts": n.counts,
        "compared_streams": n.compared_streams,
        "compared_counts": n.compared_counts,
        "compared_baseline_counts": n.compared_baseline_counts,
        "pass_rate": rate.map(round1),
        "pass_rate_delta_pts": compared.zip(compared_before).map(|(a, b)| round1(a - b)),
        "worst_rate": n.worst_rate.map(round1),
        "zero_test_streams": n.zero_test_streams,
        "signatures": {
            "all": n.all.len(), "new": n.new.len(), "unknown": n.unknown.len(),
            "persistent": n.persistent.len(), "no_longer_observed": n.no_longer_observed.len(),
            "config_not_run": n.config_not_run.len(), "undecided": n.undecided.len(),
        },
        "trend": colour_name(n.trend),
        "readiness": colour_name(n.readiness),
        "grey": n.grey,
        "elapsed_s": n.elapsed_s.map(round1),
        "elapsed_partial": n.elapsed_partial,
        "cpu_s": n.cpu_s.map(round1),
        "cpu_slots": n.cpu_slots,
        "cpu_measured": n.cpu_measured,
        "cpu_complete": n.cpu_complete,
        "cpu_scope": n.cpu_scope,
        "cpu_delta_s": n.cpu_delta_s.map(round1),
    })
}

fn user_label(actor: &Actor) -> Result<String, AppError> {
    match actor {
        Actor::User { user_id, .. } => Ok(format!("user:{user_id}")),
        Actor::Collector { .. } => Err(AppError::new(ErrorCode::Forbidden, "people only")),
    }
}

impl App {
    /// Imports the project hierarchy: a new revision when it differs from the current one
    /// (A→B→A makes three), a no-op receipt when it is the current one.
    ///
    /// # Errors
    /// Authorization (admin), invalid file (every problem located), unknown producer,
    /// maintenance, database errors.
    pub async fn import_hierarchy(
        &self,
        actor: &Actor,
        project: &str,
        h: &Hierarchy,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::HierarchyWrite)
            .await?;
        let who = user_label(actor)?;
        let problems = h.validate();
        if let Some(first) = problems.first() {
            let all: Vec<String> = problems
                .iter()
                .take(20)
                .map(|p| format!("{}: {}", p.at, p.message))
                .collect();
            return Err(invalid(all.join("; "), &first.at));
        }
        let body = serde_json::to_value(h)?;
        let digest = digest_of(&body).map_err(|_| AppError::internal("hierarchy digest"))?;
        let mut tx = super::begin_write(&self.db).await?;
        // Imports of one project serialize on its head row.
        sqlx::query(
            "INSERT INTO project_heads (project_id) VALUES ($1) ON CONFLICT (project_id) DO NOTHING",
        )
        .bind(pid)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT 1 FROM project_heads WHERE project_id = $1 FOR UPDATE")
            .bind(pid)
            .execute(&mut *tx)
            .await?;
        let current: Option<(i32, String)> = sqlx::query_as(
            "SELECT revision, digest FROM area_trees WHERE project_id = $1
              ORDER BY revision DESC LIMIT 1",
        )
        .bind(pid)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((rev, d)) = &current
            && d == digest.as_str()
        {
            tx.commit().await?;
            return Ok(json!({"revision": rev, "digest": d, "result": "duplicate"}));
        }
        // Producers by name, in this project only.
        let names: BTreeSet<&str> = h.streams.iter().map(|s| s.producer.as_str()).collect();
        let known: BTreeMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
            "SELECT name, id FROM producers WHERE project_id = $1 AND name = ANY($2)",
        )
        .bind(pid)
        .bind(names.iter().copied().collect::<Vec<_>>())
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .collect();
        for (i, s) in h.streams.iter().enumerate() {
            if !known.contains_key(&s.producer) {
                return Err(invalid(
                    format!(
                        "streams[{i}].producer: no producer {:?} in project {project}",
                        s.producer
                    ),
                    &format!("streams[{i}].producer"),
                ));
            }
        }
        let rev = current.map_or(1, |(r, _)| r + 1);
        sqlx::query(
            "INSERT INTO area_trees (project_id, revision, digest, body, imported_by)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(pid)
        .bind(rev)
        .bind(digest.as_str())
        .bind(&body)
        .bind(&who)
        .execute(&mut *tx)
        .await?;
        for (ord, n) in h.nodes.iter().enumerate() {
            let title = n
                .title
                .clone()
                .unwrap_or_else(|| n.path.rsplit('/').next().unwrap_or(&n.path).to_string());
            sqlx::query(
                "INSERT INTO areas (project_id, revision, path, parent_path, title, ord)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(pid)
            .bind(rev)
            .bind(&n.path)
            .bind(hierarchy::parent(&n.path))
            .bind(&title)
            .bind(i32::try_from(ord).unwrap_or(i32::MAX))
            .execute(&mut *tx)
            .await?;
        }
        let attach = |node: &str, s: &StreamRef, home: bool, cadence: Option<i32>| {
            let (repo, name) = hierarchy::split_branch(&s.branch).unwrap_or(("", ""));
            (
                node.to_string(),
                known.get(&s.producer).copied().unwrap_or(0),
                s.suite.clone(),
                repo.to_string(),
                name.to_string(),
                home,
                cadence,
            )
        };
        let mut rows = vec![];
        for s in &h.streams {
            let c = hierarchy::cadence_hours(s.cadence.as_deref()).unwrap_or(None);
            rows.push(attach(&s.node, &s.stream(), true, c));
        }
        for l in &h.links {
            rows.push(attach(&l.node, &l.stream, false, None));
        }
        for (path, prod, suite, repo, name, home, cadence) in rows {
            sqlx::query(
                "INSERT INTO area_streams (project_id, revision, path, producer_id, suite,
                        branch_repository, branch_name, home, cadence_hours)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(pid)
            .bind(rev)
            .bind(path)
            .bind(prod)
            .bind(suite)
            .bind(repo)
            .bind(name)
            .bind(home)
            .bind(cadence)
            .execute(&mut *tx)
            .await?;
        }
        super::audit(
            &mut tx,
            &who,
            "hierarchy.import",
            &format!("{project}/hierarchy/{rev}"),
            json!({"digest": digest.as_str(), "nodes": h.nodes.len(),
                   "streams": h.streams.len(), "links": h.links.len()}),
        )
        .await?;
        bump_project(&mut tx, pid, "hierarchy", &format!("hierarchy:{rev}")).await?;
        tx.commit().await?;
        Ok(
            json!({"revision": rev, "digest": digest.as_str(), "result": "imported",
                  "nodes": h.nodes.len(), "streams": h.streams.len(), "links": h.links.len()}),
        )
    }

    /// The current hierarchy (`null` body without one).
    ///
    /// # Errors
    /// Authorization (viewer), database errors.
    pub async fn read_hierarchy(&self, actor: &Actor, project: &str) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::HierarchyRead)
            .await?;
        let row: Option<(i32, String, Value, OffsetDateTime)> = sqlx::query_as(
            "SELECT revision, digest, body, imported_at FROM area_trees WHERE project_id = $1
              ORDER BY revision DESC LIMIT 1",
        )
        .bind(pid)
        .fetch_optional(&self.db)
        .await?;
        Ok(match row {
            Some((rev, d, body, at)) => {
                json!({"revision": rev, "digest": d, "imported_at": rfc(at), "hierarchy": body})
            }
            None => json!({"revision": null, "hierarchy": null}),
        })
    }

    /// The health of a node (`area`: a path, `~unassigned`, or the project level when
    /// absent): its own streams, one roll-up per child, and the roll-up of its subtree.
    ///
    /// # Errors
    /// Authorization (viewer), unknown area, work budget exceeded (`E_TOO_LARGE`), deadline
    /// (`E_UNAVAILABLE`), database errors.
    pub async fn read_health(
        &self,
        actor: &Actor,
        project: &str,
        area: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        self.read_health_with(actor, project, area, now, &Limits::default())
            .await
    }

    /// [`Self::read_health`] under explicit limits.
    ///
    /// # Errors
    /// As [`Self::read_health`].
    pub async fn read_health_with(
        &self,
        actor: &Actor,
        project: &str,
        area: Option<&str>,
        now: OffsetDateTime,
        lim: &Limits,
    ) -> Result<Value, AppError> {
        let (pid, policy) = self
            .read_project(actor, project, Action::HealthRead)
            .await?;
        let fut = self.health_in(pid, project, policy, area, now, lim);
        match tokio::time::timeout(lim.deadline, fut).await {
            Ok(r) => r,
            Err(_) => Err(AppError::new(
                ErrorCode::Unavailable,
                "the health read took longer than its deadline: retry, or open a lower node",
            )),
        }
    }

    #[allow(clippy::too_many_lines)] // one snapshot: tree, streams, budget, loads, roll-ups
    async fn health_in(
        &self,
        pid: i64,
        project: &str,
        policy: Policy,
        area: Option<&str>,
        now: OffsetDateTime,
        lim: &Limits,
    ) -> Result<Value, AppError> {
        let mut tx = self.snapshot().await?;
        let watermark: i64 = sqlx::query_scalar(
            "SELECT coalesce(max(change_seq), 0) FROM project_heads WHERE project_id = $1",
        )
        .bind(pid)
        .fetch_one(&mut *tx)
        .await?;
        let tree = load_tree(&mut tx, pid).await?;
        // Streams outside the tree matter only where Unassigned is shown.
        let seen = if matches!(area, None | Some("" | UNASSIGNED)) {
            // Every attached stream plus the page's stream limit: more distinct streams
            // than that cannot fit the page, so the read is refused before loading them.
            let cap = lim
                .streams
                .saturating_add(i64::try_from(tree.attachments.len()).unwrap_or(i64::MAX))
                .saturating_add(1);
            let seen = all_streams(&mut tx, pid, cap).await?;
            if i64::try_from(seen.len()).unwrap_or(i64::MAX) >= cap {
                return Err(AppError::new(
                    ErrorCode::TooLarge,
                    format!(
                        "this project has more than {} streams outside its hierarchy: open a node of the hierarchy, or attach them",
                        lim.streams
                    ),
                ));
            }
            seen
        } else {
            vec![]
        };
        let attached: BTreeSet<&Stream> = tree.attachments.iter().map(|a| &a.stream).collect();
        let unassigned: Vec<Stream> = seen
            .iter()
            .filter(|s| !attached.contains(s))
            .cloned()
            .collect();
        let homes: BTreeMap<&Stream, &Attachment> = tree
            .attachments
            .iter()
            .filter(|a| a.home)
            .map(|a| (&a.stream, a))
            .collect();
        // The node, its breadcrumb, own attachments and children.
        let roots: Vec<&String> = tree
            .nodes
            .iter()
            .filter(|(_, (_, p, _))| p.is_none())
            .map(|(k, _)| k)
            .collect();
        let children_of = |path: &str| -> Vec<String> {
            let mut c: Vec<(&i32, &String)> = tree
                .nodes
                .iter()
                .filter(|(_, (_, p, _))| p.as_deref() == Some(path))
                .map(|(k, (_, _, o))| (o, k))
                .collect();
            c.sort();
            c.into_iter().map(|(_, k)| k.clone()).collect()
        };
        let in_subtree =
            |root: &str, path: &str| path == root || path.starts_with(&format!("{root}/"));
        let subtree_streams = |root: &str| -> BTreeSet<Stream> {
            if root == UNASSIGNED {
                return unassigned.iter().cloned().collect();
            }
            tree.attachments
                .iter()
                .filter(|a| in_subtree(root, &a.path))
                .map(|a| a.stream.clone())
                .collect()
        };
        let (kind, path, title, breadcrumb, own, children): NodeView = match area {
            None | Some("") => {
                let mut ch: Vec<(String, String)> = {
                    let mut r: Vec<(&i32, &String)> =
                        roots.iter().map(|k| (&tree.nodes[*k].2, *k)).collect();
                    r.sort();
                    r.into_iter()
                        .map(|(_, k)| (k.clone(), tree.nodes[k].0.clone()))
                        .collect()
                };
                // Without a hierarchy every stream is the project's own.
                let own = if tree.revision.is_none() {
                    unassigned
                        .iter()
                        .map(|s| Attachment {
                            path: String::new(),
                            stream: s.clone(),
                            home: true,
                            cadence_hours: None,
                        })
                        .collect()
                } else {
                    if !unassigned.is_empty() {
                        ch.push((UNASSIGNED.to_string(), "Unassigned".to_string()));
                    }
                    vec![]
                };
                (
                    "project",
                    String::new(),
                    project.to_string(),
                    vec![],
                    own,
                    ch,
                )
            }
            Some(UNASSIGNED) => {
                let own = unassigned
                    .iter()
                    .map(|s| Attachment {
                        path: UNASSIGNED.into(),
                        stream: s.clone(),
                        home: true,
                        cadence_hours: None,
                    })
                    .collect();
                (
                    "unassigned",
                    UNASSIGNED.to_string(),
                    "Unassigned".to_string(),
                    vec![],
                    own,
                    vec![],
                )
            }
            Some(p) => {
                let Some((t, _, _)) = tree.nodes.get(p) else {
                    return Err(AppError::new(ErrorCode::NotFound, format!("no area {p}")));
                };
                let mut bc = vec![];
                let mut cur = hierarchy::parent(p);
                while let Some(c) = cur {
                    bc.push(json!({"path": c, "title": tree.nodes.get(c).map(|n| n.0.clone())}));
                    cur = hierarchy::parent(c);
                }
                bc.reverse();
                let own = tree
                    .attachments
                    .iter()
                    .filter(|a| a.path == p)
                    .cloned()
                    .collect();
                let ch = children_of(p)
                    .into_iter()
                    .map(|k| {
                        let t = tree.nodes[&k].0.clone();
                        (k, t)
                    })
                    .collect();
                ("node", p.to_string(), t.clone(), bc, own, ch)
            }
        };
        // Every distinct stream the page needs: own ones and each child's subtree.
        let mut needed: BTreeSet<Stream> = own.iter().map(|a| a.stream.clone()).collect();
        let child_sets: Vec<BTreeSet<Stream>> =
            children.iter().map(|(k, _)| subtree_streams(k)).collect();
        for c in &child_sets {
            needed.extend(c.iter().cloned());
        }
        if i64::try_from(needed.len()).unwrap_or(i64::MAX) > lim.streams {
            return Err(AppError::new(
                ErrorCode::TooLarge,
                format!(
                    "this node covers {} streams (at most {} per read): open a lower node",
                    needed.len(),
                    lim.streams
                ),
            ));
        }
        let picks = pick_regressions(&mut tx, pid, &needed).await?;
        let ids: Vec<i64> = picks
            .values()
            .flat_map(|p| {
                [
                    p.latest.as_ref().map(|r| r.id),
                    p.baseline.as_ref().map(|r| r.id),
                ]
            })
            .flatten()
            .collect();
        budget(&mut tx, pid, &ids, lim).await?;
        // One health per stream, cadence from its home.
        let mut by_stream: BTreeMap<Stream, StreamHealth> = BTreeMap::new();
        let mut valid_until: Option<OffsetDateTime> = None;
        for s in &needed {
            let p = &picks[s];
            let cadence = homes
                .get(s)
                .and_then(|a| a.cadence_hours)
                .map(|h| i64::from(h) * health::HOUR_MS);
            let (h, expiry) = stream_health(&mut tx, pid, policy, s, p, cadence, now).await?;
            for t in expiry.into_iter().chain(h.overdue_at.and_then(from_ms)) {
                if t > now {
                    valid_until = Some(valid_until.map_or(t, |v: OffsetDateTime| v.min(t)));
                }
            }
            by_stream.insert(s.clone(), h);
        }
        tx.commit().await?;
        // Roll-up work, counted before combining: the KPI over every stream, then each
        // distinct child stream set once (children with the same set share one roll-up).
        let entries = |h: &StreamHealth| -> i64 {
            let s = &h.signatures;
            i64::try_from(
                s.all.len()
                    + s.new.len()
                    + s.unknown.len()
                    + s.persistent.len()
                    + s.no_longer_observed.len()
                    + s.config_not_run.len()
                    + s.undecided.len(),
            )
            .unwrap_or(i64::MAX)
        };
        let distinct_sets: BTreeSet<&BTreeSet<Stream>> = child_sets.iter().collect();
        let work: i64 = by_stream.values().map(entries).sum::<i64>()
            + distinct_sets
                .iter()
                .map(|set| set.iter().map(|s| entries(&by_stream[s])).sum::<i64>())
                .sum::<i64>();
        if work > lim.rollup_entries {
            return Err(AppError::new(
                ErrorCode::TooLarge,
                format!(
                    "this page combines {work} signature entries (at most {}): open a lower node",
                    lim.rollup_entries
                ),
            ));
        }
        let kpi = health::rollup(by_stream.values());
        let own_rows: Vec<Value> = own
            .iter()
            .map(|a| {
                let h = &by_stream[&a.stream];
                let mut row = stream_json(h);
                row["stream"] = a.stream.json();
                row["home"] = json!(a.home);
                row["shared_from"] = if a.home {
                    Value::Null
                } else {
                    homes.get(&a.stream).map_or(Value::Null, |h| json!(h.path))
                };
                row["cadence_hours"] = json!(homes.get(&a.stream).and_then(|h| h.cadence_hours));
                row
            })
            .collect();
        let mut rolled: BTreeMap<&BTreeSet<Stream>, Value> = BTreeMap::new();
        let child_rows: Vec<Value> = children
            .iter()
            .zip(&child_sets)
            .map(|((k, t), set)| {
                let health = rolled
                    .entry(set)
                    .or_insert_with(|| {
                        node_json(&health::rollup(set.iter().map(|s| &by_stream[s])))
                    })
                    .clone();
                let own_here = tree.attachments.iter().filter(|a| &a.path == k).count();
                json!({"path": k, "title": t,
                       "own_streams": if k == UNASSIGNED { set.len() } else { own_here },
                       "children": if k == UNASSIGNED { 0 } else { children_of(k).len() },
                       "health": health})
            })
            .collect();
        Ok(json!({
            "project": project,
            "hierarchy_revision": tree.revision,
            "watermark": watermark,
            "evaluated_at": rfc(now),
            "valid_until": valid_until.map(rfc),
            "node": {"kind": kind, "path": path, "title": title, "breadcrumb": breadcrumb},
            "kpi": node_json(&kpi),
            "own": own_rows,
            "children": child_rows,
        }))
    }

    /// One stream's last regressions (newest first), each against its predecessor (also one
    /// outside the window): verdicts, trend and undecided signatures as of `now`, with the
    /// history's own `valid_until`.
    ///
    /// # Errors
    /// Authorization (viewer), invalid stream, work budget, deadline, database errors.
    pub async fn read_health_history(
        &self,
        actor: &Actor,
        project: &str,
        stream: &StreamRef,
        limit: i64,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        self.read_health_history_with(actor, project, stream, limit, now, &Limits::default())
            .await
    }

    /// [`Self::read_health_history`] under explicit limits.
    ///
    /// # Errors
    /// As [`Self::read_health_history`].
    pub async fn read_health_history_with(
        &self,
        actor: &Actor,
        project: &str,
        stream: &StreamRef,
        limit: i64,
        now: OffsetDateTime,
        lim: &Limits,
    ) -> Result<Value, AppError> {
        let (pid, policy) = self
            .read_project(actor, project, Action::HealthRead)
            .await?;
        let fut = self.history_in(pid, policy, stream, limit.clamp(1, MAX_HISTORY), now, lim);
        match tokio::time::timeout(lim.deadline, fut).await {
            Ok(r) => r,
            Err(_) => Err(AppError::new(
                ErrorCode::Unavailable,
                "the history read took longer than its deadline: retry with a smaller limit",
            )),
        }
    }

    /// The test inventory of a node over the last `days` UTC days (today included): per day,
    /// the required runs and the distinct required tests of every stream's latest sealed
    /// regression started by the end of that day (a stream keeps its last value until its
    /// next regression), and how many streams had one. A drop, or a stream at 0, shows.
    ///
    /// # Errors
    /// Authorization (viewer), unknown area, `days` outside 1..=[`MAX_GROWTH_DAYS`], work
    /// budget (`E_TOO_LARGE`), deadline, database errors.
    pub async fn read_health_growth(
        &self,
        actor: &Actor,
        project: &str,
        area: Option<&str>,
        days: i64,
        now: OffsetDateTime,
    ) -> Result<Value, AppError> {
        self.read_health_growth_with(actor, project, area, days, now, &Limits::default())
            .await
    }

    /// [`Self::read_health_growth`] under explicit limits.
    ///
    /// # Errors
    /// As [`Self::read_health_growth`].
    pub async fn read_health_growth_with(
        &self,
        actor: &Actor,
        project: &str,
        area: Option<&str>,
        days: i64,
        now: OffsetDateTime,
        lim: &Limits,
    ) -> Result<Value, AppError> {
        let (pid, _) = self
            .read_project(actor, project, Action::HealthRead)
            .await?;
        if !(1..=MAX_GROWTH_DAYS).contains(&days) {
            return Err(AppError::field(
                ErrorCode::Invalid,
                format!("days is 1 to {MAX_GROWTH_DAYS}"),
                "days",
            ));
        }
        let fut = self.growth_in(pid, area, days, now, lim);
        match tokio::time::timeout(lim.deadline, fut).await {
            Ok(r) => r,
            Err(_) => Err(AppError::new(
                ErrorCode::Unavailable,
                "the growth read took longer than its deadline: retry with a shorter period",
            )),
        }
    }

    #[allow(clippy::too_many_lines)] // one snapshot: streams, regressions, budget, counts
    async fn growth_in(
        &self,
        pid: i64,
        area: Option<&str>,
        days: i64,
        now: OffsetDateTime,
        lim: &Limits,
    ) -> Result<Value, AppError> {
        let now = now.to_offset(time::UtcOffset::UTC);
        let mut tx = self.snapshot().await?;
        let watermark: i64 = sqlx::query_scalar(
            "SELECT coalesce(max(change_seq), 0) FROM project_heads WHERE project_id = $1",
        )
        .bind(pid)
        .fetch_one(&mut *tx)
        .await?;
        let tree = load_tree(&mut tx, pid).await?;
        let streams = node_streams(&mut tx, pid, &tree, area, lim.streams).await?;
        let first_day = now.replace_time(time::Time::MIDNIGHT) - time::Duration::days(days - 1);
        let (ids, sus, repos, brs): (Vec<i64>, Vec<String>, Vec<String>, Vec<String>) = {
            let mut v = (vec![], vec![], vec![], vec![]);
            for st in &streams {
                v.0.push(st.producer_id);
                v.1.push(st.suite.clone());
                v.2.push(st.repository.clone());
                v.3.push(st.branch.clone());
            }
            v
        };
        // The candidates, counted no further than the limit, then listed without touching
        // their slots (the index `regressions_stream_sealed` serves both parts without
        // visiting unsealed or other producers' regressions).
        let cap = lim.growth_regressions.saturating_add(1);
        let n: i64 = sqlx::query_scalar(concat!(
            "SELECT count(*) FROM (SELECT 1 FROM (",
            growth_candidates!(),
            ") y LIMIT $8) x"
        ))
        .bind(pid)
        .bind(&ids)
        .bind(&sus)
        .bind(&repos)
        .bind(&brs)
        .bind(first_day)
        .bind(now)
        .bind(cap)
        .fetch_one(&mut *tx)
        .await?;
        if n > lim.growth_regressions {
            return Err(AppError::new(
                ErrorCode::TooLarge,
                format!(
                    "this period has more than {} regressions: choose a shorter period or a lower node",
                    lim.growth_regressions
                ),
            ));
        }
        type Key = (i64, String, String, String);
        let mut regs: Vec<(i64, Key, OffsetDateTime)> = sqlx::query(growth_candidates!())
            .bind(pid)
            .bind(&ids)
            .bind(&sus)
            .bind(&repos)
            .bind(&brs)
            .bind(first_day)
            .bind(now)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|r| (r.get(0), (r.get(1), r.get(2), r.get(3), r.get(4)), r.get(5)))
            .collect();
        regs.sort_by_key(|r| (r.2, r.0));
        // Day by day: each stream's latest regression started before the day's end (now for
        // today). Only these winners are ever read further; days with the same set share one
        // distinct-test count.
        let mut latest: BTreeMap<&Key, i64> = BTreeMap::new();
        let mut next = 0usize;
        let mut days_out: Vec<(String, usize, usize)> = vec![]; // date, streams, set index
        let mut sets: Vec<Vec<i64>> = vec![];
        for d in 0..days {
            let day = first_day + time::Duration::days(d);
            let end = (day + time::Duration::days(1)).min(now + time::Duration::milliseconds(1));
            while next < regs.len() && regs[next].2 < end {
                latest.insert(&regs[next].1, regs[next].0);
                next += 1;
            }
            let mut set: Vec<i64> = latest.values().copied().collect();
            set.sort_unstable();
            if sets.last() != Some(&set) {
                sets.push(set);
            }
            days_out.push((day.date().to_string(), latest.len(), sets.len() - 1));
        }
        let winners: Vec<i64> = sets
            .iter()
            .flatten()
            .copied()
            .collect::<BTreeSet<i64>>()
            .into_iter()
            .collect();
        let too_many_slots = |what: &str, n: i64| {
            AppError::new(
                ErrorCode::TooLarge,
                format!(
                    "{what} {n} slots (limit {}): choose a shorter period or a lower node",
                    lim.growth_slots
                ),
            )
        };
        // The winners' slot rows, counted no further than the limit before they are read.
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM (SELECT 1 FROM slots
                                    WHERE project_id = $1 AND regression_id = ANY($2)
                                    LIMIT $3) x",
        )
        .bind(pid)
        .bind(&winners)
        .bind(lim.growth_slots.saturating_add(1))
        .fetch_one(&mut *tx)
        .await?;
        if rows > lim.growth_slots {
            return Err(too_many_slots(
                "the regressions of this period have more than",
                lim.growth_slots,
            ));
        }
        let mut per: BTreeMap<i64, (i64, i64)> = BTreeMap::new(); // id → (required, all rows)
        for r in sqlx::query(
            "SELECT regression_id,
                    count(*) FILTER (WHERE removed_revision IS NULL AND required), count(*)
               FROM slots WHERE project_id = $1 AND regression_id = ANY($2)
              GROUP BY regression_id",
        )
        .bind(pid)
        .bind(&winners)
        .fetch_all(&mut *tx)
        .await?
        {
            per.insert(r.get(0), (r.get(1), r.get(2)));
        }
        // The distinct-test counts read every row of each distinct set once.
        let scan: i64 = sets
            .iter()
            .map(|set| {
                set.iter()
                    .map(|id| per.get(id).map_or(0, |p| p.1))
                    .sum::<i64>()
            })
            .fold(0i64, i64::saturating_add);
        if scan > lim.growth_slots {
            return Err(too_many_slots(
                "the distinct-test counts of this period scan",
                scan,
            ));
        }
        let runs: Vec<i64> = sets
            .iter()
            .map(|set| set.iter().map(|id| per.get(id).map_or(0, |p| p.0)).sum())
            .collect();
        let rows: Vec<(String, i64, usize, usize)> = days_out
            .into_iter()
            .map(|(date, n, k)| (date, runs[k], n, k))
            .collect();
        let (keys, members): (Vec<i32>, Vec<i64>) = sets
            .iter()
            .enumerate()
            .flat_map(|(k, set)| {
                set.iter()
                    .map(move |id| (i32::try_from(k).unwrap_or(i32::MAX), *id))
            })
            .unzip();
        let mut tests: BTreeMap<i32, i64> = BTreeMap::new();
        for r in sqlx::query(
            "SELECT d.k, count(DISTINCT s.test)
               FROM unnest($2::int[], $3::bigint[]) AS d(k, reg)
               JOIN slots s ON s.project_id = $1 AND s.regression_id = d.reg
                           AND s.removed_revision IS NULL AND s.required
              GROUP BY d.k",
        )
        .bind(pid)
        .bind(&keys)
        .bind(&members)
        .fetch_all(&mut *tx)
        .await?
        {
            tests.insert(r.get(0), r.get(1));
        }
        tx.commit().await?;
        let out: Vec<Value> = rows
            .into_iter()
            .map(|(date, runs, n, k)| {
                json!({"date": date, "required_runs": runs, "tests": tests.get(&i32::try_from(k).unwrap_or(i32::MAX)).copied().unwrap_or(0), "streams": n})
            })
            .collect();
        Ok(json!({
            "schema": "dviscope.health-growth/1",
            "area": area.unwrap_or(""),
            "days": out,
            "streams": streams.len(),
            "watermark": watermark,
            "evaluated_at": now.format(&Rfc3339).unwrap_or_default(),
        }))
    }

    #[allow(clippy::too_many_lines)] // one snapshot: window, predecessor, budget, rows
    async fn history_in(
        &self,
        pid: i64,
        policy: Policy,
        stream: &StreamRef,
        limit: i64,
        now: OffsetDateTime,
        lim: &Limits,
    ) -> Result<Value, AppError> {
        let (repo, name) = hierarchy::split_branch(&stream.branch)
            .ok_or_else(|| invalid("branch is repo/name", "branch"))?;
        let s = Stream {
            producer_id: 0,
            producer: stream.producer.clone(),
            suite: stream.suite.clone(),
            repository: repo.to_string(),
            branch: name.to_string(),
        };
        let mut tx = self.snapshot().await?;
        let watermark: i64 = sqlx::query_scalar(
            "SELECT coalesce(max(change_seq), 0) FROM project_heads WHERE project_id = $1",
        )
        .bind(pid)
        .fetch_one(&mut *tx)
        .await?;
        // The stream's home in the current tree: its cadence and node (for navigation).
        let tree = load_tree(&mut tx, pid).await?;
        let home = tree.attachments.iter().find(|a| {
            a.home
                && a.stream.producer == s.producer
                && a.stream.suite == s.suite
                && a.stream.repository == s.repository
                && a.stream.branch == s.branch
        });
        let cadence_hours = home.and_then(|a| a.cadence_hours);
        let home_path = home.map(|a| a.path.clone());
        let pick = |r: (i64, String, String, OffsetDateTime)| Pick {
            id: r.0,
            regression: r.1,
            state: r.2,
            started_at: r.3,
        };
        let rows: Vec<Pick> = sqlx::query_as::<_, (i64, String, String, OffsetDateTime)>(
            "SELECT r.id, r.ref, r.state, r.started_at FROM regressions r
               JOIN producers p ON p.project_id = r.project_id AND p.id = r.producer_id
              WHERE r.project_id = $1 AND p.name = $2 AND r.suite = $3
                AND r.branch_repository = $4 AND r.branch_name = $5
              ORDER BY r.started_at DESC, r.id DESC LIMIT $6",
        )
        .bind(pid)
        .bind(&stream.producer)
        .bind(&stream.suite)
        .bind(repo)
        .bind(name)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(pick)
        .collect();
        // The oldest row's predecessor may lie outside the window: fetch it (and budget it).
        let outside: Option<Pick> = match rows.last() {
            Some(last) => sqlx::query_as::<_, (i64, String, String, OffsetDateTime)>(
                "SELECT r.id, r.ref, r.state, r.started_at FROM regressions r
                   JOIN producers p ON p.project_id = r.project_id AND p.id = r.producer_id
                  WHERE r.project_id = $1 AND p.name = $2 AND r.suite = $3
                    AND r.branch_repository = $4 AND r.branch_name = $5 AND r.state = 'finished'
                    AND (r.started_at, r.id) < ($6, $7)
                  ORDER BY r.started_at DESC, r.id DESC LIMIT 1",
            )
            .bind(pid)
            .bind(&stream.producer)
            .bind(&stream.suite)
            .bind(repo)
            .bind(name)
            .bind(last.started_at)
            .bind(last.id)
            .fetch_optional(&mut *tx)
            .await?
            .map(pick),
            None => None,
        };
        let mut ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        ids.extend(outside.as_ref().map(|r| r.id));
        budget(&mut tx, pid, &ids, lim).await?;
        // Load every regression once.
        let mut loaded: BTreeMap<i64, Loaded> = BTreeMap::new();
        for p in rows.iter().chain(outside.as_ref()) {
            let l = App::load(&mut tx, pid, policy, &p.regression, Some(&stream.producer)).await?;
            loaded.insert(p.id, l);
        }
        // Each row's predecessor: the most recent earlier finished regression (newest first:
        // the next finished row below it, else the one outside the window).
        let mut out = vec![];
        let mut valid_until: Option<OffsetDateTime> = None;
        for (i, row) in rows.iter().enumerate() {
            let pred = rows[i + 1..]
                .iter()
                .find(|r| r.state == "finished")
                .or(outside.as_ref());
            let base = pred.and_then(|p| loaded.get(&p.id).map(|l| (p, l)));
            // Only the latest regression can be overdue.
            let cadence = (i == 0)
                .then_some(cadence_hours)
                .flatten()
                .map(|h| i64::from(h) * health::HOUR_MS);
            let (h, expiries) = health_of(
                &mut tx,
                pid,
                policy,
                &s,
                row,
                &loaded[&row.id],
                base,
                cadence,
                now,
            )
            .await?;
            for t in expiries
                .into_iter()
                .chain(h.overdue_at.and_then(from_ms))
                .filter(|t| *t > now)
            {
                valid_until = Some(valid_until.map_or(t, |v: OffsetDateTime| v.min(t)));
            }
            out.push(stream_json(&h));
        }
        tx.commit().await?;
        Ok(json!({
            "stream": stream,
            "watermark": watermark,
            "evaluated_at": rfc(now),
            "valid_until": valid_until.map(rfc),
            "cadence_hours": cadence_hours,
            "home": home_path,
            "regressions": out,
        }))
    }
}

async fn load_tree(tx: &mut Transaction<'_, Postgres>, pid: i64) -> Result<Tree, AppError> {
    let rev: Option<i32> =
        sqlx::query_scalar("SELECT max(revision) FROM area_trees WHERE project_id = $1")
            .bind(pid)
            .fetch_one(&mut **tx)
            .await
            .or_else(|e| match &e {
                // A database before migration 0020 has no hierarchy.
                sqlx::Error::Database(d) if d.code().as_deref() == Some("42P01") => Ok(None),
                _ => Err(e),
            })?;
    let mut t = Tree {
        revision: rev,
        nodes: BTreeMap::new(),
        attachments: vec![],
    };
    let Some(rev) = rev else {
        return Ok(t);
    };
    for r in sqlx::query(
        "SELECT path, title, parent_path, ord FROM areas WHERE project_id = $1 AND revision = $2",
    )
    .bind(pid)
    .bind(rev)
    .fetch_all(&mut **tx)
    .await?
    {
        t.nodes.insert(r.get(0), (r.get(1), r.get(2), r.get(3)));
    }
    for r in sqlx::query(
        "SELECT a.path, a.producer_id, p.name, a.suite, a.branch_repository, a.branch_name,
                a.home, a.cadence_hours
           FROM area_streams a JOIN producers p ON p.project_id = a.project_id AND p.id = a.producer_id
          WHERE a.project_id = $1 AND a.revision = $2",
    )
    .bind(pid)
    .bind(rev)
    .fetch_all(&mut **tx)
    .await?
    {
        t.attachments.push(Attachment {
            path: r.get(0),
            stream: Stream {
                producer_id: r.get(1),
                producer: r.get(2),
                suite: r.get(3),
                repository: r.get(4),
                branch: r.get(5),
            },
            home: r.get(6),
            cadence_hours: r.get(7),
        });
    }
    Ok(t)
}

/// Every stream of a node's subtree: the project level has every stream (attached or
/// not), Unassigned the streams outside the hierarchy, a node those attached in its subtree.
async fn node_streams(
    tx: &mut Transaction<'_, Postgres>,
    pid: i64,
    tree: &Tree,
    area: Option<&str>,
    cap: i64,
) -> Result<BTreeSet<Stream>, AppError> {
    let attached: BTreeSet<Stream> = tree.attachments.iter().map(|a| a.stream.clone()).collect();
    let refuse = |n: usize| {
        AppError::new(
            ErrorCode::TooLarge,
            format!("this node has more than {cap} streams: open a lower node ({n} found)"),
        )
    };
    let out: BTreeSet<Stream> = match area {
        None | Some("") | Some(UNASSIGNED) => {
            let limit = cap
                .saturating_add(i64::try_from(attached.len()).unwrap_or(i64::MAX))
                .saturating_add(1);
            let seen = all_streams(tx, pid, limit).await?;
            if i64::try_from(seen.len()).unwrap_or(i64::MAX) >= limit {
                return Err(refuse(seen.len()));
            }
            if area == Some(UNASSIGNED) {
                seen.into_iter().filter(|s| !attached.contains(s)).collect()
            } else {
                seen.into_iter().chain(attached).collect()
            }
        }
        Some(p) => {
            if !tree.nodes.contains_key(p) {
                return Err(AppError::new(ErrorCode::NotFound, format!("no area {p}")));
            }
            tree.attachments
                .iter()
                .filter(|a| a.path == p || a.path.starts_with(&format!("{p}/")))
                .map(|a| a.stream.clone())
                .collect()
        }
    };
    if i64::try_from(out.len()).unwrap_or(i64::MAX) > cap {
        return Err(refuse(out.len()));
    }
    Ok(out)
}

async fn all_streams(
    tx: &mut Transaction<'_, Postgres>,
    pid: i64,
    cap: i64,
) -> Result<Vec<Stream>, AppError> {
    Ok(sqlx::query(
        "SELECT DISTINCT r.producer_id, p.name, r.suite, r.branch_repository, r.branch_name
           FROM regressions r JOIN producers p ON p.project_id = r.project_id AND p.id = r.producer_id
          WHERE r.project_id = $1
          ORDER BY 2, 3, 4, 5
          LIMIT $2",
    )
    .bind(pid)
    .bind(cap)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|r| Stream {
        producer_id: r.get(0),
        producer: r.get(1),
        suite: r.get(2),
        repository: r.get(3),
        branch: r.get(4),
    })
    .collect())
}

#[derive(Debug, Clone)]
struct Pick {
    id: i64,
    regression: String,
    state: String,
    started_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default)]
struct Picks {
    latest: Option<Pick>,
    baseline: Option<Pick>,
}

/// The latest regression of each stream and its predecessor (the most recent earlier
/// finished one, `(started_at, id)` order).
async fn pick_regressions(
    tx: &mut Transaction<'_, Postgres>,
    pid: i64,
    streams: &BTreeSet<Stream>,
) -> Result<BTreeMap<Stream, Picks>, AppError> {
    let mut out: BTreeMap<Stream, Picks> = streams
        .iter()
        .map(|s| (s.clone(), Picks::default()))
        .collect();
    if streams.is_empty() {
        return Ok(out);
    }
    let (p, su, re, br): (Vec<i64>, Vec<String>, Vec<String>, Vec<String>) = streams.iter().fold(
        (vec![], vec![], vec![], vec![]),
        |(mut a, mut b, mut c, mut d), s| {
            a.push(s.producer_id);
            b.push(s.suite.clone());
            c.push(s.repository.clone());
            d.push(s.branch.clone());
            (a, b, c, d)
        },
    );
    let rows = sqlx::query(
        "WITH k AS (SELECT * FROM unnest($2::bigint[], $3::text[], $4::text[], $5::text[])
                      AS k(producer_id, suite, repo, branch)),
              l AS (SELECT DISTINCT ON (k.producer_id, k.suite, k.repo, k.branch)
                           k.producer_id, k.suite, k.repo, k.branch,
                           r.id, r.ref, r.state, r.started_at
                      FROM k JOIN regressions r ON r.project_id = $1 AND r.producer_id = k.producer_id
                       AND r.suite = k.suite AND r.branch_repository = k.repo AND r.branch_name = k.branch
                     ORDER BY k.producer_id, k.suite, k.repo, k.branch, r.started_at DESC, r.id DESC)
         SELECT l.producer_id, l.suite, l.repo, l.branch, l.id, l.ref, l.state, l.started_at,
                b.id, b.ref, b.state, b.started_at
           FROM l LEFT JOIN LATERAL (
                SELECT b.id, b.ref, b.state, b.started_at FROM regressions b
                 WHERE b.project_id = $1 AND b.producer_id = l.producer_id AND b.suite = l.suite
                   AND b.branch_repository = l.repo AND b.branch_name = l.branch
                   AND b.state = 'finished' AND (b.started_at, b.id) < (l.started_at, l.id)
                 ORDER BY b.started_at DESC, b.id DESC LIMIT 1) b ON true",
    )
    .bind(pid)
    .bind(&p)
    .bind(&su)
    .bind(&re)
    .bind(&br)
    .fetch_all(&mut **tx)
    .await?;
    for r in rows {
        let key = streams
            .iter()
            .find(|s| {
                s.producer_id == r.get::<i64, _>(0)
                    && s.suite == r.get::<String, _>(1)
                    && s.repository == r.get::<String, _>(2)
                    && s.branch == r.get::<String, _>(3)
            })
            .cloned();
        let Some(key) = key else { continue };
        let latest = Pick {
            id: r.get(4),
            regression: r.get(5),
            state: r.get(6),
            started_at: r.get(7),
        };
        let baseline = r.get::<Option<i64>, _>(8).map(|id| Pick {
            id,
            regression: r.get(9),
            state: r.get(10),
            started_at: r.get(11),
        });
        out.insert(
            key,
            Picks {
                latest: Some(latest),
                baseline,
            },
        );
    }
    Ok(out)
}

/// Counts of the work budget: slots, attempts, report revisions, buckets, distinct builds,
/// slot-build pairs, build references, declared requirements.
type Budget = (i64, i64, i64, i64, i64, i64, i64, i64);

/// Refuses work above the budgets, counted before anything is loaded.
async fn budget(
    tx: &mut Transaction<'_, Postgres>,
    pid: i64,
    ids: &[i64],
    lim: &Limits,
) -> Result<(), AppError> {
    if ids.is_empty() {
        return Ok(());
    }
    let (slots, attempts, revisions, buckets, distinct_builds, pairs, refs, reqs): Budget = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM slots s WHERE s.project_id = $1 AND s.regression_id = ANY($2)),
           (SELECT count(*) FROM attempts a JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
             WHERE a.project_id = $1 AND s.regression_id = ANY($2)),
           (SELECT count(*) FROM attempt_facts f
              JOIN attempts a ON a.project_id = f.project_id AND a.id = f.attempt_id
              JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
             WHERE f.project_id = $1 AND s.regression_id = ANY($2))
           -- Build report revisions as `load` reads them: once per loaded regression that
           -- uses the build (each regression's load probes its builds' history again).
           + (SELECT count(*) FROM (
                SELECT DISTINCT s.regression_id, b.id FROM slots s
                  JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
                  CROSS JOIN LATERAL jsonb_array_elements_text(s.build_reqs) q(req)
                  JOIN build_attempts b ON b.project_id = s.project_id AND b.producer_id = r.producer_id
                                       AND b.build_req = q.req
                 WHERE s.project_id = $1 AND s.regression_id = ANY($2)) rb
              JOIN build_facts f ON f.project_id = $1 AND f.build_attempt_id = rb.id),
           (SELECT count(*) FROM buckets b
              JOIN attempts a ON a.project_id = b.project_id AND a.id = b.attempt_id
                             AND a.head_revision = b.report_revision
              JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
             WHERE b.project_id = $1 AND s.regression_id = ANY($2)),
           (SELECT count(DISTINCT b.id) FROM slots s
              JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
              CROSS JOIN LATERAL jsonb_array_elements_text(s.build_reqs) q(req)
              JOIN build_attempts b ON b.project_id = s.project_id AND b.producer_id = r.producer_id
                                   AND b.build_req = q.req
             WHERE s.project_id = $1 AND s.regression_id = ANY($2)),
           (SELECT count(*) FROM slots s
              JOIN regressions r ON r.project_id = s.project_id AND r.id = s.regression_id
              CROSS JOIN LATERAL jsonb_array_elements_text(s.build_reqs) q(req)
              JOIN build_attempts b ON b.project_id = s.project_id AND b.producer_id = r.producer_id
                                   AND b.build_req = q.req
             WHERE s.project_id = $1 AND s.regression_id = ANY($2)),
           (SELECT coalesce(sum(jsonb_array_length(f.build_refs)), 0)::bigint FROM attempts a
              JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
              JOIN attempt_facts f ON f.project_id = a.project_id AND f.attempt_id = a.id
                                  AND f.report_revision = a.head_revision
             WHERE a.project_id = $1 AND s.regression_id = ANY($2)),
           (SELECT coalesce(sum(jsonb_array_length(s.build_reqs)), 0)::bigint FROM slots s
             WHERE s.project_id = $1 AND s.regression_id = ANY($2))",
    )
    .bind(pid)
    .bind(ids)
    .fetch_one(&mut **tx)
    .await?;
    for (what, n, max) in [
        ("slots", slots, lim.slots),
        ("attempts", attempts, lim.attempts),
        ("report revisions", revisions, lim.fact_revisions),
        ("diagnostic buckets", buckets, lim.buckets),
        ("build attempts", distinct_builds, lim.builds),
        ("slot-build pairs", pairs, lim.build_pairs),
        ("build references", refs, lim.build_refs),
        ("declared build requirements", reqs, lim.requirements),
    ] {
        if n > max {
            return Err(AppError::new(
                ErrorCode::TooLarge,
                format!(
                    "this read needs {n} {what} (at most {max}): open a lower node or a shorter history"
                ),
            ));
        }
    }
    Ok(())
}

/// A loaded regression as health reads it (metrics from the retained facts).
#[allow(clippy::too_many_arguments)]
async fn reg_input(
    tx: &mut Transaction<'_, Postgres>,
    pid: i64,
    regression_id: i64,
    regression: &str,
    state: &str,
    started_at: OffsetDateTime,
    l: &Loaded,
    verdict: Verdict,
    undecided: BTreeSet<Digest>,
) -> Result<RegInput, AppError> {
    // (slot_ref, attempt_seq) → metrics of the head revision (absent before 0020).
    let mut metrics: BTreeMap<(String, u32), (Metrics, Option<i64>)> = BTreeMap::new();
    let rows = sqlx::query(
        "SELECT s.slot_ref, a.attempt_seq, m.wall_s::float8, m.cpu_s::float8, m.cpu_scope,
                m.run_finished_at
           FROM attempt_metrics m
           JOIN attempts a ON a.project_id = m.project_id AND a.id = m.attempt_id
                          AND a.head_revision = m.report_revision
           JOIN slots s ON s.project_id = a.project_id AND s.id = a.slot_id
          WHERE m.project_id = $1 AND s.regression_id = $2",
    )
    .bind(pid)
    .bind(regression_id)
    .fetch_all(&mut **tx)
    .await
    .or_else(|e| match &e {
        sqlx::Error::Database(d) if d.code().as_deref() == Some("42P01") => Ok(vec![]),
        _ => Err(e),
    })?;
    for r in rows {
        let seq = u32::try_from(r.get::<i32, _>(1)).unwrap_or(0);
        let scope: Option<String> = r.get(4);
        metrics.insert(
            (r.get(0), seq),
            (
                Metrics {
                    wall_s: r.get(2),
                    cpu_s: r.get(3),
                    cpu_scope: scope.as_deref().and_then(static_scope),
                },
                r.get::<Option<OffsetDateTime>, _>(5).map(ms),
            ),
        );
    }
    let slots = l
        .slots
        .iter()
        .zip(&l.attempts)
        .map(|((s, v), atts)| {
            let get = |seq: u32| metrics.get(&(s.slot_ref.clone(), seq));
            HealthSlot {
                view: v.clone(),
                required: s.required,
                deciding: s.deciding.map(|d| get(d).map(|m| m.0).unwrap_or_default()),
                terminal_ends: atts
                    .iter()
                    .filter(|a| a.terminal)
                    .map(|a| get(a.attempt_seq).and_then(|m| m.1))
                    .collect(),
            }
        })
        .collect();
    Ok(RegInput {
        regression: regression.to_string(),
        state: match state {
            "finished" => RegState::Finished,
            "sealed" => RegState::Sealed,
            _ => RegState::Unsealed,
        },
        started_at: ms(started_at),
        verdict,
        undecided,
        slots,
    })
}

/// One stream's health, and the expiries of live exceptions on any signature it shows.
async fn stream_health(
    tx: &mut Transaction<'_, Postgres>,
    pid: i64,
    policy: Policy,
    s: &Stream,
    p: &Picks,
    cadence: Option<i64>,
    now: OffsetDateTime,
) -> Result<(StreamHealth, Vec<OffsetDateTime>), AppError> {
    let Some(latest) = &p.latest else {
        return Ok((
            health::summarize(&StreamInput {
                cadence,
                now: ms(now),
                latest: None,
                baseline: None,
            }),
            vec![],
        ));
    };
    let cur = App::load(tx, pid, policy, &latest.regression, Some(&s.producer)).await?;
    let base = match &p.baseline {
        Some(b) => Some((
            b,
            App::load(tx, pid, policy, &b.regression, Some(&s.producer)).await?,
        )),
        None => None,
    };
    health_of(
        tx,
        pid,
        policy,
        s,
        latest,
        &cur,
        base.as_ref().map(|(p, l)| (*p, l)),
        cadence,
        now,
    )
    .await
}

/// A loaded regression's health against its loaded predecessor: dispositions and both merge
/// verdicts as the comparison computes them (same snapshot, same clock), and the expiries
/// of every live exception on a signature either shows (used or not: an expiry can change a
/// disposition or a verdict).
#[allow(clippy::too_many_arguments)]
async fn health_of(
    tx: &mut Transaction<'_, Postgres>,
    pid: i64,
    policy: Policy,
    s: &Stream,
    latest: &Pick,
    cur: &Loaded,
    base: Option<(&Pick, &Loaded)>,
    cadence: Option<i64>,
    now: OffsetDateTime,
) -> Result<(StreamHealth, Vec<OffsetDateTime>), AppError> {
    let cmp = App::comparison_of(
        tx,
        pid,
        policy,
        cur,
        base.map(|(_, l)| l),
        base.map(|(p, _)| p.regression.clone()),
        String::new(),
        now,
    )
    .await?;
    let undecided: BTreeSet<Digest> = cmp
        .comparison
        .rows
        .iter()
        .filter(|r: &&compare::Row| r.group.is_none())
        .filter(|r| {
            cmp.decisions
                .get(r.signature.as_str())
                .is_some_and(|d| d.disposition == "needs_decision")
        })
        .map(|r| r.signature.clone())
        .collect();
    let verdict = verdict_of(&cmp.finish["merge_verdict"]);
    let base_input = match base {
        Some((b, bl)) => {
            let bc =
                App::comparison_of(tx, pid, policy, bl, None, None, String::new(), now).await?;
            Some(
                reg_input(
                    tx,
                    pid,
                    b.id,
                    &b.regression,
                    &b.state,
                    b.started_at,
                    bl,
                    verdict_of(&bc.finish["merge_verdict"]),
                    BTreeSet::new(),
                )
                .await?,
            )
        }
        None => None,
    };
    let cur_input = reg_input(
        tx,
        pid,
        latest.id,
        &latest.regression,
        &latest.state,
        latest.started_at,
        cur,
        verdict,
        undecided,
    )
    .await?;
    let mut fps: BTreeSet<String> = BTreeSet::new();
    for l in std::iter::once(cur).chain(base.map(|(_, l)| l)) {
        for (_, v) in &l.slots {
            fps.extend(v.signatures.keys().map(|d: &Digest| d.to_string()));
        }
    }
    let expiries: Vec<OffsetDateTime> = sqlx::query_scalar(
        "SELECT e.expires_at FROM exceptions e
           JOIN signatures g ON g.project_id = e.project_id AND g.id = e.signature_id
          WHERE e.project_id = $1 AND e.branch = $2 AND e.suite = $3
            AND e.revoked_at IS NULL AND e.superseded_by IS NULL AND e.expires_at > $4
            AND g.fingerprint = ANY($5)",
    )
    .bind(pid)
    .bind(format!("{}/{}", s.repository, s.branch))
    .bind(&s.suite)
    .bind(now)
    .bind(fps.into_iter().collect::<Vec<_>>())
    .fetch_all(&mut **tx)
    .await?;
    Ok((
        health::summarize(&StreamInput {
            cadence,
            now: ms(now),
            latest: Some(cur_input),
            baseline: base_input,
        }),
        expiries,
    ))
}
