//! Regression health (dashboard): one stream's latest regression against its predecessor,
//! and roll-ups over a set of streams. Pure; the server loads both regressions and both
//! readiness verdicts in one snapshot with one clock.
//!
//! Counting is over **required** slots. A signature counts on failed or blocked slots (as
//! the comparison); synthetic build/elaboration groups are never signatures. Trends compare
//! the *matched population*: required slots whose configuration settled in both
//! regressions, so configurations added or removed cannot hide or invent a change.

use std::collections::{BTreeMap, BTreeSet};

use dviscope_model::canonical::Digest;
use serde::Serialize;

use crate::compare::SlotView;

/// Milliseconds since the Unix epoch (UTC), or a duration in milliseconds. The core reads
/// no clock: the server converts its clock and its timestamps.
pub type Millis = i64;

/// One hour in milliseconds.
pub const HOUR_MS: Millis = 3_600_000;
use crate::readiness::Verdict;
use crate::settlement::{FailReason, SlotState};

/// Collection state of a regression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegState {
    /// Still being declared.
    Unsealed,
    /// Declared, not finished.
    Sealed,
    /// Finished.
    Finished,
}

/// Runner metrics of one attempt (each unknown when not reported).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Metrics {
    /// Wall time, seconds.
    pub wall_s: Option<f64>,
    /// CPU time, seconds.
    pub cpu_s: Option<f64>,
    /// What `cpu_s` covers (`process`, `process_and_waited_children`, `job`).
    pub cpu_scope: Option<&'static str>,
}

/// One slot as health reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthSlot {
    /// The settled view (state, configuration, signatures).
    pub view: SlotView,
    /// Required by the manifest.
    pub required: bool,
    /// Metrics of the deciding attempt, when there is one.
    pub deciding: Option<Metrics>,
    /// Runner end of each **terminal** attempt of the slot (`None` = not reported);
    /// running attempts are not listed.
    pub terminal_ends: Vec<Option<Millis>>,
}

/// One regression as health reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct RegInput {
    /// Reference.
    pub regression: String,
    /// Collection state.
    pub state: RegState,
    /// Start.
    pub started_at: Millis,
    /// Readiness verdict, evaluated in the same snapshot and clock as the other.
    pub verdict: Verdict,
    /// Signatures needing a triage decision.
    pub undecided: BTreeSet<Digest>,
    /// Slots.
    pub slots: Vec<HealthSlot>,
}

/// One stream's inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamInput {
    /// Expected cadence (`None`: never overdue).
    pub cadence: Option<Millis>,
    /// Evaluation clock.
    pub now: Millis,
    /// Latest regression.
    pub latest: Option<RegInput>,
    /// Its predecessor (the most recent earlier finished regression of the stream).
    pub baseline: Option<RegInput>,
}

/// Slot counts over required slots.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Required slots.
    pub required: u64,
    /// Passed.
    pub passed: u64,
    /// Failed (timeouts included).
    pub failed: u64,
    /// Of the failed: timeouts.
    pub of_which_timeout: u64,
    /// Blocked.
    pub blocked: u64,
    /// Missing.
    pub missing: u64,
    /// Running.
    pub running: u64,
    /// Cancelled.
    pub cancelled: u64,
    /// Skipped.
    pub skipped: u64,
    /// Optional slots (outside every rate).
    pub optional: u64,
}

impl Counts {
    /// Missing, running, cancelled and skipped required slots.
    #[must_use]
    pub fn not_settled(&self) -> u64 {
        self.missing + self.running + self.cancelled + self.skipped
    }

    fn add(&mut self, o: &Counts) {
        self.required += o.required;
        self.passed += o.passed;
        self.failed += o.failed;
        self.of_which_timeout += o.of_which_timeout;
        self.blocked += o.blocked;
        self.missing += o.missing;
        self.running += o.running;
        self.cancelled += o.cancelled;
        self.skipped += o.skipped;
        self.optional += o.optional;
    }
}

/// Signature sets of a regression against its predecessor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Signatures {
    /// All signatures of the regression.
    pub all: BTreeSet<Digest>,
    /// New: absent from the predecessor although one of its configurations settled there.
    pub new: BTreeSet<Digest>,
    /// Absent from the predecessor, none of its configurations settled there.
    pub unknown: BTreeSet<Digest>,
    /// In both.
    pub persistent: BTreeSet<Digest>,
    /// In the predecessor only, one of its configurations settled again now.
    pub no_longer_observed: BTreeSet<Digest>,
    /// In the predecessor only, none of its configurations settled now.
    pub config_not_run: BTreeSet<Digest>,
    /// Needing a triage decision.
    pub undecided: BTreeSet<Digest>,
}

/// Runtime and CPU of a regression.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cost {
    /// Latest observed runner end over all attempts.
    pub last_end: Option<Millis>,
    /// Some terminal attempt did not report its end.
    pub last_end_partial: bool,
    /// The latest end is before the regression's start (clock problem): no elapsed time.
    pub times_inconsistent: bool,
    /// `last_end` − start, seconds.
    pub elapsed_s: Option<f64>,
    /// Longest deciding attempt, seconds.
    pub longest_run_s: Option<f64>,
    /// Sum of deciding attempts' wall time, seconds.
    pub machine_s: Option<f64>,
    /// A deciding attempt did not report its wall time.
    pub machine_partial: bool,
    /// Sum of deciding attempts' CPU time, seconds (over the measured ones).
    pub cpu_s: Option<f64>,
    /// Required slots with a deciding attempt.
    pub cpu_slots: u64,
    /// Of those, with a measured CPU time.
    pub cpu_measured: u64,
    /// Scopes of the measured CPU times.
    pub cpu_scopes: BTreeSet<&'static str>,
    /// Measured CPU times without a scope.
    pub cpu_unscoped: u64,
}

impl Cost {
    /// Every deciding attempt measured its CPU time (and there is at least one: nothing
    /// measured is unknown, not complete).
    #[must_use]
    pub fn cpu_complete(&self) -> bool {
        self.cpu_slots > 0 && self.cpu_measured == self.cpu_slots
    }

    /// The single known CPU scope of a complete measurement (`None`: incomplete, unknown
    /// or mixed scopes).
    #[must_use]
    pub fn cpu_scope(&self) -> Option<&'static str> {
        if self.cpu_complete() && self.cpu_unscoped == 0 && self.cpu_scopes.len() == 1 {
            self.cpu_scopes.iter().next().copied()
        } else {
            None
        }
    }
}

/// Deltas of cost between a regression and its predecessor: `None` when either side is
/// partial or not comparable (a missing metric never reads as an improvement).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CostDeltas {
    /// Elapsed, seconds.
    pub elapsed_s: Option<f64>,
    /// Machine time, seconds.
    pub machine_s: Option<f64>,
    /// CPU, seconds: both complete with the same single known scope.
    pub cpu_s: Option<f64>,
}

/// See [`CostDeltas`].
#[must_use]
pub fn cost_deltas(now: &Cost, before: &Cost) -> CostDeltas {
    CostDeltas {
        elapsed_s: match (now.elapsed_s, before.elapsed_s) {
            (Some(a), Some(b)) if !now.last_end_partial && !before.last_end_partial => Some(a - b),
            _ => None,
        },
        machine_s: match (now.machine_s, before.machine_s) {
            (Some(a), Some(b)) if !now.machine_partial && !before.machine_partial => Some(a - b),
            _ => None,
        },
        cpu_s: match (now.cpu_scope(), before.cpu_scope(), now.cpu_s, before.cpu_s) {
            (Some(x), Some(y), Some(a), Some(b)) if x == y => Some(a - b),
            _ => None,
        },
    }
}

/// Trend against the predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trend {
    /// No regression yet.
    NoData,
    /// The latest regression is not finished.
    Running,
    /// No predecessor.
    NoBaseline,
    /// No configuration settled in both.
    NotComparable,
    /// No failure, nothing unsettled, readiness pass.
    Green,
    /// Failures persist without getting worse (or readiness not pass, not worse).
    Yellow,
    /// Worse than the predecessor.
    Red,
}

impl Trend {
    /// A grey state (no colour).
    #[must_use]
    pub fn is_grey(self) -> bool {
        matches!(
            self,
            Self::NoData | Self::Running | Self::NoBaseline | Self::NotComparable
        )
    }
}

/// Why a trend is red.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Worse {
    /// New signatures.
    NewSignatures,
    /// The matched failed+blocked rate rose.
    FailureRate,
    /// More required slots without a result.
    NotSettled,
    /// The readiness verdict got worse.
    Readiness,
}

/// One stream's health.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamHealth {
    /// Latest regression reference.
    pub latest: Option<String>,
    /// Its collection state.
    pub state: Option<RegState>,
    /// Its start.
    pub started_at: Option<Millis>,
    /// Predecessor reference.
    pub baseline: Option<String>,
    /// Readiness verdict of the latest.
    pub verdict: Option<Verdict>,
    /// Readiness verdict of the predecessor.
    pub baseline_verdict: Option<Verdict>,
    /// Counts of the latest.
    pub counts: Counts,
    /// Counts of the predecessor.
    pub baseline_counts: Option<Counts>,
    /// Required slots whose configuration settled in both.
    pub matched: u64,
    /// Failed+blocked among them now; the predecessor's matched slots and failed+blocked.
    pub matched_bad: u64,
    /// See `matched_bad`.
    pub baseline_matched: u64,
    /// See `matched_bad`.
    pub baseline_matched_bad: u64,
    /// Configurations declared (required) now and not before, and the reverse.
    pub configs_added: u64,
    /// See `configs_added`.
    pub configs_removed: u64,
    /// Signature sets.
    pub signatures: Signatures,
    /// Cost of the latest.
    pub cost: Cost,
    /// Cost of the predecessor.
    pub baseline_cost: Option<Cost>,
    /// Trend.
    pub trend: Trend,
    /// Why red.
    pub worse: Vec<Worse>,
    /// Overdue by its cadence.
    pub overdue: bool,
    /// When it becomes overdue (a future instant only).
    pub overdue_at: Option<Millis>,
}

/// Pass rate in percent (N/A when no required slot).
#[must_use]
pub fn pass_rate(c: &Counts) -> Option<f64> {
    // Slot counts stay far below 2^52: the conversion is exact.
    #[allow(clippy::cast_precision_loss)]
    (c.required > 0).then(|| 100.0 * c.passed as f64 / c.required as f64)
}

fn is_bad(s: SlotState) -> bool {
    matches!(s, SlotState::Failed(_) | SlotState::Blocked(_))
}

fn settled(s: SlotState) -> bool {
    matches!(
        s,
        SlotState::Passed | SlotState::Failed(_) | SlotState::Blocked(_)
    )
}

fn counts(r: &RegInput) -> Counts {
    let mut c = Counts::default();
    for s in &r.slots {
        if !s.required {
            c.optional += 1;
            continue;
        }
        c.required += 1;
        match s.view.state {
            SlotState::Passed => c.passed += 1,
            SlotState::Failed(f) => {
                c.failed += 1;
                if f == FailReason::Timeout {
                    c.of_which_timeout += 1;
                }
            }
            SlotState::Blocked(_) => c.blocked += 1,
            SlotState::Missing => c.missing += 1,
            SlotState::Running => c.running += 1,
            SlotState::Cancelled => c.cancelled += 1,
            SlotState::Skipped => c.skipped += 1,
        }
    }
    c
}

fn settled_configs(r: &RegInput) -> BTreeSet<&Digest> {
    r.slots
        .iter()
        .filter(|s| s.required && settled(s.view.state))
        .map(|s| &s.view.config)
        .collect()
}

/// Signature → the configurations of the slots showing it (failed or blocked, required).
fn sig_configs(r: &RegInput) -> BTreeMap<&Digest, BTreeSet<&Digest>> {
    let mut m: BTreeMap<&Digest, BTreeSet<&Digest>> = BTreeMap::new();
    for s in r
        .slots
        .iter()
        .filter(|s| s.required && is_bad(s.view.state))
    {
        for sig in s.view.signatures.keys() {
            m.entry(sig).or_default().insert(&s.view.config);
        }
    }
    m
}

fn signatures(cur: &RegInput, base: Option<&RegInput>) -> Signatures {
    let now = sig_configs(cur);
    let all: BTreeSet<Digest> = now.keys().map(|d| (*d).clone()).collect();
    // Only signatures of required failures count, undecided ones included.
    let undecided = cur.undecided.intersection(&all).cloned().collect();
    let mut out = Signatures {
        all,
        undecided,
        ..Signatures::default()
    };
    let Some(base) = base else {
        out.unknown.clone_from(&out.all);
        return out;
    };
    let before = sig_configs(base);
    let base_settled = settled_configs(base);
    let cur_settled = settled_configs(cur);
    for (sig, cfgs) in &now {
        if before.contains_key(sig) {
            out.persistent.insert((*sig).clone());
        } else if cfgs.iter().any(|c| base_settled.contains(c)) {
            out.new.insert((*sig).clone());
        } else {
            out.unknown.insert((*sig).clone());
        }
    }
    for (sig, cfgs) in &before {
        if now.contains_key(sig) {
            continue;
        }
        if cfgs.iter().any(|c| cur_settled.contains(c)) {
            out.no_longer_observed.insert((*sig).clone());
        } else {
            out.config_not_run.insert((*sig).clone());
        }
    }
    out
}

fn cost(r: &RegInput) -> Cost {
    let mut c = Cost::default();
    let mut walls = vec![];
    let mut cpu = 0.0;
    for s in r.slots.iter().filter(|s| s.required) {
        for e in &s.terminal_ends {
            match e {
                Some(t) => c.last_end = Some(c.last_end.map_or(*t, |l| l.max(*t))),
                None => c.last_end_partial = true,
            }
        }
        if let Some(m) = &s.deciding {
            c.cpu_slots += 1;
            match m.wall_s {
                Some(w) => walls.push(w),
                None => c.machine_partial = true,
            }
            if let Some(x) = m.cpu_s {
                c.cpu_measured += 1;
                cpu += x;
                match m.cpu_scope {
                    Some(sc) => {
                        c.cpu_scopes.insert(sc);
                    }
                    None => c.cpu_unscoped += 1,
                }
            }
        }
    }
    // An end before the start is inconsistent: no elapsed time (never a fake improvement).
    c.elapsed_s = c.last_end.and_then(|e| {
        // Millisecond differences stay far below 2^52: the conversion is exact.
        #[allow(clippy::cast_precision_loss)]
        let s = (e - r.started_at) as f64 / 1000.0;
        if s < 0.0 {
            c.times_inconsistent = true;
            None
        } else {
            Some(s)
        }
    });
    c.longest_run_s = walls.iter().copied().reduce(f64::max);
    c.machine_s = (!walls.is_empty()).then(|| walls.iter().sum());
    c.cpu_s = (c.cpu_measured > 0).then_some(cpu);
    c
}

fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Pass => 0,
        Verdict::AcceptedWithExceptions => 1,
        Verdict::InsufficientEvidence => 2,
        Verdict::Fail => 3,
    }
}

/// Grace after a missed cadence: a quarter of it, at least two hours.
fn grace(cadence: Millis) -> Millis {
    (cadence / 4).max(2 * HOUR_MS)
}

/// One stream's health.
#[must_use]
pub fn summarize(input: &StreamInput) -> StreamHealth {
    let latest = input.latest.as_ref();
    let base = input.baseline.as_ref();
    let counts_now = latest.map(counts).unwrap_or_default();
    let counts_before = base.map(counts);
    // Matched population: required slots of configurations settled in both; each side's
    // rate over its own slots of those configurations.
    let (mut matched, mut bad_now, mut base_matched, mut bad_before) = (0, 0, 0, 0);
    // Declared configurations added or removed (a declaration change, not an evidence one:
    // a configuration that went from passed to missing is still declared).
    let (mut added, mut removed) = (0, 0);
    if let (Some(l), Some(b)) = (latest, base) {
        let declared = |r: &RegInput| -> BTreeSet<Digest> {
            r.slots
                .iter()
                .filter(|s| s.required)
                .map(|s| s.view.config.clone())
                .collect()
        };
        let (ld, bd) = (declared(l), declared(b));
        added = ld.difference(&bd).count() as u64;
        removed = bd.difference(&ld).count() as u64;
        // A configuration is matched when it settled in both; its unsettled sibling slots
        // (same digest) stay out of the rates and count as `not_settled`.
        let ls = settled_configs(l);
        let bs = settled_configs(b);
        let common: BTreeSet<&Digest> = ls.intersection(&bs).copied().collect();
        let bad_in = |r: &RegInput| {
            r.slots
                .iter()
                .filter(|s| s.required && settled(s.view.state) && common.contains(&s.view.config))
                .fold((0u64, 0u64), |(n, bad), s| {
                    (n + 1, bad + u64::from(is_bad(s.view.state)))
                })
        };
        (matched, bad_now) = bad_in(l);
        (base_matched, bad_before) = bad_in(b);
    }
    let sigs = latest.map(|l| signatures(l, base)).unwrap_or_default();
    let (overdue, overdue_at) = match (input.cadence, latest) {
        (Some(c), Some(l)) => {
            let start = l.started_at.min(input.now);
            let deadline = start + c + grace(c);
            (
                input.now >= deadline,
                (deadline > input.now).then_some(deadline),
            )
        }
        _ => (false, None),
    };
    let mut worse = vec![];
    let trend = match (latest, base) {
        (None, _) => Trend::NoData,
        (Some(l), _) if l.state != RegState::Finished => Trend::Running,
        (Some(_), None) => Trend::NoBaseline,
        (Some(_), Some(_)) if matched == 0 => Trend::NotComparable,
        (Some(l), Some(b)) => {
            if !sigs.new.is_empty() {
                worse.push(Worse::NewSignatures);
            }
            // rate_now > rate_before  ⇔  bad_now * base_matched > bad_before * matched
            if u128::from(bad_now) * u128::from(base_matched)
                > u128::from(bad_before) * u128::from(matched)
            {
                worse.push(Worse::FailureRate);
            }
            if counts_now.not_settled() > counts_before.unwrap_or_default().not_settled() {
                worse.push(Worse::NotSettled);
            }
            if verdict_rank(l.verdict) > verdict_rank(b.verdict) {
                worse.push(Worse::Readiness);
            }
            if !worse.is_empty() {
                Trend::Red
            } else if counts_now.failed == 0
                && counts_now.blocked == 0
                && counts_now.not_settled() == 0
                && l.verdict == Verdict::Pass
            {
                Trend::Green
            } else {
                Trend::Yellow
            }
        }
    };
    StreamHealth {
        latest: latest.map(|l| l.regression.clone()),
        state: latest.map(|l| l.state),
        started_at: latest.map(|l| l.started_at),
        baseline: base.map(|b| b.regression.clone()),
        verdict: latest.map(|l| l.verdict),
        baseline_verdict: base.map(|b| b.verdict),
        counts: counts_now,
        baseline_counts: counts_before,
        matched,
        matched_bad: bad_now,
        baseline_matched: base_matched,
        baseline_matched_bad: bad_before,
        configs_added: added,
        configs_removed: removed,
        signatures: sigs,
        cost: latest.map(cost).unwrap_or_default(),
        baseline_cost: base.map(cost),
        trend,
        worse,
        overdue,
        overdue_at,
    }
}

/// Colour of a readiness verdict (grey for insufficient evidence).
#[must_use]
pub fn verdict_colour(v: Verdict) -> Colour {
    match v {
        Verdict::Pass => Colour::Green,
        Verdict::AcceptedWithExceptions => Colour::Yellow,
        Verdict::Fail => Colour::Red,
        Verdict::InsufficientEvidence => Colour::Grey,
    }
}

/// A badge colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Colour {
    /// No colour (unknown or not comparable).
    Grey,
    /// Good.
    Green,
    /// Not worse, not clean.
    Yellow,
    /// Bad or worse.
    Red,
}

/// A node's health: the roll-up of the distinct streams of its subtree.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct NodeHealth {
    /// Distinct streams.
    pub streams: u64,
    /// Summed counts of every stream's latest regression.
    pub counts: Counts,
    /// Streams with a predecessor: deltas are over these only, so a stream that appears
    /// or has no predecessor never reads as a change.
    pub compared_streams: u64,
    /// Latest counts of the compared streams.
    pub compared_counts: Counts,
    /// Their predecessors' counts.
    pub compared_baseline_counts: Counts,
    /// Lowest pass rate among streams that have one.
    pub worst_rate: Option<f64>,
    /// Streams whose latest regression has no required test (an emptied run list shows).
    pub zero_test_streams: u64,
    /// Signature unions (one identity counted once across streams).
    pub all: BTreeSet<Digest>,
    /// See `all`.
    pub new: BTreeSet<Digest>,
    /// See `all`.
    pub unknown: BTreeSet<Digest>,
    /// See `all`.
    pub persistent: BTreeSet<Digest>,
    /// See `all`.
    pub no_longer_observed: BTreeSet<Digest>,
    /// See `all`.
    pub config_not_run: BTreeSet<Digest>,
    /// Needing a decision in any stream.
    pub undecided: BTreeSet<Digest>,
    /// Worst coloured trend (`None`: no stream has a colour).
    pub trend: Option<Colour>,
    /// Worst coloured readiness.
    pub readiness: Option<Colour>,
    /// Streams per grey state (`no_data`, `running`, `no_baseline`, `not_comparable`,
    /// `insufficient_evidence`, `overdue`).
    pub grey: BTreeMap<&'static str, u64>,
    /// Slowest stream's elapsed time, seconds.
    pub elapsed_s: Option<f64>,
    /// Some stream's elapsed time is partial, inconsistent or unknown.
    pub elapsed_partial: bool,
    /// Summed CPU over the measured deciding attempts, seconds.
    pub cpu_s: Option<f64>,
    /// Deciding attempts and how many measured CPU (coverage).
    pub cpu_slots: u64,
    /// See `cpu_slots`.
    pub cpu_measured: u64,
    /// Every stream has a latest regression with complete CPU.
    pub cpu_complete: bool,
    /// The single known scope of every stream's complete CPU (`None`: not comparable).
    pub cpu_scope: Option<&'static str>,
    /// Summed per-stream CPU deltas of the compared streams, only when every one of them
    /// has a comparable delta.
    pub cpu_delta_s: Option<f64>,
}

fn trend_colour(t: Trend) -> Option<Colour> {
    match t {
        Trend::Green => Some(Colour::Green),
        Trend::Yellow => Some(Colour::Yellow),
        Trend::Red => Some(Colour::Red),
        _ => None,
    }
}

fn grey_name(t: Trend) -> &'static str {
    match t {
        Trend::NoData => "no_data",
        Trend::Running => "running",
        Trend::NoBaseline => "no_baseline",
        _ => "not_comparable",
    }
}

/// Roll-up over the distinct streams of a subtree (the caller resolves links and own
/// streams so that each stream appears once).
#[must_use]
pub fn rollup<'a, I>(streams: I) -> NodeHealth
where
    I: IntoIterator<Item = &'a StreamHealth> + Clone,
{
    let mut n = NodeHealth {
        cpu_complete: true,
        ..NodeHealth::default()
    };
    let mut cpu = 0.0;
    let mut any_cpu = false;
    let mut cpu_delta = Some(0.0);
    for h in streams.clone() {
        n.streams += 1;
        n.counts.add(&h.counts);
        if let Some(b) = &h.baseline_counts {
            n.compared_streams += 1;
            n.compared_counts.add(&h.counts);
            n.compared_baseline_counts.add(b);
            let d = h
                .baseline_cost
                .as_ref()
                .and_then(|bc| cost_deltas(&h.cost, bc).cpu_s);
            cpu_delta = cpu_delta.zip(d).map(|(a, b)| a + b);
        }
        if let Some(r) = pass_rate(&h.counts) {
            n.worst_rate = Some(n.worst_rate.map_or(r, |w: f64| w.min(r)));
        }
        if h.latest.is_some() && h.counts.required == 0 {
            n.zero_test_streams += 1;
        }
        let s = &h.signatures;
        for (into, from) in [
            (&mut n.all, &s.all),
            (&mut n.new, &s.new),
            (&mut n.unknown, &s.unknown),
            (&mut n.persistent, &s.persistent),
            (&mut n.no_longer_observed, &s.no_longer_observed),
            (&mut n.config_not_run, &s.config_not_run),
            (&mut n.undecided, &s.undecided),
        ] {
            into.extend(from.iter().cloned());
        }
        match trend_colour(h.trend) {
            Some(c) => n.trend = Some(n.trend.map_or(c, |w| w.max(c))),
            None => *n.grey.entry(grey_name(h.trend)).or_default() += 1,
        }
        match h.verdict.map(verdict_colour) {
            Some(Colour::Grey) => *n.grey.entry("insufficient_evidence").or_default() += 1,
            Some(c) => n.readiness = Some(n.readiness.map_or(c, |w| w.max(c))),
            None => {}
        }
        if h.overdue {
            *n.grey.entry("overdue").or_default() += 1;
        }
        match h.cost.elapsed_s {
            Some(e) => n.elapsed_s = Some(n.elapsed_s.map_or(e, |m: f64| m.max(e))),
            None => n.elapsed_partial = true,
        }
        if h.cost.last_end_partial || h.cost.times_inconsistent {
            n.elapsed_partial = true;
        }
        if let Some(c) = h.cost.cpu_s {
            cpu += c;
            any_cpu = true;
        }
        n.cpu_slots += h.cost.cpu_slots;
        n.cpu_measured += h.cost.cpu_measured;
        if !h.cost.cpu_complete() || h.latest.is_none() {
            n.cpu_complete = false;
        }
    }
    n.cpu_s = any_cpu.then_some(cpu);
    let scopes: BTreeSet<Option<&'static str>> =
        streams.into_iter().map(|h| h.cost.cpu_scope()).collect();
    n.cpu_scope = match scopes.into_iter().collect::<Vec<_>>().as_slice() {
        [Some(s)] if n.cpu_complete => Some(*s),
        _ => None,
    };
    n.cpu_delta_s = if n.compared_streams > 0 {
        cpu_delta
    } else {
        None
    };
    n
}

/// Largest hierarchy file.
pub const MAX_HIERARCHY_BYTES: usize = 4 * 1024 * 1024;

/// Parses a `dviscope.hierarchy/1` YAML file (bounded: no aliases, one document).
///
/// # Errors
/// Too large, not YAML, or not a hierarchy.
pub fn parse_hierarchy(text: &str) -> Result<dviscope_model::wire::hierarchy::Hierarchy, String> {
    if text.len() > MAX_HIERARCHY_BYTES {
        return Err(format!("file larger than {MAX_HIERARCHY_BYTES} bytes"));
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_depth = crate::packs::limits::MAX_YAML_DEPTH;
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_documents = 1;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    serde_saphyr::from_str_with_options(text, options)
        .map_err(|e| e.to_string().lines().next().unwrap_or_default().to_string())
}

#[cfg(test)]
mod tests;
