//! Feature mode: checklist items judged against one candidate regression
//! per test and configuration.
//!
//! **Selection** comes first and uses only the permanent candidate index: for each test and
//! configuration matching an item's selectors, the candidate is the most recent regression
//! of the branch containing such a slot, by **execution time** (the reported `started_at`;
//! ties by regression ID). A regression whose reported start is implausibly later than its
//! receipt has *uncertain time*: it is ordered by receipt time and cannot be fresh. The
//! candidate is kept whatever its facts turn out to be (expired, incomplete, quarantined):
//! an older regression's pass never reappears.
//!
//! **Judgement** then reads the candidate's settled slots. Item states, most severe first:
//! `failed`, `insufficient`, `missing`, `outdated`, `unreviewed`, `satisfied`; every reason
//! is kept. Times are Unix microseconds (full precision; no clock is read here).

use std::collections::BTreeMap;

use dviscope_model::wire::checklist::ChecklistItem;
use serde::Serialize;

use crate::settlement::{FailReason, SlotState};

/// Largest checklist file.
pub const MAX_CHECKLIST_BYTES: usize = 1 << 20;

/// Parses a `dviscope.checklist/1.0` YAML file (bounded: no aliases or anchors, one
/// document, limited depth and size).
///
/// # Errors
/// Too large, not YAML, or not a checklist (the message is the parser's first line).
pub fn parse_checklist(text: &str) -> Result<dviscope_model::wire::checklist::Checklist, String> {
    if text.len() > MAX_CHECKLIST_BYTES {
        return Err(format!("file larger than {MAX_CHECKLIST_BYTES} bytes"));
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

/// A start reported this much later than its receipt is implausible (uncertain time), in
/// microseconds (5 minutes).
pub const SKEW_TOLERANCE_MICROS: i64 = 300 * 1_000_000;
/// Most test/configuration pairs one item may select.
pub const MAX_PAIRS: usize = 1000;
/// One day in microseconds.
const DAY: i64 = 86_400 * 1_000_000;

/// One candidate-index row: a regression of the branch containing a slot of this test and
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// Test name.
    pub test: String,
    /// Configuration digest.
    pub config_digest: String,
    /// Simulator label (vendor) of the configuration.
    pub simulator: String,
    /// Regression row ID (tie-breaker).
    pub regression_id: i64,
    /// Regression reference.
    pub regression_ref: String,
    /// Reported start (execution time).
    pub started_at: i64,
    /// When the server first received the regression (`None`: unknown, e.g. a legacy
    /// regression whose receipt expired; its time is uncertain).
    pub received_at: Option<i64>,
    /// With an unknown receipt time: an upper bound of it (orders the regression at its
    /// latest possible execution time).
    pub receipt_bound: Option<i64>,
    /// The regression's facts still exist (not expired or deleted).
    pub live: bool,
}

impl IndexEntry {
    /// Reported start implausibly later than the receipt.
    #[must_use]
    pub fn time_uncertain(&self) -> bool {
        self.received_at
            .is_none_or(|r| self.started_at > r.saturating_add(SKEW_TOLERANCE_MICROS))
    }

    fn order_key(&self) -> (i64, i64) {
        let t = match self.received_at {
            // A skewed start: ordered by receipt time as a last resort.
            Some(r) if self.time_uncertain() => r,
            Some(_) => self.started_at,
            // Unknown receipt time: its latest possible execution time (the bound plus the
            // tolerance), or newest without a bound; it never lets an older pass win, and
            // only a regression provably run later outranks it.
            None => self
                .receipt_bound
                .map_or(i64::MAX, |b| b.saturating_add(SKEW_TOLERANCE_MICROS)),
        };
        (t, self.regression_id)
    }
}

/// `*` and `?` globs over test names.
#[must_use]
pub fn glob(pattern: &str, s: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), s.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None::<usize>, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn config_matches(selectors: &[String], e: &IndexEntry) -> bool {
    selectors.is_empty()
        || selectors.iter().any(|s| {
            if s.starts_with("sha256:") {
                *s == e.config_digest
            } else {
                s.eq_ignore_ascii_case(&e.simulator)
            }
        })
}

/// Whether an item applies to a repository-qualified branch.
#[must_use]
pub fn applies(item: &ChecklistItem, branch: &str) -> bool {
    let a = &item.applies_to;
    a.branch.as_deref().is_none_or(|b| b == branch)
        && (a.repositories.is_empty()
            || branch
                .split_once('/')
                .is_some_and(|(repo, _)| a.repositories.iter().any(|r| r == repo)))
}

/// Requirement selectors that match nothing: each test glob, on each configuration
/// selector (or any configuration), must match at least one indexed test/configuration.
#[must_use]
pub fn unmatched(item: &ChecklistItem, entries: &[IndexEntry]) -> Vec<String> {
    let mut out = vec![];
    for g in &item.requires.tests {
        let tests: Vec<&IndexEntry> = entries.iter().filter(|e| glob(g, &e.test)).collect();
        if item.requires.configs.is_empty() {
            if tests.is_empty() {
                out.push(g.clone());
            }
            continue;
        }
        for c in &item.requires.configs {
            if !tests
                .iter()
                .any(|e| config_matches(std::slice::from_ref(c), e))
            {
                out.push(format!("{g} on {c}"));
            }
        }
    }
    out
}

/// The selected candidate of one test and configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The candidate's index row.
    pub candidate: IndexEntry,
}

/// Selection failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// The selectors match more than [`MAX_PAIRS`] test/configuration pairs.
    TooBroad(usize),
}

/// Selects one candidate per matching test and configuration (sorted by test, config).
///
/// # Errors
/// More than [`MAX_PAIRS`] pairs.
pub fn select(item: &ChecklistItem, entries: &[IndexEntry]) -> Result<Vec<Selection>, SelectError> {
    let mut best: BTreeMap<(&str, &str), &IndexEntry> = BTreeMap::new();
    for e in entries {
        if !item.requires.tests.iter().any(|g| glob(g, &e.test))
            || !config_matches(&item.requires.configs, e)
        {
            continue;
        }
        let k = (e.test.as_str(), e.config_digest.as_str());
        match best.get(&k) {
            Some(b) if b.order_key() >= e.order_key() => {}
            _ => {
                best.insert(k, e);
            }
        }
    }
    if best.len() > MAX_PAIRS {
        return Err(SelectError::TooBroad(best.len()));
    }
    Ok(best
        .into_values()
        .map(|e| Selection {
            candidate: e.clone(),
        })
        .collect())
}

/// The candidate regression's facts for one test and configuration (`None`: expired or
/// deleted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFacts {
    /// Sealed and finished.
    pub complete: bool,
    /// The slots of this test and configuration: (seed, settled state).
    pub slots: Vec<(String, SlotState)>,
}

/// Item states, most severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// A required test failed in its candidate.
    Failed,
    /// The candidate's evidence cannot settle it (ineligible, quarantined, too broad).
    Insufficient,
    /// No candidate, an expired or incomplete candidate, missing results or seeds.
    Missing,
    /// Too old, or time uncertain.
    Outdated,
    /// External evidence not attested (or the attestation no longer matches).
    Unreviewed,
    /// Every requirement met.
    Satisfied,
}

/// One test/configuration of an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairResult {
    /// Test.
    pub test: String,
    /// Configuration digest.
    pub config_digest: String,
    /// Simulator label.
    pub simulator: String,
    /// Candidate regression.
    pub regression: String,
    /// Candidate execution time.
    pub started_at: i64,
    /// Ordered by receipt time (reported start implausible).
    pub time_uncertain: bool,
    /// Distinct passing seeds achieved.
    pub passing_seeds: u32,
    /// Required.
    pub required_seeds: u32,
    /// State of this pair.
    pub state: ItemState,
    /// Every reason (empty when satisfied).
    pub reasons: Vec<String>,
}

/// One item's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemResult {
    /// Item ID.
    pub item_id: String,
    /// State.
    pub state: ItemState,
    /// Every reason, most severe first.
    pub reasons: Vec<String>,
    /// Per test and configuration.
    pub pairs: Vec<PairResult>,
    /// When a satisfied item stops being fresh.
    pub valid_until: Option<i64>,
}

fn pair(
    sel: &Selection,
    facts: Option<&CandidateFacts>,
    required: u32,
    freshness_days: u32,
    now: i64,
) -> (PairResult, Option<i64>) {
    let c = &sel.candidate;
    let mut reasons: Vec<(ItemState, String)> = vec![];
    let r = &c.regression_ref;
    let mut seeds = std::collections::BTreeSet::new();
    match facts {
        None => reasons.push((
            ItemState::Missing,
            format!("evidence expired (regression {r})"),
        )),
        Some(f) => {
            if !f.complete {
                reasons.push((
                    ItemState::Missing,
                    format!("candidate incomplete (regression {r})"),
                ));
            }
            if f.slots.is_empty() {
                reasons.push((ItemState::Missing, format!("no slot in candidate {r}")));
            }
            for (seed, st) in &f.slots {
                match st {
                    SlotState::Passed => {
                        seeds.insert(seed.as_str());
                    }
                    SlotState::Failed(FailReason::Insufficient) => reasons.push((
                        ItemState::Insufficient,
                        format!("seed {seed}: evidence not eligible (regression {r})"),
                    )),
                    SlotState::Failed(_) | SlotState::Blocked(_) => reasons.push((
                        ItemState::Failed,
                        format!("seed {seed} failed (regression {r})"),
                    )),
                    SlotState::Missing | SlotState::Running => reasons.push((
                        ItemState::Missing,
                        format!("seed {seed}: no result (regression {r})"),
                    )),
                    SlotState::Cancelled | SlotState::Skipped => reasons.push((
                        ItemState::Missing,
                        format!("seed {seed} not run (regression {r})"),
                    )),
                }
            }
            let n = u32::try_from(seeds.len()).unwrap_or(u32::MAX);
            if n < required {
                reasons.push((
                    ItemState::Missing,
                    format!("{n}/{required} passing seeds (regression {r})"),
                ));
            }
        }
    }
    let deadline = c.started_at.saturating_add(i64::from(freshness_days) * DAY);
    if c.time_uncertain() {
        reasons.push((
            ItemState::Outdated,
            format!("time uncertain (regression {r}; ordered by receipt time)"),
        ));
    } else if now >= deadline {
        reasons.push((
            ItemState::Outdated,
            format!("older than {freshness_days} days (regression {r})"),
        ));
    }
    reasons.sort();
    let state = reasons.first().map_or(ItemState::Satisfied, |(s, _)| *s);
    (
        PairResult {
            test: c.test.clone(),
            config_digest: c.config_digest.clone(),
            simulator: c.simulator.clone(),
            regression: c.regression_ref.clone(),
            started_at: c.started_at,
            time_uncertain: c.time_uncertain(),
            passing_seeds: u32::try_from(seeds.len()).unwrap_or(u32::MAX),
            required_seeds: required,
            state,
            reasons: reasons.into_iter().map(|(_, m)| m).collect(),
        },
        (state == ItemState::Satisfied).then_some(deadline),
    )
}

/// Judges one item from its selection (or selection error) and the candidates' facts.
#[must_use]
pub fn judge(
    item: &ChecklistItem,
    selected: Result<&[(Selection, Option<CandidateFacts>)], &SelectError>,
    unmatched: &[String],
    attested: bool,
    now: i64,
) -> ItemResult {
    let required = item.requires.min_passing_seeds.unwrap_or(1).max(1);
    let mut reasons: Vec<(ItemState, String)> = vec![];
    let mut pairs = vec![];
    let mut deadlines = vec![];
    match selected {
        Err(SelectError::TooBroad(n)) => reasons.push((
            ItemState::Insufficient,
            format!("selector matches {n} test/configuration pairs (at most {MAX_PAIRS})"),
        )),
        Ok([]) if unmatched.is_empty() => {
            reasons.push((
                ItemState::Missing,
                "no test matches the selector".to_string(),
            ));
        }
        Ok(sel) => {
            for (s, f) in sel {
                let (p, d) = pair(s, f.as_ref(), required, item.freshness_days, now);
                if p.state != ItemState::Satisfied {
                    for m in &p.reasons {
                        reasons.push((p.state, format!("{} [{}]: {m}", p.test, p.simulator)));
                    }
                }
                deadlines.extend(d);
                pairs.push(p);
            }
        }
    }
    for u in unmatched {
        reasons.push((ItemState::Missing, format!("no test matches {u}")));
    }
    if !item.evidence.is_empty() && !attested {
        reasons.push((
            ItemState::Unreviewed,
            "external evidence not attested".to_string(),
        ));
    }
    reasons.sort_by_key(|r| r.0);
    let state = reasons.first().map_or(ItemState::Satisfied, |(s, _)| *s);
    ItemResult {
        item_id: item.item_id.clone(),
        state,
        reasons: reasons.into_iter().map(|(_, m)| m).collect(),
        pairs,
        valid_until: (state == ItemState::Satisfied)
            .then(|| deadlines.into_iter().min())
            .flatten(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dviscope_model::wire::checklist::{AppliesTo, Requires};

    const NOW: i64 = 1_800_000_000;

    fn item(tests: &[&str], seeds: u32, days: u32) -> ChecklistItem {
        ChecklistItem {
            item_id: "i1".into(),
            title: "t".into(),
            owner: None,
            requires: Requires {
                tests: tests.iter().map(|s| (*s).to_string()).collect(),
                configs: vec![],
                min_passing_seeds: Some(seeds),
            },
            applies_to: AppliesTo::default(),
            freshness_days: days,
            evidence: vec![],
        }
    }

    fn entry(r: &str, id: i64, started: i64, received: i64) -> IndexEntry {
        IndexEntry {
            test: "uart_tx".into(),
            config_digest: "sha256:c1".into(),
            simulator: "questa".into(),
            regression_id: id,
            regression_ref: r.into(),
            started_at: started,
            received_at: Some(received),
            receipt_bound: None,
            live: true,
        }
    }

    fn facts(states: &[(&str, SlotState)]) -> CandidateFacts {
        CandidateFacts {
            complete: true,
            slots: states
                .iter()
                .map(|(s, st)| ((*s).to_string(), *st))
                .collect(),
        }
    }

    fn run(
        it: &ChecklistItem,
        entries: &[IndexEntry],
        f: &BTreeMap<&str, Option<CandidateFacts>>,
    ) -> ItemResult {
        let sel = select(it, entries);
        let un = unmatched(it, entries);
        match &sel {
            Ok(s) => {
                let with: Vec<(Selection, Option<CandidateFacts>)> = s
                    .iter()
                    .map(|x| {
                        (
                            x.clone(),
                            f.get(x.candidate.regression_ref.as_str())
                                .cloned()
                                .flatten(),
                        )
                    })
                    .collect();
                judge(it, Ok(&with), &un, false, NOW)
            }
            Err(e) => judge(it, Err(e), &un, false, NOW),
        }
    }

    #[test]
    fn parses_checklist_yaml() {
        let y = "checklist_id: uart-fs
title: UART
version: '1'
feature: uart
owner: Ana
items:
  - item_id: tx
    title: TX
    requires: {tests: ['uart_tx*'], min_passing_seeds: 3}
    freshness_days: 7
";
        let c = parse_checklist(y).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(c.items[0].requires.min_passing_seeds, Some(3));
        assert!(
            parse_checklist(
                "a: &x 1
b: *x
"
            )
            .is_err()
        );
        assert!(
            parse_checklist(
                "checklist_id: x
surprise: 1
"
            )
            .is_err()
        );
    }

    #[test]
    fn globs() {
        assert!(glob("uart_*", "uart_tx"));
        assert!(glob("*_tx", "uart_tx"));
        assert!(glob("u?rt*", "uart_tx"));
        assert!(glob("*", ""));
        assert!(!glob("uart_rx", "uart_tx"));
        assert!(!glob("uart", "uart_tx"));
        assert!(glob("a*b*c", "axxbyyc"));
        assert!(!glob("a*b*c", "axxbyy"));
    }

    #[test]
    fn newer_failing_candidate_wins_over_older_pass() {
        let it = item(&["uart_*"], 1, 30);
        let r1 = entry("R1", 1, NOW - 2 * DAY, NOW - 2 * DAY);
        let r2 = entry("R2", 2, NOW - DAY, NOW - DAY);
        let f = BTreeMap::from([
            (
                "R1",
                Some(facts(&[
                    ("1", SlotState::Passed),
                    ("2", SlotState::Passed),
                    ("3", SlotState::Passed),
                ])),
            ),
            (
                "R2",
                Some(facts(&[
                    ("1", SlotState::Passed),
                    ("2", SlotState::Failed(FailReason::Functional)),
                ])),
            ),
        ]);
        let out = run(&it, &[r1, r2.clone()], &f);
        assert_eq!(out.state, ItemState::Failed, "{out:?}");
        assert_eq!(out.pairs[0].regression, "R2");
        // R2 quarantined (not eligible): insufficient, still R2 — no fallback to R1.
        let f2 = BTreeMap::from([
            ("R1", Some(facts(&[("1", SlotState::Passed)]))),
            (
                "R2",
                Some(facts(&[("1", SlotState::Failed(FailReason::Insufficient))])),
            ),
        ]);
        let out = run(
            &it,
            &[entry("R1", 1, NOW - 2 * DAY, NOW - 2 * DAY), r2.clone()],
            &f2,
        );
        assert_eq!(out.state, ItemState::Insufficient);
        assert_eq!(out.pairs[0].regression, "R2");
        // R2's facts expired: missing (evidence expired), still R2.
        let f3 = BTreeMap::from([
            ("R1", Some(facts(&[("1", SlotState::Passed)]))),
            ("R2", None),
        ]);
        let out = run(
            &it,
            &[entry("R1", 1, NOW - 2 * DAY, NOW - 2 * DAY), r2],
            &f3,
        );
        assert_eq!(out.state, ItemState::Missing);
        assert!(out.reasons[0].contains("evidence expired"), "{out:?}");
    }

    #[test]
    fn late_delivery_does_not_make_evidence_newer() {
        let it = item(&["uart_tx"], 1, 30);
        // R_old ran 10 days ago but was delivered now; R_new ran yesterday.
        let old = entry("R_old", 9, NOW - 10 * DAY, NOW);
        let new = entry("R_new", 3, NOW - DAY, NOW - DAY);
        let f = BTreeMap::from([
            ("R_old", Some(facts(&[("1", SlotState::Passed)]))),
            (
                "R_new",
                Some(facts(&[("1", SlotState::Failed(FailReason::Functional))])),
            ),
        ]);
        let out = run(&it, &[new, old], &f);
        assert_eq!(out.pairs[0].regression, "R_new");
        assert_eq!(out.state, ItemState::Failed);
    }

    #[test]
    fn skewed_time_is_outdated_and_ordered_by_receipt() {
        let it = item(&["uart_tx"], 1, 30);
        // Claims to start in the future relative to its receipt.
        let skew = entry("R_skew", 5, NOW + 100 * DAY, NOW - 3 * DAY);
        let normal = entry("R_ok", 4, NOW - 2 * DAY, NOW - 2 * DAY);
        let f = BTreeMap::from([
            ("R_skew", Some(facts(&[("1", SlotState::Passed)]))),
            ("R_ok", Some(facts(&[("1", SlotState::Passed)]))),
        ]);
        // Ordered by receipt (3 days ago) it is older than R_ok: R_ok is the candidate.
        let out = run(&it, &[skew.clone(), normal], &f);
        assert_eq!(out.pairs[0].regression, "R_ok");
        assert_eq!(out.state, ItemState::Satisfied);
        // Alone, it cannot be fresh.
        let out = run(&it, &[skew], &f);
        assert_eq!(out.state, ItemState::Outdated);
        assert!(out.reasons[0].contains("time uncertain"), "{out:?}");
    }

    #[test]
    fn incomplete_newest_candidate_is_missing() {
        let it = item(&["uart_tx"], 1, 30);
        let mut inc = facts(&[("1", SlotState::Passed)]);
        inc.complete = false;
        let f = BTreeMap::from([
            ("R1", Some(facts(&[("1", SlotState::Passed)]))),
            ("R3", Some(inc)),
        ]);
        let out = run(
            &it,
            &[
                entry("R1", 1, NOW - 2 * DAY, NOW - 2 * DAY),
                entry("R3", 3, NOW - DAY, NOW - DAY),
            ],
            &f,
        );
        assert_eq!(out.state, ItemState::Missing);
        assert!(out.reasons[0].contains("candidate incomplete"), "{out:?}");
    }

    #[test]
    fn freshness_boundary() {
        let it = item(&["uart_tx"], 1, 7);
        let f = BTreeMap::from([("R", Some(facts(&[("1", SlotState::Passed)])))]);
        let start = NOW - 7 * DAY;
        for (delta, want) in [
            (1, ItemState::Satisfied),
            (0, ItemState::Outdated),
            (-1, ItemState::Outdated),
        ] {
            let out = run(&it, &[entry("R", 1, start + delta, start + delta)], &f);
            assert_eq!(out.state, want, "deadline {delta:+}s");
        }
        let out = run(&it, &[entry("R", 1, start + 1, start + 1)], &f);
        assert_eq!(out.valid_until, Some(NOW + 1));
    }

    #[test]
    fn seeds_are_distinct_and_unmatched_selectors_are_missing() {
        let it = item(&["uart_tx"], 2, 30);
        let f = BTreeMap::from([(
            "R",
            Some(facts(&[("1", SlotState::Passed), ("1", SlotState::Passed)])),
        )]);
        let out = run(&it, &[entry("R", 1, NOW - DAY, NOW - DAY)], &f);
        assert_eq!(out.state, ItemState::Missing);
        assert_eq!(out.pairs[0].passing_seeds, 1);
        assert!(out.reasons[0].contains("1/2 passing seeds"), "{out:?}");
        let none = run(
            &item(&["spi_*"], 1, 30),
            &[entry("R", 1, NOW - DAY, NOW - DAY)],
            &f,
        );
        assert_eq!(none.state, ItemState::Missing);
        assert_eq!(none.reasons, vec!["no test matches spi_*".to_string()]);
    }

    #[test]
    fn evidence_needs_an_attestation() {
        let mut it = item(&["uart_tx"], 1, 30);
        it.evidence = vec![dviscope_model::wire::checklist::ExternalEvidence {
            name: "coverage report".into(),
            digest: serde_json::from_value(serde_json::json!(format!("sha256:{}", "a".repeat(64))))
                .unwrap_or_else(|e| panic!("{e}")),
            uri_hint: None,
        }];
        let f = BTreeMap::from([("R", Some(facts(&[("1", SlotState::Passed)])))]);
        let s = select(&it, &[entry("R", 1, NOW - DAY, NOW - DAY)]).unwrap_or_default();
        let with: Vec<_> = s.into_iter().map(|x| (x, f["R"].clone())).collect();
        assert_eq!(
            judge(&it, Ok(&with), &[], false, NOW).state,
            ItemState::Unreviewed
        );
        assert_eq!(
            judge(&it, Ok(&with), &[], true, NOW).state,
            ItemState::Satisfied
        );
    }

    #[test]
    fn config_selectors_and_applicability() {
        let mut it = item(&["uart_tx"], 1, 30);
        it.requires.configs = vec!["VCS".into()];
        assert_eq!(
            select(&it, &[entry("R", 1, NOW, NOW)])
                .unwrap_or_default()
                .len(),
            0
        );
        it.requires.configs = vec!["Questa".into()];
        assert_eq!(
            select(&it, &[entry("R", 1, NOW, NOW)])
                .unwrap_or_default()
                .len(),
            1
        );
        it.requires.configs = vec!["sha256:c1".into()];
        assert_eq!(
            select(&it, &[entry("R", 1, NOW, NOW)])
                .unwrap_or_default()
                .len(),
            1
        );
        it.applies_to.repositories = vec!["rtl".into()];
        assert!(applies(&it, "rtl/main"));
        assert!(!applies(&it, "dv/main"));
        it.applies_to.branch = Some("rtl/release".into());
        assert!(!applies(&it, "rtl/main"));
    }

    #[test]
    fn too_broad_is_insufficient() {
        let it = item(&["*"], 1, 30);
        let many: Vec<IndexEntry> = (0..=MAX_PAIRS)
            .map(|i| IndexEntry {
                test: format!("t{i}"),
                ..entry("R", 1, NOW, NOW)
            })
            .collect();
        let out = run(&it, &many, &BTreeMap::new());
        assert_eq!(out.state, ItemState::Insufficient);
    }

    #[test]
    fn every_requirement_selector_must_match() {
        // uart_tx passes; uart_rx was never run: not satisfied.
        let it = item(&["uart_tx", "uart_rx"], 1, 30);
        let f = BTreeMap::from([("R", Some(facts(&[("1", SlotState::Passed)])))]);
        let out = run(&it, &[entry("R", 1, NOW - DAY, NOW - DAY)], &f);
        assert_eq!(out.state, ItemState::Missing, "{out:?}");
        assert!(
            out.reasons.iter().any(|r| r == "no test matches uart_rx"),
            "{out:?}"
        );
        // Required on two simulators, run on one.
        let mut it = item(&["uart_tx"], 1, 30);
        it.requires.configs = vec!["questa".into(), "vcs".into()];
        let out = run(&it, &[entry("R", 1, NOW - DAY, NOW - DAY)], &f);
        assert_eq!(out.state, ItemState::Missing, "{out:?}");
        assert!(
            out.reasons
                .iter()
                .any(|r| r == "no test matches uart_tx on vcs"),
            "{out:?}"
        );
    }

    #[test]
    fn unknown_receipt_time_is_uncertain() {
        let it = item(&["uart_tx"], 1, 30);
        let mut e = entry("R", 1, NOW - DAY, NOW - DAY);
        e.received_at = None;
        let f = BTreeMap::from([("R", Some(facts(&[("1", SlotState::Passed)])))]);
        let out = run(&it, &[e], &f);
        assert_eq!(out.state, ItemState::Outdated, "{out:?}");
        assert!(out.reasons[0].contains("time uncertain"));
    }

    #[test]
    fn unknown_receipt_time_never_reveals_an_older_pass() {
        let it = item(&["uart_tx"], 1, 30);
        // R2 failed more recently but its receipt time is unknown; R1 passed earlier.
        let mut r2 = entry("R2", 2, NOW - DAY, NOW - DAY);
        r2.received_at = None;
        let r1 = entry("R1", 1, NOW - 2 * DAY, NOW - 2 * DAY);
        let f = BTreeMap::from([
            ("R1", Some(facts(&[("1", SlotState::Passed)]))),
            (
                "R2",
                Some(facts(&[("1", SlotState::Failed(FailReason::Functional))])),
            ),
        ]);
        let out = run(&it, &[r1, r2], &f);
        assert_eq!(out.pairs[0].regression, "R2", "{out:?}");
        assert_ne!(out.state, ItemState::Satisfied);
    }

    #[test]
    fn an_unknown_time_is_never_fresh_and_yields_only_to_provably_later_runs() {
        let it = item(&["uart_tx"], 1, 30);
        let pass = BTreeMap::from([
            ("L", Some(facts(&[("1", SlotState::Passed)]))),
            ("K", Some(facts(&[("1", SlotState::Passed)]))),
        ]);
        // Legacy L: start yesterday (unverifiable), receipt unknown, bound two days ago.
        let mut legacy = entry("L", 1, NOW - DAY, NOW - DAY);
        legacy.received_at = None;
        legacy.receipt_bound = Some(NOW - 2 * DAY);
        let out = run(&it, &[legacy.clone()], &pass);
        assert_eq!(out.state, ItemState::Outdated, "never fresh: {out:?}");
        // K ran after the bound: provably later, it is the candidate.
        let later = entry("K", 2, NOW - DAY, NOW - DAY);
        let out = run(&it, &[legacy.clone(), later], &pass);
        assert_eq!(out.pairs[0].regression, "K");
        assert_eq!(out.state, ItemState::Satisfied);
        // K ran before the bound: not provably later, the legacy run stays the candidate.
        let earlier = entry("K", 2, NOW - 3 * DAY, NOW - 3 * DAY);
        let out = run(&it, &[legacy, earlier], &pass);
        assert_eq!(out.pairs[0].regression, "L");
        assert_ne!(out.state, ItemState::Satisfied);
    }

    #[test]
    fn sub_second_starts_order_candidates_and_skew() {
        let it = item(&["uart_tx"], 1, 30);
        let base = NOW - DAY;
        // Failing R1 started 0.8 s after passing R2; R2 arrived later (larger id).
        let r1 = entry("R1", 1, base + 900_000, base + 900_000);
        let r2 = entry("R2", 2, base + 100_000, base + 2_000_000);
        let f = BTreeMap::from([
            (
                "R1",
                Some(facts(&[("1", SlotState::Failed(FailReason::Functional))])),
            ),
            ("R2", Some(facts(&[("1", SlotState::Passed)]))),
        ]);
        let out = run(&it, &[r1, r2], &f);
        assert_eq!(out.pairs[0].regression, "R1", "{out:?}");
        assert_eq!(out.state, ItemState::Failed);
        // Skew boundary: exactly the tolerance is plausible, one microsecond more is not.
        let at = entry("R", 1, base + SKEW_TOLERANCE_MICROS, base);
        assert!(!at.time_uncertain());
        let over = entry("R", 1, base + SKEW_TOLERANCE_MICROS + 1, base);
        assert!(over.time_uncertain());
    }
}
