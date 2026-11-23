//! Slots and settlement: validity first, then the ordered slot lifecycle, the
//! retry policies, the build proof and the combined build state. States are computed from
//! facts; the result does not depend on the order the facts are given in (A06a).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::Serialize;

use crate::eligibility::Eligibility;
use crate::outcome::{BlockingPhase, Effective, Outcome};

/// Retry policy of a suite (v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    /// Any eligible failing attempt fails the slot.
    Strict,
    /// The latest eligible terminal attempt decides; a cleared failure stays visible.
    RetryPassAccepted,
}

/// Why a slot failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailReason {
    /// A functional failure.
    Functional,
    /// Tool or infrastructure error.
    Error,
    /// Timeout.
    Timeout,
    /// Killed.
    Killed,
    /// The evidence cannot settle it (quarantine, withdrawn pipeline, unknown termination,
    /// build not proven).
    Insufficient,
    /// The expected outcome was not met.
    Expectation,
}

/// What blocked a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedBy {
    /// A build (compile) failed.
    Build,
    /// Elaboration failed (incl. at run time, F7).
    Elaboration,
}

/// Slot state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum SlotState {
    /// Passed.
    Passed,
    /// Failed.
    Failed(FailReason),
    /// Blocked.
    Blocked(BlockedBy),
    /// No result (yet).
    Missing,
    /// An attempt is running.
    Running,
    /// Marked cancelled.
    Cancelled,
    /// Marked skipped.
    Skipped,
}

/// Why rule 1 (barrier) applies to an attempt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Barrier {
    /// A report revision from a quarantined credential (not released).
    pub quarantined_credential: bool,
    /// Classified under a withdrawn pipeline (not restored).
    pub withdrawn_pipeline: bool,
    /// A referenced build attempt has a quarantined revision (not released).
    pub quarantined_build: bool,
}

impl Barrier {
    fn any(self) -> bool {
        self.quarantined_credential || self.withdrawn_pipeline || self.quarantined_build
    }
}

/// The terminal report of a simulation attempt, as derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    /// Observed outcome.
    pub outcome: Outcome,
    /// For `blocked`.
    pub blocking_phase: Option<BlockingPhase>,
    /// Effective result.
    pub effective: Effective,
    /// Whether the expectation was not met.
    pub expectation_not_met: bool,
    /// Termination `unknown`.
    pub termination_unknown: bool,
    /// The build attempt used for each build requirement.
    pub build_refs: Vec<String>,
}

/// One simulation attempt of a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptFacts {
    /// Producer's attempt sequence.
    pub attempt_seq: u32,
    /// Eligibility (B.7.1).
    pub eligibility: Eligibility,
    /// Rule-1 barrier facts.
    pub barrier: Barrier,
    /// The terminal report; `None` while only started.
    pub terminal: Option<Terminal>,
}

/// Terminal state of a build attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildResult {
    /// Built.
    Pass,
    /// Compile or elaboration failed.
    Fail,
    /// Tool or infrastructure error.
    Error,
}

/// One build attempt of a requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildFacts {
    /// Build reference.
    pub build_ref: String,
    /// The requirement (`build_req` digest) it builds.
    pub requirement: String,
    /// Server-assigned order among builds of the requirement.
    pub build_order: u64,
    /// Eligible and not quarantined.
    pub eligible: bool,
    /// Terminal result; `None` while only started.
    pub result: Option<BuildResult>,
}

/// The build attempts of a slot's requirements: shared by the slots that have the same
/// requirements (one copy per regression) and indexed by build reference, so a build-proof
/// lookup is not a scan of the whole history.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SharedBuilds(Arc<(Vec<BuildFacts>, BTreeMap<String, usize>)>);

impl SharedBuilds {
    /// Every build attempt (any order).
    pub fn iter(&self) -> std::slice::Iter<'_, BuildFacts> {
        self.0.0.iter()
    }

    /// The build attempt with this reference (the first, if listed twice).
    #[must_use]
    pub fn get(&self, build_ref: &str) -> Option<&BuildFacts> {
        self.0.1.get(build_ref).map(|&i| &self.0.0[i])
    }

    /// Number of build attempts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.0.len()
    }

    /// No build attempt.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.0.is_empty()
    }
}

impl From<Vec<BuildFacts>> for SharedBuilds {
    fn from(list: Vec<BuildFacts>) -> Self {
        let mut index = BTreeMap::new();
        for (i, b) in list.iter().enumerate() {
            index.entry(b.build_ref.clone()).or_insert(i);
        }
        Self(Arc::new((list, index)))
    }
}

impl<'a> IntoIterator for &'a SharedBuilds {
    type Item = &'a BuildFacts;
    type IntoIter = std::slice::Iter<'a, BuildFacts>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<BuildFacts> for SharedBuilds {
    fn from_iter<I: IntoIterator<Item = BuildFacts>>(it: I) -> Self {
        it.into_iter().collect::<Vec<_>>().into()
    }
}

/// Mark on a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mark {
    /// Cancelled.
    Cancelled,
    /// Skipped.
    Skipped,
}

/// Everything settlement reads about one slot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SlotFacts {
    /// Simulation attempts (any order).
    pub attempts: Vec<AttemptFacts>,
    /// The slot's build requirements (digests).
    pub build_requirements: Vec<String>,
    /// Build attempts of those requirements (any order). Shared: slots with the same
    /// requirements read one list (a regression's slots often share a build).
    pub builds: SharedBuilds,
    /// A cancelled/skipped mark.
    pub mark: Option<Mark>,
}

/// A settled slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Settled {
    /// State.
    pub state: SlotState,
    /// Explanation shown with the state.
    pub note: Option<String>,
    /// `attempt_seq` of the deciding attempt.
    pub deciding: Option<u32>,
}

fn settled(state: SlotState, note: Option<&str>, deciding: Option<u32>) -> Settled {
    Settled {
        state,
        note: note.map(str::to_string),
        deciding,
    }
}

/// How one terminal attempt failed (its own outcome; the slot reports the deciding one):
/// blocked (build or elaboration, never exceptable) or failed for a reason.
///
/// # Errors
///
/// `Err` names what blocked the attempt (its outcome was `blocked`).
pub fn attempt_failure(t: &Terminal) -> Result<FailReason, BlockedBy> {
    if t.outcome == Outcome::Blocked {
        Err(blocked_by(t.blocking_phase))
    } else {
        Ok(fail_reason(t))
    }
}

fn fail_reason(t: &Terminal) -> FailReason {
    match t.outcome {
        Outcome::Error => FailReason::Error,
        Outcome::Timeout => FailReason::Timeout,
        Outcome::Killed => FailReason::Killed,
        _ if t.expectation_not_met => FailReason::Expectation,
        _ => FailReason::Functional,
    }
}

fn blocked_by(phase: Option<BlockingPhase>) -> BlockedBy {
    match phase {
        Some(BlockingPhase::Compile) => BlockedBy::Build,
        _ => BlockedBy::Elaboration,
    }
}

/// Combined build state of the slot's requirements (B.7.3), for slots not yet run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CombinedBuild {
    /// Every requirement built.
    Passed,
    /// Some requirement failed.
    Failed,
    /// Some requirement is building.
    Running,
    /// Some requirement has no build yet.
    Missing,
}

/// The combined build state.
#[must_use]
pub fn combined_build(slot: &SlotFacts) -> CombinedBuild {
    let mut any_running = false;
    let mut any_missing = false;
    // The eligible builds grouped by requirement in one pass (not one scan per requirement).
    let mut by_req: BTreeMap<&str, Vec<&BuildFacts>> = BTreeMap::new();
    for b in slot.builds.iter().filter(|b| b.eligible) {
        by_req.entry(b.requirement.as_str()).or_default().push(b);
    }
    for req in &slot.build_requirements {
        let mut builds: Vec<&BuildFacts> = by_req.get(req.as_str()).cloned().unwrap_or_default();
        builds.sort_by(|a, b| (a.build_order, &a.build_ref).cmp(&(b.build_order, &b.build_ref)));
        let latest_terminal = builds.iter().rev().find(|b| b.result.is_some());
        let started_after = builds.iter().any(|b| {
            b.result.is_none() && latest_terminal.is_none_or(|t| b.build_order > t.build_order)
        });
        match latest_terminal.and_then(|b| b.result) {
            Some(BuildResult::Fail | BuildResult::Error) if !started_after => {
                return CombinedBuild::Failed;
            }
            _ if started_after => any_running = true,
            Some(BuildResult::Pass) => {}
            _ => any_missing = true,
        }
    }
    if any_running {
        CombinedBuild::Running
    } else if any_missing {
        CombinedBuild::Missing
    } else {
        CombinedBuild::Passed
    }
}

/// Whether every build attempt an executed attempt used is eligible and terminally passed
/// (B.7.3 build proof). Another build of the same requirement is never substituted.
#[must_use]
pub fn build_proven(slot: &SlotFacts, t: &Terminal) -> bool {
    // Exactly one distinct referenced build per requirement, each of that requirement,
    // eligible and terminally passed; nothing unrelated, duplicated or missing.
    let referenced: BTreeSet<&String> = t.build_refs.iter().collect();
    let required: BTreeSet<&String> = slot.build_requirements.iter().collect();
    if referenced.len() != t.build_refs.len() || referenced.len() != required.len() {
        return false;
    }
    let mut covered = BTreeSet::new();
    for r in &referenced {
        let Some(b) = slot.builds.get(r) else {
            return false;
        };
        if !required.contains(&b.requirement) || !b.eligible || b.result != Some(BuildResult::Pass)
        {
            return false;
        }
        if !covered.insert(&b.requirement) {
            return false;
        }
    }
    covered.len() == required.len()
}

/// Settles a slot.
#[must_use]
#[allow(clippy::too_many_lines)] // the B.7.2 rules in order
pub fn settle(slot: &SlotFacts, policy: Policy) -> Settled {
    let mut all: Vec<&AttemptFacts> = slot.attempts.iter().collect();
    all.sort_by_key(|a| a.attempt_seq);
    // Rule 1: barrier, unless followed by a later eligible terminal attempt free of it. One
    // pass: a barrier is cleared exactly when the last clearing attempt comes after it.
    let last_clearing = all.iter().rposition(|b| {
        b.eligibility == Eligibility::Eligible && b.terminal.is_some() && !b.barrier.any()
    });
    for (i, a) in all.iter().enumerate() {
        if a.barrier.any() {
            let cleared = last_clearing.is_some_and(|l| l > i);
            if !cleared {
                let why = if a.barrier.quarantined_credential {
                    "evidence from a quarantined credential"
                } else if a.barrier.withdrawn_pipeline {
                    "evidence from a withdrawn pipeline"
                } else {
                    "built by a quarantined build"
                };
                return settled(
                    SlotState::Failed(FailReason::Insufficient),
                    Some(why),
                    Some(a.attempt_seq),
                );
            }
        }
    }
    let eligible: Vec<&AttemptFacts> = all
        .iter()
        .copied()
        .filter(|a| a.eligibility == Eligibility::Eligible)
        .collect();
    // Rule 2.
    if let Some(a) = eligible.iter().find(|a| a.terminal.is_none()) {
        return settled(SlotState::Running, None, Some(a.attempt_seq));
    }
    let terminal: Vec<(&AttemptFacts, &Terminal)> = eligible
        .iter()
        .filter_map(|a| a.terminal.as_ref().map(|t| (*a, t)))
        .collect();
    if let Some((latest, t)) = terminal.last() {
        // Rule 3.
        if t.outcome == Outcome::Blocked {
            return settled(
                SlotState::Blocked(blocked_by(t.blocking_phase)),
                None,
                Some(latest.attempt_seq),
            );
        }
        // Rule 4.
        if t.termination_unknown {
            return settled(
                SlotState::Failed(FailReason::Insufficient),
                Some("interrupted; outcome not recoverable"),
                Some(latest.attempt_seq),
            );
        }
        // Rule 5: policy, then the build proof of the deciding attempt.
        let failures: Vec<&(&AttemptFacts, &Terminal)> = terminal
            .iter()
            .filter(|(_, t)| t.effective == Effective::Failed)
            .collect();
        let (state, note, deciding) = match policy {
            Policy::Strict => {
                if let Some((a, t)) = failures
                    .iter()
                    .rev()
                    .find(|(_, t)| t.outcome == Outcome::Blocked)
                {
                    (
                        SlotState::Blocked(blocked_by(t.blocking_phase)),
                        None,
                        (*a, *t),
                    )
                } else if let Some((a, t)) = failures.last() {
                    (SlotState::Failed(fail_reason(t)), None, (*a, *t))
                } else {
                    (SlotState::Passed, None, (*latest, *t))
                }
            }
            Policy::RetryPassAccepted => {
                if t.effective == Effective::Passed {
                    let note = (!failures.is_empty())
                        .then_some("cleared by accepted retry (retry-pass-accepted v1)");
                    (SlotState::Passed, note, (*latest, *t))
                } else {
                    (SlotState::Failed(fail_reason(t)), None, (*latest, *t))
                }
            }
        };
        if !build_proven(slot, deciding.1) {
            return settled(
                SlotState::Failed(FailReason::Insufficient),
                Some("build not proven"),
                Some(deciding.0.attempt_seq),
            );
        }
        return settled(state, note, Some(deciding.0.attempt_seq));
    }
    // Rule 6.
    match slot.mark {
        Some(Mark::Cancelled) => return settled(SlotState::Cancelled, None, None),
        Some(Mark::Skipped) => return settled(SlotState::Skipped, None, None),
        None => {}
    }
    // Rules 7-9.
    match combined_build(slot) {
        CombinedBuild::Failed => settled(SlotState::Blocked(BlockedBy::Build), None, None),
        CombinedBuild::Running => settled(SlotState::Missing, Some("waiting for build"), None),
        CombinedBuild::Missing | CombinedBuild::Passed => settled(SlotState::Missing, None, None),
    }
}
