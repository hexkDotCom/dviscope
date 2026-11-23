//! Merge readiness, the pure part: **validate → adjudicate → obligations →
//! exceptions**, over settled slots and their authoritative attempts. The server assembles
//! the inputs inside one snapshot and computes the decision-input digest; this module
//! decides.
//!
//! Exceptions never cover contradictions, unexplained or incomplete evidence, missing or
//! not-run results, ineligible evidence, accounting overflow or expectation mismatches:
//! only a failed slot whose authoritative attempts all have complete accounting and whose
//! every failure signature is covered by an active exception for the branch and suite.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::settlement::{BlockedBy, FailReason, Policy, SlotState};

/// One attempt as readiness reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent facts of one attempt
pub struct AttemptView {
    /// Producer's attempt sequence.
    pub attempt_seq: u32,
    /// Eligible (B.7.1).
    pub eligible: bool,
    /// Has a terminal report.
    pub terminal: bool,
    /// Effective result failed (terminal only).
    pub failed: bool,
    /// Complete accounting (completion complete, no overflow).
    pub complete: bool,
    /// An unexplained contradiction.
    pub contradiction: bool,
    /// Failed without any failure diagnostic (`UNEXPLAINED_FAILURE`): never exceptable.
    pub unexplained: bool,
    /// Every build attempt it used is eligible and terminally passed (B.7.3); `true` for a
    /// slot without build requirements.
    pub build_proven: bool,
    /// Why this attempt failed (terminal and failed only); `None` otherwise or unknown.
    pub fail_reason: Option<FailReason>,
    /// The attempt was blocked (build or elaboration): never exceptable.
    pub blocked: Option<BlockedBy>,
    /// Signatures of its failing buckets.
    pub signatures: BTreeSet<String>,
}

/// One planned slot as readiness reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotInput {
    /// Producer slot key.
    pub slot: String,
    /// Required by readiness.
    pub required: bool,
    /// Settled state (B.7).
    pub state: SlotState,
    /// Attempts (any order).
    pub attempts: Vec<AttemptView>,
}

/// An active exception: a signature covered for the evaluated branch and suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExceptionView {
    /// Exception ID.
    pub id: String,
    /// Revision.
    pub revision: u32,
    /// Covered signature.
    pub signature: String,
    /// Expiry (RFC 3339; compared as text by the server's clock).
    pub expires_at: String,
}

/// Regression-level facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The regression's source digest equals the expected one.
    pub source_matches: bool,
    /// Manifest sealed and regression finished, no quarantined expected-set change pending.
    pub collection_closed: bool,
}

/// Everything a merge evaluation reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeInput {
    /// Candidate binding and closure.
    pub candidate: Candidate,
    /// Policy of the suite.
    pub policy: Policy,
    /// Planned slots.
    pub slots: Vec<SlotInput>,
    /// Active exceptions for the branch and suite.
    pub exceptions: Vec<ExceptionView>,
}

/// Kinds of blocker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockerKind {
    /// The regression's sources are not the candidate's.
    SourceMismatch,
    /// The manifest is not sealed or the regression not finished.
    CollectionOpen,
    /// No result yet.
    Missing,
    /// Still running.
    Running,
    /// Blocked by a build or elaboration failure.
    Blocked {
        /// What blocked it.
        by: BlockedBy,
    },
    /// Failed.
    Failed {
        /// Why.
        reason: FailReason,
    },
    /// A required slot marked skipped or cancelled.
    RequiredNotRun,
    /// The evidence cannot settle it.
    InsufficientEvidence {
        /// Why.
        reason: String,
    },
    /// An unexplained contradiction in an authoritative attempt.
    Contradiction,
    /// An incomplete authoritative attempt.
    IncompleteEvidence,
    /// A failure the evidence does not explain (no failure diagnostic): never exceptable.
    Unexplained,
}

impl BlockerKind {
    /// Whether the blocker makes the result `insufficient_evidence`.
    #[must_use]
    pub fn insufficient(&self) -> bool {
        matches!(
            self,
            Self::SourceMismatch | Self::CollectionOpen | Self::InsufficientEvidence { .. }
        )
    }
}

/// One blocker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocker {
    /// What it is.
    #[serde(flatten)]
    pub kind: BlockerKind,
    /// The slot (absent for regression-level blockers).
    pub slot: Option<String>,
    /// Signatures involved (failed slots).
    pub signatures: Vec<String>,
    /// Whether an exception could clear it.
    pub exceptable: bool,
}

/// The verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every required obligation is met.
    Pass,
    /// Met, some failures covered by exceptions.
    AcceptedWithExceptions,
    /// A blocker.
    Fail,
    /// The evidence cannot decide.
    InsufficientEvidence,
}

/// The decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeDecision {
    /// Verdict.
    pub verdict: Verdict,
    /// Blockers (slot order), regression-level ones first.
    pub blockers: Vec<Blocker>,
    /// Exceptions used.
    pub exceptions_used: Vec<ExceptionView>,
    /// Earliest expiry of the exceptions used (the result's `valid_until`).
    pub valid_until: Option<String>,
    /// Counts: planned, passed, failed, blocked, missing.
    pub counts: BTreeMap<&'static str, u64>,
}

/// The authoritative attempts of a slot (B.11 step 4): eligible terminal attempts; under
/// `retry-pass-accepted` only the accepting pass when the slot passed.
fn authoritative(slot: &SlotInput, policy: Policy) -> Vec<&AttemptView> {
    let terminal: Vec<&AttemptView> = slot
        .attempts
        .iter()
        .filter(|a| a.eligible && a.terminal)
        .collect();
    if policy == Policy::RetryPassAccepted && slot.state == SlotState::Passed {
        return terminal
            .iter()
            .filter(|a| !a.failed)
            .max_by_key(|a| a.attempt_seq)
            .into_iter()
            .copied()
            .collect();
    }
    terminal
}

/// An evidence problem of the slot's authoritative attempts that no result can stand on
/// (a contradiction, an unproven build, incomplete accounting), whatever the slot's state.
/// Merge readiness blocks on it; feature mode counts the slot as insufficient evidence.
#[must_use]
pub fn evidence_problem(slot: &SlotInput, policy: Policy) -> Option<BlockerKind> {
    let auth = authoritative(slot, policy);
    if auth.iter().any(|a| a.contradiction) {
        return Some(BlockerKind::Contradiction);
    }
    // Every authoritative attempt needs its own build proof (not only the deciding one).
    if auth.iter().any(|a| a.terminal && !a.build_proven) {
        return Some(BlockerKind::InsufficientEvidence {
            reason: "an authoritative attempt used an unproven build".into(),
        });
    }
    if auth.iter().any(|a| !a.complete) {
        return Some(BlockerKind::IncompleteEvidence);
    }
    None
}

fn blocker(kind: BlockerKind, slot: &str, signatures: Vec<String>, exceptable: bool) -> Blocker {
    Blocker {
        kind,
        slot: Some(slot.to_string()),
        signatures,
        exceptable,
    }
}

/// Evaluates merge readiness.
#[must_use]
#[allow(clippy::too_many_lines)] // the B.11 sequence, obligation by obligation
pub fn evaluate(input: &MergeInput) -> MergeDecision {
    let mut blockers = vec![];
    if !input.candidate.source_matches {
        blockers.push(Blocker {
            kind: BlockerKind::SourceMismatch,
            slot: None,
            signatures: vec![],
            exceptable: false,
        });
    }
    if !input.candidate.collection_closed {
        blockers.push(Blocker {
            kind: BlockerKind::CollectionOpen,
            slot: None,
            signatures: vec![],
            exceptable: false,
        });
    }
    let active: BTreeMap<&str, &ExceptionView> = input
        .exceptions
        .iter()
        .map(|e| (e.signature.as_str(), e))
        .collect();
    let mut used: BTreeMap<String, ExceptionView> = BTreeMap::new();
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    for s in &input.slots {
        *counts.entry("planned").or_default() += 1;
        match s.state {
            SlotState::Passed => *counts.entry("passed").or_default() += 1,
            SlotState::Failed(_) => *counts.entry("failed").or_default() += 1,
            SlotState::Blocked(_) => *counts.entry("blocked").or_default() += 1,
            SlotState::Missing | SlotState::Running => *counts.entry("missing").or_default() += 1,
            SlotState::Cancelled | SlotState::Skipped => {}
        }
        if !s.required {
            continue; // optional slots produce no blockers
        }
        let auth = authoritative(s, input.policy);
        // Obligation-level evidence problems, whatever the state: never exceptable.
        if let Some(kind) = evidence_problem(s, input.policy) {
            blockers.push(blocker(kind, &s.slot, vec![], false));
            continue;
        }
        match s.state {
            SlotState::Passed => {}
            SlotState::Missing => {
                let only_ineligible = !s.attempts.is_empty()
                    && s.attempts.iter().any(|a| a.terminal)
                    && s.attempts
                        .iter()
                        .filter(|a| a.terminal)
                        .all(|a| !a.eligible);
                if only_ineligible {
                    blockers.push(blocker(
                        BlockerKind::InsufficientEvidence {
                            reason: "only ineligible evidence".into(),
                        },
                        &s.slot,
                        vec![],
                        false,
                    ));
                } else {
                    blockers.push(blocker(BlockerKind::Missing, &s.slot, vec![], false));
                }
            }
            SlotState::Running => {
                blockers.push(blocker(BlockerKind::Running, &s.slot, vec![], false));
            }
            SlotState::Blocked(by) => {
                blockers.push(blocker(BlockerKind::Blocked { by }, &s.slot, vec![], false));
            }
            SlotState::Cancelled | SlotState::Skipped => {
                blockers.push(blocker(BlockerKind::RequiredNotRun, &s.slot, vec![], false));
            }
            SlotState::Failed(FailReason::Insufficient) => blockers.push(blocker(
                BlockerKind::InsufficientEvidence {
                    reason: "quarantine, withdrawn pipeline, unknown termination or unproven build"
                        .into(),
                },
                &s.slot,
                vec![],
                false,
            )),
            SlotState::Failed(_) if auth.iter().any(|a| a.failed && a.unexplained) => {
                let sigs: BTreeSet<String> = auth
                    .iter()
                    .filter(|a| a.failed)
                    .flat_map(|a| a.signatures.iter().cloned())
                    .collect();
                blockers.push(blocker(
                    BlockerKind::Unexplained,
                    &s.slot,
                    sigs.into_iter().collect(),
                    false,
                ));
            }
            SlotState::Failed(deciding) => {
                let sigs: BTreeSet<String> = auth
                    .iter()
                    .filter(|a| a.failed)
                    .flat_map(|a| a.signatures.iter().cloned())
                    .collect();
                // An authoritative attempt that was blocked keeps the slot blocked for
                // readiness, whatever failed later: never exceptable.
                if let Some(by) = auth.iter().filter(|a| a.failed).find_map(|a| a.blocked) {
                    blockers.push(blocker(
                        BlockerKind::Blocked { by },
                        &s.slot,
                        sigs.into_iter().collect(),
                        false,
                    ));
                    continue;
                }
                // Every authoritative failure counts, not only the deciding one: an earlier timeout stays a timeout after a later functional failure.
                let reason = auth
                    .iter()
                    .filter(|a| a.failed)
                    .filter_map(|a| a.fail_reason)
                    .find(|r| *r != FailReason::Functional)
                    .unwrap_or(deciding);
                // Exceptable: functional failures only (each attempt's own reason known),
                // whose every failure signature is covered (an expectation mismatch, an
                // error, a timeout or a kill is not).
                let exceptable = reason == FailReason::Functional
                    && auth
                        .iter()
                        .filter(|a| a.failed)
                        .all(|a| a.fail_reason == Some(FailReason::Functional))
                    && !sigs.is_empty();
                let covered = exceptable && sigs.iter().all(|g| active.contains_key(g.as_str()));
                if covered {
                    for g in &sigs {
                        if let Some(e) = active.get(g.as_str()) {
                            used.insert(e.id.clone(), (*e).clone());
                        }
                    }
                } else {
                    blockers.push(blocker(
                        BlockerKind::Failed { reason },
                        &s.slot,
                        sigs.into_iter().collect(),
                        exceptable,
                    ));
                }
            }
        }
    }
    let exceptions_used: Vec<ExceptionView> = used.into_values().collect();
    let verdict = if blockers.iter().any(|b| b.kind.insufficient()) {
        Verdict::InsufficientEvidence
    } else if !blockers.is_empty() {
        Verdict::Fail
    } else if !exceptions_used.is_empty() {
        Verdict::AcceptedWithExceptions
    } else {
        Verdict::Pass
    };
    let valid_until = exceptions_used.iter().map(|e| e.expires_at.clone()).min();
    MergeDecision {
        verdict,
        blockers,
        exceptions_used,
        valid_until,
        counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(seq: u32, failed: bool, sigs: &[&str]) -> AttemptView {
        AttemptView {
            unexplained: false,
            build_proven: true,
            fail_reason: failed.then_some(FailReason::Functional),
            blocked: None,
            attempt_seq: seq,
            eligible: true,
            terminal: true,
            failed,
            complete: true,
            contradiction: false,
            signatures: sigs.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn slot(name: &str, state: SlotState, attempts: Vec<AttemptView>) -> SlotInput {
        SlotInput {
            slot: name.into(),
            required: true,
            state,
            attempts,
        }
    }

    fn input(slots: Vec<SlotInput>, exceptions: Vec<ExceptionView>) -> MergeInput {
        MergeInput {
            candidate: Candidate {
                source_matches: true,
                collection_closed: true,
            },
            policy: Policy::Strict,
            slots,
            exceptions,
        }
    }

    fn exc(sig: &str, exp: &str) -> ExceptionView {
        ExceptionView {
            id: format!("x-{sig}"),
            revision: 1,
            signature: sig.into(),
            expires_at: exp.into(),
        }
    }

    #[test]
    fn pass_fail_and_exceptions() {
        let ok = input(
            vec![slot("a", SlotState::Passed, vec![att(1, false, &[])])],
            vec![],
        );
        assert_eq!(evaluate(&ok).verdict, Verdict::Pass);
        let failed = slot(
            "b",
            SlotState::Failed(FailReason::Functional),
            vec![att(1, true, &["S1", "S2"])],
        );
        let d = evaluate(&input(vec![failed.clone()], vec![exc("S1", "2026-12-01")]));
        assert_eq!(d.verdict, Verdict::Fail, "two families, one excepted");
        let d = evaluate(&input(
            vec![failed],
            vec![exc("S1", "2026-12-01"), exc("S2", "2026-11-20")],
        ));
        assert_eq!(d.verdict, Verdict::AcceptedWithExceptions);
        assert_eq!(d.valid_until.as_deref(), Some("2026-11-20"));
    }

    #[test]
    fn evidence_problems_are_never_excepted() {
        let mut a = att(1, true, &["S1"]);
        a.contradiction = true;
        let d = evaluate(&input(
            vec![slot(
                "a",
                SlotState::Failed(FailReason::Functional),
                vec![a],
            )],
            vec![exc("S1", "z")],
        ));
        assert_eq!(d.blockers[0].kind, BlockerKind::Contradiction);
        let mut a = att(1, true, &["S1"]);
        a.complete = false;
        let d = evaluate(&input(
            vec![slot(
                "a",
                SlotState::Failed(FailReason::Functional),
                vec![a],
            )],
            vec![exc("S1", "z")],
        ));
        assert_eq!(d.blockers[0].kind, BlockerKind::IncompleteEvidence);
        assert_eq!(d.verdict, Verdict::Fail);
        // An expectation mismatch is not exceptable.
        let d = evaluate(&input(
            vec![slot(
                "a",
                SlotState::Failed(FailReason::Expectation),
                vec![att(1, true, &["S1"])],
            )],
            vec![exc("S1", "z")],
        ));
        assert!(!d.blockers[0].exceptable);
        assert_eq!(d.verdict, Verdict::Fail);
    }

    #[test]
    fn missing_not_run_and_insufficient() {
        let mut opt = slot("o", SlotState::Missing, vec![]);
        opt.required = false;
        let d = evaluate(&input(
            vec![slot("m", SlotState::Missing, vec![]), opt],
            vec![],
        ));
        assert_eq!(d.blockers.len(), 1, "an optional slot does not block");
        assert_eq!(d.verdict, Verdict::Fail);
        let d = evaluate(&input(vec![slot("s", SlotState::Skipped, vec![])], vec![]));
        assert_eq!(d.blockers[0].kind, BlockerKind::RequiredNotRun);
        assert!(!d.blockers[0].exceptable);
        let d = evaluate(&input(
            vec![slot(
                "q",
                SlotState::Failed(FailReason::Insufficient),
                vec![att(1, true, &[])],
            )],
            vec![],
        ));
        assert_eq!(d.verdict, Verdict::InsufficientEvidence);
        let mut i = input(
            vec![slot("a", SlotState::Passed, vec![att(1, false, &[])])],
            vec![],
        );
        i.candidate.source_matches = false;
        assert_eq!(evaluate(&i).verdict, Verdict::InsufficientEvidence);
    }

    #[test]
    fn accepted_retry_has_one_authoritative_attempt() {
        // fail -> pass under retry-pass-accepted: the failing attempt (incomplete, with a
        // contradiction) is superseded and produces no blocker.
        let mut first = att(1, true, &["S1"]);
        first.complete = false;
        first.contradiction = true;
        let mut i = input(
            vec![slot(
                "a",
                SlotState::Passed,
                vec![first, att(2, false, &[])],
            )],
            vec![],
        );
        i.policy = Policy::RetryPassAccepted;
        let d = evaluate(&i);
        assert_eq!(d.verdict, Verdict::Pass);
        assert_eq!(d.exceptions_used, vec![]);
    }

    #[test]
    fn unexplained_failures_are_never_excepted() {
        let mut a = att(1, true, &["dviscope:unexplained"]);
        a.unexplained = true;
        let input = input(
            vec![slot(
                "s1",
                SlotState::Failed(FailReason::Functional),
                vec![a],
            )],
            vec![exc("dviscope:unexplained", "2099-01-01T00:00:00Z")],
        );
        let d = evaluate(&input);
        assert_eq!(d.verdict, Verdict::Fail, "{d:?}");
        assert_eq!(d.blockers[0].kind, BlockerKind::Unexplained);
        assert!(!d.blockers[0].exceptable);
        assert_eq!(d.exceptions_used.len(), 0);
    }

    #[test]
    fn every_authoritative_attempt_needs_its_build_proof() {
        // Strict: attempt 1 (unproven build) and attempt 2 (proven) fail the same way.
        let mut a1 = att(1, true, &["S1"]);
        a1.build_proven = false;
        let a2 = att(2, true, &["S1"]);
        let d = evaluate(&input(
            vec![slot(
                "s",
                SlotState::Failed(FailReason::Functional),
                vec![a1, a2],
            )],
            vec![exc("S1", "2099-01-01T00:00:00Z")],
        ));
        assert_eq!(d.verdict, Verdict::InsufficientEvidence, "{d:?}");
        assert_eq!(d.exceptions_used.len(), 0);
    }

    #[test]
    fn an_earlier_non_functional_failure_is_never_exceptable() {
        // Strict policy, attempt 1 timed out (error, killed, expectation),
        // attempt 2 failed functionally; exceptions cover both signatures.
        let both = || vec![exc("S1", "2026-12-01"), exc("S2", "2026-12-01")];
        for first in [
            FailReason::Timeout,
            FailReason::Error,
            FailReason::Killed,
            FailReason::Expectation,
        ] {
            let mut a1 = att(1, true, &["S1"]);
            a1.fail_reason = Some(first);
            let a2 = att(2, true, &["S2"]);
            let s = slot(
                "t1",
                SlotState::Failed(FailReason::Functional),
                vec![a1, a2],
            );
            let d = evaluate(&input(vec![s], both()));
            assert_eq!(d.verdict, Verdict::Fail, "{first:?}: {d:?}");
            assert!(d.exceptions_used.is_empty(), "{first:?}");
            let [b] = d.blockers.as_slice() else {
                panic!("{d:?}")
            };
            assert_eq!(b.kind, BlockerKind::Failed { reason: first });
            assert!(!b.exceptable);
        }
        // Both functional: excepted.
        let s = slot(
            "t1",
            SlotState::Failed(FailReason::Functional),
            vec![att(1, true, &["S1"]), att(2, true, &["S2"])],
        );
        assert_eq!(
            evaluate(&input(vec![s], both())).verdict,
            Verdict::AcceptedWithExceptions
        );
        // An attempt whose own reason is unknown fails closed.
        let mut a1 = att(1, true, &["S1"]);
        a1.fail_reason = None;
        let s = slot("t1", SlotState::Failed(FailReason::Functional), vec![a1]);
        assert_eq!(evaluate(&input(vec![s], both())).verdict, Verdict::Fail);
    }

    #[test]
    fn an_earlier_blocked_attempt_is_never_exceptable() {
        // Retry-pass-accepted, attempt 1 blocked in elaboration (or the build),
        // attempt 2 failed functionally; exceptions cover both signatures.
        let both = || vec![exc("S1", "2026-12-01"), exc("S2", "2026-12-01")];
        for by in [BlockedBy::Elaboration, BlockedBy::Build] {
            for policy in [Policy::RetryPassAccepted, Policy::Strict] {
                let mut a1 = att(1, true, &["S1"]);
                a1.fail_reason = None;
                a1.blocked = Some(by);
                let a2 = att(2, true, &["S2"]);
                let s = slot(
                    "t1",
                    SlotState::Failed(FailReason::Functional),
                    vec![a1, a2],
                );
                let mut i = input(vec![s], both());
                i.policy = policy;
                let d = evaluate(&i);
                assert_eq!(d.verdict, Verdict::Fail, "{by:?} {policy:?}: {d:?}");
                assert!(d.exceptions_used.is_empty(), "{by:?} {policy:?}");
                let [b] = d.blockers.as_slice() else {
                    panic!("{d:?}")
                };
                assert_eq!(b.kind, BlockerKind::Blocked { by });
                assert!(!b.exceptable);
            }
            // Control: blocked, then a passing retry under retry-pass-accepted passes.
            let mut a1 = att(1, true, &["S1"]);
            a1.fail_reason = None;
            a1.blocked = Some(by);
            let s = slot("t1", SlotState::Passed, vec![a1, att(2, false, &[])]);
            let mut i = input(vec![s], vec![]);
            i.policy = Policy::RetryPassAccepted;
            assert_eq!(evaluate(&i).verdict, Verdict::Pass, "{by:?}");
        }
    }
}
