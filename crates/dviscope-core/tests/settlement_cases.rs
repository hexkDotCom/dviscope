//! Core-layer settlement cases (A02, A03 core part, A06a, A11 core part,
//! A21 core part, A26a, A26c).

use dviscope_core::eligibility::{Eligibility, IneligibleReason};
use dviscope_core::outcome::{BlockingPhase, Effective, Outcome};
use dviscope_core::settlement::{
    AttemptFacts, Barrier, BlockedBy, BuildFacts, BuildResult, CombinedBuild, FailReason, Mark,
    Policy, SlotFacts, SlotState, Terminal, combined_build, settle,
};
use proptest::prelude::*;

fn terminal(outcome: Outcome) -> Terminal {
    Terminal {
        outcome,
        blocking_phase: (outcome == Outcome::Blocked).then_some(BlockingPhase::Elaborate),
        effective: if outcome == Outcome::Pass {
            Effective::Passed
        } else {
            Effective::Failed
        },
        expectation_not_met: false,
        termination_unknown: false,
        build_refs: vec!["b1".into()],
    }
}

fn attempt(seq: u32, outcome: Option<Outcome>) -> AttemptFacts {
    AttemptFacts {
        attempt_seq: seq,
        eligibility: Eligibility::Eligible,
        barrier: Barrier::default(),
        terminal: outcome.map(terminal),
    }
}

fn build(r: &str, order: u64, result: Option<BuildResult>) -> BuildFacts {
    BuildFacts {
        build_ref: r.into(),
        requirement: "req".into(),
        build_order: order,
        eligible: true,
        result,
    }
}

fn slot(attempts: Vec<AttemptFacts>) -> SlotFacts {
    SlotFacts {
        attempts,
        build_requirements: vec!["req".into()],
        builds: vec![build("b1", 1, Some(BuildResult::Pass))].into(),
        mark: None,
    }
}

#[test]
fn a02_retry_policies() {
    let fail_pass = slot(vec![
        attempt(1, Some(Outcome::Fail)),
        attempt(2, Some(Outcome::Pass)),
    ]);
    assert_eq!(
        settle(&fail_pass, Policy::Strict).state,
        SlotState::Failed(FailReason::Functional)
    );
    let s = settle(&fail_pass, Policy::RetryPassAccepted);
    assert_eq!(s.state, SlotState::Passed);
    assert!(s.note.is_some_and(|n| n.contains("accepted retry")));
    let pass_fail = slot(vec![
        attempt(1, Some(Outcome::Pass)),
        attempt(2, Some(Outcome::Fail)),
    ]);
    for p in [Policy::Strict, Policy::RetryPassAccepted] {
        assert_eq!(
            settle(&pass_fail, p).state,
            SlotState::Failed(FailReason::Functional)
        );
    }
    // fail -> ineligible pass stays failed.
    let mut ineligible = attempt(2, Some(Outcome::Pass));
    ineligible.eligibility = Eligibility::Ineligible(IneligibleReason::SourceMismatch);
    let s = slot(vec![attempt(1, Some(Outcome::Fail)), ineligible]);
    assert_eq!(
        settle(&s, Policy::RetryPassAccepted).state,
        SlotState::Failed(FailReason::Functional)
    );
    // Historical blocked attempt, later pass.
    let s = slot(vec![
        attempt(1, Some(Outcome::Blocked)),
        attempt(2, Some(Outcome::Pass)),
    ]);
    assert_eq!(
        settle(&s, Policy::Strict).state,
        SlotState::Blocked(BlockedBy::Elaboration)
    );
    assert_eq!(
        settle(&s, Policy::RetryPassAccepted).state,
        SlotState::Passed
    );
    // Infrastructure reasons are kept.
    let s = slot(vec![attempt(1, Some(Outcome::Timeout))]);
    assert_eq!(
        settle(&s, Policy::Strict).state,
        SlotState::Failed(FailReason::Timeout)
    );
}

#[test]
fn a03_builds_and_elaboration() {
    // Not yet run: the combined build state decides.
    let mut s = slot(vec![]);
    s.builds = vec![build("b1", 1, Some(BuildResult::Fail))].into();
    assert_eq!(
        settle(&s, Policy::Strict).state,
        SlotState::Blocked(BlockedBy::Build)
    );
    // compile fail -> pass: dependents missing until they run.
    s.builds = s
        .builds
        .iter()
        .cloned()
        .chain([build("b2", 2, Some(BuildResult::Pass))])
        .collect();
    assert_eq!(settle(&s, Policy::Strict).state, SlotState::Missing);
    // pass -> fail: not-yet-run dependents blocked; already-run ones keep their result.
    s.builds = vec![
        build("b1", 1, Some(BuildResult::Pass)),
        build("b2", 2, Some(BuildResult::Fail)),
    ]
    .into();
    assert_eq!(
        settle(&s, Policy::Strict).state,
        SlotState::Blocked(BlockedBy::Build)
    );
    s.attempts = vec![attempt(1, Some(Outcome::Pass))];
    assert_eq!(settle(&s, Policy::Strict).state, SlotState::Passed);
    // A started build: waiting.
    let mut w = slot(vec![]);
    w.builds = vec![build("b1", 1, None)].into();
    assert_eq!(combined_build(&w), CombinedBuild::Running);
    assert_eq!(
        settle(&w, Policy::Strict).note.as_deref(),
        Some("waiting for build")
    );
    // Run-time elaboration failure; cleared by a later attempt that loads the design.
    let e = slot(vec![attempt(1, Some(Outcome::Blocked))]);
    assert_eq!(
        settle(&e, Policy::RetryPassAccepted).state,
        SlotState::Blocked(BlockedBy::Elaboration)
    );
    let e = slot(vec![
        attempt(1, Some(Outcome::Blocked)),
        attempt(2, Some(Outcome::Pass)),
    ]);
    assert_eq!(
        settle(&e, Policy::RetryPassAccepted).state,
        SlotState::Passed
    );
}

#[test]
fn a11_quarantine_never_exposes_an_earlier_pass() {
    let mut q = attempt(2, Some(Outcome::Fail));
    q.eligibility = Eligibility::Ineligible(IneligibleReason::Quarantined);
    q.barrier.quarantined_credential = true;
    let s = slot(vec![attempt(1, Some(Outcome::Pass)), q.clone()]);
    for p in [Policy::Strict, Policy::RetryPassAccepted] {
        assert_eq!(
            settle(&s, p).state,
            SlotState::Failed(FailReason::Insufficient)
        );
    }
    // A later eligible attempt from a valid credential clears it.
    let s = slot(vec![
        attempt(1, Some(Outcome::Pass)),
        q,
        attempt(3, Some(Outcome::Pass)),
    ]);
    assert_eq!(settle(&s, Policy::Strict).state, SlotState::Passed);
}

#[test]
fn a21_unknown_termination_needs_a_new_attempt() {
    let mut t = terminal(Outcome::Error);
    t.termination_unknown = true;
    let mut a = attempt(1, None);
    a.terminal = Some(t);
    let s = slot(vec![a]);
    assert_eq!(
        settle(&s, Policy::RetryPassAccepted).state,
        SlotState::Failed(FailReason::Insufficient)
    );
    // A started attempt without a terminal report keeps the slot running.
    let s = slot(vec![attempt(1, Some(Outcome::Pass)), attempt(2, None)]);
    assert_eq!(settle(&s, Policy::Strict).state, SlotState::Running);
}

#[test]
fn a26_build_proof() {
    // (a) passing simulation built with B2; B2 quarantined; an older passing B1 exists.
    let mut s = slot(vec![attempt(1, Some(Outcome::Pass))]);
    if let Some(t) = s.attempts[0].terminal.as_mut() {
        t.build_refs = vec!["b2".into()];
    }
    s.builds = vec![
        build("b1", 1, Some(BuildResult::Pass)),
        BuildFacts {
            eligible: false,
            ..build("b2", 2, Some(BuildResult::Pass))
        },
    ]
    .into();
    let r = settle(&s, Policy::Strict);
    assert_eq!(r.state, SlotState::Failed(FailReason::Insufficient));
    assert_eq!(r.note.as_deref(), Some("build not proven"));
    // (c) the referenced build has no terminal report while a later B2 passes.
    s.builds = vec![
        build("b2", 1, None),
        build("b3", 2, Some(BuildResult::Pass)),
    ]
    .into();
    assert_eq!(
        settle(&s, Policy::Strict).state,
        SlotState::Failed(FailReason::Insufficient)
    );
}

#[test]
fn marks_never_override_a_terminal_attempt() {
    let mut s = slot(vec![]);
    s.mark = Some(Mark::Skipped);
    assert_eq!(settle(&s, Policy::Strict).state, SlotState::Skipped);
    s.attempts = vec![attempt(1, Some(Outcome::Fail))];
    assert_eq!(
        settle(&s, Policy::Strict).state,
        SlotState::Failed(FailReason::Functional)
    );
}

fn arb_outcome() -> impl Strategy<Value = Option<Outcome>> {
    prop_oneof![
        Just(None),
        Just(Some(Outcome::Pass)),
        Just(Some(Outcome::Fail)),
        Just(Some(Outcome::Timeout)),
        Just(Some(Outcome::Blocked)),
    ]
}

proptest! {
    /// A06a: settlement is identical for any order of the same fact set (incl. its
    /// assigned build_order values).
    #[test]
    fn a06a_order_invariance(
        outcomes in prop::collection::vec(arb_outcome(), 0..5),
        builds in prop::collection::vec((0u64..5, prop::option::of(prop_oneof![Just(BuildResult::Pass), Just(BuildResult::Fail)])), 0..4),
        quarantine in any::<u8>(),
        seed in any::<u64>(),
    ) {
        let attempts: Vec<AttemptFacts> = outcomes.iter().enumerate().map(|(i, o)| {
            let mut a = attempt(u32::try_from(i).unwrap_or(0) + 1, *o);
            if quarantine & (1 << (i % 8)) != 0 && i % 3 == 0 {
                a.eligibility = Eligibility::Ineligible(IneligibleReason::Quarantined);
                a.barrier.quarantined_credential = true;
            }
            a
        }).collect();
        let builds: Vec<BuildFacts> = builds.iter().enumerate()
            .map(|(i, (order, r))| build(&format!("b{i}"), *order * 10 + i as u64, *r))
            .collect();
        let base = SlotFacts { attempts, build_requirements: vec!["req".into()], builds: builds.into(), mark: None };
        let mut shuffled = base.clone();
        // Deterministic permutation from the seed.
        let n = shuffled.attempts.len();
        for i in (1..n).rev() {
            let j = usize::try_from((seed >> (i % 32)) % (i as u64 + 1)).unwrap_or(0);
            shuffled.attempts.swap(i, j);
        }
        shuffled.builds = shuffled.builds.iter().rev().cloned().collect();
        for p in [Policy::Strict, Policy::RetryPassAccepted] {
            prop_assert_eq!(settle(&base, p), settle(&shuffled, p));
        }
    }
}
