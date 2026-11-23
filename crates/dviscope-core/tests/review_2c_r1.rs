//! Regression tests.

use std::collections::BTreeMap;

use dviscope_core::compare::{SignatureCounts, SlotView, compare};
use dviscope_core::eligibility::Eligibility;
use dviscope_core::expectation::Assessment;
use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::outcome::{BlockingPhase, Effective, Input, Outcome, Reason, derive};
use dviscope_core::packs::{PackInput, compile, shipped};
use dviscope_core::settlement::{
    AttemptFacts, Barrier, BuildFacts, BuildResult, FailReason, Policy, SlotFacts, SlotState,
    Terminal, settle,
};
use dviscope_model::canonical::Digest;
use dviscope_model::values::UtcTime;
use dviscope_model::wire::ingest::{Runner, Termination, TerminationKind};
use dviscope_model::wire::manifest::{
    Expected, ExpectedCount, ExpectedDiagnostic, ExpectedVerdict, Extras, Severity,
};

fn runner() -> Runner {
    let t = UtcTime::new(time::OffsetDateTime::UNIX_EPOCH);
    Runner {
        termination: Termination {
            kind: TerminationKind::Exited,
            exit_code: Some(0),
            posix_signal: None,
            windows_status: None,
        },
        started_at: t,
        finished_at: Some(t),
        wall_s: None,
        timeout_s: None,
        cpu_s: None,
        cpu_scope: None,
        peak_rss_kb: None,
        peak_scope: None,
        host: None,
    }
}

const TRAILER: &str = "$finish at simulation time 1\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n";

#[test]
fn c1_suppressed_errors_never_explain_a_counter() {
    let pack = "format: dviscope.rules/1.0\npack: proj\nversion: 1.0.0\ntier: project\nrules:\n  - {id: s, version: 1.0.0, kind: suppression, owner: o, reason: r, action: not_an_error, diag_ids: ['uvm:NOISE']}\n";
    let mut inputs = shipped::default_inputs();
    inputs.push(PackInput {
        name: "p.yaml".into(),
        text: pack.into(),
    });
    let p = compile(&inputs).unwrap_or_else(|e| panic!("{e}"));
    let mut text = String::from("UVM_ERROR @ 1: env [CHK] expected one\n");
    for i in 0..9 {
        text.push_str(&format!("UVM_ERROR @ {i}: env [NOISE] unexpected\n"));
    }
    text.push_str("--- UVM Report Summary ---\nUVM_INFO :    0\nUVM_WARNING :    0\nUVM_ERROR :   10\nUVM_FATAL :    0\n");
    text.push_str(TRAILER);
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = Some("vcs".into());
    let ev = extract_bytes(&p, o, text.as_bytes()).0;
    let x = Expected {
        verdict: ExpectedVerdict::Fail,
        diagnostics: vec![ExpectedDiagnostic {
            diag_id: "uvm:CHK".into(),
            severity: Severity::Error,
            checker_id: None,
            site: None,
            count: ExpectedCount::Exact(1),
        }],
        extras: Extras::None,
        reason: "r".into(),
    };
    let r = runner();
    let d = derive(&Input {
        evidence: Some(&ev),
        runner: &r,
        producer: None,
        has_build_requirement: false,
        exit_code_meaningful: false,
        expected: Some(&x),
    });
    assert_eq!(d.assessment, Assessment::NotMet, "{:?}", d.contract);
    assert_eq!(d.effective, Effective::Failed);
}

fn attempt_with(refs: &[&str]) -> AttemptFacts {
    AttemptFacts {
        attempt_seq: 1,
        eligibility: Eligibility::Eligible,
        barrier: Barrier::default(),
        terminal: Some(Terminal {
            outcome: Outcome::Pass,
            blocking_phase: None::<BlockingPhase>,
            effective: Effective::Passed,
            expectation_not_met: false,
            termination_unknown: false,
            build_refs: refs.iter().map(|s| (*s).to_string()).collect(),
        }),
    }
}

fn build(r: &str, req: &str) -> BuildFacts {
    BuildFacts {
        build_ref: r.into(),
        requirement: req.into(),
        build_order: 1,
        eligible: true,
        result: Some(BuildResult::Pass),
    }
}

#[test]
fn c2_build_proof_covers_every_requirement() {
    let slot = |refs: &[&str], builds: Vec<BuildFacts>| SlotFacts {
        attempts: vec![attempt_with(refs)],
        build_requirements: vec!["R1".into(), "R2".into()],
        builds: builds.into(),
        mark: None,
    };
    let insufficient = SlotState::Failed(FailReason::Insufficient);
    assert_eq!(
        settle(
            &slot(&["B1", "B1"], vec![build("B1", "R1")]),
            Policy::Strict
        )
        .state,
        insufficient
    );
    assert_eq!(
        settle(
            &slot(&["B1", "B2"], vec![build("B1", "R1"), build("B2", "R1")]),
            Policy::Strict
        )
        .state,
        insufficient
    );
    assert_eq!(
        settle(
            &slot(&["B1", "B2"], vec![build("B1", "R1"), build("B2", "R2")]),
            Policy::Strict
        )
        .state,
        SlotState::Passed
    );
}

#[test]
fn c3_rows_count_per_signature() {
    let d = |s: &str| Digest::of_bytes(s.as_bytes());
    let mut sigs = BTreeMap::new();
    sigs.insert(
        d("x"),
        SignatureCounts {
            attempts: 1,
            diagnostics: 10,
        },
    );
    sigs.insert(
        d("y"),
        SignatureCounts {
            attempts: 1,
            diagnostics: 1,
        },
    );
    let v = SlotView {
        slot: "s".into(),
        config: d("c"),
        simulator: "vcs".into(),
        state: SlotState::Failed(FailReason::Functional),
        signatures: sigs,
    };
    let c = compare(&[v], None);
    let by: BTreeMap<_, _> = c
        .rows
        .iter()
        .map(|r| (r.signature.clone(), (r.failing_attempts, r.diagnostics)))
        .collect();
    assert_eq!(by[&d("x")], (1, 10));
    assert_eq!(by[&d("y")], (1, 1));
}

#[test]
fn c4_row_9_adds_no_verdict() {
    let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = Some("vcs".into());
    let ev = extract_bytes(&p, o, TRAILER.as_bytes()).0;
    let r = runner();
    let d = derive(&Input {
        evidence: Some(&ev),
        runner: &r,
        producer: None,
        has_build_requirement: false,
        exit_code_meaningful: false,
        expected: None,
    });
    assert_eq!(d.outcome, Outcome::Fail);
    assert!(d.reasons.contains(&Reason::NoVerdict), "{:?}", d.reasons);
}

/// The simulator pack is the one whose completion profile the
/// evidence records (every pack of the pipeline is listed in the evidence).
#[test]
fn s3_r1_3_the_simulator_is_found_by_profile() {
    let p = dviscope_core::packs::shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
    let v = p
        .pack_of_profile("verilator-run")
        .map(|c| (c.id.as_str(), c.exit_code_meaningful));
    assert_eq!(v, Some(("verilator", true)));
    let q = p
        .pack_of_profile("vcs-run")
        .map(|c| (c.id.as_str(), c.exit_code_meaningful));
    assert_eq!(q, Some(("vcs", false)));
    assert!(p.pack_of_profile("unknown").is_none());
}
