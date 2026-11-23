//! Core-layer acceptance cases (A07, A08, A09, A26e, A26f) on invented logs in
//! the shipped packs' message forms. No simulator output.

use dviscope_core::expectation::Assessment;
use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::outcome::{Derived, Effective, Input, Outcome, derive, synthetic};
use dviscope_core::packs::{PackInput, Pipeline, compile, shipped};
use dviscope_model::values::UtcTime;
use dviscope_model::wire::evidence::Evidence;
use dviscope_model::wire::ingest::{ReportedOutcome, Runner, Termination, TerminationKind};
use dviscope_model::wire::manifest::{
    Expected, ExpectedCount, ExpectedDiagnostic, ExpectedVerdict, Extras, Severity,
};

const PROJECT: &str = r#"
format: dviscope.rules/1.0
pack: proj
version: 1.0.0
tier: project
rules:
  - {id: quiet, version: 1.0.0, kind: suppression, owner: o, reason: r, action: not_an_error,
     diag_ids: ['display:error']}
"#;

fn pipeline(project: bool) -> Pipeline {
    let mut inputs = shipped::default_inputs();
    if project {
        inputs.push(PackInput {
            name: "proj.yaml".into(),
            text: PROJECT.into(),
        });
    }
    match compile(&inputs) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    }
}

fn evidence(p: &Pipeline, sim: &str, text: &str) -> Evidence {
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = Some(sim.into());
    extract_bytes(p, o, text.as_bytes()).0
}

fn runner(kind: TerminationKind, exit: Option<i32>) -> Runner {
    let t = UtcTime::new(time::OffsetDateTime::UNIX_EPOCH);
    Runner {
        termination: Termination {
            kind,
            exit_code: exit,
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

fn run(ev: Option<&Evidence>, r: &Runner, expected: Option<&Expected>) -> Derived {
    derive(&Input {
        evidence: ev,
        runner: r,
        producer: None,
        has_build_requirement: true,
        exit_code_meaningful: false,
        expected,
    })
}

fn exited() -> Runner {
    runner(TerminationKind::Exited, Some(0))
}

/// A complete VCS-style UVM run: the given body, a UVM summary and the trailer.
fn vcs_run(body: &str, errors: u32, fatals: u32) -> String {
    format!(
        "{body}--- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    {errors}\nUVM_FATAL :    {fatals}\n$finish at simulation time 100\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n"
    )
}

fn has(d: &Derived, id: &str) -> bool {
    d.synthetic.iter().any(|s| s.diag_id == id)
}

#[test]
fn a07_incomplete_evidence_never_passes() {
    let p = pipeline(false);
    let clean = evidence(&p, "vcs", &vcs_run("UVM_INFO @ 1: top [HELLO] hi\n", 0, 0));
    let d = run(Some(&clean), &exited(), None);
    assert_eq!((d.outcome, d.effective), (Outcome::Pass, Effective::Passed));

    let truncated = evidence(&p, "vcs", "UVM_INFO @ 1: top [HELLO] hi\n");
    let d = run(Some(&truncated), &exited(), None);
    assert_eq!(d.outcome, Outcome::Fail);
    assert!(has(&d, synthetic::INCOMPLETE_EVIDENCE));

    let d = run(
        Some(&clean),
        &runner(TerminationKind::TerminatedByRunner, None),
        None,
    );
    assert_eq!(d.outcome, Outcome::Killed);
    let d = run(
        Some(&truncated),
        &runner(TerminationKind::Timeout, None),
        None,
    );
    assert_eq!(d.outcome, Outcome::Timeout);
    assert_eq!(d.primary.as_deref(), Some(synthetic::RUNNER_TIMEOUT));

    let empty = evidence(&p, "vcs", "");
    let d = run(
        Some(&empty),
        &runner(TerminationKind::Exited, Some(127)),
        None,
    );
    assert_eq!(d.outcome, Outcome::Error);
    assert!(has(&d, synthetic::NO_LOG));

    // Unknown termination with a complete-looking log: error, never pass or met.
    let x = expected_fail(vec![sel("uvm:CHK", Severity::Error, 1)]);
    let d = run(
        Some(&clean),
        &runner(TerminationKind::Unknown, None),
        Some(&x),
    );
    assert_eq!(d.outcome, Outcome::Error);
    assert!(!d.completion_complete);
    assert_eq!(d.assessment, Assessment::Unassessable);
    assert_eq!(d.primary.as_deref(), Some(synthetic::RUNNER_UNKNOWN));

    // Unknown completion profile (undetected simulator).
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = None;
    let undetected = extract_bytes(&p, o, b"just text\n").0;
    assert_eq!(
        run(Some(&undetected), &exited(), None).outcome,
        Outcome::Fail
    );

    // A warning-only log passes.
    let warn = evidence(
        &p,
        "vcs",
        &vcs_run("UVM_WARNING @ 1: top [W] careful\n", 0, 0)
            .replace("UVM_WARNING :    0", "UVM_WARNING :    1"),
    );
    let d = run(Some(&warn), &exited(), None);
    assert_eq!(d.outcome, Outcome::Pass, "{:?}", d.reasons);
}

#[test]
fn a08_error_storm_with_passing_summary_fails() {
    let p = pipeline(false);
    // VCS: authoritative $error family, UVM summary says 0 errors.
    let storm: String = (0..50)
        .map(|i| format!("Error: \"tb.sv\", 46: tb: at time {i} ps\nglitch {i}\n"))
        .collect();
    let ev = evidence(&p, "vcs", &vcs_run(&storm, 0, 0));
    let d = run(Some(&ev), &exited(), None);
    assert_eq!(d.outcome, Outcome::Fail);
    assert!(d.contradictions.iter().any(|c| !c.explained));
    // Questa: the closing Errors: counter fails the run even when no line is extracted as
    // a failure (display errors suppressed by a broad project rule).
    let p = pipeline(true);
    let text = "# ERROR: glitch 1\n# ERROR: glitch 2\n# --- UVM Report Summary ---\n# UVM_INFO :    0\n# UVM_WARNING :    0\n# UVM_ERROR :    0\n# UVM_FATAL :    0\n# End time: 10:00:00 on Jan 01,2026, Elapsed time: 0:00:01\n# Errors: 2, Warnings: 0\n";
    let ev = evidence(&p, "questa", text);
    let d = run(Some(&ev), &exited(), None);
    assert_eq!(d.outcome, Outcome::Fail, "{:?}", d.reasons);
    assert!(has(&d, synthetic::UNEXPLAINED_FAILURE));
}

fn sel(id: &str, sev: Severity, n: u32) -> ExpectedDiagnostic {
    ExpectedDiagnostic {
        diag_id: id.into(),
        severity: sev,
        checker_id: None,
        site: None,
        count: ExpectedCount::Exact(n),
    }
}

fn expected_fail(d: Vec<ExpectedDiagnostic>) -> Expected {
    Expected {
        verdict: ExpectedVerdict::Fail,
        diagnostics: d,
        extras: Extras::None,
        reason: "negative test".into(),
    }
}

fn uvm_errors(n: usize, id: &str) -> String {
    (0..n)
        .map(|i| format!("UVM_ERROR src/chk.sv(12) @ {i}: env.chk [{id}] value differs\n"))
        .collect()
}

#[test]
fn a09_expectation_truth_table() {
    let p = pipeline(false);
    let failing = evidence(&p, "vcs", &vcs_run(&uvm_errors(2, "CHK"), 2, 0));
    // Met: right ID, count and counters.
    let x = expected_fail(vec![sel("uvm:CHK", Severity::Error, 2)]);
    let d = run(Some(&failing), &exited(), Some(&x));
    assert_eq!(
        (d.outcome, d.assessment, d.effective),
        (Outcome::Fail, Assessment::Met, Effective::Passed)
    );
    // Wrong count.
    let x = expected_fail(vec![sel("uvm:CHK", Severity::Error, 3)]);
    assert_eq!(
        run(Some(&failing), &exited(), Some(&x)).assessment,
        Assessment::NotMet
    );
    // Wrong severity.
    let x = expected_fail(vec![sel("uvm:CHK", Severity::Fatal, 2)]);
    let d = run(Some(&failing), &exited(), Some(&x));
    assert_eq!(d.assessment, Assessment::NotMet);
    assert_eq!(d.primary.as_deref(), Some(synthetic::EXPECTATION_MISMATCH));
    assert!(
        d.contract
            .as_ref()
            .is_some_and(|c| !c.wrong_severity.is_empty())
    );
    // Right ID at the wrong site.
    let mut s = sel("uvm:CHK", Severity::Error, 2);
    s.site = Some("src/other.sv:12".into());
    let d = run(Some(&failing), &exited(), Some(&expected_fail(vec![s])));
    assert_eq!(d.assessment, Assessment::NotMet);
    assert!(
        d.contract
            .as_ref()
            .is_some_and(|c| !c.wrong_site.is_empty())
    );
    // Unexpected pass.
    let clean = evidence(&p, "vcs", &vcs_run("", 0, 0));
    let x = expected_fail(vec![sel("uvm:CHK", Severity::Error, 2)]);
    assert_eq!(
        run(Some(&clean), &exited(), Some(&x)).assessment,
        Assessment::NotMet
    );
    // Expected diagnostics plus a timeout.
    let d = run(
        Some(&failing),
        &runner(TerminationKind::Timeout, None),
        Some(&x),
    );
    assert_eq!(d.outcome, Outcome::Timeout);
    assert_ne!(d.assessment, Assessment::Met);
    // An extra warning with extras: none, and with warnings_allowed.
    let body = format!("{}UVM_WARNING @ 5: env [W] note\n", uvm_errors(2, "CHK"));
    let warned = evidence(
        &p,
        "vcs",
        &vcs_run(&body, 2, 0).replace("UVM_WARNING :    0", "UVM_WARNING :    1"),
    );
    let x = expected_fail(vec![sel("uvm:CHK", Severity::Error, 2)]);
    assert_eq!(
        run(Some(&warned), &exited(), Some(&x)).assessment,
        Assessment::NotMet
    );
    let mut x2 = x.clone();
    x2.extras = Extras::WarningsAllowed;
    assert_eq!(
        run(Some(&warned), &exited(), Some(&x2)).assessment,
        Assessment::Met
    );
    // One expected error printed once while UVM counted 10: not met.
    let once = evidence(&p, "vcs", &vcs_run(&uvm_errors(1, "CHK"), 10, 0));
    let x = expected_fail(vec![sel("uvm:CHK", Severity::Error, 1)]);
    let d = run(Some(&once), &exited(), Some(&x));
    assert_eq!(d.assessment, Assessment::NotMet);
    assert!(has(&d, synthetic::UNEXPLAINED_FAILURE));
}

#[test]
fn a09_pass_with_expected_diagnostics_and_early_fatal() {
    let p = pipeline(false);
    // SVUnit-style: a passing runner with expected assertion errors.
    let text = "INFO:  [0][u_ut]: t1::RUNNING\n[0] %Error: m.sv:39: Assertion failed in pkg.m.f: bad input\nINFO:  [0][u_ut]: t1::PASSED\nINFO:  [0][testrunner]: PASSED (1 of 1 suites passing) [SVUnit 1.0]\n- S i m u l a t i o n   R e p o r t: Verilator 5\n- Verilator: $finish at 0s; walltime 0.1 s\n";
    let ev = evidence(&p, "verilator", text);
    let x = Expected {
        verdict: ExpectedVerdict::Pass,
        diagnostics: vec![ExpectedDiagnostic {
            diag_id: "sv:severity_task".into(),
            severity: Severity::Error,
            checker_id: None,
            site: Some("m.sv:39".into()),
            count: ExpectedCount::Exact(1),
        }],
        extras: Extras::None,
        reason: "error path test".into(),
    };
    let d = run(Some(&ev), &exited(), Some(&x));
    assert_eq!(d.outcome, Outcome::Fail, "{:?}", d.reasons);
    assert_eq!(
        (d.assessment, d.effective),
        (Assessment::Met, Effective::Passed),
        "{:?}",
        d.contract
    );
    assert!(d.contradictions.iter().all(|c| c.explained));
    // Expected fatal: early-fatal completion, assessment met.
    let text = "UVM_FATAL src/w.sv(9) @ 100: watchdog [WDOG] no heartbeat\n$finish at simulation time 100\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n";
    let ev = evidence(&p, "vcs", text);
    let x = expected_fail(vec![sel("uvm:WDOG", Severity::Fatal, 1)]);
    let d = run(Some(&ev), &exited(), Some(&x));
    assert!(d.completion_complete);
    assert_eq!(
        (d.assessment, d.effective),
        (Assessment::Met, Effective::Passed),
        "{:?}",
        d.contract
    );
}

#[test]
fn a26e_producer_fail_with_clean_log_is_unexplained() {
    let p = pipeline(false);
    let clean = evidence(&p, "vcs", &vcs_run("", 0, 0));
    let r = exited();
    let d = derive(&Input {
        evidence: Some(&clean),
        runner: &r,
        producer: Some(ReportedOutcome::Fail),
        has_build_requirement: true,
        exit_code_meaningful: false,
        expected: None,
    });
    assert_eq!(d.outcome, Outcome::Fail);
    assert!(has(&d, synthetic::UNEXPLAINED_FAILURE));
}

#[test]
fn a26f_elaboration_diagnostic_without_design_load_line_blocks() {
    let p = pipeline(false);
    let text = "# ** Error (suppressible): tb.sv(46): (vopt-2912) Port 'clock' not found.\n# End time: 10:00:00 on Jan 01,2026, Elapsed time: 0:00:01\n# Errors: 1, Warnings: 0\n";
    let ev = evidence(&p, "questa", text);
    let d = run(Some(&ev), &exited(), None);
    assert_eq!(d.outcome, Outcome::Blocked, "{:?}", d.reasons);
    assert_eq!(
        d.blocking_phase,
        Some(dviscope_core::outcome::BlockingPhase::Elaborate)
    );
    // Without a build requirement the same log is an error.
    let r = exited();
    let d = derive(&Input {
        evidence: Some(&ev),
        runner: &r,
        producer: None,
        has_build_requirement: false,
        exit_code_meaningful: false,
        expected: None,
    });
    assert_eq!(d.outcome, Outcome::Error);
}
