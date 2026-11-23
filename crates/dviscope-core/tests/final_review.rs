//! Core regression tests, each a test
//! that tries to turn a failure green. Invented toy formats and the shipped packs' message
//! forms only.

use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::outcome::{Effective, Input, Outcome, derive};
use dviscope_core::packs::{PackInput, compile, shipped};
use dviscope_core::rule_check::{SampleCase, SampleManifest};
use dviscope_model::values::UtcTime;
use dviscope_model::wire::evidence::{CompletionState, Evidence, VerdictValue};
use dviscope_model::wire::ingest::{Runner, Termination, TerminationKind};

fn project(body: &str) -> PackInput {
    PackInput {
        name: "proj.yaml".into(),
        text: format!(
            "format: dviscope.rules/1.0\npack: proj\nversion: 1.0.0\ntier: project\n{body}"
        ),
    }
}

fn with_defaults(extra: Vec<PackInput>) -> Result<dviscope_core::packs::Pipeline, String> {
    let mut inputs = shipped::default_inputs();
    inputs.extend(extra);
    compile(&inputs).map_err(|e| e.to_string())
}

fn runner(exit: i32) -> Runner {
    let t = UtcTime::new(time::OffsetDateTime::UNIX_EPOCH);
    Runner {
        termination: Termination {
            kind: TerminationKind::Exited,
            exit_code: Some(exit),
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

fn outcome(ev: &Evidence) -> (Outcome, Effective) {
    let d = derive(&Input {
        evidence: Some(ev),
        runner: &runner(0),
        producer: None,
        has_build_requirement: true,
        exit_code_meaningful: true,
        expected: None,
    });
    (d.outcome, d.effective)
}

/// C1: a rule that fails the run can never resolve below warning (such diagnostics never
/// enter accounting), literal or mapped, default included.
#[test]
fn c1_a_failing_rule_never_resolves_below_warning() {
    let rule = |sev: &str| {
        project(&format!(
            "rules:\n  - {{id: f, version: 1.0.0, kind: project_pattern, owner: o, reason: r, fails_run: true,\n     record: {{id: f, start: '^TOY FAIL (?P<k>\\w+)$', emit: {{framework: project, severity: {sev}, diag_id: 'toy:f', message: 'm'}}}}}}\n"
        ))
    };
    for bad in [
        "info",
        "{from: k, map: {A: info}}",
        "{from: k, map: {A: error}, default: info}",
    ] {
        let e = compile(&[rule(bad)])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(e.contains("fails_run"), "{bad}: {e}");
    }
    for good in ["warning", "error", "{from: k, map: {A: error, B: warning}}"] {
        assert!(compile(&[rule(good)]).is_ok(), "{good}");
    }
}

/// C2: a required verdict is decisive: "not applicable" alone neither completes a log nor
/// lets an otherwise complete run pass (an invented toy simulator).
#[test]
fn c2_not_applicable_never_satisfies_a_required_verdict() {
    let toysim = PackInput {
        name: "toysim.yaml".into(),
        text: "format: dviscope.rules/1.0\npack: toysim\nversion: 1.0.0\ntier: simulator\nsimulator: toysim\nexit_code_meaningful: true\ndetect: ['^TOYSIM$']\nmarkers:\n  - {id: end, match: '^TOYSIM END$', trailer: true}\ncompletion:\n  profiles:\n    - {name: toysim-run, subject: simulation, requires: [end], verdict_required: true}\n".into(),
    };
    let verdicts = project(
        "verdicts:\n  - {id: v, source: test_result, match: '^TOY RESULT (?P<v>PASS|NA)$', value: {from: v, map: {PASS: pass, NA: not_applicable}}}\n",
    );
    let p = compile(&[toysim, verdicts]).unwrap_or_else(|e| panic!("{e}"));
    let run = |verdict: &str| {
        let text = format!("TOY RESULT {verdict}\nTOYSIM END\n");
        let mut o = ExtractOptions::simulation("t.log");
        o.simulator = Some("toysim".into());
        extract_bytes(&p, o, text.as_bytes()).0
    };
    let pass = run("PASS");
    assert_eq!(
        pass.completion.state,
        CompletionState::Complete,
        "{:?}",
        pass.completion
    );
    assert_eq!(outcome(&pass).0, Outcome::Pass);
    let na = run("NA");
    assert_ne!(
        na.completion.state,
        CompletionState::Complete,
        "{:?}",
        na.completion
    );
    assert_ne!(outcome(&na).0, Outcome::Pass);
    // Even evidence claiming completion fails when its only verdict is not applicable.
    let mut forged = pass.clone();
    for v in &mut forged.verdict_sources {
        v.value = VerdictValue::NotApplicable;
    }
    assert_eq!(outcome(&forged), (Outcome::Fail, Effective::Failed));
}

/// C3: a completion profile name is declared by one pack of a pipeline only (evidence
/// records the name; the server resolves the simulator and its exit policy from it).
#[test]
fn c3_completion_profile_names_are_unique_in_a_pipeline() {
    let custom = PackInput {
        name: "mysim.yaml".into(),
        text: "format: dviscope.rules/1.0\npack: mysim\nversion: 1.0.0\ntier: simulator\nsimulator: mysim\nexit_code_meaningful: true\ndetect: ['^MYSIM$']\nmarkers:\n  - {id: end, match: '^MYSIM END$'}\ncompletion:\n  profiles:\n    - {name: vcs-run, subject: simulation, requires: [end]}\n".into(),
    };
    let e = with_defaults(vec![custom]).err().unwrap_or_default();
    assert!(e.contains("vcs-run"), "{e}");
}

/// C4: a sample value canonical JSON cannot carry exactly is refused, never given a shared
/// fallback identity.
#[test]
fn c4_a_noncanonical_sample_is_refused() {
    let case = |max: u64| SampleCase {
        case: "c".into(),
        log_sha256: "0".repeat(64),
        bytes: 1,
        expect: serde_json::from_value(serde_json::json!({
            "format": "dviscope.expect/1", "max_unclaimed": max
        }))
        .unwrap_or_else(|e| panic!("{e}")),
    };
    let m = |max: u64| SampleManifest {
        format: "dviscope.sample/1".into(),
        cases: vec![case(max)],
    };
    assert!(m(5).validate().is_ok());
    let e = m(9_007_199_254_740_992)
        .validate()
        .err()
        .unwrap_or_default();
    assert!(e.contains("canonical"), "{e}");
}

/// Structural evidence naming a completion profile (no log text): an empty extraction
/// through the shipped packs, its profile set.
fn evidence_with_profile(profile: &str) -> Evidence {
    let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
    let mut ev = extract_bytes(&p, ExtractOptions::simulation("t.log"), b"").0;
    ev.completion.profile = profile.into();
    ev
}

/// C5: activation decides whether the exit code means anything as ingestion does (the
/// shipped simulator pack's policy), so it sees the outcome the server will derive.
#[test]
fn c5_exit_code_policy_is_shared() {
    assert!(!shipped::exit_code_meaningful(&evidence_with_profile(
        "vcs-run"
    )));
    assert!(!shipped::exit_code_meaningful(&evidence_with_profile(
        "questa-run"
    )));
    assert!(shipped::exit_code_meaningful(&evidence_with_profile(
        "verilator-run"
    )));
    // A profile no shipped pack declares, or a customized pack: meaningful.
    assert!(shipped::exit_code_meaningful(&evidence_with_profile(
        "mysim-run"
    )));
    let mut custom = evidence_with_profile("vcs-run");
    for r in &mut custom.packs {
        r.digest = dviscope_model::canonical::Digest::of_bytes(b"customized");
    }
    assert!(shipped::exit_code_meaningful(&custom));
}

/// C6: a template repeating a capture renders within a fixed bound.
#[test]
fn c6_template_rendering_is_bounded() {
    let msg = "${m}".repeat(20_000);
    let p = compile(&[project(&format!(
        "rules:\n  - {{id: big, version: 1.0.0, kind: project_pattern, owner: o, reason: r,\n     record: {{id: big, start: '^TOY BIG (?P<m>.*)$', emit: {{framework: project, severity: error, diag_id: 'toy:big', message: '{msg}'}}}}}}\n"
    ))])
    .unwrap_or_else(|e| panic!("{e}"));
    let line = format!("TOY BIG {}\n", "x".repeat(10_000));
    let mut o = ExtractOptions::simulation("t.log");
    o.trace = true;
    let (ev, _) = extract_bytes(&p, o, line.as_bytes());
    let longest = ev
        .events
        .iter()
        .map(|e| e.message_raw.len())
        .max()
        .unwrap_or(0);
    assert!(
        longest > 0 && longest <= dviscope_core::packs::MAX_RENDER_BYTES,
        "{longest}"
    );
}

/// A rule that fails the run without an emit (a record consumed silently)
/// is refused.
#[test]
fn c1_a_failing_rule_without_an_emit_is_refused() {
    let e = compile(&[project(
        "rules:\n  - {id: f, version: 1.0.0, kind: project_pattern, owner: o, reason: r, fails_run: true,\n     record: {id: f, start: '^TOY FAIL$'}}\n",
    )])
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default();
    assert!(e.contains("fails_run"), "{e}");
}

/// An identifier cut at the render bound could equal another one (and match
/// a suppression meant for it): the log is then incomplete, never a pass.
#[test]
fn c6_a_cut_identifier_makes_the_log_incomplete() {
    let toysim = PackInput {
        name: "toysim.yaml".into(),
        text: "format: dviscope.rules/1.0\npack: toysim\nversion: 1.0.0\ntier: simulator\nsimulator: toysim\nexit_code_meaningful: true\ndetect: ['^TOYSIM$']\nmarkers:\n  - {id: end, match: '^TOYSIM END$', trailer: true}\ncompletion:\n  profiles:\n    - {name: toysim-run, subject: simulation, requires: [end]}\n".into(),
    };
    let ids = "${k}".repeat(10);
    let rules = project(&format!(
        "rules:\n  - {{id: f, version: 1.0.0, kind: project_pattern, owner: o, reason: r, fails_run: true,\n     record: {{id: f, start: '^TOY FAIL (?P<k>\\w+)$', emit: {{framework: project, severity: error, diag_id: 'toy:{ids}', message: 'm'}}}}}}\n"
    ));
    let p = compile(&[toysim, rules]).unwrap_or_else(|e| panic!("{e}"));
    let run = |key: &str| {
        let text = format!("TOY FAIL {key}\nTOYSIM END\n");
        let mut o = ExtractOptions::simulation("t.log");
        o.simulator = Some("toysim".into());
        extract_bytes(&p, o, text.as_bytes()).0
    };
    // A short key: complete (and failing).
    assert_eq!(run("abc").completion.state, CompletionState::Complete);
    // A key whose identifier exceeds the bound: incomplete.
    let long = run(&"a".repeat(8_000));
    assert_eq!(
        long.completion.state,
        CompletionState::Incomplete,
        "{:?}",
        long.completion
    );
    assert_ne!(outcome(&long).0, Outcome::Pass);
}
