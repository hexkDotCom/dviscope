//! Verilator models with their own C++ main (`verilator-model-main`). Invented
//! toy markers in a project pack, Verilator's shipped message forms; no simulator output.
//! The profile is chosen only by the run's declaration (`ExtractOptions::model_main`); the
//! log is the program log, then the console, joined at `begin_console`.

use dviscope_core::extract::{ExtractOptions, Extractor};
use dviscope_core::outcome::{Derived, Effective, Input, Outcome, derive};
use dviscope_core::packs::{PackInput, Pipeline, compile, shipped};
use dviscope_model::values::UtcTime;
use dviscope_model::wire::evidence::{
    CompletionReason as R, CompletionState, Evidence, LogSegmentName,
};
use dviscope_model::wire::ingest::{Runner, Termination, TerminationKind};

const MODEL: &str = r#"
format: dviscope.rules/1.0
pack: toymodel
version: 1.0.0
tier: project
detect: ['^TOY DETECT NEVER$']
markers:
  - {id: begin, match: '^TOY MODEL BEGIN$'}
  - {id: stats, match: '^TOY STATS$'}
  - {id: end, match: '^TOY END \d+$'}
verdicts:
  - id: res
    source: test_result
    match: '^TOY RESULT (?P<v>PASS|FAIL|NA)$'
    value: {from: v, map: {PASS: pass, FAIL: fail, NA: not_applicable}}
rules:
  - {id: err, version: 1.0.0, kind: project_pattern, owner: o, reason: r, fails_run: true,
     record: {id: err, start: '^TOY ERR (?P<m>.*)$',
              continuation: {max_lines: 1, lines: [{match: '^(?P<b>.*)$', capture: true, mandatory: true}]},
              emit: {framework: project, severity: error, diag_id: 'toy:err', message: '${m}'}}}
completion:
  model_main: {start: begin, trailer: [stats, end]}
"#;

fn pipeline_with(extra: &[&str]) -> Result<Pipeline, String> {
    let mut inputs = shipped::default_inputs();
    for (i, t) in extra.iter().enumerate() {
        inputs.push(PackInput {
            name: format!("p{i}.yaml"),
            text: (*t).to_string(),
        });
    }
    compile(&inputs).map_err(|e| e.to_string())
}

fn pipeline() -> Pipeline {
    pipeline_with(&[MODEL]).unwrap_or_else(|e| panic!("{e}"))
}

/// Extracts a declared model-main run: the program bytes, then (when given) the console.
fn mm(p: &Pipeline, program: &str, console: Option<&str>) -> Evidence {
    let mut o = ExtractOptions::simulation("joined.log");
    o.model_main = true;
    let mut x = Extractor::new(p, o);
    x.push(program.as_bytes());
    if let Some(c) = console {
        x.begin_console();
        x.push(c.as_bytes());
    }
    x.finish()
}

const FINISH: &str = "- rtl/top.sv:12: Verilog $finish\n";

fn console(body: &str) -> String {
    format!("TOY MODEL BEGIN\n{body}{FINISH}TOY STATS\nTOY END 42\n")
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

fn outcome(ev: &Evidence) -> Derived {
    derive(&Input {
        evidence: Some(ev),
        runner: &runner(0),
        producer: None,
        has_build_requirement: true,
        exit_code_meaningful: true,
        expected: None,
    })
}

/// Incomplete with `reason`, and never a pass.
fn incomplete(ev: &Evidence, reason: R) {
    assert_eq!(
        ev.completion.profile, "verilator-model-main",
        "{:?}",
        ev.completion
    );
    assert_eq!(
        ev.completion.state,
        CompletionState::Incomplete,
        "{:?}",
        ev.completion
    );
    assert!(
        ev.completion.reasons.contains(&reason),
        "{reason:?} not in {:?}",
        ev.completion.reasons
    );
    let d = outcome(ev);
    assert_ne!(d.outcome, Outcome::Pass, "{:?}", ev.completion);
    assert_eq!(d.effective, Effective::Failed);
}

fn complete(ev: &Evidence) {
    assert_eq!(ev.completion.profile, "verilator-model-main");
    assert_eq!(
        ev.completion.state,
        CompletionState::Complete,
        "{:?}",
        ev.completion
    );
}

#[test]
fn a_declared_complete_run_passes_with_its_segments() {
    let p = pipeline();
    let ev = mm(&p, "TOY RESULT PASS\n", Some(&console("")));
    complete(&ev);
    let d = outcome(&ev);
    assert_eq!((d.outcome, d.effective), (Outcome::Pass, Effective::Passed));
    let s = ev
        .source
        .segments
        .as_ref()
        .unwrap_or_else(|| panic!("segments"));
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].name, LogSegmentName::Program);
    assert_eq!(s[1].name, LogSegmentName::Console);
    let n = |v: Option<dviscope_model::values::SafeU64>| v.map(|x| x.get());
    assert_eq!((n(s[0].line_start), n(s[0].line_end)), (Some(1), Some(1)));
    assert_eq!((n(s[1].line_start), n(s[1].line_end)), (Some(2), Some(5)));
    assert_eq!((s[0].byte_start.get(), s[0].byte_end.get()), (0, 16));
    assert_eq!(s[1].byte_start.get(), 16);
    assert_eq!(s[1].byte_end.get(), ev.source.bytes.get());
    // The verdict is the program's, the witnesses the console's.
    assert_eq!(
        ev.completion.sections_seen,
        vec![
            "toymodel/begin",
            "verilator/design_finish",
            "toymodel/stats",
            "toymodel/end"
        ]
    );
}

#[test]
fn without_the_declaration_the_same_bytes_never_pass() {
    // A cut `--binary` run: verdict and `$finish`, no report. The default profile stays.
    let p = pipeline();
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = Some("verilator".into());
    let text = format!("TOY RESULT PASS\n{}", console(""));
    let ev = dviscope_core::extract::extract_bytes(&p, o, text.as_bytes()).0;
    assert_eq!(ev.completion.profile, "verilator-run");
    assert_eq!(ev.completion.state, CompletionState::Incomplete);
    assert!(ev.source.segments.is_none());
    assert_ne!(outcome(&ev).outcome, Outcome::Pass);
    // Detection alone never picks the declared profile either.
    let ev = dviscope_core::extract::extract_bytes(
        &p,
        ExtractOptions::simulation("t.log"),
        text.as_bytes(),
    )
    .0;
    assert_ne!(ev.completion.profile, "verilator-model-main");
    assert_ne!(outcome(&ev).outcome, Outcome::Pass);
}

#[test]
fn every_console_witness_exactly_once_and_in_order() {
    let p = pipeline();
    let pass = "TOY RESULT PASS\n";
    // Cut before the end of the trailer, inside it, before `$finish`.
    incomplete(
        &mm(
            &p,
            pass,
            Some(&format!("TOY MODEL BEGIN\n{FINISH}TOY STATS\n")),
        ),
        R::WitnessCount,
    );
    incomplete(
        &mm(&p, pass, Some(&format!("TOY MODEL BEGIN\n{FINISH}"))),
        R::WitnessCount,
    );
    incomplete(&mm(&p, pass, Some("TOY MODEL BEGIN\n")), R::WitnessCount);
    // A complete execution followed by a cut one (two banners), or the reverse.
    let two = format!("{}TOY MODEL BEGIN\n", console(""));
    incomplete(&mm(&p, pass, Some(&two)), R::WitnessCount);
    let two = format!("TOY MODEL BEGIN\n{}", console(""));
    incomplete(&mm(&p, pass, Some(&two)), R::WitnessCount);
    // `$finish` twice; a trailer marker twice.
    incomplete(&mm(&p, pass, Some(&console(FINISH))), R::WitnessCount);
    let dup = format!("{}TOY END 43\n", console(""));
    incomplete(&mm(&p, pass, Some(&dup)), R::WitnessCount);
    // Out of order: the trailer before `$finish`, the end before the statistics, the banner
    // after `$finish`.
    let c = format!("TOY MODEL BEGIN\nTOY STATS\n{FINISH}TOY END 42\n");
    incomplete(&mm(&p, pass, Some(&c)), R::WitnessOrder);
    let c = format!("TOY MODEL BEGIN\n{FINISH}TOY END 42\nTOY STATS\n");
    incomplete(&mm(&p, pass, Some(&c)), R::WitnessOrder);
    let c = format!("{FINISH}TOY MODEL BEGIN\nTOY STATS\nTOY END 42\n");
    incomplete(&mm(&p, pass, Some(&c)), R::WitnessOrder);
}

#[test]
fn program_text_never_stands_in_for_the_console() {
    let p = pipeline();
    // Every witness in the program log, an empty console.
    let program = format!("TOY RESULT PASS\n{}", console(""));
    let ev = mm(&p, &program, Some(""));
    incomplete(&ev, R::WitnessSegment);
    let s = ev
        .source
        .segments
        .as_ref()
        .unwrap_or_else(|| panic!("segments"));
    assert!(
        s[1].line_start.is_none() && s[1].line_end.is_none(),
        "{s:?}"
    );
    assert_eq!(s[1].byte_start, s[1].byte_end);
    // One witness (the banner) in the program, the rest in the console.
    let c = format!("{FINISH}TOY STATS\nTOY END 42\n");
    incomplete(
        &mm(&p, "TOY RESULT PASS\nTOY MODEL BEGIN\n", Some(&c)),
        R::WitnessSegment,
    );
    // No console at all: not joined.
    incomplete(&mm(&p, &program, None), R::SegmentsMissing);
}

#[test]
fn verdicts_positive_spanned_and_console_ones_before_the_finish() {
    let p = pipeline();
    // A console verdict before `$finish`: complete.
    complete(&mm(&p, "", Some(&console("TOY RESULT PASS\n"))));
    // After `$finish`: refused.
    let c = format!("TOY MODEL BEGIN\n{FINISH}TOY RESULT PASS\nTOY STATS\nTOY END 42\n");
    incomplete(&mm(&p, "", Some(&c)), R::WitnessSegment);
    // No verdict; only not-applicable: never complete.
    incomplete(&mm(&p, "", Some(&console(""))), R::NoEndMarker);
    incomplete(
        &mm(&p, "TOY RESULT NA\n", Some(&console(""))),
        R::NoEndMarker,
    );
    // A spanless (section-derived) passing verdict, from a complete UVM summary in the
    // program log, never satisfies the profile.
    let uvm = "UVM_INFO @ 1: top [HELLO] hi\n--- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    0\nUVM_FATAL :    0\n";
    let ev = mm(&p, uvm, Some(&console("")));
    assert!(
        ev.verdict_sources.iter().any(|v| v.span.is_none()),
        "the summary gives a spanless verdict: {:?}",
        ev.verdict_sources
    );
    incomplete(&ev, R::NoEndMarker);
}

#[test]
fn failures_keep_precedence_over_a_complete_model_run() {
    let p = pipeline();
    // A failing verdict beside a passing one.
    let ev = mm(&p, "TOY RESULT PASS\nTOY RESULT FAIL\n", Some(&console("")));
    complete(&ev);
    assert_eq!(outcome(&ev).outcome, Outcome::Fail);
    // A failing project diagnostic in the program log.
    let ev = mm(
        &p,
        "TOY RESULT PASS\nTOY ERR boom\n  detail\n",
        Some(&console("")),
    );
    complete(&ev);
    let d = outcome(&ev);
    assert_eq!((d.outcome, d.effective), (Outcome::Fail, Effective::Failed));
    // A run-time assertion in Verilator's form on the console.
    let ev = mm(
        &p,
        "TOY RESULT PASS\n",
        Some(&console(
            "[10] %Error: top.sv:9: Assertion failed in top.chk: too big\n",
        )),
    );
    assert_eq!(outcome(&ev).outcome, Outcome::Fail);
    // A meaningful non-zero exit.
    let ev = mm(&p, "TOY RESULT PASS\n", Some(&console("")));
    let d = derive(&Input {
        evidence: Some(&ev),
        runner: &runner(3),
        producer: None,
        has_build_requirement: true,
        exit_code_meaningful: true,
        expected: None,
    });
    assert_ne!(d.outcome, Outcome::Pass);
}

#[test]
fn a_verilator_report_or_another_simulator_is_a_conflict() {
    let p = pipeline();
    let c = console("- S i m u l a t i o n   R e p o r t: Verilator 5\n");
    incomplete(&mm(&p, "TOY RESULT PASS\n", Some(&c)), R::ProfileConflict);
    let mut o = ExtractOptions::simulation("t.log");
    o.model_main = true;
    o.simulator = Some("vcs".into());
    let mut x = Extractor::new(&p, o);
    x.push(b"TOY RESULT PASS\n");
    x.begin_console();
    x.push(console("").as_bytes());
    incomplete(&x.finish(), R::ProfileConflict);
}

#[test]
fn the_finish_line_takes_any_path_and_nothing_after_it() {
    let p = pipeline();
    let with = |fin: &str| {
        mm(
            &p,
            "TOY RESULT PASS\n",
            Some(&format!("TOY MODEL BEGIN\n{fin}TOY STATS\nTOY END 1\n")),
        )
    };
    complete(&with("- C:/my work/rtl/top.sv:12: Verilog $finish\n"));
    complete(&with("- rtl/top.sv:12: Verilog $finish  \n"));
    incomplete(
        &with("- rtl/top.sv:12: Verilog $finish later\n"),
        R::WitnessCount,
    );
    incomplete(&with("- rtl/top.sv: Verilog $finish\n"), R::WitnessCount);
}

#[test]
fn the_declaration_is_needed_and_unique() {
    // Declared run, no pack declaring the model's markers: fail closed.
    let p = pipeline_with(&[]).unwrap_or_else(|e| panic!("{e}"));
    incomplete(
        &mm(&p, "TOY RESULT PASS\n", Some(&console(""))),
        R::ModelMainUndeclared,
    );
    // Two packs declaring it.
    let other = MODEL.replace("pack: toymodel", "pack: toymodel2");
    let e = pipeline_with(&[MODEL, &other]).err().unwrap_or_default();
    assert!(e.contains("more than one pack"), "{e}");
}

#[test]
fn an_empty_declared_log_keeps_the_declared_profile() {
    let p = pipeline();
    let ev = mm(&p, "", Some(""));
    assert_eq!(ev.completion.profile, "verilator-model-main");
    assert_eq!(ev.completion.state, CompletionState::Missing);
    assert_eq!(ev.completion.reasons, vec![R::EmptyLog]);
    // An empty log has no segments, joined or not (no log at all, as after an
    // interruption), and passes the server's check for a declared slot.
    for ev in [ev, mm(&p, "", None)] {
        assert!(ev.source.segments.is_none(), "{:?}", ev.source.segments);
        assert_eq!(
            dviscope_core::model_main::check_simulation(true, &ev),
            Ok(())
        );
    }
}

#[test]
fn the_segment_boundary_ends_lines_and_records() {
    let p = pipeline();
    // A program log without a final newline: its last line ends at the boundary, and the
    // first console line starts at the boundary (its span is the console's).
    let ev2 = mm(&p, "x", Some(&format!("TOY RESULT PASS\n{}", console(""))));
    complete(&ev2);
    assert_eq!(
        dviscope_core::model_main::check_simulation(true, &ev2),
        Ok(())
    );
    let v = ev2.verdict_sources[0]
        .span
        .unwrap_or_else(|| panic!("span"));
    assert_eq!((v.line_start.get(), v.byte_start.get()), (2, 1));
    let ev = mm(&p, "TOY RESULT PASS", Some(&console("")));
    complete(&ev);
    let s = ev
        .source
        .segments
        .as_ref()
        .unwrap_or_else(|| panic!("segments"));
    assert_eq!(s[0].line_end.map(|x| x.get()), Some(1));
    assert_eq!(s[1].line_start.map(|x| x.get()), Some(2));
    // A CR closing the program and an LF opening the console: two line ends, an empty
    // first console line, never one CRLF.
    let ev = mm(&p, "TOY RESULT PASS\r", Some(&format!("\n{}", console(""))));
    complete(&ev);
    let s = ev
        .source
        .segments
        .as_ref()
        .unwrap_or_else(|| panic!("segments"));
    assert_eq!(s[1].line_start.map(|x| x.get()), Some(2));
    assert_eq!(s[1].line_end.map(|x| x.get()), Some(6));
    // A record whose mandatory line would be the console's first line is cut at the
    // boundary, as at the end of a file.
    // (a plain first console line: it would otherwise complete the cut record)
    let ev = mm(
        &p,
        "TOY RESULT PASS\nTOY ERR cut",
        Some(&format!("plain\n{}", console(""))),
    );
    incomplete(&ev, R::RecordCut);
    // Both segments empty but one byte of line break each side.
    let ev = mm(&p, "\n", Some("\n"));
    let s = ev
        .source
        .segments
        .as_ref()
        .unwrap_or_else(|| panic!("segments"));
    assert_eq!(s[0].line_start.map(|x| x.get()), Some(1));
    assert_eq!(s[1].line_start.map(|x| x.get()), Some(2));
}

#[test]
fn sections_of_detected_packs_and_exactness_still_apply() {
    let p = pipeline();
    // A UVM run inside the model (detected) without its summary: incomplete.
    let ev = mm(
        &p,
        "UVM_INFO @ 1: top [HELLO] hi\nTOY RESULT PASS\n",
        Some(&console("")),
    );
    incomplete(&ev, R::NoEndMarker);
    // A cut (over-long) line on the console.
    let long = format!("{}\n", "x".repeat(70_000));
    incomplete(
        &mm(&p, "TOY RESULT PASS\n", Some(&console(&long))),
        R::LineCut,
    );
}

#[test]
fn pack_validation_of_the_declared_profile_and_markers() {
    let sim = |profiles: &str| {
        format!(
            "format: dviscope.rules/1.0\npack: s\nversion: 1.0.0\ntier: simulator\nsimulator: toysim\n\
             detect: ['^S$']\nmarkers:\n  - {{id: m, match: '^M$'}}\ncompletion:\n  profiles:\n{profiles}"
        )
    };
    let only = |t: String| {
        compile(&[PackInput {
            name: "x.yaml".into(),
            text: t,
        }])
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default()
    };
    // A declared profile other than Verilator's model-main.
    let e = only(sim(
        "    - {name: toysim-run, subject: simulation, requires: [m]}\n    - {name: other, subject: simulation, select: declared, requires: [m]}\n",
    ));
    assert!(e.contains("declared profile"), "{e}");
    // Only declared profiles for a subject (a Verilator pack, so the declared profile itself
    // is allowed).
    let e = only(
        sim("    - {name: verilator-model-main, subject: simulation, select: declared, requires: [m]}\n")
            .replace("simulator: toysim", "simulator: verilator"),
    );
    assert!(e.contains("no default profile"), "{e}");
    // Duplicate names.
    let e = only(sim(
        "    - {name: a, subject: simulation, requires: [m]}\n    - {name: a, subject: build, requires: [m]}\n",
    ));
    assert!(e.contains("duplicate profile"), "{e}");
    // model_main: project tier, own markers, non-empty and distinct.
    let proj = |mm: &str| {
        format!(
            "format: dviscope.rules/1.0\npack: q\nversion: 1.0.0\ntier: project\n\
             markers:\n  - {{id: a, match: '^A$'}}\n  - {{id: b, match: '^B$'}}\ncompletion:\n  model_main: {mm}\n"
        )
    };
    for (decl, want) in [
        ("{start: a, trailer: []}", "empty"),
        ("{start: a, trailer: [zz]}", "not a marker"),
        ("{start: a, trailer: [b, b]}", "twice"),
        ("{start: a, trailer: [a]}", "twice"),
    ] {
        let e = only(proj(decl));
        assert!(e.contains(want), "{decl}: {e}");
    }
    let e = only(
        sim("    - {name: toysim-run, subject: simulation, requires: [m]}\n  model_main: {start: m, trailer: [n]}\n")
            .replace("markers:\n", "markers:\n  - {id: n, match: '^N$'}\n"),
    );
    assert!(e.contains("only project packs"), "{e}");
}

/// The default profile never depends on declaration order: a Verilator pack listing its
/// declared profile first still judges an undeclared run by `verilator-run`.
#[test]
fn the_declared_profile_is_never_a_default_whatever_its_place() {
    let mut inputs = shipped::default_inputs();
    let v = inputs
        .iter_mut()
        .find(|i| i.name == "verilator.yaml")
        .unwrap_or_else(|| panic!("verilator pack"));
    let block = "    - name: verilator-model-main\n      subject: simulation\n      select: declared\n      requires: [design_finish]\n      verdict_required: true\n";
    assert!(v.text.contains(block), "the shipped profile block moved");
    v.text = v
        .text
        .replace(block, "")
        .replace("  profiles:\n", &format!("  profiles:\n{block}"));
    let p = compile(&inputs).unwrap_or_else(|e| panic!("{e}"));
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = Some("verilator".into());
    let ev = dviscope_core::extract::extract_bytes(&p, o, console("").as_bytes()).0;
    assert_eq!(ev.completion.profile, "verilator-run");
}

mod server_checks {
    use super::*;
    use dviscope_core::model_main::{check_build, check_simulation, declares};
    use dviscope_model::values::SafeU64;
    use dviscope_model::wire::manifest::ExecInputs;

    fn exec(main: Option<&str>) -> ExecInputs {
        let mut v = serde_json::json!({"test": "t", "seed": "1"});
        if let Some(m) = main {
            v["extra"] = serde_json::json!({"tool": {"main": m}});
        }
        serde_json::from_value(v).unwrap_or_else(|e| panic!("{e}"))
    }

    fn good() -> Evidence {
        mm(&pipeline(), "TOY RESULT PASS\n", Some(&console("")))
    }

    #[test]
    fn the_declaration_reads_model_or_nothing() {
        assert_eq!(declares(&exec(None)), Ok(false));
        assert_eq!(declares(&exec(Some("model"))), Ok(true));
        assert!(declares(&exec(Some("binary"))).is_err());
    }

    #[test]
    fn evidence_must_agree_with_the_declaration_both_ways() {
        let ev = good();
        assert_eq!(check_simulation(true, &ev), Ok(()));
        // The declared profile for a slot that does not declare it.
        assert!(check_simulation(false, &ev).is_err());
        // ... even without segments (the profile alone decides).
        let mut bare = ev.clone();
        bare.source.segments = None;
        assert!(check_simulation(false, &bare).is_err());
        // A declared slot with the default profile (a producer switching per attempt).
        let p = pipeline();
        let mut o = ExtractOptions::simulation("t.log");
        o.simulator = Some("verilator".into());
        let plain = dviscope_core::extract::extract_bytes(&p, o, b"TOY RESULT PASS\n").0;
        assert!(check_simulation(true, &plain).is_err());
        assert_eq!(check_simulation(false, &plain), Ok(()));
        // An empty declared log (recovery) keeps the declared profile and has no lines.
        let empty = mm(&p, "", Some(""));
        assert_eq!(check_simulation(true, &empty), Ok(()));
        // Segments on undeclared evidence; declared evidence without segments.
        let mut seg = plain.clone();
        seg.source.segments = ev.source.segments.clone();
        assert!(check_simulation(false, &seg).is_err());
        let mut none = ev.clone();
        none.source.segments = None;
        assert!(check_simulation(true, &none).is_err());
        // Build evidence never has segments.
        assert!(check_build(&ev).is_err());
        assert_eq!(check_build(&plain), Ok(()));
    }

    #[test]
    fn malformed_segments_are_refused() {
        let ev = good();
        let bad = |f: &dyn Fn(&mut Evidence)| {
            let mut e = ev.clone();
            f(&mut e);
            check_simulation(true, &e)
        };
        // Order, a gap, an overlap, short of the end, past the end.
        assert!(
            bad(&|e| e
                .source
                .segments
                .as_mut()
                .unwrap_or_else(|| panic!())
                .reverse())
            .is_err()
        );
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[1].byte_start = SafeU64::saturating(s[1].byte_start.get() + 1);
            })
            .is_err()
        );
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[0].byte_end = SafeU64::saturating(s[0].byte_end.get() + 1);
            })
            .is_err()
        );
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[1].byte_end = SafeU64::saturating(s[1].byte_end.get() - 1);
            })
            .is_err()
        );
        assert!(
            bad(&|e| {
                e.source.bytes = SafeU64::saturating(e.source.bytes.get() - 1);
            })
            .is_err()
        );
        // Lines: overlapping, descending, one bound null, lines in an empty segment.
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[1].line_start = s[0].line_end;
            })
            .is_err()
        );
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[1].line_end = Some(SafeU64::saturating(1));
            })
            .is_err()
        );
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[0].line_end = None;
            })
            .is_err()
        );
        let empty = mm(&pipeline(), "TOY RESULT PASS\n", Some(""));
        let mut e = empty.clone();
        let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
        s[1].line_start = Some(SafeU64::saturating(2));
        s[1].line_end = Some(SafeU64::saturating(2));
        assert!(check_simulation(true, &e).is_err());
        // A span crossing the boundary (the program verdict stretched into the console).
        assert!(
            bad(&|e| {
                if let Some(sp) = e.verdict_sources[0].span.as_mut() {
                    sp.line_end = SafeU64::saturating(2);
                }
            })
            .is_err()
        );
        assert_eq!(check_simulation(true, &ev), Ok(()));
    }

    /// Impossible spans and segment lines.
    #[test]
    fn impossible_spans_and_segment_lines_are_refused() {
        let ev = good();
        let bad = |f: &dyn Fn(&mut Evidence)| {
            let mut e = ev.clone();
            f(&mut e);
            check_simulation(true, &e)
        };
        // A verdict span past the end with a zero end byte; a reversed line span.
        assert!(
            bad(&|e| {
                if let Some(sp) = e.verdict_sources[0].span.as_mut() {
                    sp.byte_start = SafeU64::saturating(e.source.bytes.get() + 10);
                    sp.byte_end = SafeU64::saturating(0);
                }
            })
            .is_err()
        );
        assert!(
            bad(&|e| {
                if let Some(sp) = e.verdict_sources[0].span.as_mut() {
                    sp.line_start = SafeU64::saturating(1);
                    sp.line_end = SafeU64::saturating(0);
                }
            })
            .is_err()
        );
        // A segment holding bytes but no lines; a gap in the line numbering; lines not
        // starting at 1.
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[1].line_start = None;
                s[1].line_end = None;
            })
            .is_err()
        );
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[1].line_start = Some(SafeU64::saturating(
                    s[1].line_start.map_or(0, |x| x.get()) + 1,
                ));
            })
            .is_err()
        );
        assert!(
            bad(&|e| {
                let s = e.source.segments.as_mut().unwrap_or_else(|| panic!());
                s[0].line_start = Some(SafeU64::saturating(0));
            })
            .is_err()
        );
        // Non-verdict spans: a log event and a counter outside the segments.
        let failing = mm(
            &pipeline(),
            "TOY RESULT PASS\n",
            Some(&console(
                "[10] %Error: top.sv:9: Assertion failed in top.chk: too big\n",
            )),
        );
        assert_eq!(check_simulation(true, &failing), Ok(()));
        let mut e = failing.clone();
        let mut moved = false;
        for ev in &mut e.events {
            if let dviscope_model::wire::evidence::EventProvenance::Log { span, .. } =
                &mut ev.provenance
            {
                span.line_end = SafeU64::saturating(99);
                moved = true;
            }
        }
        assert!(moved, "the failing evidence has a log event");
        assert!(check_simulation(true, &e).is_err());
        let mut e = failing.clone();
        e.coverage
            .unclaimed_examples
            .push(dviscope_model::wire::evidence::Span {
                line_start: SafeU64::saturating(1),
                line_end: SafeU64::saturating(1),
                byte_start: SafeU64::saturating(0),
                byte_end: SafeU64::saturating(e.source.bytes.get() + 1),
            });
        assert!(check_simulation(true, &e).is_err());
        // An empty program segment: the console's lines start at 1.
        let console_only = mm(
            &pipeline(),
            "",
            Some(&format!("TOY RESULT PASS\n{}", console(""))),
        );
        complete(&console_only);
        assert_eq!(check_simulation(true, &console_only), Ok(()));
    }
}

/// `rules check` runs a model case joined, so a change
/// of the model's markers between two pipelines is seen.
#[test]
fn rules_check_runs_a_model_case_joined() {
    use dviscope_core::rule_check::{SampleCase, SampleManifest, check};
    let old = pipeline();
    // The new pipeline renames the model's end marker pattern: the end never matches.
    let new_text = MODEL.replace("'^TOY END \\d+$'", "'^TOY FINISHED \\d+$'");
    assert_ne!(new_text, MODEL);
    let new = pipeline_with(&[&new_text]).unwrap_or_else(|e| panic!("{e}"));
    let program = "TOY RESULT PASS\n";
    let log = format!("{program}{}", console(""));
    let case = |x: serde_json::Value| SampleCase {
        case: "model".into(),
        log_sha256: dviscope_model::canonical::Digest::of_bytes(log.as_bytes())
            .as_str()
            .trim_start_matches("sha256:")
            .to_string(),
        bytes: log.len() as u64,
        expect: serde_json::from_value(x).unwrap_or_else(|e| panic!("{e}")),
    };
    let sample = |x: serde_json::Value| SampleManifest {
        format: "dviscope.sample/1".into(),
        cases: vec![case(x)],
    };
    let x = serde_json::json!({"format": "dviscope.expect/1", "simulator": "verilator",
        "model_main": true, "console_at": program.len(), "completion": "complete"});
    // Same pipeline: the joined case is complete and passes.
    let r =
        check(&old, &old, &sample(x.clone()), &[log.as_bytes()]).unwrap_or_else(|e| panic!("{e}"));
    assert!(r.pass, "{r:?}");
    // The changed marker: completion differs, undeclared.
    let r = check(&old, &new, &sample(x), &[log.as_bytes()]).unwrap_or_else(|e| panic!("{e}"));
    assert!(!r.pass);
    assert!(
        r.cases[0]
            .undeclared_changes
            .contains(&"completion".to_string()),
        "{:?}",
        r.cases[0]
    );
    // model_main and console_at go together, within the log.
    for x in [
        serde_json::json!({"format": "dviscope.expect/1", "model_main": true}),
        serde_json::json!({"format": "dviscope.expect/1", "console_at": 3}),
        serde_json::json!({"format": "dviscope.expect/1", "model_main": true, "console_at": 999_999}),
    ] {
        assert!(sample(x.clone()).validate().is_err(), "{x}");
    }
}
