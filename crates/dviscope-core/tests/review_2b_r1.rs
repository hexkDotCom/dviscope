//! Regression tests. Invented text only.

use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::packs::{PackInput, Pipeline, compile, shipped};
use dviscope_model::limits::MAX_EXCERPT_BYTES;
use dviscope_model::wire::evidence::{CompletionReason, CompletionState, Evidence};

fn pipeline(extra: &[&str]) -> Pipeline {
    let mut inputs = shipped::default_inputs();
    for (i, t) in extra.iter().enumerate() {
        inputs.push(PackInput {
            name: format!("p{i}.yaml"),
            text: (*t).to_string(),
        });
    }
    match compile(&inputs) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    }
}

fn extract(p: &Pipeline, sim: Option<&str>, build: bool, text: &str) -> Evidence {
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = sim.map(str::to_string);
    if build {
        o.subject = dviscope_core::extract::Subject::Build;
    }
    extract_bytes(p, o, text.as_bytes()).0
}

fn reason(ev: &Evidence, r: CompletionReason) -> bool {
    ev.completion.reasons.contains(&r)
}

const TRAILER: &str = "$finish at simulation time 1\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n";

fn project(body: &str) -> String {
    format!("format: dviscope.rules/1.0\npack: proj\nversion: 1.0.0\ntier: project\n{body}")
}

#[test]
fn f01_project_patterns_keep_declaration_order() {
    let pack = project(
        "rules:\n  - {id: first, version: 1.0.0, kind: project_pattern, owner: o, reason: r,\n     record: {id: first, start: '^BAD (?P<m>.*)$', emit: {framework: project, severity: error, diag_id: 'p:first', message: '${m}'}}}\n  - {id: second, version: 1.0.0, kind: project_pattern, owner: o, reason: r,\n     record: {id: second, start: '^BAD (?P<m>.*)$', emit: {framework: project, severity: warning, diag_id: 'p:second', message: '${m}'}}}\n",
    );
    let p = pipeline(&[&pack]);
    let ev = extract(&p, Some("vcs"), false, "BAD thing\n");
    assert_eq!(ev.buckets.len(), 1);
    assert_eq!(ev.buckets[0].diag_id, "p:first");
    assert!(ev.buckets[0].fails_run);
}

#[test]
fn f02_suppression_selectors_constrain_each_other() {
    let pack = project(
        "rules:\n  - {id: s, version: 1.0.0, kind: suppression, owner: o, reason: r, action: not_an_error,\n     diag_ids: ['display:error'], match: '^benign$'}\n",
    );
    let p = pipeline(&[&pack]);
    let ev = extract(&p, Some("vcs"), false, "ERROR: benign\nERROR: serious\n");
    let failing: u64 = ev
        .buckets
        .iter()
        .filter(|b| b.fails_run)
        .map(|b| b.count.as_str().parse::<u64>().unwrap_or(0))
        .sum();
    assert_eq!(failing, 1);
    assert_eq!(ev.suppressed.len(), 1);
}

#[test]
fn f03_protected_counter_lines_are_not_records() {
    let pack = project(
        "counters:\n  - {id: errs, domain: project, protected: true, match: '^Error: (?P<n>\\d+)$', values: [{key: errors, from: n, role: failure_count}]}\n",
    );
    let p = pipeline(&[&pack]);
    let ev = extract(&p, Some("vcs"), false, "Error: 0\n");
    assert!(ev.buckets.is_empty(), "{:?}", ev.buckets);
    assert_eq!(ev.counters.len(), 1);
}

#[test]
fn f05_a_cut_summary_line_is_never_a_counter() {
    let p = pipeline(&[]);
    let text = format!(
        "UVM_ERROR @ 1: env [X] bad\n--- UVM Report Summary ---\nUVM_INFO :    0\nUVM_WARNING :    0\nUVM_ERROR : {}1\nUVM_FATAL :    0\n{TRAILER}",
        "0".repeat(17_000)
    );
    let ev = extract(&p, Some("vcs"), false, &text);
    assert_eq!(ev.completion.state, CompletionState::Incomplete);
    assert!(reason(&ev, CompletionReason::LineCut));
}

#[test]
fn f06_cuts_follow_the_final_failure_predicate() {
    let pack = project(
        "rules:\n  - {id: w, version: 1.0.0, kind: project_pattern, owner: o, reason: r, fails_run: true,\n     record: {id: w, start: '^WARN (?P<m>.*)$', continuation: {max_lines: 1, lines: [{match: '^(?P<b>.*)$', capture: true, mandatory: true}]},\n              emit: {framework: project, severity: warning, diag_id: 'p:w', message: '${m}'}}}\n",
    );
    let p = pipeline(&[&pack]);
    let ev = extract(&p, Some("vcs"), false, &format!("{TRAILER}WARN cut here\n"));
    assert!(
        reason(&ev, CompletionReason::RecordCut),
        "{:?}",
        ev.completion
    );
}

#[test]
fn f07_invalid_counter_values_are_not_witnesses() {
    let p = pipeline(&[]);
    let text = format!("Errors: {}, Warnings: 0\n", "9".repeat(40));
    let ev = extract(&p, Some("questa"), true, &text);
    assert_eq!(ev.completion.state, CompletionState::Incomplete);
    assert!(ev.counters.is_empty());
}

#[test]
fn f09_witnesses_are_qualified_by_their_pack() {
    let pack = project(
        "markers:\n  - {id: cpu_time, match: '^PROJECT PASS$', trailer: true}\nverdicts:\n  - {id: v, source: test_result, match: '^PROJECT PASS$', value: pass}\n",
    );
    let p = pipeline(&[&pack]);
    let ev = extract(&p, Some("vcs"), false, "PROJECT PASS\n");
    assert_eq!(ev.completion.state, CompletionState::Incomplete);
}

#[test]
fn f10_a_suppressed_fatal_is_no_early_fatal_witness() {
    let pack = project(
        "rules:\n  - {id: s, version: 1.0.0, kind: suppression, owner: o, reason: r, action: not_an_error, diag_ids: ['uvm:F']}\n",
    );
    let p = pipeline(&[&pack]);
    let ev = extract(
        &p,
        Some("vcs"),
        false,
        &format!("UVM_FATAL @ 1: env [F] stop\n{TRAILER}"),
    );
    assert_eq!(
        ev.completion.state,
        CompletionState::Incomplete,
        "{:?}",
        ev.completion
    );
}

#[test]
fn f11_questa_totals_are_reconciled() {
    let p = pipeline(&[]);
    let ev = extract(
        &p,
        Some("questa"),
        true,
        "** Error: (vlog-1) a.sv(3): bad\nErrors: 0, Warnings: 0\n",
    );
    assert!(
        reason(&ev, CompletionReason::CountMismatch),
        "{:?}",
        ev.completion
    );
    let ev = extract(
        &p,
        Some("questa"),
        true,
        "** Error: (vlog-1) a.sv(3): bad\nErrors: 1, Warnings: 0\n",
    );
    assert_eq!(
        ev.completion.state,
        CompletionState::Complete,
        "{:?}",
        ev.completion
    );
}

#[test]
fn f12_unbased_literals_keep_zero_and_nonzero_apart() {
    let p = pipeline(&[shipped::example("hexk-report-server")
        .map(|e| e.text)
        .unwrap_or_default()
        .as_str()]);
    let line = |v: &str| {
        format!("E1  10.000ns a.sv:4  REF_MATCHED  env  packet results matched: act={v} exp='1\n")
    };
    let a = extract(&p, Some("vcs"), false, &line("'0"));
    let b = extract(&p, Some("vcs"), false, &line("'1"));
    assert_ne!(a.families[0].fingerprint, b.families[0].fingerprint);
}

#[test]
fn f15_summary_accounting_is_bounded() {
    let p = pipeline(&[]);
    let text = "Errors: 0, Warnings: 0\n".repeat(5_000);
    let ev = extract(&p, Some("questa"), true, &text);
    assert!(ev.counters.len() <= 2);
    assert!(reason(&ev, CompletionReason::CountMismatch));
}

#[test]
fn f17_excerpt_budget_is_on_serialized_bytes() {
    let p = pipeline(&[]);
    let ctl: String = std::iter::repeat_n('\u{1}', 1024).collect();
    let mut text = String::new();
    for _ in 0..60 {
        text.push_str(&ctl);
        text.push('\n');
    }
    text.push_str("ERROR: here\n");
    for _ in 0..60 {
        text.push_str(&ctl);
        text.push('\n');
    }
    let ev = extract(&p, Some("vcs"), false, &text);
    let size = serde_json::to_vec(&ev.excerpt).map_or(usize::MAX, |v| v.len());
    assert!(size <= MAX_EXCERPT_BYTES, "{size}");
    assert!(ev.excerpt.truncated);
}

#[test]
fn f18_aggregate_compiled_size_is_limited() {
    let mut body = String::from("records:\n");
    for i in 0..400 {
        body.push_str(&format!("  - {{id: r{i}, start: '^\\w{{60}}{i}$'}}\n"));
    }
    let res = compile(&[PackInput {
        name: "big.yaml".into(),
        text: project(&body),
    }]);
    assert!(res.is_err());
}

#[test]
fn f19_unresolved_references_are_rejected() {
    let within = project(
        "counters:\n  - {id: c, domain: project, within: typo, match: '^N (?P<n>\\d+)$', values: [{key: n, from: n, role: info}]}\n",
    );
    assert!(
        compile(&[PackInput {
            name: "a".into(),
            text: within
        }])
        .is_err()
    );
}

#[test]
fn f20_prefix_needs_anchoring_on_every_alternative() {
    let pack = project("records:\n  - {id: r, prefix: [A, B], start: '^A|B'}\n");
    assert!(
        compile(&[PackInput {
            name: "a".into(),
            text: pack
        }])
        .is_err()
    );
    let ok = project("records:\n  - {id: r, prefix: [A, B], start: '^(?:A|B)'}\n");
    assert!(
        compile(&[PackInput {
            name: "a".into(),
            text: ok
        }])
        .is_ok()
    );
}

// ----------------------------------------------------------------------------------------

#[test]
fn r2_05_a_cut_line_that_no_longer_matches_is_still_incomplete() {
    let p = pipeline(&[]);
    let text = format!(
        "Errors: 0, Warnings: 0\nErrors: {}1, Warnings: 0\n",
        "0".repeat(17_000)
    );
    let ev = extract(&p, Some("questa"), true, &text);
    assert_eq!(ev.completion.state, CompletionState::Incomplete);
    assert!(reason(&ev, CompletionReason::LineCut));
}

#[test]
fn r2_07_an_empty_capture_is_no_zero() {
    let pack = project(
        "counters:\n  - {id: c, domain: project, protected: true, match: '^COUNT (?P<n>\\d*)$', values: [{key: n, from: n, role: failure_count}]}\n",
    );
    let p = pipeline(&[&pack]);
    let ev = extract(&p, Some("vcs"), false, &format!("COUNT \n{TRAILER}"));
    assert!(ev.counters.is_empty());
    assert!(reason(&ev, CompletionReason::CountMismatch));
}

#[test]
fn r2_19_dynamic_keys_match_the_whole_template() {
    let ok = project(
        "counters:\n  - {id: c, domain: project, match: '^(?P<id>\\w+) (?P<n>\\d+)$', values: [{key: '${id}:count', keys: ['X:count'], from: n, role: info}]}\nreconcile:\n  - {template: uvm_errors, counters: ['project:X:count'], frameworks: [uvm], severities: [error]}\n",
    );
    assert!(
        compile(&[PackInput {
            name: "a".into(),
            text: ok
        }])
        .is_ok()
    );
    let typo = project(
        "counters:\n  - {id: c, domain: project, match: '^(?P<id>\\w+) (?P<n>\\d+)$', values: [{key: '${id}:count', from: n, role: info}]}\nreconcile:\n  - {template: uvm_errors, counters: ['project:X:count_typo'], frameworks: [uvm], severities: [error]}\n",
    );
    assert!(
        compile(&[PackInput {
            name: "a".into(),
            text: typo
        }])
        .is_err()
    );
}

#[test]
fn r2_n1_unrepresentable_reconciliation_totals_are_incomplete() {
    let p = pipeline(&[]);
    let text = format!(
        "UVM_ERROR @ 1: env [X] bad\n--- UVM Report Summary ---\nUVM_INFO :    0\nUVM_WARNING :    0\nUVM_ERROR : 340282366920938463463374607431768211455\nUVM_FATAL : 1\n{TRAILER}"
    );
    let ev = extract(&p, Some("vcs"), false, &text);
    assert!(reason(&ev, CompletionReason::CountMismatch));
}

#[test]
fn r2_n2_a_counter_outside_its_section_claims_nothing() {
    let pack = project(
        "markers:\n  - {id: head, match: '^== SUMMARY ==$'}\nsections:\n  - {id: s, open: head, requires: [head]}\ncounters:\n  - {id: c, domain: project, within: s, match: '^ERROR: (?P<n>\\d+)$', values: [{key: n, from: n, role: failure_count}]}\n",
    );
    let p = pipeline(&[&pack]);
    let ev = extract(&p, Some("vcs"), false, &format!("ERROR: 1\n{TRAILER}"));
    assert!(ev.buckets.iter().any(|b| b.fails_run), "{:?}", ev.buckets);
}

#[test]
fn r2_n3_verilator_error_exit_keeps_its_failure_count() {
    let p = pipeline(&[]);
    let ev = extract(
        &p,
        Some("verilator"),
        true,
        "%Error: Exiting due to 3 error(s)\n",
    );
    assert!(
        ev.counters
            .iter()
            .any(|c| c.key == "errors" && c.value.as_str() == "3")
    );
}
