//! Regression tests. Invented text only.

use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::packs::{PackInput, compile, shipped};
use dviscope_model::wire::evidence::{CompletionReason, CompletionState};

fn project(body: &str) -> String {
    format!("format: dviscope.rules/1.0\npack: proj\nversion: 1.0.0\ntier: project\n{body}")
}

fn compile_err(pack: String) -> String {
    compile(&[PackInput {
        name: "a".into(),
        text: pack,
    }])
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default()
}

#[test]
fn r5_n6_a_marker_cannot_take_a_counter_reference() {
    // The round-5 reproduction: a marker named like the counter it stands in for.
    let e = compile_err(project(
        r"markers:
  - {id: 'project:n', match: '^COUNT [0-9]+$'}
sections:
  - id: s
    open: 'project:n'
    requires: ['project:n']
    verdict: {source: uvm_summary, fail_if_nonzero: ['project:n']}
counters:
  - {id: c, domain: project, within: s, protected: true, match: '^COUNT (?P<n>[0-9]+)$', values: [{key: n, from: n, role: info}]}
",
    ));
    assert!(e.contains("may not contain ':'"), "{e}");
}

#[test]
fn r5_n6_a_verdict_reads_counters_only() {
    let e = compile_err(project(
        r"markers:
  - {id: head, match: '^HEAD$'}
  - {id: tail, match: '^TAIL$'}
sections:
  - id: s
    open: head
    requires: [tail]
    verdict: {source: uvm_summary, fail_if_nonzero: [tail]}
",
    ));
    assert!(e.contains("not a counter of the pack"), "{e}");
}

#[test]
fn r5_n7_an_unresolved_counter_role_is_invalid_evidence() {
    let pack = project(
        r"counters:
  - id: c
    domain: project
    protected: true
    match: '^COUNT (?P<kind>BAD|GOOD) (?P<n>[0-9]+)$'
    values:
      - {key: failures, from: n, role: {from: kind, map: {GOOD: success_count}}}
",
    );
    let mut inputs = shipped::default_inputs();
    inputs.push(PackInput {
        name: "p.yaml".into(),
        text: pack,
    });
    let p = compile(&inputs).unwrap_or_else(|e| panic!("{e}"));
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = Some("vcs".into());
    let ev = extract_bytes(&p, o, b"COUNT BAD 3\n").0;
    assert!(
        !ev.counters.iter().any(|c| c.key == "failures"),
        "an unresolved role must not become a silent info counter: {:?}",
        ev.counters
    );
    assert_eq!(ev.completion.state, CompletionState::Incomplete);
    assert!(
        ev.completion
            .reasons
            .contains(&CompletionReason::CountMismatch),
        "{:?}",
        ev.completion.reasons
    );
    // A mapped role, or an explicit default, still counts.
    let pack = project(
        r"counters:
  - id: c
    domain: project
    protected: true
    match: '^COUNT (?P<kind>BAD|GOOD) (?P<n>[0-9]+)$'
    values:
      - {key: failures, from: n, role: {from: kind, map: {GOOD: success_count}, default: failure_count}}
",
    );
    let mut inputs = shipped::default_inputs();
    inputs.push(PackInput {
        name: "p.yaml".into(),
        text: pack,
    });
    let p = compile(&inputs).unwrap_or_else(|e| panic!("{e}"));
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = Some("vcs".into());
    let ev = extract_bytes(&p, o, b"COUNT BAD 3\n").0;
    assert!(
        ev.counters
            .iter()
            .any(|c| c.key == "failures" && c.value.as_str() == "3"),
        "{:?}",
        ev.counters
    );
}
