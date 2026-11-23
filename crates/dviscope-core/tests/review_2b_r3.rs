//! Regression tests. Invented text only.

use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::packs::{PackInput, compile, shipped};

fn project(body: &str) -> String {
    format!("format: dviscope.rules/1.0\npack: proj\nversion: 1.0.0\ntier: project\n{body}")
}

#[test]
fn r3_19_repeated_captures_in_a_key_are_rejected() {
    let pack = project(
        r"counters:
  - {id: c, domain: project, match: '^(?P<id>\w+) (?P<n>\d+)$', values: [{key: '${id}:${id}:count', from: n, role: info}]}
",
    );
    let e = compile(&[PackInput {
        name: "a".into(),
        text: pack,
    }])
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default();
    assert!(e.contains("each capture at most once"), "{e}");
}

#[test]
fn r3_n5_key_validation_is_bounded() {
    // Many variables: rejected cleanly (no deep recursion, no exponential search).
    let mut groups = String::new();
    let mut key = String::new();
    for i in 0..2_048 {
        groups.push_str(&format!("(?P<g{i}>X)"));
        key.push_str(&format!("${{g{i}}}"));
    }
    let pack = project(&format!(
        "counters:\n  - {{id: c, domain: project, match: '^{groups} (?P<n>\\d+)$', values: [{{key: '{key}', from: n, role: info}}]}}\nreconcile:\n  - {{template: uvm_errors, counters: ['project:{}'], frameworks: [uvm], severities: [error]}}\n",
        "X".repeat(2_048)
    ));
    // (The test harness's own timeout bounds the time; recursion would overflow the stack.)
    assert!(
        compile(&[PackInput {
            name: "a".into(),
            text: pack
        }])
        .is_err()
    );
}

#[test]
fn r3_n4_a_counter_on_its_sections_opening_line_counts() {
    let pack = project(
        r"markers:
  - {id: head, match: '^COUNT [0-9]+$'}
sections:
  - {id: s, open: head, requires: [head]}
counters:
  - {id: c, domain: project, within: s, protected: true, match: '^COUNT (?P<n>[0-9]+)$', values: [{key: n, from: n, role: failure_count}]}
",
    );
    let mut inputs = shipped::default_inputs();
    inputs.push(PackInput {
        name: "p.yaml".into(),
        text: pack,
    });
    let p = match compile(&inputs) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    };
    let mut o = ExtractOptions::simulation("t.log");
    o.simulator = Some("vcs".into());
    let ev = extract_bytes(&p, o, b"COUNT 3\n").0;
    assert!(
        ev.counters
            .iter()
            .any(|c| c.key == "n" && c.value.as_str() == "3"),
        "{:?}",
        ev.counters
    );
}

// ----------------------------------------------------------------------------------------

#[test]
fn r4_19_dynamic_key_references_need_declared_keys() {
    let body = |reference: &str| {
        project(&format!(
            r"counters:
  - {{id: c, domain: project, match: '^(?P<sev>ERROR|FATAL) : (?P<n>[0-9]+)$', values: [{{key: 'X_${{sev}}', keys: [X_ERROR, X_FATAL], from: n, role: failure_count}}]}}
reconcile:
  - {{template: uvm_errors, counters: ['{reference}'], frameworks: [uvm], severities: [error]}}
"
        ))
    };
    assert!(
        compile(&[PackInput {
            name: "a".into(),
            text: body("project:X_ERROR")
        }])
        .is_ok()
    );
    assert!(
        compile(&[PackInput {
            name: "a".into(),
            text: body("project:X_EROR")
        }])
        .is_err()
    );
}

#[test]
fn r4_n6_section_verdict_counters_must_be_required() {
    let pack = project(
        r"markers:
  - {id: head, match: '^COUNT [0-9]+$'}
sections:
  - id: s
    open: head
    requires: [head]
    verdict: {source: uvm_summary, fail_if_nonzero: ['project:n']}
counters:
  - {id: c, domain: project, within: s, protected: true, match: '^COUNT (?P<n>[0-9]+)$', values: [{key: n, from: n, role: info}]}
",
    );
    let e = compile(&[PackInput {
        name: "a".into(),
        text: pack,
    }])
    .err()
    .map(|e| e.to_string())
    .unwrap_or_default();
    assert!(e.contains("must also be in requires"), "{e}");
}
