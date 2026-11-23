//! The rule activation check. Invented logs only.

use dviscope_core::packs::{self, PackInput, Pipeline, shipped};
use dviscope_core::rule_check::{
    self, Expectation, SAMPLE_FORMAT, SampleCase, SampleManifest, Structural,
};
use dviscope_model::canonical::Digest;

const QUIET: &str = r#"
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
            text: QUIET.into(),
        });
    }
    packs::compile(&inputs).unwrap_or_else(|e| panic!("{e}"))
}

fn expect(edit: impl FnOnce(&mut Expectation)) -> Expectation {
    let mut x: Expectation = serde_json::from_value(serde_json::json!({
        "format": "dviscope.expect/1", "simulator": "vcs"
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    edit(&mut x);
    x
}

fn sample(log: &str, x: Expectation) -> SampleManifest {
    let d = Digest::of_bytes(log.as_bytes());
    SampleManifest {
        format: SAMPLE_FORMAT.into(),
        cases: vec![SampleCase {
            case: "c1".into(),
            log_sha256: d.as_str().trim_start_matches("sha256:").into(),
            bytes: log.len() as u64,
            expect: x,
        }],
    }
}

fn run(old: &Pipeline, new: &Pipeline, log: &str, x: Expectation) -> Structural {
    rule_check::check(old, new, &sample(log, x), &[log.as_bytes()])
        .unwrap_or_else(|e| panic!("{e}"))
}

const LOG: &str = "ERROR: serious\n";

#[test]
fn a18_a_lost_must_survive_failure_blocks() {
    let (old, new) = (pipeline(false), pipeline(true));
    let r = run(
        &old,
        &new,
        LOG,
        expect(|x| {
            x.must_survive = vec!["display:error".into()];
            x.expect_changes = vec!["display:error".into(), "outcome".into()];
        }),
    );
    assert!(!r.pass, "{r:?}");
    assert_eq!(r.cases[0].lost_must_survive, ["display:error"]);
    assert_eq!(r.old_pipeline, old.digest);
    assert_eq!(r.new_pipeline, new.digest);
}

#[test]
fn undeclared_changes_block_and_declared_ones_pass() {
    let (old, new) = (pipeline(false), pipeline(true));
    let r = run(&old, &new, LOG, expect(|_| {}));
    assert!(!r.pass);
    assert!(
        r.cases[0]
            .undeclared_changes
            .contains(&"failing:display:error".to_string()),
        "{r:?}"
    );
    let r = run(
        &old,
        &new,
        LOG,
        expect(|x| {
            x.expect_changes = vec![
                "display:error".into(),
                "outcome".into(),
                "primary".into(),
                "suppressed".into(),
            ];
        }),
    );
    assert!(r.pass, "{r:?}");
    assert!(r.cases[0].undeclared_changes.is_empty());
    assert!(!r.cases[0].declared_changes.is_empty());
}

#[test]
fn an_unchanged_pipeline_passes_and_checks_are_deterministic() {
    let old = pipeline(false);
    let x = expect(|x| {
        x.must_survive = vec!["display:error".into()];
        x.failures = [("display:error".to_string(), 1)].into();
    });
    let a = run(&old, &old, LOG, x.clone());
    assert!(a.pass, "{a:?}");
    let b = run(&old, &pipeline(false), LOG, x);
    assert_eq!(a, b, "same inputs, same structural result");
}

#[test]
fn must_remain_distinct_lines_report_merges_and_unresolved_lines() {
    let p = pipeline(false);
    // Numbers are normalized: lines 1 and 2 share a family; line 3 is another family.
    let log = "ERROR: count 1\nERROR: count 2\nERROR: other thing\n";
    let r = run(
        &p,
        &p,
        log,
        expect(|x| x.must_remain_distinct = vec![[1, 2], [1, 3], [1, 99]]),
    );
    assert!(!r.pass);
    assert_eq!(r.cases[0].merged, [[1, 2]], "{r:?}");
    assert_eq!(r.cases[0].unresolved_lines, [99]);
}

#[test]
fn a_tampered_log_or_sample_is_refused() {
    let p = pipeline(false);
    let s = sample(LOG, expect(|_| {}));
    assert!(rule_check::check(&p, &p, &s, &[b"ERROR: other\n"]).is_err());
    let mut bad = s.clone();
    bad.format = "x".into();
    assert!(rule_check::check(&p, &p, &bad, &[LOG.as_bytes()]).is_err());
    let mut empty = s;
    empty.cases.clear();
    assert!(rule_check::check(&p, &p, &empty, &[]).is_err());
}

/// A pack whose self-test fails never passes the check.
#[test]
fn a_failing_self_test_fails_the_check() {
    let broken = PackInput {
        name: "broken.yaml".into(),
        text: r#"
format: dviscope.rules/1.0
pack: broken
version: 1.0.0
tier: project
rules:
  - {id: q, version: 1.0.0, kind: suppression, owner: o, reason: r, action: not_an_error,
     diag_ids: ['proj:never']}
tests:
  - name: claims an event that never appears
    simulator: vcs
    input: |
      all quiet
    events: ['display:error@1']
"#
        .into(),
    };
    let old = pipeline(false);
    let mut inputs = shipped::default_inputs();
    inputs.push(broken);
    let new = packs::compile(&inputs).unwrap_or_else(|e| panic!("{e}"));
    let r = run(&old, &new, LOG, expect(|_| {}));
    assert!(!r.self_test_failures.is_empty(), "{r:?}");
    assert!(!r.pass);
    assert!(r.cases.iter().all(|c| c.ok), "the sample alone would pass");
}

/// Equivalent samples in another case order give identical results.
#[test]
fn the_case_order_does_not_matter() {
    let p = pipeline(false);
    let case = |name: &str, log: &str| SampleCase {
        case: name.into(),
        log_sha256: Digest::of_bytes(log.as_bytes())
            .as_str()
            .trim_start_matches("sha256:")
            .into(),
        bytes: log.len() as u64,
        expect: expect(|_| {}),
    };
    let (la, lb) = (
        "ERROR: a
",
        "ERROR: b
",
    );
    let ab = SampleManifest {
        format: SAMPLE_FORMAT.into(),
        cases: vec![case("a", la), case("b", lb)],
    };
    let ba = SampleManifest {
        format: SAMPLE_FORMAT.into(),
        cases: vec![case("b", lb), case("a", la)],
    };
    assert_eq!(ab.digest(), ba.digest());
    let x = rule_check::check(&p, &p, &ab, &[la.as_bytes(), lb.as_bytes()])
        .unwrap_or_else(|e| panic!("{e}"));
    let y = rule_check::check(&p, &p, &ba, &[lb.as_bytes(), la.as_bytes()])
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(x, y);
}
