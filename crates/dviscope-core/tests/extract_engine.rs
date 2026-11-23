//! Engine tests on invented ("toy") formats: record ownership, cuts, chunk invariance,
//! bounded output, suppression, detection buffering. No simulator text.

use dviscope_core::extract::{ExtractOptions, Extractor, Subject, extract_bytes};
use dviscope_core::packs::{PackInput, Pipeline, compile};
use dviscope_model::limits::{MAX_BUCKETS, MAX_EVENTS, MAX_EXCERPT_BYTES, MAX_FAMILIES};
use dviscope_model::wire::evidence::{CompletionState, Evidence, Provenance};
use dviscope_model::wire::manifest::Severity;
use proptest::prelude::*;

const TOY_SIM: &str = r#"
format: dviscope.rules/1.0
pack: toysim
version: 1.0.0
tier: simulator
simulator: toysim
detect: ['^TOY-SIM ready$']
framing: {strip_prefix: '> '}
normalize: [hex, number, whitespace]
boundaries: ['^-- ']
records:
  - id: two_line
    prefix: 'HDR '
    start: '^HDR (?P<site>\w+):(?P<line>\d+)$'
    continuation:
      max_lines: 1
      lines: [{match: '^(?P<msg>.*)$', capture: true, mandatory: true}]
    emit: {framework: simulator, severity: error, diag_id: 'toy:two_line', message: '${msg}',
           anchor: {path: site, line: line}}
  - id: block
    prefix: 'BLK '
    start: '^BLK (?P<id>\w+) (?P<title>.*)$'
    continuation:
      max_lines: 3
      until: blank
      lines: [{match: '^\s+(?P<text>.*)$', append_to: detail}]
    emit: {framework: simulator, severity: warning, diag_id: 'toy:${id}', checker_id: '${id}',
           message: '${title}', display_fields: [detail]}
  - id: fail_line
    prefix: 'FAIL '
    start: '^FAIL (?P<msg>.*)$'
    emit: {framework: simulator, severity: error, diag_id: 'toy:fail', message: '${msg}'}
markers:
  - {id: the_end, match: '^TOY-SIM end$', trailer: true, design_loaded: true}
counters:
  - id: totals
    domain: sim_tool
    protected: true
    match: '^TOTAL errors=(?P<e>\d+)$'
    values: [{key: errors, from: e, role: failure_count}]
verdicts:
  - id: result
    source: test_result
    match: '^RESULT (?P<v>PASS|FAIL)$'
    value: {from: v, map: {PASS: pass, FAIL: fail}}
completion:
  profiles:
    - {name: toysim-run, subject: simulation, requires: [the_end, totals], verdict_required: true}
"#;

const TOY_PROJECT: &str = r#"
format: dviscope.rules/1.0
pack: toyproj
version: 1.0.0
tier: project
records:
  - id: proj
    prefix: 'P! '
    start: '^P! (?P<msg>.*)$'
    continuation:
      max_lines: 5
      lines: [{match: '^(?P<text>.*)$', append_to: detail}]
    emit: {framework: project, severity: error, diag_id: 'proj:x', message: '${msg}'}
rules:
  - id: quiet-fail
    version: 1.0.0
    kind: suppression
    owner: me
    reason: known noise
    action: not_an_error
    diag_ids: ['toy:fail']
"#;

fn pipeline(with_project: bool) -> Pipeline {
    let mut inputs = vec![PackInput {
        name: "toysim.yaml".into(),
        text: TOY_SIM.into(),
    }];
    if with_project {
        inputs.push(PackInput {
            name: "toyproj.yaml".into(),
            text: TOY_PROJECT.into(),
        });
    }
    match compile(&inputs) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    }
}

fn opts() -> ExtractOptions {
    let mut o = ExtractOptions::simulation("toy.log");
    o.simulator = Some("toysim".into());
    o.trace = true;
    o
}

fn run(
    p: &Pipeline,
    o: ExtractOptions,
    text: &str,
) -> (Evidence, Vec<dviscope_core::extract::TraceRecord>) {
    extract_bytes(p, o, text.as_bytes())
}

fn records(t: &[dviscope_core::extract::TraceRecord]) -> Vec<(String, u64, u64, bool)> {
    t.iter()
        .map(|r| {
            (
                r.rule.split('@').next().unwrap_or_default().to_string(),
                r.start_line,
                r.end_line,
                r.cut,
            )
        })
        .collect()
}

#[test]
fn mandatory_body_is_taken_before_any_start() {
    let p = pipeline(false);
    let (_, t) = run(&p, opts(), "HDR a:1\nFAIL looks like a start\nFAIL real\n");
    assert_eq!(
        records(&t),
        [
            ("toysim/two_line".into(), 1, 2, false),
            ("toysim/fail_line".into(), 3, 3, false)
        ]
    );
}

#[test]
fn boundary_or_eof_where_the_body_was_expected_cuts_the_record() {
    let p = pipeline(false);
    let (ev, t) = run(&p, opts(), "HDR a:1\n-- boundary\nHDR b:2\n");
    assert_eq!(
        records(&t),
        [
            ("toysim/two_line".into(), 1, 1, true),
            ("toysim/two_line".into(), 3, 3, true)
        ]
    );
    assert!(
        ev.completion
            .reasons
            .iter()
            .any(|r| format!("{r:?}") == "RecordCut")
    );
}

#[test]
fn max_lines_lookahead_marks_a_cut_only_when_more_continuation_follows() {
    let p = pipeline(false);
    let (_, t) = run(&p, opts(), "BLK A t\n x\n y\n z\nFAIL next\n");
    assert_eq!(records(&t)[0], ("toysim/block".into(), 1, 4, false));
    let (_, t) = run(&p, opts(), "BLK A t\n x\n y\n z\n w\n");
    assert_eq!(records(&t)[0], ("toysim/block".into(), 1, 4, true));
}

#[test]
fn lower_tier_starts_do_not_interrupt_a_project_record_but_boundaries_do() {
    let p = pipeline(true);
    let (_, t) = run(&p, opts(), "P! one\nFAIL inside\n-- stop\nFAIL outside\n");
    assert_eq!(
        records(&t),
        [
            ("toyproj/proj".into(), 1, 2, false),
            ("toysim/fail_line".into(), 4, 4, false)
        ]
    );
    assert_eq!(t[1].suppressed_by.as_deref(), Some("quiet-fail@1.0.0"));
}

#[test]
fn suppression_drops_rule_events_but_never_an_authoritative_failure() {
    let p = pipeline(true);
    let (ev, _) = run(&p, opts(), "FAIL noise\n");
    assert!(ev.buckets.is_empty());
    assert_eq!(ev.suppressed.len(), 1);
    assert_eq!(ev.suppressed[0].count.as_str(), "1");
    // A line no rule claims but the fixed recognizers mark authoritative still fails the run.
    let (ev, _) = run(&p, opts(), "** Error: (x-1) something\n");
    assert_eq!(ev.buckets.len(), 1);
    let b = &ev.buckets[0];
    assert_eq!(
        (b.provenance, b.fails_run, b.observed_severity),
        (Provenance::Authoritative, true, Severity::Error)
    );
    assert_eq!(b.diag_id, "dviscope:unclaimed_authoritative");
}

#[test]
fn lines_before_detection_are_buffered_and_framed() {
    let p = pipeline(false);
    let mut o = opts();
    o.simulator = None;
    let (ev, t) = run(
        &p,
        o,
        "> FAIL early\n> TOY-SIM ready\n> FAIL late\n> TOTAL errors=2\n> TOY-SIM end\n> RESULT FAIL\n",
    );
    assert_eq!(
        t.iter()
            .filter(|r| r.diag_id.as_deref() == Some("toy:fail"))
            .count(),
        2
    );
    assert_eq!(ev.completion.state, CompletionState::Complete);
    assert_eq!(ev.completion.profile, "toysim-run");
}

#[test]
fn undetected_logs_have_no_profile() {
    let p = pipeline(false);
    let mut o = opts();
    o.simulator = None;
    let (ev, _) = run(&p, o, "nothing to see\n");
    assert_eq!(ev.completion.state, CompletionState::Incomplete);
    assert_eq!(ev.completion.profile, "unknown");
}

#[test]
fn completion_needs_trailer_counter_and_verdict() {
    let p = pipeline(false);
    let full = "TOTAL errors=0\nTOY-SIM end\nRESULT PASS\n";
    assert_eq!(
        run(&p, opts(), full).0.completion.state,
        CompletionState::Complete
    );
    for cut in [
        "TOTAL errors=0\nTOY-SIM end\n",
        "TOY-SIM end\nRESULT PASS\n",
        "TOTAL errors=0\nRESULT PASS\n",
    ] {
        assert_eq!(
            run(&p, opts(), cut).0.completion.state,
            CompletionState::Incomplete,
            "{cut:?}"
        );
    }
    let empty = run(&p, opts(), "").0;
    assert_eq!(empty.completion.state, CompletionState::Missing);
}

#[test]
fn bucket_and_family_caps_keep_exact_counts() {
    let p = pipeline(false);
    // Distinct sites, same message: one family per site (no checker ID), so the family cap
    // binds first; every event is still counted.
    let n = 1_100;
    let text: String = (0..n)
        .map(|i| format!("HDR s{i}:1\nsame message\n"))
        .collect();
    let (ev, _) = run(&p, opts(), &text);
    assert!(ev.families.len() <= MAX_FAMILIES && ev.buckets.len() <= MAX_BUCKETS);
    let counted: u64 = ev
        .buckets
        .iter()
        .map(|b| b.count.as_str().parse::<u64>().unwrap_or(0))
        .sum();
    let overflow: u64 = ev
        .overflow
        .iter()
        .map(|o| o.count.as_str().parse::<u64>().unwrap_or(0))
        .sum();
    assert_eq!(counted + overflow, n);
    assert!(overflow > 0);
    // Every bucket references an existing family and every family's buckets exist.
    for f in &ev.families {
        for b in &f.buckets {
            let idx = usize::try_from(b.get()).unwrap_or(usize::MAX);
            assert_eq!(ev.buckets[idx].family, f.fingerprint);
        }
    }
    assert!(ev.events.len() <= MAX_EVENTS);
}

#[test]
fn storms_merge_by_normalization_and_examples_are_bounded() {
    let p = pipeline(false);
    let text: String = (0..5_000)
        .map(|i| format!("HDR s:1\nvalue {i} data=0x{i:08x}\n"))
        .collect();
    let (ev, _) = run(&p, opts(), &text);
    assert_eq!(ev.families.len(), 1);
    assert_eq!(ev.buckets[0].count.as_str(), "5000");
    assert!(ev.events.len() <= MAX_EVENTS);
    // The display-primary example (the first failure) is kept.
    assert_eq!(ev.events[0].ordinal.get(), 1);
}

#[test]
fn excerpt_is_bounded_with_long_lines() {
    let p = pipeline(false);
    let long = "x".repeat(20_000);
    let text: String = (0..300).map(|_| format!("{long}\n")).collect::<String>() + "FAIL here\n";
    let (ev, _) = run(&p, opts(), &text);
    let bytes: usize = ev
        .excerpt
        .segments
        .iter()
        .flat_map(|s| s.lines.iter())
        .map(|l| l.len() + 1)
        .sum();
    assert!(bytes <= MAX_EXCERPT_BYTES);
    // Cut lines make the log incomplete (a cut line may hide a summary).
    assert!(
        ev.completion
            .reasons
            .iter()
            .any(|r| format!("{r:?}") == "LineCut")
    );
}

#[test]
fn crlf_and_lf_give_the_same_classification() {
    let p = pipeline(false);
    let lf = "HDR a:1\nmsg 1\nBLK B t\n d\n\nTOTAL errors=1\nTOY-SIM end\nRESULT FAIL\n";
    let crlf = lf.replace('\n', "\r\n");
    let (a, _) = run(&p, opts(), lf);
    let (b, _) = run(&p, opts(), &crlf);
    assert_eq!(a.families, b.families);
    assert_eq!(a.completion, b.completion);
    assert_eq!(a.buckets.len(), b.buckets.len());
}

fn toy_log() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        Just(b"HDR s:1\n".to_vec()),
        Just(b"body text 12\n".to_vec()),
        Just(b"BLK A title\n".to_vec()),
        Just(b"  detail\n".to_vec()),
        Just(b"\n".to_vec()),
        Just(b"FAIL x 0xbeef\r\n".to_vec()),
        Just(b"-- b\r".to_vec()),
        Just(b"P! proj\n".to_vec()),
        Just(b"** Error: (t-1) a\n".to_vec()),
        Just(b"TOTAL errors=3\n".to_vec()),
        Just(b"TOY-SIM end\n".to_vec()),
        Just(vec![0xE2, 0x82]),
        Just(vec![0xAC, b'\n']),
        Just(vec![0xFF, b'\n']),
    ];
    prop::collection::vec(piece, 0..60).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, ..ProptestConfig::default() })]

    #[test]
    fn chunking_never_changes_the_evidence(
        log in toy_log(), cuts in prop::collection::vec(0usize..2000, 0..12), detect in any::<bool>(),
    ) {
        let p = pipeline(true);
        let opts = || {
            let mut o = opts();
            if detect {
                o.simulator = None;
            }
            o
        };
        let (whole, _) = extract_bytes(&p, opts(), &log);
        let mut points: Vec<usize> = cuts.into_iter().map(|c| c % (log.len() + 1)).collect();
        points.sort_unstable();
        let mut x = Extractor::new(&p, opts());
        let mut last = 0;
        for c in points {
            x.push(&log[last..c]);
            last = c;
        }
        x.push(&log[last..]);
        let chunked = x.finish();
        prop_assert_eq!(serde_json::to_value(&whole).ok(), serde_json::to_value(&chunked).ok());
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_stay_bounded(log in prop::collection::vec(any::<u8>(), 0..4096)) {
        let p = pipeline(true);
        let mut o = opts();
        o.simulator = None;
        o.subject = Subject::Build;
        let (ev, _) = extract_bytes(&p, o, &log);
        prop_assert!(ev.events.len() <= MAX_EVENTS);
        prop_assert_eq!(ev.source.bytes.get(), log.len() as u64);
    }
}

fn uvm_log(errors: usize, counted: usize, summaries: usize) -> String {
    let mut s = String::new();
    for i in 0..errors {
        s.push_str(&format!("UVM_ERROR @ {i}: env.chk [CHK] value differs\n"));
    }
    for _ in 0..summaries {
        s.push_str(&format!(
            "--- UVM Report Summary ---\nUVM_INFO :    0\nUVM_WARNING :    0\nUVM_ERROR :    {counted}\nUVM_FATAL :    0\n"
        ));
    }
    s
}

fn shipped() -> Pipeline {
    match dviscope_core::packs::shipped::default_pipeline() {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    }
}

fn mismatch(ev: &Evidence) -> bool {
    ev.completion
        .reasons
        .iter()
        .any(|r| format!("{r:?}") == "CountMismatch")
}

#[test]
fn uvm_reconciliation_is_extracted_at_most_counted() {
    let p = shipped();
    let o = || ExtractOptions::simulation("u.log");
    let (ev, _) = run(&p, o(), &uvm_log(2, 2, 1));
    assert!(!mismatch(&ev));
    assert_eq!(ev.reconciliation.len(), 1);
    // UVM counted more than it printed: not a mismatch (outcome explains it later).
    let (ev, _) = run(&p, o(), &uvm_log(2, 5, 1));
    assert!(!mismatch(&ev));
    let r = &ev.reconciliation[0];
    assert_eq!(
        (r.counted.as_str(), r.extracted.as_str(), r.holds),
        ("5", "2", true)
    );
    // More extracted than counted: mismatch.
    let (ev, _) = run(&p, o(), &uvm_log(3, 2, 1));
    assert!(mismatch(&ev));
    // Two summaries in one log: one report population only.
    let (ev, _) = run(&p, o(), &uvm_log(2, 2, 2));
    assert!(mismatch(&ev));
}

#[test]
fn overflow_makes_completion_incomplete() {
    let p = pipeline(false);
    let text: String = (0..1_100)
        .map(|i| format!("HDR s{i}:1\nm\n"))
        .collect::<String>()
        + "TOTAL errors=1100\nTOY-SIM end\nRESULT FAIL\n";
    let (ev, _) = run(&p, opts(), &text);
    assert!(!ev.overflow.is_empty());
    assert_eq!(ev.completion.state, CompletionState::Incomplete);
    assert!(
        ev.completion
            .reasons
            .iter()
            .any(|r| format!("{r:?}") == "AccountingOverflow")
    );
}
