use super::*;
use crate::compare::SignatureCounts;
use crate::settlement::BlockedBy;

fn d(s: &str) -> Digest {
    Digest::of_bytes(s.as_bytes())
}

/// 2026-11-13T22:00:00Z in milliseconds.
const T0: Millis = 1_794_607_200_000;

/// Durations in milliseconds (the core has no time library).
mod dur {
    use super::Millis;
    pub fn seconds(n: i64) -> Millis {
        n * 1_000
    }
    pub fn minutes(n: i64) -> Millis {
        n * 60_000
    }
    pub fn hours(n: i64) -> Millis {
        n * 3_600_000
    }
    pub fn days(n: i64) -> Millis {
        n * 86_400_000
    }
}

fn slot(name: &str, cfg: &str, state: SlotState, sigs: &[&str]) -> HealthSlot {
    HealthSlot {
        view: SlotView {
            slot: name.into(),
            config: d(cfg),
            simulator: "vcs".into(),
            state,
            signatures: sigs
                .iter()
                .map(|s| {
                    (
                        d(s),
                        SignatureCounts {
                            attempts: 1,
                            diagnostics: 1,
                        },
                    )
                })
                .collect(),
        },
        required: true,
        deciding: None,
        terminal_ends: vec![],
    }
}

fn pass(name: &str) -> HealthSlot {
    slot(name, name, SlotState::Passed, &[])
}

fn fail(name: &str, sigs: &[&str]) -> HealthSlot {
    slot(name, name, SlotState::Failed(FailReason::Functional), sigs)
}

fn reg(name: &str, verdict: Verdict, slots: Vec<HealthSlot>) -> RegInput {
    RegInput {
        regression: name.into(),
        state: RegState::Finished,
        started_at: T0,
        verdict,
        undecided: BTreeSet::new(),
        slots,
    }
}

fn input(latest: Option<RegInput>, baseline: Option<RegInput>) -> StreamInput {
    StreamInput {
        cadence: None,
        now: T0 + dur::hours(8),
        latest,
        baseline,
    }
}

fn trend(latest: Option<RegInput>, baseline: Option<RegInput>) -> (Trend, Vec<Worse>) {
    let h = summarize(&input(latest, baseline));
    (h.trend, h.worse)
}

#[test]
fn trend_rows_in_order() {
    // 1. no data
    assert_eq!(trend(None, None).0, Trend::NoData);
    // 2. running wins over everything else
    let mut r = reg("n2", Verdict::Fail, vec![fail("a", &["x"])]);
    r.state = RegState::Sealed;
    assert_eq!(
        trend(Some(r), Some(reg("n1", Verdict::Pass, vec![pass("a")]))).0,
        Trend::Running
    );
    // 3. no baseline
    assert_eq!(
        trend(Some(reg("n1", Verdict::Pass, vec![pass("a")])), None).0,
        Trend::NoBaseline
    );
    // 4. disjoint configurations
    assert_eq!(
        trend(
            Some(reg("n2", Verdict::Pass, vec![pass("a")])),
            Some(reg("n1", Verdict::Pass, vec![pass("b")]))
        )
        .0,
        Trend::NotComparable
    );
    // 6. green
    assert_eq!(
        trend(
            Some(reg("n2", Verdict::Pass, vec![pass("a")])),
            Some(reg("n1", Verdict::Pass, vec![pass("a")]))
        )
        .0,
        Trend::Green
    );
    // 7. yellow: a persisting failure, nothing worse
    let b = reg("n1", Verdict::Fail, vec![fail("a", &["x"]), pass("b")]);
    let l = reg("n2", Verdict::Fail, vec![fail("a", &["x"]), pass("b")]);
    assert_eq!(trend(Some(l), Some(b)), (Trend::Yellow, vec![]));
}

#[test]
fn red_reasons() {
    let base = || reg("n1", Verdict::Pass, vec![pass("a"), pass("b")]);
    // a new signature on a configuration that ran before
    let (t, w) = trend(
        Some(reg("n2", Verdict::Fail, vec![fail("a", &["x"]), pass("b")])),
        Some(base()),
    );
    assert_eq!(t, Trend::Red);
    assert!(
        w.contains(&Worse::NewSignatures)
            && w.contains(&Worse::FailureRate)
            && w.contains(&Worse::Readiness)
    );
    // a slot without a result
    let (t, w) = trend(
        Some(reg(
            "n2",
            Verdict::Pass,
            vec![pass("a"), slot("b", "b", SlotState::Missing, &[])],
        )),
        Some(base()),
    );
    assert_eq!((t, w), (Trend::Red, vec![Worse::NotSettled]));
    // readiness worse alone (insufficient evidence, every slot passed)
    let (t, w) = trend(
        Some(reg(
            "n2",
            Verdict::InsufficientEvidence,
            vec![pass("a"), pass("b")],
        )),
        Some(base()),
    );
    assert_eq!((t, w), (Trend::Red, vec![Worse::Readiness]));
}

#[test]
fn all_passed_but_readiness_failing_like_before_is_yellow() {
    let b = reg("n1", Verdict::Fail, vec![pass("a")]);
    let l = reg("n2", Verdict::Fail, vec![pass("a")]);
    assert_eq!(trend(Some(l), Some(b)), (Trend::Yellow, vec![]));
}

#[test]
fn finished_with_running_slots_unchanged_is_yellow() {
    let run = || slot("b", "b", SlotState::Running, &[]);
    let b = reg("n1", Verdict::InsufficientEvidence, vec![pass("a"), run()]);
    let l = reg("n2", Verdict::InsufficientEvidence, vec![pass("a"), run()]);
    assert_eq!(trend(Some(l), Some(b)), (Trend::Yellow, vec![]));
}

#[test]
fn added_passing_configurations_do_not_dilute_a_rate_rise() {
    // Before: 1 failed of 4. Now: the same 4 with 2 failed, plus 96 new passing configs.
    // The whole-regression rate falls (3 % < 25 %); the matched rate rises (50 % > 25 %).
    let b = reg(
        "n1",
        Verdict::Fail,
        vec![fail("a", &["x"]), pass("b"), pass("c"), pass("e")],
    );
    let mut slots = vec![fail("a", &["x"]), fail("b", &["x"]), pass("c"), pass("e")];
    slots.extend((0..96).map(|i| pass(&format!("new{i}"))));
    let h = summarize(&input(Some(reg("n2", Verdict::Fail, slots)), Some(b)));
    assert_eq!(h.trend, Trend::Red);
    assert_eq!(h.worse, vec![Worse::FailureRate]);
    assert_eq!(
        (
            h.matched,
            h.matched_bad,
            h.baseline_matched,
            h.baseline_matched_bad
        ),
        (4, 2, 4, 1)
    );
    assert_eq!((h.configs_added, h.configs_removed), (96, 0));
}

#[test]
fn signature_sets_new_unknown_persistent_gone() {
    let b = reg(
        "n1",
        Verdict::Fail,
        vec![
            fail("a", &["old"]),
            fail("b", &["keep"]),
            fail("gone_cfg", &["vanished"]),
            pass("c"),
        ],
    );
    let l = reg(
        "n2",
        Verdict::Fail,
        vec![
            pass("a"),                           // "old" no longer observed (a ran again)
            fail("b", &["keep"]),                // persistent
            fail("c", &["fresh"]),               // new: c settled before
            fail("brand_new_cfg", &["mystery"]), // unknown: config not run before
            fail("spans", &["mixed"]),           // spans an unmatched config ...
            fail("c2", &["mixed"]),              // ... and a matched one below
        ],
    );
    let mut b = b;
    b.slots.push(pass("c2"));
    let s = summarize(&input(Some(l), Some(b))).signatures;
    assert_eq!(s.persistent, BTreeSet::from([d("keep")]));
    assert_eq!(
        s.new,
        BTreeSet::from([d("fresh"), d("mixed")]),
        "one settled config suffices"
    );
    assert_eq!(s.unknown, BTreeSet::from([d("mystery")]));
    assert_eq!(s.no_longer_observed, BTreeSet::from([d("old")]));
    assert_eq!(s.config_not_run, BTreeSet::from([d("vanished")]));
}

#[test]
fn blocked_slots_with_real_signatures_count() {
    let b = reg("n1", Verdict::Pass, vec![pass("a")]);
    let l = reg(
        "n2",
        Verdict::Fail,
        vec![slot(
            "a",
            "a",
            SlotState::Blocked(BlockedBy::Build),
            &["elab"],
        )],
    );
    let h = summarize(&input(Some(l), Some(b)));
    assert_eq!(h.signatures.new, BTreeSet::from([d("elab")]));
    assert_eq!(h.counts.blocked, 1);
    // A blocked slot without a signature (a synthetic group in the comparison) adds none.
    let l = reg(
        "n2",
        Verdict::Fail,
        vec![slot("a", "a", SlotState::Blocked(BlockedBy::Build), &[])],
    );
    assert!(summarize(&input(Some(l), None)).signatures.all.is_empty());
}

#[test]
fn required_only_rates_and_zero_denominators() {
    let mut opt = fail("o", &["x"]);
    opt.required = false;
    let mut timeout = slot("t", "t", SlotState::Failed(FailReason::Timeout), &[]);
    timeout.required = true;
    let h = summarize(&input(
        Some(reg("n1", Verdict::Fail, vec![pass("a"), timeout, opt])),
        None,
    ));
    assert_eq!(h.counts.required, 2);
    assert_eq!(
        (
            h.counts.failed,
            h.counts.of_which_timeout,
            h.counts.optional
        ),
        (1, 1, 1)
    );
    assert_eq!(pass_rate(&h.counts), Some(50.0));
    assert!(
        h.signatures.all.is_empty(),
        "optional slots carry no signatures"
    );
    let empty = summarize(&input(Some(reg("n1", Verdict::Pass, vec![])), None));
    assert_eq!(pass_rate(&empty.counts), None);
}

#[test]
fn last_end_over_all_attempts_and_cpu_coverage() {
    let mut a = pass("a");
    // Strict policy may decide on an earlier attempt; the later retry still ended later.
    a.terminal_ends = vec![Some(T0 + dur::minutes(10)), Some(T0 + dur::minutes(40))];
    a.deciding = Some(Metrics {
        wall_s: Some(600.0),
        cpu_s: Some(550.0),
        cpu_scope: Some("job"),
    });
    let mut b = pass("b");
    b.terminal_ends = vec![None];
    b.deciding = Some(Metrics {
        wall_s: Some(900.0),
        cpu_s: None,
        cpu_scope: None,
    });
    let mut c = pass("c");
    c.terminal_ends = vec![Some(T0 + dur::minutes(20))];
    c.deciding = Some(Metrics {
        wall_s: Some(100.0),
        cpu_s: Some(80.0),
        cpu_scope: Some("process_and_waited_children"),
    });
    let h = summarize(&input(Some(reg("n1", Verdict::Pass, vec![a, b, c])), None));
    assert_eq!(h.cost.last_end, Some(T0 + dur::minutes(40)));
    assert!(h.cost.last_end_partial);
    assert_eq!(h.cost.elapsed_s, Some(2400.0));
    assert_eq!(
        (h.cost.longest_run_s, h.cost.machine_s),
        (Some(900.0), Some(1600.0))
    );
    assert_eq!(
        (h.cost.cpu_s, h.cost.cpu_measured, h.cost.cpu_slots),
        (Some(630.0), 2, 3)
    );
    assert!(!h.cost.cpu_complete());
    assert_eq!(
        h.cost.cpu_scopes,
        BTreeSet::from(["job", "process_and_waited_children"])
    );
}

#[test]
fn overdue_boundaries() {
    let l = || Some(reg("n1", Verdict::Pass, vec![pass("a")]));
    let day = dur::hours(24);
    // deadline = start + 24 h + 6 h grace
    let at = |now| {
        summarize(&StreamInput {
            cadence: Some(day),
            now,
            latest: l(),
            baseline: None,
        })
    };
    let h = at(T0 + dur::hours(30) - dur::seconds(1));
    assert!(!h.overdue);
    assert_eq!(
        h.overdue_at,
        Some(T0 + dur::hours(30)),
        "the refresh point is the deadline"
    );
    let h = at(T0 + dur::hours(30));
    assert!(h.overdue, "at the deadline it is overdue: no lost timer");
    assert_eq!(h.overdue_at, None);
    assert_eq!(at(T0).overdue_at, Some(T0 + dur::hours(30)));
    // weekly: grace 42 h; a 2 h cadence: grace at least 2 h
    assert_eq!(grace(dur::hours(168)), dur::hours(42));
    assert_eq!(grace(dur::hours(2)), dur::hours(2));
    // a start in the future counts as now
    let mut r = reg("n1", Verdict::Pass, vec![pass("a")]);
    r.started_at = T0 + dur::days(3);
    let h = summarize(&StreamInput {
        cadence: Some(day),
        now: T0,
        latest: Some(r),
        baseline: None,
    });
    assert_eq!(h.overdue_at, Some(T0 + dur::hours(30)));
    // never seen: no data, never overdue
    let h = summarize(&StreamInput {
        cadence: Some(day),
        now: T0,
        latest: None,
        baseline: None,
    });
    assert_eq!((h.trend, h.overdue), (Trend::NoData, false));
}

#[test]
fn rollup_counts_each_stream_once_and_unions_signatures() {
    let s1 = summarize(&input(
        Some(reg(
            "n2",
            Verdict::Fail,
            vec![fail("a", &["shared"]), pass("b")],
        )),
        Some(reg("n1", Verdict::Pass, vec![pass("a"), pass("b")])),
    ));
    let s2 = summarize(&input(
        Some(reg(
            "m2",
            Verdict::Pass,
            vec![pass("c"), pass("e"), pass("f"), pass("g")],
        )),
        Some(reg(
            "m1",
            Verdict::Pass,
            vec![pass("c"), pass("e"), pass("f"), pass("g")],
        )),
    ));
    let mut k2 = reg("k2", Verdict::Fail, vec![fail("h", &["shared"])]);
    k2.undecided = BTreeSet::from([d("shared")]);
    let s3 = summarize(&input(Some(k2), None));
    let mut m: BTreeMap<&str, StreamHealth> = BTreeMap::new();
    m.insert("dma", s1);
    m.insert("core", s2);
    m.insert("io", s3);
    let n = rollup(m.values());
    assert_eq!(n.streams, 3);
    assert_eq!(
        (n.counts.required, n.counts.passed, n.counts.failed),
        (7, 5, 2)
    );
    assert_eq!(
        n.all,
        BTreeSet::from([d("shared")]),
        "one identity across streams"
    );
    assert_eq!(n.undecided.len(), 1);
    assert_eq!(n.new, BTreeSet::from([d("shared")]));
    assert_eq!(n.trend, Some(Colour::Red));
    assert_eq!(n.readiness, Some(Colour::Red));
    assert_eq!(n.grey.get("no_baseline"), Some(&1));
    assert_eq!(n.worst_rate, Some(0.0));
    assert_eq!(n.zero_test_streams, 0);
    // A stream whose latest regression has no required test counts; one without any
    // regression does not.
    m.insert(
        "empty",
        summarize(&input(Some(reg("e1", Verdict::Pass, vec![])), None)),
    );
    m.insert("never", summarize(&input(None, None)));
    assert_eq!(rollup(m.values()).zero_test_streams, 1);
    // No metrics at all: CPU unknown, never zero, never complete.
    assert_eq!((n.cpu_s, n.cpu_complete, n.cpu_scope), (None, false, None));
    assert_eq!((n.cpu_slots, n.cpu_measured), (0, 0));
    // Deltas only over the two streams with a predecessor (io has none).
    assert_eq!(n.compared_streams, 2);
    assert_eq!(
        (n.compared_counts.required, n.compared_counts.failed),
        (6, 1)
    );
    assert_eq!(
        (
            n.compared_baseline_counts.required,
            n.compared_baseline_counts.failed
        ),
        (6, 0)
    );
}

#[test]
fn rollup_of_grey_streams_only_has_no_colour() {
    let mut m = BTreeMap::new();
    m.insert(1, summarize(&input(None, None)));
    let mut r = reg(
        "n1",
        Verdict::InsufficientEvidence,
        vec![slot("a", "a", SlotState::Running, &[])],
    );
    r.state = RegState::Unsealed;
    m.insert(2, summarize(&input(Some(r), None)));
    let n = rollup(m.values());
    assert_eq!((n.trend, n.readiness), (None, None));
    assert_eq!(n.grey.get("no_data"), Some(&1));
    assert_eq!(n.grey.get("running"), Some(&1));
    assert_eq!(n.grey.get("insufficient_evidence"), Some(&1));
    assert_eq!(n.worst_rate, Some(0.0));
    assert!(!n.cpu_complete);
}

#[test]
fn worst_rate_ignores_streams_without_required_slots() {
    let mut m = BTreeMap::new();
    m.insert(
        1,
        summarize(&input(Some(reg("e", Verdict::Pass, vec![])), None)),
    );
    m.insert(
        2,
        summarize(&input(
            Some(reg("f", Verdict::Pass, vec![pass("a"), fail("b", &[])])),
            None,
        )),
    );
    assert_eq!(rollup(m.values()).worst_rate, Some(50.0));
    let mut only_empty = BTreeMap::new();
    only_empty.insert(
        1,
        summarize(&input(Some(reg("e", Verdict::Pass, vec![])), None)),
    );
    assert_eq!(rollup(only_empty.values()).worst_rate, None);
}

fn cost_of(
    metrics: &[(Option<f64>, Option<f64>, Option<&'static str>)],
    ends: &[Option<i64>],
) -> Cost {
    let slots = metrics
        .iter()
        .enumerate()
        .map(|(i, (w, c, sc))| {
            let mut s = pass(&format!("s{i}"));
            s.deciding = Some(Metrics {
                wall_s: *w,
                cpu_s: *c,
                cpu_scope: *sc,
            });
            s.terminal_ends = ends
                .get(i)
                .map(|e| vec![e.map(|m| T0 + dur::minutes(m))])
                .unwrap_or_default();
            s
        })
        .collect();
    summarize(&input(Some(reg("r", Verdict::Pass, slots)), None)).cost
}

#[test]
fn cpu_delta_needs_one_known_scope_on_both_sides() {
    let job = Some("job");
    let proc_ = Some("process");
    let a = cost_of(
        &[(Some(1.0), Some(100.0), job), (Some(1.0), Some(10.0), job)],
        &[Some(5), Some(6)],
    );
    let b = cost_of(
        &[(Some(1.0), Some(90.0), job), (Some(1.0), Some(10.0), job)],
        &[Some(5), Some(6)],
    );
    assert_eq!(cost_deltas(&a, &b).cpu_s, Some(10.0));
    // The same scope *set* with the scopes swapped per configuration: not comparable.
    let mixed1 = cost_of(
        &[
            (Some(1.0), Some(100.0), job),
            (Some(1.0), Some(10.0), proc_),
        ],
        &[],
    );
    let mixed2 = cost_of(
        &[
            (Some(1.0), Some(10.0), proc_),
            (Some(1.0), Some(100.0), job),
        ],
        &[],
    );
    assert_eq!(mixed1.cpu_scopes, mixed2.cpu_scopes);
    assert_eq!(cost_deltas(&mixed1, &mixed2).cpu_s, None);
    // An unknown scope or a missing measurement: not comparable.
    let unknown = cost_of(
        &[(Some(1.0), Some(100.0), None), (Some(1.0), Some(10.0), job)],
        &[],
    );
    assert_eq!(cost_deltas(&unknown, &b).cpu_s, None);
    let partial = cost_of(
        &[(Some(1.0), None, None), (Some(1.0), Some(10.0), job)],
        &[],
    );
    assert_eq!(cost_deltas(&partial, &b).cpu_s, None);
}

#[test]
fn partial_runtime_never_reads_as_an_improvement() {
    let full = cost_of(
        &[(Some(100.0), None, None), (Some(50.0), None, None)],
        &[Some(30), Some(40)],
    );
    let no_wall = cost_of(
        &[(Some(100.0), None, None), (None, None, None)],
        &[Some(30), Some(40)],
    );
    let no_end = cost_of(
        &[(Some(100.0), None, None), (Some(50.0), None, None)],
        &[Some(30), None],
    );
    assert!(no_wall.machine_partial && !full.machine_partial);
    assert_eq!(cost_deltas(&no_wall, &full).machine_s, None);
    assert_eq!(cost_deltas(&full, &full).machine_s, Some(0.0));
    assert!(no_end.last_end_partial);
    assert_eq!(cost_deltas(&no_end, &full).elapsed_s, None);
    assert_eq!(cost_deltas(&full, &full).elapsed_s, Some(0.0));
    // Nonzero deltas keep their sign (now − before).
    let slower = cost_of(
        &[(Some(160.0), None, None), (Some(50.0), None, None)],
        &[Some(50), Some(40)],
    );
    let d = cost_deltas(&slower, &full);
    assert_eq!((d.machine_s, d.elapsed_s), (Some(60.0), Some(600.0)));
    let d = cost_deltas(&full, &slower);
    assert_eq!((d.machine_s, d.elapsed_s), (Some(-60.0), Some(-600.0)));
    // An end before the start: no elapsed time, flagged (never an improvement).
    let early = cost_of(&[(Some(1.0), None, None)], &[Some(-5)]);
    assert!(early.times_inconsistent);
    assert_eq!(early.elapsed_s, None);
    assert_eq!(cost_deltas(&early, &full).elapsed_s, None);
}

#[test]
fn rollup_cpu_scope_only_when_every_stream_agrees() {
    let s = |scope| {
        let mut x = pass("a");
        x.deciding = Some(Metrics {
            wall_s: Some(1.0),
            cpu_s: Some(2.0),
            cpu_scope: scope,
        });
        summarize(&input(Some(reg("r", Verdict::Pass, vec![x])), None))
    };
    let mut m = BTreeMap::new();
    m.insert(1, s(Some("job")));
    m.insert(2, s(Some("job")));
    assert_eq!(rollup(m.values()).cpu_scope, Some("job"));
    m.insert(3, s(Some("process")));
    assert_eq!(rollup(m.values()).cpu_scope, None);
}

#[test]
fn undecided_in_one_stream_is_undecided_once_at_the_parent() {
    // The same signature: covered (decided) in one suite, needing a decision in another.
    let covered = summarize(&input(
        Some(reg(
            "a",
            Verdict::AcceptedWithExceptions,
            vec![fail("x", &["sig"])],
        )),
        None,
    ));
    let mut b = reg("b", Verdict::Fail, vec![fail("y", &["sig"])]);
    b.undecided = BTreeSet::from([d("sig")]);
    let open = summarize(&input(Some(b), None));
    let mut m = BTreeMap::new();
    m.insert("suite-a", covered);
    m.insert("suite-b", open);
    let n = rollup(m.values());
    assert_eq!(n.undecided, BTreeSet::from([d("sig")]));
    assert_eq!(n.all.len(), 1);
}

#[test]
fn undecided_only_from_required_failures() {
    let mut opt = fail("o", &["optional_only"]);
    opt.required = false;
    let mut r = reg("n1", Verdict::Fail, vec![fail("a", &["req"]), opt]);
    r.undecided = BTreeSet::from([d("req"), d("optional_only")]);
    let h = summarize(&input(Some(r), None));
    assert_eq!(h.signatures.undecided, BTreeSet::from([d("req")]));
}

#[test]
fn sibling_slots_of_one_configuration() {
    // Two slots share a configuration digest; one is unsettled now.
    let sib = |n: &str, st| slot(n, "cfg", st, &[]);
    let b = reg(
        "n1",
        Verdict::Pass,
        vec![sib("a", SlotState::Passed), sib("b", SlotState::Passed)],
    );
    let l = reg(
        "n2",
        Verdict::InsufficientEvidence,
        vec![sib("a", SlotState::Passed), sib("b", SlotState::Missing)],
    );
    let h = summarize(&input(Some(l), Some(b)));
    // The configuration is matched (settled in both); the unsettled sibling stays out of
    // the rates and counts as not settled.
    assert_eq!((h.matched, h.baseline_matched), (1, 2));
    assert_eq!(h.counts.not_settled(), 1);
    assert_eq!(h.trend, Trend::Red);
    assert!(h.worse.contains(&Worse::NotSettled));
    // Still declared: not a removed configuration.
    assert_eq!((h.configs_added, h.configs_removed), (0, 0));
}

#[test]
fn passed_to_missing_is_not_a_removed_configuration() {
    let b = reg("n1", Verdict::Pass, vec![pass("a"), pass("b")]);
    let l = reg(
        "n2",
        Verdict::InsufficientEvidence,
        vec![pass("a"), slot("b", "b", SlotState::Missing, &[])],
    );
    let h = summarize(&input(Some(l), Some(b)));
    assert_eq!((h.configs_added, h.configs_removed), (0, 0));
    let l = reg("n3", Verdict::Pass, vec![pass("a"), pass("z")]);
    let h = summarize(&input(
        Some(l),
        Some(reg("n1", Verdict::Pass, vec![pass("a"), pass("b")])),
    ));
    assert_eq!((h.configs_added, h.configs_removed), (1, 1));
}

#[test]
fn rollup_partial_elapsed_and_cpu_delta_over_compared_streams() {
    let with = |slots: Vec<HealthSlot>, base: Option<Vec<HealthSlot>>| {
        summarize(&input(
            Some(reg("now", Verdict::Pass, slots)),
            base.map(|b| reg("before", Verdict::Pass, b)),
        ))
    };
    let m = |cpu: f64, end: Option<i64>| {
        let mut s = pass("a");
        s.deciding = Some(Metrics {
            wall_s: Some(1.0),
            cpu_s: Some(cpu),
            cpu_scope: Some("job"),
        });
        s.terminal_ends = vec![end.map(|x| T0 + dur::minutes(x))];
        s
    };
    let mut map = BTreeMap::new();
    map.insert(
        1,
        with(vec![m(30.0, Some(10))], Some(vec![m(20.0, Some(10))])),
    );
    map.insert(
        2,
        with(vec![m(5.0, Some(20))], Some(vec![m(7.0, Some(20))])),
    );
    let n = rollup(map.values());
    assert_eq!(n.cpu_delta_s, Some(8.0));
    assert_eq!(
        (n.cpu_s, n.cpu_scope, n.cpu_complete),
        (Some(35.0), Some("job"), true)
    );
    assert_eq!((n.elapsed_s, n.elapsed_partial), (Some(1200.0), false));
    // A stream without a predecessor does not enter the delta; one with a partial end
    // makes the node's elapsed partial.
    map.insert(3, with(vec![m(100.0, None)], None));
    let n = rollup(map.values());
    assert_eq!(n.cpu_delta_s, Some(8.0));
    assert!(n.elapsed_partial);
    // A compared stream without a comparable CPU delta removes the node delta.
    let mut unscoped = m(9.0, Some(5));
    if let Some(m) = unscoped.deciding.as_mut() {
        m.cpu_scope = None;
    }
    map.insert(4, with(vec![unscoped], Some(vec![m(9.0, Some(5))])));
    assert_eq!(rollup(map.values()).cpu_delta_s, None);
}
