//! Rule activation check: the same code runs locally (`dviscope rules
//! import`) and on the server (activation). It compares an old and a new pipeline over a
//! project's activation sample and reports, per case, what changed structurally: expected
//! structural results, lost `must_survive` failures, merged `must_remain_distinct` lines,
//! and differences not declared in `expect_changes`. The structural result is bound to the
//! `(old pipeline, new pipeline, sample)` digests; timing is reported apart (it differs
//! between machines and never takes part in the comparison of two checks).
//!
//! Output never contains log text: IDs, counts, states, line numbers and digests only.

use std::collections::{BTreeMap, BTreeSet};

use dviscope_model::canonical::{Digest, digest_of};
use dviscope_model::wire::evidence::{CompletionState, Evidence, Framework};
use dviscope_model::wire::ingest::Runner;
use serde::{Deserialize, Serialize};

use crate::extract::{ExtractOptions, Subject, TraceRecord, extract_bytes};
use crate::outcome::{self, Input};
use crate::packs::{self, PackInput, Pipeline, shipped};

/// Pipeline definition format.
pub const DEFINITION_FORMAT: &str = "dviscope.pipeline/1";
/// A definition's pack texts are at most 4 MiB together.
pub const MAX_DEFINITION_BYTES: usize = 4 * 1024 * 1024;

/// One pack of a definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackText {
    /// File name (messages; part of the pipeline digest).
    pub name: String,
    /// Pack source.
    pub text: String,
}

/// A pipeline as packs: the shipped defaults (unless `default_packs` is false) followed by
/// `packs`, in order. Its compiled digest is the pipeline digest evidence names; the
/// client and the server compile the same definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineDefinition {
    /// Always `dviscope.pipeline/1`.
    pub format: String,
    /// Whether the shipped packs come first.
    pub default_packs: bool,
    /// Extra packs, in order.
    pub packs: Vec<PackText>,
}

impl PipelineDefinition {
    /// The shipped default pipeline (a project's pipeline before any activation).
    #[must_use]
    pub fn shipped() -> Self {
        Self {
            format: DEFINITION_FORMAT.into(),
            default_packs: true,
            packs: vec![],
        }
    }

    /// Compiles the definition.
    ///
    /// # Errors
    /// A bad format, size (the message names 4 MiB) or pack.
    pub fn compile(&self) -> Result<Pipeline, String> {
        if self.format != DEFINITION_FORMAT {
            return Err(format!("format must be {DEFINITION_FORMAT}"));
        }
        let size: usize = self.packs.iter().map(|p| p.text.len() + p.name.len()).sum();
        if size > MAX_DEFINITION_BYTES {
            return Err("the definition's packs exceed 4 MiB".into());
        }
        let mut inputs = if self.default_packs {
            shipped::default_inputs()
        } else {
            vec![]
        };
        inputs.extend(self.packs.iter().map(|p| PackInput {
            name: p.name.clone(),
            text: p.text.clone(),
        }));
        packs::compile(&inputs).map_err(|e| format!("the packs do not compile: {e}"))
    }
}

/// Sample format.
pub const SAMPLE_FORMAT: &str = "dviscope.sample/1";
/// Check result format.
pub const CHECK_FORMAT: &str = "dviscope.rule_check/1";
/// At most this many cases in a sample.
pub const MAX_CASES: usize = 200;
/// At most this many log bytes in a sample.
pub const MAX_SAMPLE_BYTES: u64 = 64 * 1024 * 1024;

/// A structural expectation (`dviscope.expect/1`): IDs, counts and states only, plus the
/// activation constraints of a sample case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    /// Always `dviscope.expect/1`.
    pub format: String,
    /// The log, relative to the expectation file (local samples only; default
    /// `<case>.log` beside it). Never part of a stored sample.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    /// `simulation` or `build`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Declared simulator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulator: Option<String>,
    /// A Verilator model with its own main: the case's log is the program log followed by
    /// the console capture, the console starting at byte `console_at` (both required
    /// together).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub model_main: bool,
    /// Byte offset of the console capture in a model case's log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub console_at: Option<u64>,
    /// Expected completion state (`complete`, `incomplete`, `missing`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<String>,
    /// Expected completion mode when complete (`normal`, `early_fatal`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Expected design-load state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub design_loaded: Option<String>,
    /// Verdict sources that must be present with these values (`banner: fail`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub verdicts: BTreeMap<String, String>,
    /// Exact counts of failing events (`fails_run`) by `diag_id`; with `failures_exact`,
    /// no other failing `diag_id` may appear.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, u64>,
    /// Whether `failures` lists every failing `diag_id`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub failures_exact: bool,
    /// Like `failures_exact`, for `diag_ids` with these prefixes only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact_prefixes: Vec<String>,
    /// Total failing events of the simulator and assertion frameworks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulator_errors: Option<u64>,
    /// Number of distinct families per `diag_id`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub families: BTreeMap<String, u64>,
    /// `diag_id` of the display-primary event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
    /// Maximum unclaimed error-like lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unclaimed: Option<u64>,
    /// Files (basenames) that a failing event's source anchor must name, each at least once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_anchored_in: Vec<String>,
    /// Activation: failing `diag_ids` that must still fail under the new pipeline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub must_survive: Vec<String>,
    /// Activation: pairs of log lines (1-based) whose records must stay in different
    /// families under the new pipeline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub must_remain_distinct: Vec<[u64; 2]>,
    /// Activation: intended differences between the old and the new pipeline (an aspect
    /// name such as `completion`, `failing:<diag_id>`, or a bare `diag_id` for every aspect
    /// of it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expect_changes: Vec<String>,
    /// Activation: the run's exit code (default 0), for the observed outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Activation: the slot's expected-outcome contract (as declared in its manifest), so
    /// the derived assessment is compared too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<dviscope_model::wire::manifest::Expected>,
}

/// One case of a stored sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleCase {
    /// Case name (unique in the sample).
    pub case: String,
    /// SHA-256 (hex) of the complete log bytes.
    pub log_sha256: String,
    /// Log size.
    pub bytes: u64,
    /// Expected structural results and activation constraints (without `log`).
    pub expect: Expectation,
}

/// A project's activation sample (`dviscope.sample/1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleManifest {
    /// Always `dviscope.sample/1`.
    pub format: String,
    /// Cases.
    pub cases: Vec<SampleCase>,
}

impl SampleManifest {
    /// Checks the format and the limits (≤ 200 cases, ≤ 64 MiB of logs, unique names,
    /// hex digests, expectation format).
    ///
    /// # Errors
    /// The first problem found.
    pub fn validate(&self) -> Result<(), String> {
        if self.format != SAMPLE_FORMAT {
            return Err(format!("format must be {SAMPLE_FORMAT}"));
        }
        if self.cases.is_empty() {
            return Err("a sample has at least one case".into());
        }
        if self.cases.len() > MAX_CASES {
            return Err(format!("more than {MAX_CASES} cases"));
        }
        let mut names = BTreeSet::new();
        let mut total: u64 = 0;
        for c in &self.cases {
            if c.case.is_empty() || c.case.len() > 200 || !names.insert(c.case.as_str()) {
                return Err(format!(
                    "case name {:?} is empty, too long or repeated",
                    c.case
                ));
            }
            if c.log_sha256.len() != 64 || !c.log_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("{}: log_sha256 is 64 hex digits", c.case));
            }
            if c.expect.format != "dviscope.expect/1" || c.expect.log.is_some() {
                return Err(format!(
                    "{}: expect is dviscope.expect/1 without a log path",
                    c.case
                ));
            }
            match (c.expect.model_main, c.expect.console_at) {
                (true, Some(at)) if at <= c.bytes => {}
                (false, None) => {}
                _ => {
                    return Err(format!(
                        "{}: model_main and console_at (within the log) go together",
                        c.case
                    ));
                }
            }
            total = total.saturating_add(c.bytes);
        }
        if total > MAX_SAMPLE_BYTES {
            return Err(format!("more than {MAX_SAMPLE_BYTES} bytes of logs"));
        }
        // The sample's identity is its canonical digest: a value canonical JSON cannot carry
        // exactly (an integer beyond 2^53) is refused, never given a shared fallback
        // identity.
        digest_of(self).map_err(|e| format!("the sample is not canonical JSON: {e}"))?;
        Ok(())
    }

    /// The sample digest: canonical JSON of the cases, sorted by name.
    ///
    /// # Panics
    /// Never (the manifest serializes).
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut cases = self.cases.clone();
        cases.sort_by(|a, b| a.case.cmp(&b.case));
        let canon = SampleManifest {
            format: self.format.clone(),
            cases,
        };
        digest_of(&canon).unwrap_or_else(|_| Digest::of_bytes(b"unserializable sample"))
    }
}

/// The result of one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseResult {
    /// Case name.
    pub case: String,
    /// The new pipeline's evidence against the case's expectation.
    pub expectation_failures: Vec<String>,
    /// `must_survive` `diag_ids` that no longer fail.
    pub lost_must_survive: Vec<String>,
    /// `must_remain_distinct` pairs that share a family under the new pipeline.
    pub merged: Vec<[u64; 2]>,
    /// `must_remain_distinct` lines that no record of the new pipeline classifies.
    pub unresolved_lines: Vec<u64>,
    /// Old → new differences not declared in `expect_changes`.
    pub undeclared_changes: Vec<String>,
    /// Old → new differences declared in `expect_changes` (shown, never failing).
    pub declared_changes: Vec<String>,
    /// The case passes.
    pub ok: bool,
}

/// The structural result: the part two checks of the same inputs agree on exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Structural {
    /// Always `dviscope.rule_check/1`.
    pub format: String,
    /// The pipeline active before.
    pub old_pipeline: Digest,
    /// The pipeline to activate.
    pub new_pipeline: Digest,
    /// The sample.
    pub sample: Digest,
    /// Compiled rules (records, counters, verdict sources, markers, suppressions), old.
    pub old_rules: u64,
    /// Compiled rules, new.
    pub new_rules: u64,
    /// The new pipeline's pack self-tests that fail (a pack that fails its own examples,
    /// or breaks a shipped pack's, never activates).
    pub self_test_failures: Vec<String>,
    /// Every case passes and every self-test holds.
    pub pass: bool,
    /// Per case, in sample order.
    pub cases: Vec<CaseResult>,
}

/// Runs the check (the caller measures throughput: this crate reads no clock). `logs`
/// holds each case's bytes, in sample order.
///
/// # Errors
/// An invalid sample, a case without its log, or a log whose digest or size differs from
/// the manifest.
pub fn check(
    old: &Pipeline,
    new: &Pipeline,
    sample: &SampleManifest,
    logs: &[&[u8]],
) -> Result<Structural, String> {
    sample.validate()?;
    if logs.len() != sample.cases.len() {
        return Err("one log per case".into());
    }
    // Canonical order (by case name), whatever order the sample was given in: equivalent
    // samples (same digest) give identical results.
    let mut pairs: Vec<(&SampleCase, &&[u8])> = sample.cases.iter().zip(logs).collect();
    pairs.sort_by(|a, b| a.0.case.cmp(&b.0.case));
    let mut cases = vec![];
    for (c, log) in pairs {
        if Digest::of_bytes(log).as_str() != format!("sha256:{}", c.log_sha256)
            || log.len() as u64 != c.bytes
        {
            return Err(format!("{}: the log differs from the sample", c.case));
        }
        let (old_ev, _) = run(old, &c.expect, log);
        let (new_ev, trace) = run(new, &c.expect, log);
        cases.push(judge(c, &old_ev, &new_ev, &trace));
    }
    let self_test_failures = shipped::self_test(new);
    let pass = cases.iter().all(|c| c.ok) && self_test_failures.is_empty();
    Ok(Structural {
        format: CHECK_FORMAT.into(),
        old_pipeline: old.digest.clone(),
        new_pipeline: new.digest.clone(),
        sample: sample.digest(),
        old_rules: old.rule_count(),
        new_rules: new.rule_count(),
        self_test_failures,
        pass,
        cases,
    })
}

fn run(p: &Pipeline, x: &Expectation, log: &[u8]) -> (Evidence, Vec<TraceRecord>) {
    let mut opts = ExtractOptions::simulation("sample.log");
    opts.simulator.clone_from(&x.simulator);
    opts.trace = !x.must_remain_distinct.is_empty();
    if x.subject.as_deref() == Some("build") {
        opts.subject = Subject::Build;
    }
    if let (true, Some(at)) = (x.model_main, x.console_at) {
        // The program log, then the console, joined as the collector joins them.
        opts.model_main = true;
        let at = usize::try_from(at).unwrap_or(usize::MAX).min(log.len());
        let mut e = crate::extract::Extractor::new(p, opts);
        e.push(&log[..at]);
        e.begin_console();
        e.push(&log[at..]);
        return e.finish_with_trace();
    }
    extract_bytes(p, opts, log)
}

fn judge(c: &SampleCase, old: &Evidence, new: &Evidence, trace: &[TraceRecord]) -> CaseResult {
    let x = &c.expect;
    let expectation_failures = compare(new, x);
    let failing_new = failing(new);
    let lost_must_survive: Vec<String> = x
        .must_survive
        .iter()
        .filter(|d| failing_new.get(d.as_str()).copied().unwrap_or(0) == 0)
        .cloned()
        .collect();
    let mut merged = vec![];
    let mut unresolved_lines = BTreeSet::new();
    for pair in &x.must_remain_distinct {
        let fp = |line: u64| {
            trace
                .iter()
                .find(|t| t.start_line <= line && line <= t.end_line)
                .and_then(|t| t.fingerprint.clone())
        };
        match (fp(pair[0]), fp(pair[1])) {
            (Some(a), Some(b)) if a == b => merged.push(*pair),
            (Some(_), Some(_)) => {}
            (a, b) => {
                if a.is_none() {
                    unresolved_lines.insert(pair[0]);
                }
                if b.is_none() {
                    unresolved_lines.insert(pair[1]);
                }
            }
        }
    }
    let (mut declared_changes, mut undeclared_changes) = (vec![], vec![]);
    for aspect in differences(old, new, x) {
        let declared = x
            .expect_changes
            .iter()
            .any(|e| *e == aspect || aspect.split_once(':').is_some_and(|(_, id)| id == e));
        if declared {
            declared_changes.push(aspect);
        } else {
            undeclared_changes.push(aspect);
        }
    }
    let ok = expectation_failures.is_empty()
        && lost_must_survive.is_empty()
        && merged.is_empty()
        && unresolved_lines.is_empty()
        && undeclared_changes.is_empty();
    CaseResult {
        case: c.case.clone(),
        expectation_failures,
        lost_must_survive,
        merged,
        unresolved_lines: unresolved_lines.into_iter().collect(),
        undeclared_changes,
        declared_changes,
        ok,
    }
}

/// Structural aspects that differ between two extractions of the same log.
fn differences(old: &Evidence, new: &Evidence, x: &Expectation) -> Vec<String> {
    let mut d = vec![];
    // The profile too: a pipeline change may move a log to another profile with the same
    // state (plan F2 review).
    if old.completion.profile != new.completion.profile
        || state_name(old.completion.state) != state_name(new.completion.state)
        || old.completion.mode != new.completion.mode
        || old.completion.reasons != new.completion.reasons
    {
        d.push("completion".to_string());
    }
    // Events beyond the retained buckets (overflow) count too: a failure lost there is a
    // lost failure.
    if overflow(old) != overflow(new) {
        d.push("overflow".to_string());
    }
    if old.design_loaded != new.design_loaded {
        d.push("design_loaded".to_string());
    }
    if observed(old, x) != observed(new, x) {
        d.push("outcome".to_string());
    }
    // What decides contradictions: every verdict source and reconciliation.
    let sources = |e: &Evidence| {
        let mut v: Vec<String> = e
            .verdict_sources
            .iter()
            .map(|s| serde_json::to_string(s).unwrap_or_default())
            .collect();
        v.sort();
        v
    };
    if sources(old) != sources(new) {
        d.push("verdict_sources".to_string());
    }
    let rec = |e: &Evidence| serde_json::to_value(&e.reconciliation).unwrap_or_default();
    if rec(old) != rec(new) {
        d.push("reconciliation".to_string());
    }
    let (fo, fn_) = (failing(old), failing(new));
    for id in fo.keys().chain(fn_.keys()).collect::<BTreeSet<_>>() {
        if fo.get(id) != fn_.get(id) {
            d.push(format!("failing:{id}"));
        }
    }
    let (go, gn) = (families(old), families(new));
    for id in go.keys().chain(gn.keys()).collect::<BTreeSet<_>>() {
        if go.get(id) != gn.get(id) {
            d.push(format!("families:{id}"));
        }
    }
    if primary(old) != primary(new) {
        d.push("primary".to_string());
    }
    // Everything else the evidence states structurally (counters, suppressions, coverage,
    // and any field added later) is compared as a whole, field by field, so no structural
    // change can pass unseen. Excluded: what names the pipeline itself, and
    // presentation (example events with their raw messages, the excerpt).
    let (vo, vn) = (
        serde_json::to_value(old).unwrap_or_default(),
        serde_json::to_value(new).unwrap_or_default(),
    );
    if let (Some(o), Some(n)) = (vo.as_object(), vn.as_object()) {
        for key in o.keys().chain(n.keys()).collect::<BTreeSet<_>>() {
            if GENERIC_SKIP.contains(&key.as_str()) {
                continue;
            }
            if o.get(key) != n.get(key) {
                d.push(key.clone());
            }
        }
    }
    d
}

/// Evidence fields the generic comparison skips: compared specifically above
/// (`completion`, `design_loaded`, `verdict_sources`, `reconciliation`, `overflow`,
/// `buckets`, `families`), naming the pipeline (`extractor`, `pipeline_digest`, `packs`),
/// or presentation (`events`, `excerpt`).
const GENERIC_SKIP: &[&str] = &[
    "completion",
    "design_loaded",
    "verdict_sources",
    "reconciliation",
    "overflow",
    "buckets",
    "families",
    "extractor",
    "pipeline_digest",
    "packs",
    "events",
    "excerpt",
];

/// The whole derived result (outcome, blocking phase, reasons, contradictions,
/// completion, assessment) of a run with the case's runner facts and contract.
fn observed(ev: &Evidence, x: &Expectation) -> serde_json::Value {
    let runner: Runner = serde_json::from_value(serde_json::json!({
        "termination": {"kind": "exited", "exit_code": x.exit_code.unwrap_or(0)},
        "started_at": "2026-01-01T00:00:00Z",
    }))
    .unwrap_or_else(|e| panic!("a fixed runner record parses: {e}"));
    let d = outcome::derive(&Input {
        evidence: Some(ev),
        runner: &runner,
        producer: None,
        has_build_requirement: false,
        // As ingestion decides it, so activation sees the outcome the server will derive.
        exit_code_meaningful: crate::packs::shipped::exit_code_meaningful(ev),
        expected: x.expected.as_ref(),
    });
    serde_json::to_value(d).unwrap_or_default()
}

fn failing(ev: &Evidence) -> BTreeMap<String, u64> {
    let mut m: BTreeMap<String, u64> = BTreeMap::new();
    for b in ev.buckets.iter().filter(|b| b.fails_run) {
        *m.entry(b.diag_id.clone()).or_default() += b.count.as_str().parse::<u64>().unwrap_or(0);
    }
    m
}

/// Per `diag_id`, every family's fingerprint with its buckets' classification (observed
/// and effective severity, framework, phase, kind, provenance, failing) and counts: a
/// change of identity, severity or classification is a difference, not only a change of
/// how many families there are.
fn families(ev: &Evidence) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut m: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for f in &ev.families {
        // The family's own identity facts (kind, checker scope, templates, significance).
        let identity = serde_json::to_string(&(
            &f.family_kind,
            &f.checker_scope,
            &f.identity_template,
            &f.significant,
            &f.display_template,
        ))
        .unwrap_or_default();
        m.entry(f.diag_id.clone())
            .or_default()
            .entry(f.fingerprint.as_str().to_string())
            .or_default()
            .push(identity);
    }
    for b in &ev.buckets {
        // Checker and site too: expected-outcome contracts select on them.
        let class = serde_json::to_string(&(
            (&b.checker_id, &b.site),
            &b.observed_severity,
            &b.effective_severity,
            &b.framework,
            &b.phase,
            &b.kind,
            &b.provenance,
            b.fails_run,
            b.count.as_str(),
        ))
        .unwrap_or_default();
        m.entry(b.diag_id.clone())
            .or_default()
            .entry(b.family.as_str().to_string())
            .or_default()
            .push(class);
    }
    for f in m.values_mut() {
        for v in f.values_mut() {
            v.sort();
        }
    }
    m
}

/// Overflow entries by category with their failing and total counts.
fn overflow(ev: &Evidence) -> BTreeMap<String, (u64, u64)> {
    let mut m: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for o in &ev.overflow {
        let key = serde_json::to_string(&(
            &o.framework,
            &o.phase,
            &o.kind,
            &o.observed_severity,
            &o.provenance,
        ))
        .unwrap_or_default();
        let n = o.count.as_str().parse::<u64>().unwrap_or(0);
        let e = m.entry(key).or_default();
        e.1 += n;
        if o.fails_run {
            e.0 += n;
        }
    }
    m
}

fn primary(ev: &Evidence) -> Option<String> {
    ev.events
        .iter()
        .max_by_key(|e| {
            (
                e.fails_run,
                e.observed_severity,
                std::cmp::Reverse(e.ordinal),
            )
        })
        .map(|e| e.diag_id.clone())
}

fn state_name(s: CompletionState) -> &'static str {
    match s {
        CompletionState::Complete => "complete",
        CompletionState::Incomplete => "incomplete",
        CompletionState::Missing => "missing",
    }
}

fn enum_name<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Compares evidence with an expectation; returns structural differences only.
#[must_use]
#[allow(clippy::too_many_lines)] // one check per expectation field, kept together
pub fn compare(ev: &Evidence, x: &Expectation) -> Vec<String> {
    let mut d = vec![];
    if let Some(want) = &x.completion {
        let got = state_name(ev.completion.state);
        if got != want {
            d.push(format!(
                "completion {got} {:?}, expected {want}",
                ev.completion.reasons
            ));
        }
    }
    if let Some(want) = &x.mode {
        let got = ev
            .completion
            .mode
            .as_ref()
            .map(enum_name)
            .unwrap_or_default();
        if &got != want {
            d.push(format!("completion mode {got:?}, expected {want}"));
        }
    }
    if let Some(want) = &x.design_loaded {
        let got = enum_name(&ev.design_loaded);
        if &got != want {
            d.push(format!("design_loaded {got}, expected {want}"));
        }
    }
    for (src, want) in &x.verdicts {
        let got: Vec<String> = ev
            .verdict_sources
            .iter()
            .filter(|v| &enum_name(&v.source) == src)
            .map(|v| enum_name(&v.value))
            .collect();
        if !got.iter().any(|g| g == want) {
            d.push(format!("verdict source {src}: {got:?}, expected {want}"));
        }
    }
    let failing = failing(ev);
    let overflow_failing: u64 = ev
        .overflow
        .iter()
        .filter(|o| o.fails_run)
        .map(|o| o.count.as_str().parse::<u64>().unwrap_or(0))
        .sum();
    if overflow_failing > 0 {
        d.push(format!("{overflow_failing} failing events in overflow"));
    }
    for (id, want) in &x.failures {
        let got = failing.get(id).copied().unwrap_or(0);
        if got != *want {
            d.push(format!("failing {id}: {got}, expected {want}"));
        }
    }
    if x.failures_exact || !x.exact_prefixes.is_empty() {
        for (id, n) in &failing {
            let in_scope =
                x.failures_exact || x.exact_prefixes.iter().any(|p| id.starts_with(p.as_str()));
            if in_scope && !x.failures.contains_key(id) {
                d.push(format!("unexpected failing {id}: {n}"));
            }
        }
    }
    for (id, want) in &x.families {
        let got = ev.families.iter().filter(|f| &f.diag_id == id).count() as u64;
        if got != *want {
            d.push(format!("families of {id}: {got}, expected {want}"));
        }
    }
    if let Some(want) = &x.primary {
        let got = primary(ev).unwrap_or_default();
        if &got != want {
            d.push(format!("primary {got:?}, expected {want}"));
        }
    }
    if let Some(max) = x.max_unclaimed {
        let got = ev
            .coverage
            .unclaimed_error_like_lines
            .as_str()
            .parse::<u64>()
            .unwrap_or(u64::MAX);
        if got > max {
            d.push(format!(
                "{got} unclaimed error-like lines, expected at most {max}"
            ));
        }
    }
    if let Some(want) = x.simulator_errors {
        let got: u64 = ev
            .buckets
            .iter()
            .filter(|b| {
                b.fails_run && matches!(b.framework, Framework::Simulator | Framework::Assertion)
            })
            .map(|b| b.count.as_str().parse::<u64>().unwrap_or(0))
            .sum();
        if got != want {
            d.push(format!("simulator errors {got}, expected {want}"));
        }
    }
    for file in &x.failure_anchored_in {
        let ok = ev.events.iter().filter(|e| e.fails_run).any(|e| {
            e.source_anchor.as_ref().is_some_and(|a| {
                a.path.replace('\\', "/").rsplit('/').next() == Some(file.as_str())
            })
        });
        if !ok {
            d.push(format!("no failing event anchored in {file}"));
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same failures under another family identity (another
    /// fingerprint, same counts) are a difference to declare.
    #[test]
    fn an_identity_change_is_a_difference() {
        let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
        let x: Expectation = serde_json::from_value(serde_json::json!({
            "format": "dviscope.expect/1", "simulator": "vcs"
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        let (old, _) = run(&p, &x, b"ERROR: serious\n");
        let mut new = old.clone();
        let other = Digest::of_bytes(b"another identity");
        for f in &mut new.families {
            f.fingerprint = other.clone();
        }
        for b in &mut new.buckets {
            b.family = other.clone();
        }
        assert_eq!(differences(&old, &old, &x), Vec::<String>::new());
        assert_eq!(differences(&old, &new, &x), ["families:display:error"]);
    }

    /// A failure lost from overflow, or another completion reason,
    /// is a difference.
    #[test]
    fn overflow_and_completion_reasons_are_differences() {
        let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
        let x: Expectation = serde_json::from_value(serde_json::json!({
            "format": "dviscope.expect/1", "simulator": "vcs"
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        let (mut old, _) = run(&p, &x, b"ERROR: serious\n");
        let new = old.clone();
        let mut entry: dviscope_model::wire::evidence::OverflowEntry = serde_json::from_value(
            serde_json::json!({"framework": "simulator", "phase": "run", "kind": "other",
                               "observed_severity": "error", "provenance": "authoritative",
                               "fails_run": true, "count": "1"}),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        old.overflow.push(entry.clone());
        assert_eq!(differences(&old, &new, &x), ["overflow"]);
        entry.fails_run = false;
        let mut quiet = new.clone();
        quiet.overflow.push(entry);
        old.overflow.clear();
        assert_eq!(differences(&old, &quiet, &x), ["overflow"]);
        let mut reasons = new.clone();
        reasons.completion.reasons.push(
            serde_json::from_value(serde_json::json!("no_end_marker"))
                .unwrap_or_else(|e| panic!("{e}")),
        );
        // A completion reason is part of the derived result too.
        assert_eq!(differences(&new, &reasons, &x), ["completion", "outcome"]);
    }

    /// Activation derives the outcome with the shipped simulator's exit
    /// policy, as ingestion does: a complete passing VCS run with exit 1 passes (its exit
    /// code means nothing), a customized pack's keeps the exit check. Structural evidence.
    #[test]
    fn activation_uses_the_shipped_exit_policy() {
        let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
        let mut ev = extract_bytes(&p, ExtractOptions::simulation("t.log"), b"").0;
        ev.completion = serde_json::from_value(serde_json::json!({
            "profile": "vcs-run", "state": "complete", "mode": "normal", "reasons": [],
            "sections_seen": [], "verdict_required": false
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        ev.source.bytes = dviscope_model::values::SafeU64::saturating(1);
        let x: Expectation = serde_json::from_value(serde_json::json!({
            "format": "dviscope.expect/1", "exit_code": 1
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(observed(&ev, &x)["outcome"], "pass");
        let mut custom = ev.clone();
        for r in &mut custom.packs {
            r.digest = Digest::of_bytes(b"customized");
        }
        assert_ne!(observed(&custom, &x)["outcome"], "pass");
    }

    /// F2 design review: another completion profile with the same state is a difference.
    #[test]
    fn a_profile_change_is_a_difference() {
        let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
        let x: Expectation = serde_json::from_value(serde_json::json!({
            "format": "dviscope.expect/1", "simulator": "vcs"
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        let (old, _) = run(
            &p,
            &x,
            b"ERROR: serious
",
        );
        let mut new = old.clone();
        new.completion.profile = "another-profile".into();
        assert_eq!(differences(&old, &new, &x), ["completion"]);
    }

    /// A removed verdict source, a severity change, and the derived
    /// result (contradictions, assessment) are differences.
    #[test]
    fn verdicts_severities_and_the_derived_result_are_compared() {
        let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
        let x: Expectation = serde_json::from_value(serde_json::json!({
            "format": "dviscope.expect/1", "simulator": "vcs"
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        let log = b"UVM_ERROR @ 5: top [X] bad\n--- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    1\nUVM_FATAL :    0\n$finish at simulation time 100\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n";
        let (old, _) = run(&p, &x, log);
        // A passing verdict source next to a failure is a contradiction; dropping it is
        // a difference (verdict sources and the derived result).
        let mut with_pass = old.clone();
        with_pass.verdict_sources.push(
            serde_json::from_value(serde_json::json!({"source": "banner", "value": "pass",
                "span": {"line_start": 1, "line_end": 1, "byte_start": 0, "byte_end": 1}}))
            .unwrap_or_else(|e| panic!("{e}")),
        );
        let d = differences(&with_pass, &old, &x);
        assert!(d.contains(&"verdict_sources".to_string()), "{d:?}");
        assert!(
            d.contains(&"outcome".to_string()),
            "the contradiction is gone: {d:?}"
        );
        // A severity change of the same failures.
        let mut demoted = old.clone();
        for b in &mut demoted.buckets {
            b.effective_severity = serde_json::from_value(serde_json::json!("warning"))
                .unwrap_or(b.effective_severity);
        }
        let d = differences(&old, &demoted, &x);
        assert!(d.iter().any(|a| a.starts_with("families:")), "{d:?}");
        // Another checker, or another site, of the same failures (r5 finding 1).
        let mut checker = old.clone();
        for b in &mut checker.buckets {
            b.checker_id = Some("wanted".into());
        }
        let d = differences(&old, &checker, &x);
        assert!(d.iter().any(|a| a.starts_with("families:")), "{d:?}");
        let mut site = old.clone();
        for b in &mut site.buckets {
            b.site = Some("other.sv:7".into());
        }
        let d = differences(&old, &site, &x);
        assert!(d.iter().any(|a| a.starts_with("families:")), "{d:?}");
    }

    /// Counters (value, explanation) and every other structural
    /// field are compared; presentation is not.
    #[test]
    fn every_structural_field_is_compared() {
        let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
        let x: Expectation = serde_json::from_value(serde_json::json!({
            "format": "dviscope.expect/1", "simulator": "vcs"
        }))
        .unwrap_or_else(|e| panic!("{e}"));
        let log = b"UVM_ERROR @ 5: top [X] bad\n--- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    1\nUVM_FATAL :    0\n$finish at simulation time 100\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n";
        let (old, _) = run(&p, &x, log);
        assert!(!old.counters.is_empty(), "the UVM summary has counters");
        let mut value = serde_json::to_value(&old).unwrap_or_default();
        value["counters"][0]["value"] = serde_json::json!("7");
        let changed: Evidence = serde_json::from_value(value).unwrap_or_else(|e| panic!("{e}"));
        assert!(differences(&old, &changed, &x).contains(&"counters".to_string()));
        let mut value = serde_json::to_value(&old).unwrap_or_default();
        value["counters"][0]["explained_by"] = serde_json::json!("toy:other");
        let explained: Evidence =
            serde_json::from_value(value).unwrap_or_else(|e| panic!("explained_by: {e}"));
        assert_ne!(explained.counters, old.counters, "the explanation changed");
        assert!(differences(&old, &explained, &x).contains(&"counters".to_string()));
        // Presentation only: no difference.
        let mut shown = old.clone();
        for e in &mut shown.events {
            e.message_raw = "reworded".into();
        }
        assert_eq!(differences(&old, &shown, &x), Vec::<String>::new());
        // Another family template.
        let mut tpl = old.clone();
        for f in &mut tpl.families {
            f.identity_template = "another <template>".into();
        }
        assert!(
            differences(&old, &tpl, &x)
                .iter()
                .any(|a| a.starts_with("families:"))
        );
    }
}
