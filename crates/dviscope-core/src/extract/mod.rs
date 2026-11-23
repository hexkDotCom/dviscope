//! Streaming extraction: `Extractor::new(&pipeline, options)`,
//! `push(&[u8])`, `finish() -> Evidence`. No I/O: the caller reads the log.
//!
//! Stages per line: decode → detection (buffered) → framing → protected pre-pass
//! (annotations only) → record assembly → classification → suppression → fields →
//! significance → normalization → identity → accounting and sampling → completion.

pub mod decode;
pub mod protect;
pub(crate) mod sampling;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use dviscope_model::canonical::{Digest, StreamDigest};
use dviscope_model::limits::{MAX_FIELD_BYTES, MAX_MESSAGE_BYTES, MAX_RECORD_ASSEMBLY_BYTES};
use dviscope_model::schema::EVIDENCE;
use dviscope_model::values::{DecimalInteger, SafeU64};
use dviscope_model::wire::evidence::{
    Completion, CompletionMode, CompletionReason, CompletionState, Counter, Coverage, DesignLoaded,
    Encoding, Event, EventProvenance, Evidence, Extractor as ExtractorId, FieldValue, LineEnding,
    LogResources, LogSegment, LogSegmentName, PackRef, Phase, Provenance, ReconcileRelation,
    Reconciliation, Source, Span, Suppressed, VerdictSource, VerdictSourceKind, VerdictValue,
};
use dviscope_model::wire::manifest::Severity;
use regex::Regex;
use serde::Serialize;

use crate::classify::{self, FamilyKey, normalize};
use crate::packs::{
    CRecord, EXTRACTOR_NAME, EXTRACTOR_VERSION, MODEL_MAIN_PROFILE, Pipeline, Tier, VerdictWord,
    domain_name, schema::ProfileSelect,
};
use decode::{Line, Splitter, truncate_utf8};
use sampling::{Accounting, Classified, ExcerptState, XLine};

/// Lines buffered while the simulator is not yet detected.
pub const DETECTION_MAX_LINES: usize = 2_000;
/// Bytes buffered while the simulator is not yet detected.
pub const DETECTION_MAX_BYTES: usize = 1024 * 1024;
/// Spans kept per suppression rule and for coverage examples.
pub const MAX_SPANS: usize = 5;
/// Version of the error-like heuristic.
pub const ERROR_LIKE_VERSION: &str = "error-like/1";

/// What the log is evidence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Subject {
    /// A build (compile/elaborate) log.
    Build,
    /// A simulation run log.
    Simulation,
}

/// Extraction options.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Evidence subject.
    pub subject: Subject,
    /// The simulator the run declares (`questa`, `vcs`, `verilator`); `None` detects it.
    pub simulator: Option<String>,
    /// Log file name (no directories).
    pub log_name: String,
    /// Path prefixes that make source anchors repository-relative.
    pub source_roots: Vec<String>,
    /// Keep a record trace (self-tests, `rules explain`); bounded to [`MAX_TRACE`].
    pub trace: bool,
    /// The run declares a Verilator model with its own C++ main (its slot's
    /// `extra.tool.main = "model"`): the Verilator pack is selected from the first line, the
    /// log is the program log then the console ([`Extractor::begin_console`]) and completion
    /// uses the declared profile `verilator-model-main`.
    pub model_main: bool,
}

/// Fingerprints cached per extraction.
const FINGERPRINT_CACHE: usize = 4_096;

/// Distinct counters kept (beyond: accounting overflow).
pub const MAX_COUNTERS: usize = 1_024;
/// Verdict sources kept (beyond: accounting overflow).
pub const MAX_VERDICTS: usize = 64;

/// Trace entries kept at most.
pub const MAX_TRACE: usize = 100_000;

/// Line positions kept per marker (beyond, only the count).
const MAX_MARKER_POSITIONS: usize = 8;

/// Occurrences of one marker: how many, and where (segment index, line).
#[derive(Debug, Default)]
struct Occurrences {
    count: u64,
    at: Vec<(usize, u64)>,
}

/// Where a marker appeared (`rules explain` of a model with its own main).
#[derive(Debug, Clone, Serialize)]
pub struct MarkerOccurrence {
    /// `pack/marker`.
    pub marker: String,
    /// Times seen.
    pub count: u64,
    /// First positions: segment and line.
    pub at: Vec<(Option<LogSegmentName>, u64)>,
}

/// One stream of a joined log while it is read.
#[derive(Debug)]
struct SegmentAcc {
    name: LogSegmentName,
    byte_start: u64,
    first_line: Option<u64>,
    last_line: Option<u64>,
}

impl ExtractOptions {
    /// Options for a simulation log.
    #[must_use]
    pub fn simulation(log_name: &str) -> Self {
        Self {
            subject: Subject::Simulation,
            simulator: None,
            log_name: log_name.to_string(),
            source_roots: vec![],
            trace: false,
            model_main: false,
        }
    }
}

/// One assembled record, for self-tests and `rules explain`.
#[derive(Debug, Clone, Serialize)]
pub struct TraceRecord {
    /// `pack/rule@version`.
    pub rule: String,
    /// First line.
    pub start_line: u64,
    /// Last line.
    pub end_line: u64,
    /// Whether the record was cut.
    pub cut: bool,
    /// Captures.
    pub captures: BTreeMap<String, String>,
    /// Emitted diagnostic ID (none for ignore rules).
    pub diag_id: Option<String>,
    /// Observed severity.
    pub severity: Option<Severity>,
    /// Provenance.
    pub provenance: Option<Provenance>,
    /// Fingerprint.
    pub fingerprint: Option<Digest>,
    /// Identity template.
    pub identity_template: Option<String>,
    /// Suppression applied.
    pub suppressed_by: Option<String>,
}

/// Pre-pass annotation of one line.
#[derive(Debug, Clone, Default)]
struct Ann {
    authoritative: Option<Severity>,
    /// A marker, verdict or counter matched: an implicit boundary.
    summary: bool,
    /// The pre-pass claimed the line (marker, verdict source or counter): no rule may
    /// start a record on it.
    protected: bool,
}

#[derive(Debug)]
struct Open {
    rule: usize,
    start: Line,
    end_line: u64,
    end_byte: u64,
    caps: BTreeMap<String, String>,
    mand_next: usize,
    consumed: u32,
    used_once: Vec<bool>,
    auth: Option<Severity>,
    cut: bool,
    line_cut: bool,
    bytes: usize,
    lines: Option<Vec<XLine>>,
    before: Option<Vec<XLine>>,
    failure_like: bool,
}

#[derive(Debug, Default)]
struct SectionState {
    opened: bool,
    remaining: BTreeSet<String>,
    complete: bool,
}

#[derive(Debug)]
struct SuppressionAcc {
    id: String,
    version: String,
    observed: Severity,
    count: u64,
    spans: Vec<Span>,
}

fn span(line: &Line) -> Span {
    Span {
        line_start: SafeU64::saturating(line.no),
        line_end: SafeU64::saturating(line.no),
        byte_start: SafeU64::saturating(line.start),
        byte_end: SafeU64::saturating(line.end),
    }
}

fn error_like() -> Option<&'static Regex> {
    static R: std::sync::OnceLock<Option<Regex>> = std::sync::OnceLock::new();
    // error-like/1: an error or fatal word where a message starts (after optional white
    // space, punctuation, a bracketed tag or `**`), or an upper-case ERROR, FATAL, FAILED or
    // FAILURE word anywhere.
    R.get_or_init(|| {
        Regex::new(
            r"(?i:^[\s\W]*(?:\[[^\]]*\]\s*)?(?:\*\*\s*)?(?:error|fatal)\b)|\b(?:ERROR|FATAL|FAILED|FAILURE)\b",
        )
        .ok()
    })
    .as_ref()
}

/// The streaming extractor.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // independent flags of one streaming pass
pub struct Extractor<'p> {
    p: &'p Pipeline,
    opts: ExtractOptions,
    splitter: Splitter,
    hasher: StreamDigest,
    detecting: bool,
    pending: Vec<Line>,
    pending_bytes: usize,
    sim_pack: Option<usize>,
    framing: Option<String>,
    active: Vec<bool>,
    detected: Vec<bool>,
    open: Option<Open>,
    // pre-pass state
    design_loaded: DesignLoaded,
    markers_seen: BTreeSet<String>,
    sequence: Vec<String>,
    counters: Vec<Counter>,
    verdicts: Vec<VerdictSource>,
    sections: BTreeMap<(usize, String), SectionState>,
    fatal_witness: bool,
    // classification state
    ordinal: u64,
    tally: std::collections::HashMap<(dviscope_model::wire::evidence::Framework, Severity), u64>,
    acc: Accounting,
    suppressed: Vec<SuppressionAcc>,
    failure_cut: bool,
    failure_line_cut: bool,
    excerpt: ExcerptState,
    unclaimed: u64,
    unclaimed_spans: Vec<Span>,
    trace: Vec<TraceRecord>,
    record_cuts: u64,
    fp_cache: std::collections::HashMap<String, Digest>,
    repeated_summary: bool,
    summary_cut: bool,
    invalid_summary: bool,
    summary_overflow: bool,
    // model main: marker occurrences and the joined streams
    occurrences: BTreeMap<String, Occurrences>,
    segments: Vec<SegmentAcc>,
}

impl<'p> Extractor<'p> {
    /// A new extractor over a compiled pipeline.
    #[must_use]
    pub fn new(p: &'p Pipeline, opts: ExtractOptions) -> Self {
        let n = p.packs.len();
        let mut x = Self {
            p,
            splitter: Splitter::new(),
            hasher: StreamDigest::new(),
            detecting: true,
            pending: vec![],
            pending_bytes: 0,
            sim_pack: None,
            framing: None,
            active: vec![false; n],
            detected: vec![false; n],
            open: None,
            design_loaded: DesignLoaded::Unknown,
            markers_seen: BTreeSet::new(),
            sequence: vec![],
            counters: vec![],
            verdicts: vec![],
            sections: BTreeMap::new(),
            fatal_witness: false,
            ordinal: 0,
            tally: std::collections::HashMap::new(),
            acc: Accounting::default(),
            suppressed: vec![],
            failure_cut: false,
            failure_line_cut: false,
            excerpt: ExcerptState::default(),
            unclaimed: 0,
            unclaimed_spans: vec![],
            trace: vec![],
            record_cuts: 0,
            fp_cache: std::collections::HashMap::new(),
            repeated_summary: false,
            summary_cut: false,
            invalid_summary: false,
            summary_overflow: false,
            occurrences: BTreeMap::new(),
            segments: vec![],
            opts,
        };
        if x.opts.model_main {
            // Declared before any line is read: never left to detection.
            x.segments.push(SegmentAcc {
                name: LogSegmentName::Program,
                byte_start: 0,
                first_line: None,
                last_line: None,
            });
            let sim = x
                .opts
                .simulator
                .clone()
                .unwrap_or_else(|| "verilator".into());
            let idx = p
                .packs
                .iter()
                .position(|pk| pk.tier == Tier::Simulator && pk.simulator.as_deref() == Some(&sim));
            x.select(idx);
        } else if let Some(sim) = x.opts.simulator.clone() {
            let idx = p
                .packs
                .iter()
                .position(|pk| pk.tier == Tier::Simulator && pk.simulator.as_deref() == Some(&sim));
            x.select(idx);
        }
        x
    }

    fn select(&mut self, sim: Option<usize>) {
        self.detecting = false;
        self.sim_pack = sim;
        for (i, pk) in self.p.packs.iter().enumerate() {
            self.active[i] = pk.tier != Tier::Simulator || Some(i) == sim;
        }
        if let Some(i) = sim {
            self.detected[i] = true;
            self.framing.clone_from(&self.p.packs[i].framing);
        }
    }

    /// Feeds bytes (any chunking gives the same evidence).
    pub fn push(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        let mut splitter = std::mem::take(&mut self.splitter);
        splitter.push(bytes, &mut |l| self.line(l));
        self.splitter = splitter;
    }

    /// Model main: the program log is done; the next bytes are the console capture. The
    /// boundary ends the current line and closes any open record as the end of the file
    /// does (no record spans the two streams). Called once; ignored otherwise.
    pub fn begin_console(&mut self) {
        if !self.opts.model_main || self.segments.len() != 1 {
            return;
        }
        let mut splitter = std::mem::take(&mut self.splitter);
        splitter.boundary(&mut |l| self.line(l));
        self.splitter = splitter;
        self.close_at_end();
        self.segments.push(SegmentAcc {
            name: LogSegmentName::Console,
            byte_start: self.splitter.bytes(),
            first_line: None,
            last_line: None,
        });
    }

    /// Model main: every marker seen so far, with its count and first positions (segment
    /// and line), for `rules explain`.
    #[must_use]
    pub fn marker_occurrences(&self) -> Vec<MarkerOccurrence> {
        self.occurrences
            .iter()
            .map(|(id, o)| MarkerOccurrence {
                marker: id.clone(),
                count: o.count,
                at: o
                    .at
                    .iter()
                    .map(|(seg, line)| (self.segments.get(*seg).map(|s| s.name), *line))
                    .collect(),
            })
            .collect()
    }

    /// The end of a stream closes the open record; a missing mandatory line is a cut.
    fn close_at_end(&mut self) {
        if self.open.is_some() {
            let cut = self.open.as_ref().is_some_and(|o| {
                self.p.records[o.rule]
                    .lines
                    .iter()
                    .skip(o.mand_next)
                    .any(|m| m.mandatory)
            });
            self.close(cut);
        }
    }

    fn line(&mut self, l: Line) {
        if self.detecting {
            if let Some(i) = self.detect(&l.text) {
                self.select(Some(i));
                self.flush_pending();
                self.process(&l);
                return;
            }
            self.pending_bytes += l.text.len();
            self.pending.push(l);
            if self.pending.len() >= DETECTION_MAX_LINES
                || self.pending_bytes >= DETECTION_MAX_BYTES
            {
                self.select(None);
                self.flush_pending();
            }
            return;
        }
        self.process(&l);
    }

    fn flush_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        for l in &pending {
            self.process(l);
        }
    }

    fn detect(&self, text: &str) -> Option<usize> {
        self.p.packs.iter().position(|pk| {
            pk.tier == Tier::Simulator && {
                let framed = pk.framing.as_deref().and_then(|f| text.strip_prefix(f));
                pk.detect
                    .iter()
                    .any(|r| r.is_match(text) || framed.is_some_and(|t| r.is_match(t)))
            }
        })
    }

    fn framed<'a>(&self, text: &'a str) -> &'a str {
        match self.framing.as_deref() {
            Some(f) => text.strip_prefix(f).unwrap_or(text),
            None => text,
        }
    }

    fn process(&mut self, l: &Line) {
        // A cut line may be a summary whose cut text no longer matches its pattern: every
        // cut line makes the log incomplete (conservative, docs/packs.md).
        if l.cut {
            self.summary_cut = true;
        }
        if let Some(sg) = self.segments.last_mut() {
            sg.first_line.get_or_insert(l.no);
            sg.last_line = Some(l.no);
        }
        let framed = self.framed(&l.text);
        for (i, pk) in self.p.packs.iter().enumerate() {
            if self.active[i] && !self.detected[i] && pk.detect.iter().any(|r| r.is_match(framed)) {
                self.detected[i] = true;
            }
        }
        let ann = self.prepass(l, framed);
        self.excerpt.push(l.no, &l.text);
        self.feed(l, framed, &ann);
    }

    // ---- protected pre-pass ------------------------------------------------------------

    #[allow(clippy::too_many_lines)] // markers, verdicts and counters, in declaration order
    fn prepass(&mut self, l: &Line, framed: &str) -> Ann {
        let mut ann = Ann {
            authoritative: protect::authoritative(framed),
            summary: false,
            protected: false,
        };
        let p = self.p;
        let hits = p.summary_set.matches(framed);
        if !hits.matched_any() {
            return ann;
        }
        let (n_markers, n_verdicts) = (p.markers.len(), p.verdicts.len());
        let packs_active = self.active.clone();
        let active = |pack: usize, i: usize| packs_active[pack] && hits.matched(i);
        // A counter restricted to a section counts only while that section is open; an
        // ineligible counter neither claims the line nor ends a record.
        let sections = &self.sections;
        // Sections opened by a marker on this very line count as open.
        let opened_here: BTreeSet<(usize, &str)> = p
            .markers
            .iter()
            .enumerate()
            .filter(|(i, m)| active(m.pack, *i))
            .flat_map(|(_, m)| {
                p.packs[m.pack]
                    .sections
                    .iter()
                    .filter(move |sec| sec.open == m.id)
                    .map(move |sec| (m.pack, sec.id.as_str()))
            })
            .collect();
        let counter_eligible: Vec<bool> = p
            .counters
            .iter()
            .enumerate()
            .map(|(i, k)| {
                active(k.pack, n_markers + n_verdicts + i)
                    && k.within.as_ref().is_none_or(|w| {
                        opened_here.contains(&(k.pack, w.as_str()))
                            || sections.get(&(k.pack, w.clone())).is_some_and(|s| s.opened)
                    })
            })
            .collect();
        let any_active = p.markers.iter().enumerate().any(|(i, m)| active(m.pack, i))
            || p.verdicts
                .iter()
                .enumerate()
                .any(|(i, v)| active(v.pack, n_markers + i))
            || counter_eligible.iter().any(|e| *e);
        if !any_active {
            return ann;
        }
        // A summary line cut at the line limit is never read as evidence: its numbers or
        // words may be truncated.
        ann.summary = true;
        ann.protected = true;
        if l.cut {
            self.summary_cut = true;
            return ann;
        }
        for (i, m) in p.markers.iter().enumerate() {
            if !active(m.pack, i) {
                continue;
            }
            match m.design_loaded {
                Some(false) => self.design_loaded = DesignLoaded::False,
                Some(true) if self.design_loaded == DesignLoaded::Unknown => {
                    self.design_loaded = DesignLoaded::True;
                }
                _ => {}
            }
            self.fatal_witness |= m.fatal_witness;
            let pack_id = &p.packs[m.pack].id;
            if self.opts.model_main {
                let seg = self.segments.len().saturating_sub(1);
                let o = self
                    .occurrences
                    .entry(format!("{pack_id}/{}", m.id))
                    .or_default();
                o.count += 1;
                if o.at.len() < MAX_MARKER_POSITIONS {
                    o.at.push((seg, l.no));
                }
            }
            self.seen(&format!("{pack_id}/{}", m.id));
            for sec in &p.packs[m.pack].sections {
                if sec.open == m.id {
                    let st = self.sections.entry((m.pack, sec.id.clone())).or_default();
                    if st.opened {
                        // One log = one report population: a second summary means
                        // concatenated executions.
                        self.repeated_summary = true;
                    } else {
                        st.opened = true;
                        st.remaining = sec
                            .requires
                            .iter()
                            .map(|r| format!("{pack_id}/{r}"))
                            .collect();
                    }
                }
            }
            self.section_progress(&format!("{pack_id}/{}", m.id));
        }
        for (i, v) in p.verdicts.iter().enumerate() {
            if !active(v.pack, n_markers + i) {
                continue;
            }
            let Some(c) = v.re.captures(framed) else {
                continue;
            };
            let caps = cap_map(&v.re, &c);
            let value = match v.value.resolve(&caps) {
                Some(VerdictWord::Pass) => VerdictValue::Pass,
                Some(VerdictWord::Fail) | None => VerdictValue::Fail,
                Some(VerdictWord::NotApplicable) => VerdictValue::NotApplicable,
            };
            self.push_verdict(VerdictSource {
                source: v.source,
                value,
                span: Some(span(l)),
            });
        }
        for (i, k) in p.counters.iter().enumerate() {
            if !counter_eligible[i] {
                continue;
            }
            let Some(c) = k.re.captures(framed) else {
                continue;
            };
            let caps = cap_map(&k.re, &c);
            // Every value must be present and exact before the line counts as a witness.
            let mut values = vec![];
            for v in &k.values {
                let mut missing = vec![];
                let key = v.key.render(&caps, &mut missing);
                let explained_by = v
                    .explained_by
                    .as_ref()
                    .map(|t| t.render(&caps, &mut missing));
                let value = caps
                    .get(&v.from)
                    .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
                    .map(|d| d.trim_start_matches('0'))
                    .map(|d| if d.is_empty() { "0" } else { d })
                    .and_then(|d| DecimalInteger::try_from(d).ok());
                let declared = v.keys.as_ref().is_none_or(|ks| ks.contains(&key));
                // A role the map does not resolve (and no default) is unresolved
                // classification: invalid summary evidence, never a silent `info`.
                let role = v.role.resolve(&caps);
                match (value, role, missing.is_empty() && declared) {
                    (Some(value), Some(role), true) => {
                        values.push((key, value, role, explained_by));
                    }
                    _ => self.invalid_summary = true,
                }
            }
            if values.len() != k.values.len() {
                continue;
            }
            let pack_id = &p.packs[k.pack].id;
            self.seen(&format!("{pack_id}/{}", k.id));
            for (key, value, role, explained_by) in values {
                let reference = format!("{pack_id}/{}:{key}", domain_name(k.domain));
                self.push_counter(Counter {
                    domain: k.domain,
                    key,
                    value,
                    role,
                    protected: k.protected,
                    explained_by,
                    span: span(l),
                });
                self.section_progress(&reference);
            }
        }
        ann
    }

    /// Counters are one report population: a key seen twice is a repeated population
    /// (count mismatch, the last value kept); at most [`MAX_COUNTERS`] distinct keys.
    fn push_counter(&mut self, c: Counter) {
        if let Some(old) = self
            .counters
            .iter_mut()
            .find(|o| o.domain == c.domain && o.key == c.key)
        {
            self.repeated_summary = true;
            *old = c;
        } else if self.counters.len() < MAX_COUNTERS {
            self.counters.push(c);
        } else {
            self.summary_overflow = true;
        }
    }

    fn push_verdict(&mut self, v: VerdictSource) {
        if self.verdicts.len() < MAX_VERDICTS {
            self.verdicts.push(v);
        } else {
            self.summary_overflow = true;
        }
    }

    fn seen(&mut self, id: &str) {
        if self.markers_seen.insert(id.to_string()) {
            self.sequence.push(id.to_string());
        }
    }

    fn section_progress(&mut self, item: &str) {
        let mut done = vec![];
        for ((pack, id), st) in &mut self.sections {
            if st.opened && !st.complete && st.remaining.remove(item) && st.remaining.is_empty() {
                st.complete = true;
                done.push((*pack, id.clone()));
            }
        }
        for (pack, id) in done {
            let pack_id = &self.p.packs[pack].id;
            self.seen(&format!("{pack_id}/{id}"));
            let Some(sec) = self.p.packs[pack].sections.iter().find(|s| s.id == id) else {
                continue;
            };
            if let Some(v) = &sec.verdict {
                let stored: Vec<Option<&Counter>> = v
                    .fail_if_nonzero
                    .iter()
                    .map(|r| {
                        self.counters
                            .iter()
                            .find(|c| format!("{}:{}", domain_name(c.domain), c.key) == *r)
                    })
                    .collect();
                if stored.iter().any(Option::is_none) {
                    // The section completed without a count its verdict reads: never a
                    // pass from an absent count (the evidence is incomplete instead).
                    self.invalid_summary = true;
                    continue;
                }
                let fail = stored.iter().flatten().any(|c| c.value.as_str() != "0");
                self.push_verdict(VerdictSource {
                    source: VerdictSourceKind::UvmSummary,
                    value: if fail {
                        VerdictValue::Fail
                    } else {
                        VerdictValue::Pass
                    },
                    span: None,
                });
            }
        }
    }

    // ---- record assembly ---------------------------------------------------------------

    fn is_boundary(&self, framed: &str, ann: &Ann) -> bool {
        ann.summary
            || ann.authoritative.is_some()
            || self.p.packs.iter().enumerate().any(|(i, pk)| {
                self.active[i] && pk.boundaries.as_ref().is_some_and(|b| b.is_match(framed))
            })
    }

    /// Whether some rule of a tier ≤ `max_tier` starts a record on this line.
    fn starts_record(&self, framed: &str, max_tier: Tier) -> bool {
        self.p.records.iter().any(|r| {
            r.tier <= max_tier
                && self.active[r.pack]
                && r.prefixes
                    .as_ref()
                    .is_none_or(|px| px.iter().any(|p| framed.starts_with(p.as_str())))
                && r.start.is_match(framed)
        })
    }

    /// The first rule (precedence order) whose start matches, among tiers ≤ `max_tier`.
    fn match_start(
        &self,
        framed: &str,
        max_tier: Tier,
    ) -> Option<(usize, BTreeMap<String, String>)> {
        for (i, r) in self.p.records.iter().enumerate() {
            if r.tier > max_tier || !self.active[r.pack] {
                continue;
            }
            if let Some(px) = &r.prefixes
                && !px.iter().any(|p| framed.starts_with(p.as_str()))
            {
                continue;
            }
            if let Some(c) = r.start.captures(framed) {
                return Some((i, cap_map(&r.start, &c)));
            }
        }
        None
    }

    fn feed(&mut self, l: &Line, framed: &str, ann: &Ann) {
        // At most two passes: an open record either consumes the line or closes and the
        // line is offered again with no record open.
        for _ in 0..2 {
            if self.open.is_some() {
                match self.offer(l, framed, ann) {
                    Offer::Consumed => return,
                    Offer::Close { cut } => self.close(cut),
                }
            }
            if self.open.is_none() {
                self.start_or_unclaimed(l, framed, ann);
                return;
            }
        }
    }

    fn start_or_unclaimed(&mut self, l: &Line, framed: &str, ann: &Ann) {
        if ann.protected {
            if let Some(sev) = ann.authoritative {
                self.emit_fallback(l, framed, sev);
            }
            return;
        }
        if let Some((rule, caps)) = self.match_start(framed, Tier::Generic) {
            let r = &self.p.records[rule];
            let provisional = r.emit.as_ref().and_then(|e| e.severity.resolve(&caps));
            let failure_like = ann.authoritative.is_some_and(|s| s >= Severity::Warning)
                || provisional.is_some_and(|s| s >= Severity::Warning);
            // Snapshot the excerpt context only for a record that could become primary.
            let could_be_primary = {
                let sev = provisional.max(ann.authoritative).unwrap_or(Severity::Info);
                match &self.acc.primary {
                    None => sev >= Severity::Warning,
                    Some((_, p)) => {
                        sampling::sev_rank(sev) > sampling::sev_rank(p.observed_severity)
                    }
                }
            };
            let (lines, before) = if could_be_primary {
                (
                    Some(vec![(l.no, l.text.clone())]),
                    Some(self.excerpt.snapshot_before(l.no)),
                )
            } else {
                (None, None)
            };
            let n_lines = r.lines.len();
            let has_cont = r.max_lines > 0;
            self.open = Some(Open {
                rule,
                start: l.clone(),
                end_line: l.no,
                end_byte: l.end,
                caps,
                mand_next: 0,
                consumed: 0,
                used_once: vec![false; n_lines],
                auth: ann.authoritative,
                cut: false,
                line_cut: l.cut,
                bytes: l.text.len(),
                lines,
                before,
                failure_like,
            });
            if !has_cont {
                self.close(false);
            }
            return;
        }
        // Unclaimed line. An authoritative start nobody claimed still counts as a failure.
        if let Some(sev) = ann.authoritative {
            self.emit_fallback(l, framed, sev);
            return;
        }
        if !ann.summary {
            self.count_unclaimed(l, framed);
        }
    }

    fn count_unclaimed(&mut self, l: &Line, framed: &str) {
        if error_like().is_some_and(|r| r.is_match(framed)) {
            self.unclaimed += 1;
            if self.unclaimed_spans.len() < MAX_SPANS {
                self.unclaimed_spans.push(span(l));
            }
        }
    }

    fn offer(&mut self, line: &Line, framed: &str, ann: &Ann) -> Offer {
        let boundary = self.is_boundary(framed, ann);
        let Some(open) = self.open.as_ref() else {
            return Offer::Close { cut: false };
        };
        let rule: &CRecord = &self.p.records[open.rule];
        if open.bytes + framed.len() > MAX_RECORD_ASSEMBLY_BYTES {
            return Offer::Close { cut: true };
        }
        let mandatory_left = rule.lines.iter().skip(open.mand_next).any(|m| m.mandatory);
        if mandatory_left {
            if boundary {
                return Offer::Close { cut: true };
            }
            let matcher = &rule.lines[open.mand_next];
            let Some(found) = matcher.re.captures(framed) else {
                return Offer::Close { cut: true };
            };
            let caps = cap_map(&matcher.re, &found);
            let idx = open.mand_next;
            self.consume(line, framed, idx, &caps);
            if let Some(open) = self.open.as_mut() {
                open.mand_next += 1;
            }
            return Offer::Consumed;
        }
        let blank = framed.trim().is_empty();
        let stops =
            boundary || (rule.until_blank && blank) || self.starts_record(framed, rule.tier);
        if open.consumed >= rule.max_lines {
            // One-line lookahead: a further continuation line means the record was cut.
            let more = !stops && self.continuation_match(framed).is_some();
            return Offer::Close { cut: more };
        }
        if stops {
            return Offer::Close { cut: false };
        }
        match self.continuation_match(framed) {
            Some((idx, caps)) => {
                self.consume(line, framed, idx, &caps);
                Offer::Consumed
            }
            None => Offer::Close { cut: false },
        }
    }

    fn continuation_match(&self, framed: &str) -> Option<(usize, BTreeMap<String, String>)> {
        let o = self.open.as_ref()?;
        let r = &self.p.records[o.rule];
        r.lines.iter().enumerate().find_map(|(i, m)| {
            if m.mandatory || (m.once && o.used_once[i]) {
                return None;
            }
            m.re.captures(framed).map(|c| (i, cap_map(&m.re, &c)))
        })
    }

    fn consume(&mut self, l: &Line, framed: &str, idx: usize, caps: &BTreeMap<String, String>) {
        let p = self.p;
        let Some(o) = self.open.as_mut() else {
            return;
        };
        let m = &p.records[o.rule].lines[idx];
        if m.capture {
            for (k, v) in caps {
                o.caps.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        if let Some(field) = &m.append_to {
            let text = caps.get("text").map_or(framed, String::as_str);
            let entry = o.caps.entry(field.clone()).or_default();
            if entry.len() < MAX_FIELD_BYTES {
                if !entry.is_empty() {
                    entry.push('\n');
                }
                entry.push_str(text);
            }
        }
        if m.once {
            o.used_once[idx] = true;
        }
        o.consumed += 1;
        o.end_line = l.no;
        o.end_byte = l.end;
        o.bytes += framed.len();
        o.line_cut |= l.cut;
        if let Some(lines) = o.lines.as_mut()
            && lines.len() < sampling::EXCERPT_PRIMARY
        {
            lines.push((l.no, l.text.clone()));
        }
        let failure_like = o.failure_like;
        if !failure_like {
            self.count_unclaimed(l, framed);
        }
    }

    fn close(&mut self, cut: bool) {
        let Some(mut o) = self.open.take() else {
            return;
        };
        o.cut = cut;
        if cut {
            self.record_cuts += 1;
        }
        self.classify(o);
    }

    // ---- classification ----------------------------------------------------------------

    fn emit_fallback(&mut self, l: &Line, framed: &str, sev: Severity) {
        let mut caps = BTreeMap::new();
        caps.insert("msg".to_string(), framed.to_string());
        let o = Open {
            rule: usize::MAX,
            start: l.clone(),
            end_line: l.no,
            end_byte: l.end,
            caps,
            mand_next: 0,
            consumed: 0,
            used_once: vec![],
            auth: Some(sev),
            cut: false,
            line_cut: l.cut,
            bytes: l.text.len(),
            lines: Some(vec![(l.no, l.text.clone())]),
            before: Some(self.excerpt.snapshot_before(l.no)),
            failure_like: true,
        };
        self.classify(o);
    }

    #[allow(clippy::too_many_lines)] // the B.9.5 sequence, step by step
    fn classify(&mut self, o: Open) {
        let p = self.p;
        let rule = p.records.get(o.rule);
        let emit = rule.and_then(|r| r.emit.as_ref());
        let qualified = rule.map_or_else(
            || "dviscope/unclaimed_authoritative@1.0.0".to_string(),
            |r| r.qualified.clone(),
        );
        // Info-level records only count toward the reconciliation tallies: no bucket, no
        // event, no rendering (unless a trace is requested).
        if let (Some(e), false) = (emit, self.opts.trace) {
            let sev = e.severity.resolve(&o.caps).unwrap_or(Severity::Error);
            let observed = o.auth.map_or(sev, |a| a.max(sev));
            if observed < Severity::Warning {
                self.ordinal += 1;
                *self.tally.entry((e.framework, observed)).or_default() += 1;
                return;
            }
        }
        let mut trace = TraceRecord {
            rule: qualified.clone(),
            start_line: o.start.no,
            end_line: o.end_line,
            cut: o.cut,
            captures: if self.opts.trace {
                o.caps.clone()
            } else {
                BTreeMap::new()
            },
            diag_id: None,
            severity: None,
            provenance: None,
            fingerprint: None,
            identity_template: None,
            suppressed_by: None,
        };
        // A rule without emit claims and drops its record, except an authoritative start:
        // that still yields a failure (the fallback event).
        if emit.is_none() && o.auth.is_none_or(|s| s < Severity::Error) {
            self.push_trace(trace);
            return;
        }
        let caps = &o.caps;
        let mut missing = vec![];
        let mut id_missing = vec![];
        let render =
            |t: &crate::packs::Template, missing: &mut Vec<String>| t.render(caps, missing);
        let (framework, rule_sev, diag_id, checker_id, checker_scope, kind, phase, family_kind) =
            match emit {
                Some(e) => (
                    e.framework,
                    e.severity.resolve(caps).unwrap_or(Severity::Error),
                    render(&e.diag_id, &mut id_missing),
                    e.checker_id
                        .as_ref()
                        .map(|t| render(t, &mut id_missing))
                        .filter(|s| !s.is_empty()),
                    e.checker_scope
                        .as_ref()
                        .map(|t| render(t, &mut id_missing))
                        .filter(|s| !s.is_empty()),
                    e.kind
                        .resolve(caps)
                        .unwrap_or(dviscope_model::wire::evidence::DiagKind::Other),
                    e.phase.as_ref().and_then(|ph| ph.resolve(caps)),
                    e.family.clone(),
                ),
                None => (
                    dviscope_model::wire::evidence::Framework::Simulator,
                    Severity::Error,
                    "dviscope:unclaimed_authoritative".to_string(),
                    None,
                    None,
                    dviscope_model::wire::evidence::DiagKind::Other,
                    None,
                    "tool".to_string(),
                ),
            };
        // An identifier cut at the render bound could equal another one (and match a
        // suppression meant for it): accounting is then inexact, the log incomplete, never a
        // pass.
        if id_missing
            .iter()
            .any(|m| m == crate::packs::RENDER_OVERFLOW)
        {
            self.summary_overflow = true;
        }
        missing.extend(id_missing);
        let observed = o.auth.map_or(rule_sev, |a| a.max(rule_sev));
        let provenance = if o.auth.is_some() {
            Provenance::Authoritative
        } else {
            Provenance::Rule
        };
        self.ordinal += 1;
        *self.tally.entry((framework, observed)).or_default() += 1;
        let message_raw = match emit {
            Some(e) => render(&e.message, &mut missing),
            None => caps.get("msg").cloned().unwrap_or_default(),
        };
        let message_raw = truncate_utf8(message_raw.trim_end(), MAX_MESSAGE_BYTES).to_string();
        trace.diag_id = Some(diag_id.clone());
        trace.severity = Some(observed);
        trace.provenance = Some(provenance);
        // Suppression and overrides (project rules).
        let mut effective = observed;
        let mut drop_event = false;
        for s in &p.suppressions {
            // Every selector given must match (they constrain each other).
            let hit = (s.diag_ids.is_empty() || s.diag_ids.contains(&diag_id))
                && s.pattern.as_ref().is_none_or(|r| r.is_match(&message_raw));
            if !hit {
                continue;
            }
            trace.suppressed_by = Some(format!("{}@{}", s.id, s.version));
            let authoritative_failure =
                provenance == Provenance::Authoritative && observed >= Severity::Error;
            if s.not_an_error {
                effective = Severity::Info;
                drop_event = !authoritative_failure;
            } else if let Some(sev) = s.severity {
                effective = sev;
            }
            let sp = Span {
                line_start: SafeU64::saturating(o.start.no),
                line_end: SafeU64::saturating(o.end_line),
                byte_start: SafeU64::saturating(o.start.start),
                byte_end: SafeU64::saturating(o.end_byte),
            };
            match self
                .suppressed
                .iter_mut()
                .find(|a| a.id == s.id && a.observed == observed)
            {
                Some(a) => {
                    a.count += 1;
                    if a.spans.len() < MAX_SPANS {
                        a.spans.push(sp);
                    }
                }
                None => self.suppressed.push(SuppressionAcc {
                    id: s.id.clone(),
                    version: s.version.clone(),
                    observed,
                    count: 1,
                    spans: vec![sp],
                }),
            }
            break;
        }
        // Only diagnostics of warning severity and above enter accounting.
        if drop_event || observed < Severity::Warning {
            self.push_trace(trace);
            return;
        }
        let fails_run = if provenance == Provenance::Authoritative && observed >= Severity::Error {
            true
        } else {
            emit.and_then(|e| e.fails_run)
                .unwrap_or(effective >= Severity::Error)
        };
        if fails_run && o.cut {
            self.failure_cut = true;
        }
        if fails_run && o.line_cut {
            self.failure_line_cut = true;
        }
        // Only a retained failing fatal witnesses an early end (a suppressed one does not).
        if fails_run && observed == Severity::Fatal && emit.is_some_and(|e| e.fatal_witness) {
            self.fatal_witness = true;
        }
        // Typed fields.
        let mut fields: BTreeMap<String, FieldValue> = BTreeMap::new();
        if let Some(e) = emit {
            for f in &e.fields {
                if let Some(v) = caps.get(&f.from) {
                    fields.insert(f.name.clone(), classify::typed(f.kind, v));
                }
            }
            for (name, re, k) in &e.message_fields {
                if let Some(v) = re.captures(&message_raw).and_then(|c| c.name("v")) {
                    fields.insert(name.clone(), classify::typed(*k, v.as_str()));
                }
            }
            for d in &e.display_fields {
                if let Some(v) = caps.get(d) {
                    fields.insert(
                        d.clone(),
                        FieldValue::Text(truncate_utf8(v, MAX_FIELD_BYTES).to_string()),
                    );
                }
            }
        }
        // Significance.
        let significant: BTreeMap<String, String> = emit
            .map(|e| {
                e.significance
                    .iter()
                    .map(|(n, s)| (n.clone(), classify::significant_class(s, fields.get(n))))
                    .collect()
            })
            .unwrap_or_default();
        // Normalization and identity.
        let default_norm: Vec<String> = ["path", "whitespace"].map(String::from).to_vec();
        let mut norms: Vec<String> =
            emit.map_or_else(|| default_norm.clone(), |e| e.normalize.clone());
        if let Some(extra) = emit.and_then(|e| e.normalize_for.get(&diag_id)) {
            norms.extend(extra.iter().cloned());
        }
        let norms = &norms;
        let mut normalization = vec![];
        let display_template = normalize::apply(norms, &message_raw, &mut normalization);
        let mut identity_template = display_template.clone();
        if let Some(e) = emit {
            for f in &e.identity_fields {
                let v = caps.get(f).map_or("", String::as_str);
                let nv = normalize::apply(norms, v, &mut normalization);
                let _ = write!(identity_template, " | {f}={nv}");
            }
        }
        let source_anchor = emit
            .and_then(|e| e.anchor.as_ref())
            .and_then(|(path, line, form)| {
                let pth = caps.get(path).filter(|s| !s.trim().is_empty())?;
                let ln = line
                    .as_ref()
                    .and_then(|g| caps.get(g))
                    .and_then(|s| s.parse::<u64>().ok());
                Some(classify::anchor(pth, ln, form, &self.opts.source_roots))
            });
        let site = source_anchor.as_ref().map(|a| match a.line {
            Some(n) => format!("{}:{}", a.path.replace('\\', "/"), n.get()),
            None => a.path.replace('\\', "/"),
        });
        let family = if self.opts.subject == Subject::Build {
            "build".to_string()
        } else {
            family_kind
        };
        let key = FamilyKey {
            family: family.clone(),
            diag_id: diag_id.clone(),
            checker_scope: checker_scope.clone(),
            identity_template: identity_template.clone(),
            significant: significant.clone(),
            anchor: if checker_id.is_none() {
                source_anchor.clone()
            } else {
                None
            },
        };
        let fingerprint = self.cached_fingerprint(&key);
        trace.fingerprint = Some(fingerprint.clone());
        trace.identity_template = Some(identity_template.clone());
        let phase = phase.unwrap_or(match self.opts.subject {
            Subject::Build => Phase::Compile,
            Subject::Simulation => Phase::Run,
        });
        let sim_time = emit
            .and_then(|e| e.sim_time.as_ref())
            .and_then(|(v, u, ul)| {
                let val = caps.get(v)?;
                let unit = u
                    .as_ref()
                    .and_then(|g| caps.get(g))
                    .cloned()
                    .or_else(|| ul.clone())
                    .unwrap_or_default();
                Some(format!(
                    "{val}{}{unit}",
                    if unit.is_empty() { "" } else { " " }
                ))
            });
        let context_path = emit
            .and_then(|e| e.context.as_ref())
            .map(|t| t.render(caps, &mut vec![]))
            .filter(|s| !s.is_empty());
        let event = Event {
            ordinal: SafeU64::saturating(self.ordinal),
            provenance: EventProvenance::Log {
                span: Span {
                    line_start: SafeU64::saturating(o.start.no),
                    line_end: SafeU64::saturating(o.end_line),
                    byte_start: SafeU64::saturating(o.start.start),
                    byte_end: SafeU64::saturating(o.end_byte),
                },
                rule: qualified,
            },
            phase,
            framework,
            observed_severity: observed,
            effective_severity: effective,
            fails_run,
            diag_id,
            checker_id,
            kind,
            message_raw,
            display_template,
            identity_template,
            fields,
            significant,
            sim_time,
            source_anchor,
            context_path,
            normalization,
        };
        self.push_trace(trace);
        let became_primary = self.acc.add(Classified {
            event,
            site,
            family_kind: family,
            checker_scope,
            fingerprint,
            provenance,
        });
        if became_primary {
            let before = o.before.unwrap_or_default();
            let lines = o
                .lines
                .unwrap_or_else(|| vec![(o.start.no, o.start.text.clone())]);
            self.excerpt.set_primary(before, lines);
            self.excerpt.seed_after(o.end_line + 1);
        }
    }

    /// Fingerprints repeat within a log (storms): cache them, bounded.
    fn cached_fingerprint(&mut self, key: &FamilyKey) -> Digest {
        let anchor = key
            .anchor
            .as_ref()
            .map(|a| (a.path.as_str(), a.line.map(SafeU64::get), a.form as u8));
        let k = serde_json::to_string(&(
            &key.family,
            &key.diag_id,
            &key.checker_scope,
            &key.identity_template,
            &key.significant,
            anchor,
        ))
        .unwrap_or_default();
        if let Some(d) = self.fp_cache.get(&k) {
            return d.clone();
        }
        let d = classify::fingerprint(key);
        if self.fp_cache.len() >= FINGERPRINT_CACHE {
            self.fp_cache.clear();
        }
        self.fp_cache.insert(k, d.clone());
        d
    }

    fn push_trace(&mut self, t: TraceRecord) {
        if self.opts.trace && self.trace.len() < MAX_TRACE {
            self.trace.push(t);
        }
    }

    // ---- finish ------------------------------------------------------------------------

    /// Ends the stream and returns the evidence.
    #[must_use]
    pub fn finish(self) -> Evidence {
        self.finish_with_trace().0
    }

    /// Ends the stream; also returns the record trace and, for a model with its own main,
    /// every marker's count and positions taken after the last line (`rules explain`).
    #[must_use]
    pub fn finish_explained(mut self) -> (Evidence, Vec<TraceRecord>, Vec<MarkerOccurrence>) {
        // The final unterminated line is a line too (finish_with_trace finishes again: a
        // no-op).
        let mut splitter = std::mem::take(&mut self.splitter);
        splitter.finish(&mut |l| self.line(l));
        self.splitter = splitter;
        let markers = self.marker_occurrences();
        let (ev, trace) = self.finish_with_trace();
        (ev, trace, markers)
    }

    /// Ends the stream; also returns the record trace when enabled.
    #[must_use]
    #[allow(clippy::too_many_lines)] // completion check reads every piece of state
    pub fn finish_with_trace(mut self) -> (Evidence, Vec<TraceRecord>) {
        let mut splitter = std::mem::take(&mut self.splitter);
        splitter.finish(&mut |l| self.line(l));
        self.splitter = splitter;
        if self.detecting {
            self.select(None);
            self.flush_pending();
        }
        // EOF closes the open record; a missing mandatory line is a cut.
        self.close_at_end();
        let bytes = self.splitter.bytes();
        let completion = self.completion(bytes);
        let reconciliation = self.reconciliations();
        let e = self.splitter.endings;
        let line_ending = match (e.lf > 0, e.crlf > 0, e.cr > 0) {
            (false, false, false) => LineEnding::None,
            (true, false, false) => LineEnding::Lf,
            (false, true, false) => LineEnding::Crlf,
            _ => LineEnding::Mixed,
        };
        let invalid = self.splitter.invalid_bytes;
        let Self {
            p,
            opts,
            hasher,
            design_loaded,
            counters,
            verdicts,
            acc,
            suppressed,
            excerpt,
            unclaimed,
            unclaimed_spans,
            trace,
            segments,
            ..
        } = self;
        // An empty log (no bytes in either stream, or no log at all) has no segments.
        let segments = (!segments.is_empty() && bytes > 0).then(|| {
            let ends: Vec<u64> = segments
                .iter()
                .skip(1)
                .map(|s| s.byte_start)
                .chain(std::iter::once(bytes))
                .collect();
            segments
                .iter()
                .zip(ends)
                .map(|(s, end)| LogSegment {
                    name: s.name,
                    line_start: s.first_line.map(SafeU64::saturating),
                    line_end: s.last_line.map(SafeU64::saturating),
                    byte_start: SafeU64::saturating(s.byte_start),
                    byte_end: SafeU64::saturating(end),
                })
                .collect()
        });
        let (buckets, families, overflow, events) = acc.finish();
        let evidence = Evidence {
            schema: EVIDENCE.to_string(),
            evidence_revision: 1,
            extractor: ExtractorId {
                name: EXTRACTOR_NAME.to_string(),
                version: EXTRACTOR_VERSION.to_string(),
            },
            pipeline_digest: p.digest.clone(),
            packs: p
                .packs
                .iter()
                .map(|pk| PackRef {
                    id: pk.id.clone(),
                    version: pk.version.clone(),
                    digest: pk.digest.clone(),
                })
                .collect(),
            source: Source {
                log_name: opts.log_name.clone(),
                bytes: SafeU64::saturating(bytes),
                sha256: hasher.finish_hex(),
                encoding: Encoding::Utf8,
                line_ending,
                invalid_utf8_bytes: SafeU64::saturating(invalid),
                segments,
            },
            completion,
            design_loaded,
            verdict_sources: verdicts,
            counters,
            buckets,
            families,
            overflow,
            events,
            suppressed: suppressed
                .into_iter()
                .map(|s| Suppressed {
                    rule_id: s.id,
                    rule_version: s.version,
                    observed_severity: s.observed,
                    count: DecimalInteger::from_u64(s.count),
                    first_spans: s.spans,
                })
                .collect(),
            excerpt: excerpt.finish(),
            coverage: Coverage {
                unclaimed_error_like_lines: DecimalInteger::from_u64(unclaimed),
                unclaimed_examples: unclaimed_spans,
            },
            resources: LogResources::default(),
            reconciliation,
        };
        (evidence, trace)
    }

    #[allow(clippy::too_many_lines)] // the completion matrix, item by item
    fn completion(&self, bytes: u64) -> Completion {
        let p = self.p;
        let subject = match self.opts.subject {
            Subject::Build => "build",
            Subject::Simulation => "simulation",
        };
        if self.opts.model_main && self.opts.subject == Subject::Simulation {
            return self.model_main_completion(bytes);
        }
        if bytes == 0 {
            return Completion {
                profile: "none".to_string(),
                state: CompletionState::Missing,
                mode: None,
                reasons: vec![CompletionReason::EmptyLog],
                sections_seen: vec![],
                verdict_required: false,
            };
        }
        let profile = self.sim_pack.and_then(|i| {
            p.packs[i]
                .completion
                .profiles
                .iter()
                .find(|pr| pr.subject == subject && pr.select == ProfileSelect::Default)
        });
        let Some(profile) = profile else {
            let mut reasons = vec![CompletionReason::UnknownProfile];
            reasons.extend(self.exactness_reasons());
            return Completion {
                profile: "unknown".to_string(),
                state: CompletionState::Incomplete,
                mode: None,
                reasons,
                sections_seen: self.sequence.clone(),
                verdict_required: false,
            };
        };
        let replaced: BTreeSet<&str> = p
            .packs
            .iter()
            .enumerate()
            .filter(|(i, _)| self.active[*i] && self.detected[*i])
            .flat_map(|(_, pk)| pk.replaces.iter().map(String::as_str))
            .collect();
        let mut pack_sections = vec![];
        if self.opts.subject == Subject::Simulation {
            for (i, pk) in p.packs.iter().enumerate() {
                if self.active[i] && self.detected[i] && pk.tier != Tier::Simulator {
                    for s in &pk.completion.requires_when_active {
                        if !replaced.contains(s.as_str()) {
                            pack_sections.push(format!("{}/{s}", pk.id));
                        }
                    }
                }
            }
        }
        let sim_id = self.sim_pack.map_or("", |i| p.packs[i].id.as_str());
        // A requirement `a|b` is met by either witness of the simulator pack.
        let profile_items: Vec<Vec<String>> = profile
            .requires
            .iter()
            .map(|r| r.split('|').map(|alt| format!("{sim_id}/{alt}")).collect())
            .collect();
        let sim_ok = profile_items
            .iter()
            .all(|alts| alts.iter().any(|a| self.markers_seen.contains(a)));
        let sections_ok = pack_sections.iter().all(|s| self.markers_seen.contains(s));
        // The trailer must be the simulator pack's own.
        let trailer_seen = p.markers.iter().any(|m| {
            Some(m.pack) == self.sim_pack
                && m.trailer
                && self.markers_seen.contains(&format!("{sim_id}/{}", m.id))
        });
        let loaded_ok = !profile.design_loaded_known || self.design_loaded != DesignLoaded::Unknown;
        // A required verdict is a decisive one: "not applicable" alone never completes a
        // log.
        let verdict_ok = !profile.verdict_required
            || self
                .verdicts
                .iter()
                .any(|v| v.value != VerdictValue::NotApplicable);
        let mut reasons = self.exactness_reasons();
        let exact = reasons.is_empty();
        let normal = sim_ok && sections_ok && loaded_ok && verdict_ok;
        let early =
            profile.early_fatal && self.fatal_witness && trailer_seen && sim_ok && loaded_ok;
        let (state, mode) = if exact && normal {
            (CompletionState::Complete, Some(CompletionMode::Normal))
        } else if exact && early {
            (CompletionState::Complete, Some(CompletionMode::EarlyFatal))
        } else {
            if !(sim_ok && sections_ok && loaded_ok && verdict_ok) {
                reasons.insert(0, CompletionReason::NoEndMarker);
            }
            (CompletionState::Incomplete, None)
        };
        let required: BTreeSet<&String> = profile_items
            .iter()
            .flatten()
            .chain(pack_sections.iter())
            .collect();
        Completion {
            profile: profile.name.clone(),
            state,
            mode,
            reasons,
            sections_seen: self
                .sequence
                .iter()
                .filter(|s| required.contains(s))
                .cloned()
                .collect(),
            verdict_required: profile.verdict_required,
        }
    }

    /// The segment holding a line, by index.
    fn segment_of(&self, line: u64) -> Option<usize> {
        self.segments.iter().position(|s| {
            s.first_line
                .zip(s.last_line)
                .is_some_and(|(a, b)| a <= line && line <= b)
        })
    }

    /// Completion of a Verilator model with its own main (`verilator-model-main`): the
    /// program log then the console, joined by the collector; in the console, the model's
    /// start banner, Verilator's `$finish` line and the model's trailer, each exactly once and
    /// in that order; a positive verdict with a span (a console verdict before the finish);
    /// no Verilator report; the sections of detected packs; exact accounting.
    #[allow(clippy::too_many_lines)] // one check per item of the contract
    fn model_main_completion(&self, bytes: u64) -> Completion {
        let p = self.p;
        let profile_name = MODEL_MAIN_PROFILE.to_string();
        if bytes == 0 {
            return Completion {
                profile: profile_name,
                state: CompletionState::Missing,
                mode: None,
                reasons: vec![CompletionReason::EmptyLog],
                sections_seen: vec![],
                verdict_required: true,
            };
        }
        let incomplete = |mut reasons: Vec<CompletionReason>| {
            reasons.extend(self.exactness_reasons());
            Completion {
                profile: MODEL_MAIN_PROFILE.to_string(),
                state: CompletionState::Incomplete,
                mode: None,
                reasons,
                sections_seen: vec![],
                verdict_required: true,
            }
        };
        let sim = self.sim_pack.map(|i| (i, &p.packs[i]));
        let profile = sim.and_then(|(_, pk)| {
            (pk.simulator.as_deref() == Some("verilator"))
                .then(|| {
                    pk.completion.profiles.iter().find(|pr| {
                        pr.name == MODEL_MAIN_PROFILE && pr.select == ProfileSelect::Declared
                    })
                })
                .flatten()
        });
        let (Some((sim_idx, sim_pk)), Some(profile)) = (sim, profile) else {
            return incomplete(vec![CompletionReason::ProfileConflict]);
        };
        let mut reasons = vec![];
        let joined = self.segments.len() == 2
            && self.segments[0].name == LogSegmentName::Program
            && self.segments[1].name == LogSegmentName::Console;
        if !joined {
            reasons.push(CompletionReason::SegmentsMissing);
        }
        // Verilator's own report (or any trailer of the simulator pack) means the generated
        // main ran: not a custom-main run.
        let report = p.markers.iter().any(|m| {
            m.pack == sim_idx
                && m.trailer
                && self
                    .occurrences
                    .contains_key(&format!("{}/{}", sim_pk.id, m.id))
        });
        if report {
            reasons.push(CompletionReason::ProfileConflict);
        }
        let Some((decl_pk, decl)) = p.model_main() else {
            reasons.push(CompletionReason::ModelMainUndeclared);
            return incomplete(reasons);
        };
        let finish: Vec<String> = profile
            .requires
            .iter()
            .map(|r| format!("{}/{r}", sim_pk.id))
            .collect();
        let witnesses: Vec<String> = std::iter::once(format!("{}/{}", decl_pk.id, decl.start))
            .chain(finish.iter().cloned())
            .chain(decl.trailer.iter().map(|t| format!("{}/{t}", decl_pk.id)))
            .collect();
        let console = 1usize;
        let mut lines = vec![];
        let (mut count_ok, mut segment_ok) = (true, true);
        for w in &witnesses {
            match self.occurrences.get(w) {
                Some(o) if o.count == 1 => {
                    let (seg, line) = o.at[0];
                    if seg != console {
                        segment_ok = false;
                    }
                    lines.push(line);
                }
                _ => count_ok = false,
            }
        }
        if !count_ok {
            reasons.push(CompletionReason::WitnessCount);
        }
        let ordered = count_ok && lines.windows(2).all(|w| w[0] < w[1]);
        if count_ok && !ordered {
            reasons.push(CompletionReason::WitnessOrder);
        }
        // The finish line (the profile's last simulator witness), when it is known.
        let finish_line = (count_ok)
            .then(|| lines.get(finish.len()).copied())
            .flatten();
        let late_console_verdict = self.verdicts.iter().any(|v| {
            v.span.is_some_and(|sp| {
                let line = sp.line_start.get();
                self.segment_of(line) == Some(console)
                    && finish_line.is_none_or(|f| sp.line_end.get() >= f)
            })
        });
        if !segment_ok || late_console_verdict {
            reasons.push(CompletionReason::WitnessSegment);
        }
        let positive = self.verdicts.iter().any(|v| {
            v.value == VerdictValue::Pass
                && v.source != VerdictSourceKind::Producer
                && v.span.is_some()
        });
        // Sections of the other detected packs stay required.
        let replaced: BTreeSet<&str> = p
            .packs
            .iter()
            .enumerate()
            .filter(|(i, _)| self.active[*i] && self.detected[*i])
            .flat_map(|(_, pk)| pk.replaces.iter().map(String::as_str))
            .collect();
        let mut pack_sections = vec![];
        for (i, pk) in p.packs.iter().enumerate() {
            if self.active[i] && self.detected[i] && pk.tier != Tier::Simulator {
                for s in &pk.completion.requires_when_active {
                    if !replaced.contains(s.as_str()) {
                        pack_sections.push(format!("{}/{s}", pk.id));
                    }
                }
            }
        }
        let sections_ok = pack_sections.iter().all(|s| self.markers_seen.contains(s));
        let loaded_ok = !profile.design_loaded_known || self.design_loaded != DesignLoaded::Unknown;
        if !(positive && sections_ok && loaded_ok) {
            reasons.push(CompletionReason::NoEndMarker);
        }
        reasons.extend(self.exactness_reasons());
        let required: BTreeSet<&String> = witnesses.iter().chain(pack_sections.iter()).collect();
        let sections_seen = self
            .sequence
            .iter()
            .filter(|s| required.contains(s))
            .cloned()
            .collect();
        if reasons.is_empty() {
            Completion {
                profile: profile_name,
                state: CompletionState::Complete,
                mode: Some(CompletionMode::Normal),
                reasons,
                sections_seen,
                verdict_required: true,
            }
        } else {
            Completion {
                profile: profile_name,
                state: CompletionState::Incomplete,
                mode: None,
                reasons,
                sections_seen,
                verdict_required: true,
            }
        }
    }

    /// Reasons that make accounting inexact, whatever the profile.
    fn exactness_reasons(&self) -> Vec<CompletionReason> {
        let mut reasons = vec![];
        if self.failure_cut {
            reasons.push(CompletionReason::RecordCut);
        }
        if self.failure_line_cut || self.summary_cut {
            reasons.push(CompletionReason::LineCut);
        }
        if self.repeated_summary
            || self.invalid_summary
            || self.reconciliations().iter().any(|r| !r.holds)
        {
            reasons.push(CompletionReason::CountMismatch);
        }
        if self.acc.has_overflow() || self.summary_overflow {
            reasons.push(CompletionReason::AccountingOverflow);
        }
        reasons
    }

    /// Reconciliation templates of active packs whose counters were all seen (F13; the
    /// populations are in `docs/packs.md`): extracted ≤ counted.
    fn reconciliations(&self) -> Vec<Reconciliation> {
        let mut out = vec![];
        for (i, pk) in self.p.packs.iter().enumerate() {
            if !self.active[i] {
                continue;
            }
            for r in &pk.reconcile {
                let mut counted: Option<u128> = Some(0);
                let mut all = true;
                for (d, key) in &r.counters {
                    match self
                        .counters
                        .iter()
                        .rev()
                        .find(|c| c.domain == *d && &c.key == key)
                    {
                        Some(c) => {
                            counted = counted.and_then(|t| {
                                c.value
                                    .as_str()
                                    .parse::<u128>()
                                    .ok()
                                    .and_then(|v| t.checked_add(v))
                            });
                        }
                        None => all = false,
                    }
                }
                if !all {
                    // Some counters of the template were read, others not: the inputs are
                    // inconsistent, never silently skipped.
                    let any = r.counters.iter().any(|(d, key)| {
                        self.counters
                            .iter()
                            .any(|c| c.domain == *d && &c.key == key)
                    });
                    if any {
                        out.push(Reconciliation {
                            template: r.template.clone(),
                            counted: DecimalInteger::zero(),
                            extracted: DecimalInteger::zero(),
                            relation: ReconcileRelation::AtMost,
                            holds: false,
                        });
                    }
                    continue;
                }
                let Some(counted) = counted else {
                    // Not representable exactly: never substituted; the log is incomplete.
                    out.push(Reconciliation {
                        template: r.template.clone(),
                        counted: DecimalInteger::zero(),
                        extracted: DecimalInteger::zero(),
                        relation: ReconcileRelation::AtMost,
                        holds: false,
                    });
                    continue;
                };
                let extracted: u64 = self
                    .tally
                    .iter()
                    .filter(|((fw, sev), _)| {
                        r.frameworks.contains(fw) && r.severities.contains(sev)
                    })
                    .map(|(_, n)| *n)
                    .sum();
                out.push(Reconciliation {
                    template: r.template.clone(),
                    counted: DecimalInteger::try_from(counted.to_string())
                        .unwrap_or_else(|_| DecimalInteger::zero()),
                    extracted: DecimalInteger::from_u64(extracted),
                    relation: ReconcileRelation::AtMost,
                    holds: u128::from(extracted) <= counted,
                });
            }
        }
        out
    }

    /// The number of cut records (self-tests).
    #[must_use]
    pub fn record_cuts(&self) -> u64 {
        self.record_cuts
    }
}

enum Offer {
    Consumed,
    Close { cut: bool },
}

fn cap_map(re: &Regex, c: &regex::Captures<'_>) -> BTreeMap<String, String> {
    re.capture_names()
        .flatten()
        .filter_map(|n| c.name(n).map(|m| (n.to_string(), m.as_str().to_string())))
        .collect()
}

/// Extracts a whole buffer (convenience for tests and small logs).
#[must_use]
pub fn extract_bytes(
    p: &Pipeline,
    opts: ExtractOptions,
    bytes: &[u8],
) -> (Evidence, Vec<TraceRecord>) {
    let mut x = Extractor::new(p, opts);
    x.push(bytes);
    x.finish_with_trace()
}
