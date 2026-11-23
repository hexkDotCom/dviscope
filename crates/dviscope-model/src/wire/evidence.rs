//! The evidence envelope. Every count, size, offset and ordinal is a
//! [`SafeU64`]; the envelope is always canonicalizable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::manifest::Severity;
use crate::canonical::Digest;
use crate::values::{DecimalInteger, SafeU64};

/// Identity of the extractor that produced the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Extractor {
    /// Extractor name (`dviscope`).
    pub name: String,
    /// Extractor version.
    pub version: String,
}

/// A pattern pack used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackRef {
    /// Pack ID.
    pub id: String,
    /// Pack version.
    pub version: String,
    /// Pack digest.
    pub digest: Digest,
}

/// Line ending found in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LineEnding {
    /// `\n`.
    Lf,
    /// `\r\n`.
    Crlf,
    /// Both appear.
    Mixed,
    /// No line break at all.
    None,
}

/// Text encoding the extractor read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// UTF-8 (invalid bytes replaced and counted).
    Utf8,
}

/// The source bytes the evidence describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// File name of the log (no directories).
    pub log_name: String,
    /// Size in bytes.
    pub bytes: SafeU64,
    /// SHA-256 of the bytes (hex), computed by the extractor.
    pub sha256: String,
    /// Encoding read.
    pub encoding: Encoding,
    /// Line endings.
    pub line_ending: LineEnding,
    /// Number of invalid UTF-8 bytes replaced.
    pub invalid_utf8_bytes: SafeU64,
    /// The streams the log joins, in order (a Verilator model with its own main: the
    /// program log, then the console), contiguous and covering every byte; absent for a
    /// single stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<LogSegment>>,
}

/// Which stream a segment of the log comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogSegmentName {
    /// The program's own log file (`--log`).
    Program,
    /// The console capture (`--console`).
    Console,
}

/// One stream of a joined log: its bytes (half-open) and lines (1-based, inclusive, global
/// over the joined log; both null for an empty segment).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogSegment {
    /// Stream.
    pub name: LogSegmentName,
    /// First line, or null when the segment holds no line.
    pub line_start: Option<SafeU64>,
    /// Last line, or null when the segment holds no line.
    pub line_end: Option<SafeU64>,
    /// First byte (inclusive).
    pub byte_start: SafeU64,
    /// End byte (exclusive).
    pub byte_end: SafeU64,
}

/// Completion state of the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompletionState {
    /// Every required component of the profile was seen.
    Complete,
    /// Something required is missing or was cut.
    Incomplete,
    /// No usable log.
    Missing,
}

/// How a complete log ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompletionMode {
    /// Every section present.
    Normal,
    /// A recorded fatal and the simulator trailer.
    EarlyFatal,
}

/// Why a log is not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompletionReason {
    /// The trailer is missing.
    NoEndMarker,
    /// The runner killed the process.
    Killed,
    /// The runner's timeout fired.
    TimedOut,
    /// The log is empty.
    EmptyLog,
    /// A reconciliation equation failed.
    CountMismatch,
    /// More buckets than the cap.
    AccountingOverflow,
    /// A line was cut inside a failure record or required section.
    LineCut,
    /// A record was cut.
    RecordCut,
    /// The log could not be read.
    Unreadable,
    /// The supervisor could not record the termination.
    UnrecoverableTermination,
    /// No profile applies (unknown simulator or kind).
    UnknownProfile,
    /// A Verilator model with its own main: the log is not the program log and console
    /// joined by the collector.
    SegmentsMissing,
    /// A Verilator model with its own main printed Verilator's own simulation report (or ran
    /// under another simulator): it is not a custom-main run.
    ProfileConflict,
    /// The run declares its own main but no project pack of the pipeline declares the
    /// model's markers.
    ModelMainUndeclared,
    /// The model's console witnesses are out of order.
    WitnessOrder,
    /// A console witness of the model is missing or repeated (one execution per attempt).
    WitnessCount,
    /// A console witness appears in the program log, or a console verdict after the finish.
    WitnessSegment,
}

/// Completion of the log against its profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    /// Profile name, e.g. `questa-run`.
    pub profile: String,
    /// State.
    pub state: CompletionState,
    /// Mode, only when complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<CompletionMode>,
    /// Reasons when not complete.
    #[serde(default)]
    pub reasons: Vec<CompletionReason>,
    /// Required sections seen, in order (completion witness).
    #[serde(default)]
    pub sections_seen: Vec<String>,
    /// Whether the profile requires a positive verdict source (outcome row 9).
    #[serde(default)]
    pub verdict_required: bool,
}

/// Whether the design was loaded.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DesignLoaded {
    /// Not established.
    #[default]
    Unknown,
    /// Loaded.
    True,
    /// Failed to load.
    False,
}

/// A source of a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSourceKind {
    /// UVM report summary.
    UvmSummary,
    /// A project banner (e.g. `SIMULATION PASSED`).
    Banner,
    /// A test-result line.
    TestResult,
    /// SVUnit runner summary.
    SvunitRunner,
    /// Simulator error totals.
    SimTotals,
    /// The producer's reported outcome (normalized by the server).
    Producer,
}

/// What a verdict source says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerdictValue {
    /// Pass.
    Pass,
    /// Fail.
    Fail,
    /// Not applicable.
    NotApplicable,
}

/// A byte and line span in the original log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Span {
    /// First line, 1-based, inclusive.
    pub line_start: SafeU64,
    /// Last line, 1-based, inclusive.
    pub line_end: SafeU64,
    /// First byte, 0-based, inclusive.
    pub byte_start: SafeU64,
    /// End byte, 0-based, exclusive.
    pub byte_end: SafeU64,
}

/// One verdict source observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VerdictSource {
    /// Which source.
    pub source: VerdictSourceKind,
    /// What it says.
    pub value: VerdictValue,
    /// Where (absent for the producer source).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,
}

/// Counter domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CounterDomain {
    /// UVM counts by severity.
    UvmSeverity,
    /// UVM counts by report ID.
    UvmById,
    /// Simulator tool totals.
    SimTool,
    /// Check counts (project checkers).
    Checks,
    /// SVUnit counts.
    Svunit,
    /// Banner counts.
    Banner,
    /// Project-defined.
    Project,
}

/// What a counter means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CounterRole {
    /// Counts failures; > 0 is a failure indication.
    FailureCount,
    /// Counts warnings.
    WarningCount,
    /// Counts successes.
    SuccessCount,
    /// Informational.
    Info,
}

/// A counter read from a summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Counter {
    /// Domain.
    pub domain: CounterDomain,
    /// Key within the domain (severity, ID, check name).
    pub key: String,
    /// Value, exact, as a decimal string (summaries can exceed 2^53).
    pub value: DecimalInteger,
    /// Role.
    pub role: CounterRole,
    /// Whether no rule may claim or suppress it.
    pub protected: bool,
    /// The diagnostic ID whose failing buckets account for this failure count (a check row
    /// of a project report), when the pack declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explained_by: Option<String>,
    /// Where.
    pub span: Span,
}

/// Reporting framework of a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    /// UVM report.
    Uvm,
    /// Simulator message.
    Simulator,
    /// Assertion failure.
    Assertion,
    /// SVUnit.
    Svunit,
    /// `$display`-style text.
    Display,
    /// Runner facts.
    Runner,
    /// Project pack.
    Project,
    /// DVIScope's own synthetic events.
    Dviscope,
}

/// Phase of a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Compilation.
    Compile,
    /// Elaboration.
    Elaborate,
    /// Run time.
    Run,
    /// Not known.
    Unknown,
}

/// Kind of diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiagKind {
    /// A check or comparison.
    Check,
    /// An assertion.
    Assertion,
    /// A timeout.
    Timeout,
    /// A crash.
    Crash,
    /// A build problem.
    Build,
    /// X/Z values.
    XZ,
    /// Wrong usage (unknown test, bad option).
    Usage,
    /// Resource exhaustion.
    Resource,
    /// License problem.
    License,
    /// Anything else.
    Other,
}

/// Where a bucket's failure indication comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Recognized by the fixed protected pre-pass; cannot be suppressed as a failure.
    Authoritative,
    /// Matched by a pack or project rule.
    Rule,
    /// Created by DVIScope (runner facts, evaluator, expectations).
    Synthetic,
}

/// A typed field value parsed from a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum FieldValue {
    /// Text.
    Text(String),
    /// A non-negative integer.
    Integer(SafeU64),
    /// A SystemVerilog number literal as written (`32'hdead_beef`, `4'b10x1`).
    SvLiteral(String),
    /// A simulation time with unit.
    Time {
        /// Value as written.
        value: String,
        /// Unit (`fs`..`s`).
        unit: String,
    },
}

/// Exact accounting unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Bucket {
    /// Namespaced diagnostic ID.
    pub diag_id: String,
    /// Checker identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checker_id: Option<String>,
    /// Normalized site (`file:line`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// Severity as observed.
    pub observed_severity: Severity,
    /// Severity after overrides.
    pub effective_severity: Severity,
    /// Framework.
    pub framework: Framework,
    /// Phase.
    pub phase: Phase,
    /// Kind.
    pub kind: DiagKind,
    /// Provenance.
    pub provenance: Provenance,
    /// Whether it fails the run (computed).
    pub fails_run: bool,
    /// Exact count, as a decimal string.
    pub count: DecimalInteger,
    /// Family (fingerprint) this bucket belongs to.
    pub family: Digest,
    /// Ordinal of the first occurrence.
    pub first_ordinal: SafeU64,
    /// Ordinal of a retained example, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example_ordinal: Option<SafeU64>,
}

/// Signature grouping over buckets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Family {
    /// Fingerprint (signature identity).
    pub fingerprint: Digest,
    /// Family kind (`uvm-app`, `tool`, `assertion`, `runner`, `build`, `expectation`,
    /// `unexplained`, `incomplete`).
    pub family_kind: String,
    /// Diagnostic ID.
    pub diag_id: String,
    /// Checker scope, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checker_scope: Option<String>,
    /// Identity template.
    pub identity_template: String,
    /// Significant field classes.
    #[serde(default)]
    pub significant: BTreeMap<String, String>,
    /// Display template.
    pub display_template: String,
    /// Indices into `Evidence::buckets` of this family's buckets.
    pub buckets: Vec<SafeU64>,
}

/// Overflow accounting, exact by outcome-relevant dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverflowEntry {
    /// Framework.
    pub framework: Framework,
    /// Phase.
    pub phase: Phase,
    /// Kind.
    pub kind: DiagKind,
    /// Observed severity.
    pub observed_severity: Severity,
    /// Provenance.
    pub provenance: Provenance,
    /// Fails the run.
    pub fails_run: bool,
    /// Exact count, as a decimal string.
    pub count: DecimalInteger,
}

/// Where an example event came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventProvenance {
    /// From the log.
    Log {
        /// Span in the original bytes.
        span: Span,
        /// Rule that claimed it (`pack/rule@version`).
        rule: String,
    },
    /// Created by DVIScope.
    Synthetic {
        /// Producer of the synthetic event (`runner`, `evaluator`, `expectation`).
        source: String,
        /// Detail.
        detail: String,
    },
}

/// Form of a source anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnchorForm {
    /// Full path as written.
    Full,
    /// Repository-relative.
    RepoRelative,
    /// Truncated by the tool (e.g. leading `..`); never treated as resolved.
    Truncated,
    /// Not available.
    Unavailable,
}

/// A source location named by a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAnchor {
    /// Path as written (never resolved by the core).
    pub path: String,
    /// Form.
    pub form: AnchorForm,
    /// Line, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<SafeU64>,
}

/// One normalization applied to a message or field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Normalization {
    /// Normalizer name (`sv_literal`, `hex`, `time`, `path`, ...).
    pub normalizer: String,
    /// Original text.
    pub original: String,
    /// Replacement.
    pub replacement: String,
}

/// An example event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Ordinal in the log.
    pub ordinal: SafeU64,
    /// Provenance.
    pub provenance: EventProvenance,
    /// Phase.
    pub phase: Phase,
    /// Framework.
    pub framework: Framework,
    /// Severity as observed.
    pub observed_severity: Severity,
    /// Severity after overrides.
    pub effective_severity: Severity,
    /// Fails the run.
    pub fails_run: bool,
    /// Diagnostic ID.
    pub diag_id: String,
    /// Checker identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checker_id: Option<String>,
    /// Kind.
    pub kind: DiagKind,
    /// Message as written (may contain personal data; never in URLs or metrics).
    pub message_raw: String,
    /// Display template.
    pub display_template: String,
    /// Identity template.
    pub identity_template: String,
    /// Typed fields parsed from the record.
    #[serde(default)]
    pub fields: BTreeMap<String, FieldValue>,
    /// Significant field classes.
    #[serde(default)]
    pub significant: BTreeMap<String, String>,
    /// Simulation time as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sim_time: Option<String>,
    /// Source anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_anchor: Option<SourceAnchor>,
    /// Hierarchical context path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_path: Option<String>,
    /// Normalizations applied ("why these match").
    #[serde(default)]
    pub normalization: Vec<Normalization>,
}

/// Suppression record (bounded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Suppressed {
    /// Rule ID.
    pub rule_id: String,
    /// Rule version.
    pub rule_version: String,
    /// Severity as observed.
    pub observed_severity: Severity,
    /// Lines suppressed, exact, as a decimal string.
    pub count: DecimalInteger,
    /// First spans (at most 5).
    pub first_spans: Vec<Span>,
}

/// Excerpt segment kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    /// Lines before the primary record.
    BeforePrimary,
    /// The primary record.
    Primary,
    /// Lines after it.
    AfterPrimary,
    /// The log's last lines.
    Tail,
}

/// An excerpt segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Segment {
    /// Kind.
    pub kind: SegmentKind,
    /// First line number.
    pub first_line: SafeU64,
    /// Lines.
    pub lines: Vec<String>,
}

/// Bounded excerpt.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Excerpt {
    /// Segments.
    pub segments: Vec<Segment>,
    /// Whether the budget cut it.
    pub truncated: bool,
}

/// Parser coverage: error-like lines no rule claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    /// Count of unclaimed error-like lines, as a decimal string.
    pub unclaimed_error_like_lines: DecimalInteger,
    /// Up to 5 spans of examples.
    pub unclaimed_examples: Vec<Span>,
}

/// Simulated cycles and the clock they count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cycles {
    /// Cycle count, as a decimal string.
    pub value: DecimalInteger,
    /// Name of the clock or counter behind the figure.
    pub clock: String,
}

/// Where resource figures come from.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSource {
    /// Read from the simulator's own log lines.
    #[default]
    SimulatorLog,
}

/// Resource figures read from the simulator log (the runner's figures are in `Runner`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogResources {
    /// Source of these figures.
    #[serde(default)]
    pub source: ResourceSource,
    /// Simulated cycles, when the log reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycles: Option<Cycles>,
    /// CPU seconds the simulator reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sim_cpu_s: Option<crate::values::Measure>,
    /// Memory the simulator reported, MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sim_mem_mb: Option<crate::values::Measure>,
    /// Final simulation time as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sim_time: Option<String>,
}

/// Relation a reconciliation template checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileRelation {
    /// Extracted ≤ counted (a summary may count messages it did not print).
    AtMost,
}

/// One reconciliation of summary counters with extracted events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reconciliation {
    /// Template name (`uvm_errors`, `questa_sim_errors`).
    pub template: String,
    /// Sum of the template's counters, as a decimal string.
    pub counted: DecimalInteger,
    /// Extracted events of the template's population (observed, before suppression).
    pub extracted: DecimalInteger,
    /// Relation checked.
    pub relation: ReconcileRelation,
    /// Whether the relation holds (a violation makes completion `count_mismatch`).
    pub holds: bool,
}

/// The evidence envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Schema identifier (`dviscope.evidence/1.0-dev.N`).
    pub schema: String,
    /// Evidence revision: advanced only by re-extraction (always 1 in 0.1).
    pub evidence_revision: u32,
    /// Extractor.
    pub extractor: Extractor,
    /// Pipeline digest.
    pub pipeline_digest: Digest,
    /// Packs used, in order.
    pub packs: Vec<PackRef>,
    /// Source bytes.
    pub source: Source,
    /// Completion.
    pub completion: Completion,
    /// Design load state.
    #[serde(default)]
    pub design_loaded: DesignLoaded,
    /// Every verdict source seen.
    pub verdict_sources: Vec<VerdictSource>,
    /// Counters.
    pub counters: Vec<Counter>,
    /// Exact accounting.
    pub buckets: Vec<Bucket>,
    /// Signature grouping.
    pub families: Vec<Family>,
    /// Overflow accounting.
    #[serde(default)]
    pub overflow: Vec<OverflowEntry>,
    /// Example events.
    pub events: Vec<Event>,
    /// Suppression records.
    #[serde(default)]
    pub suppressed: Vec<Suppressed>,
    /// Excerpt.
    pub excerpt: Excerpt,
    /// Parser coverage receipt.
    pub coverage: Coverage,
    /// Resource figures from the log.
    #[serde(default)]
    pub resources: LogResources,
    /// Reconciliations of summary counters with extracted events.
    #[serde(default)]
    pub reconciliation: Vec<Reconciliation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_rejects_unknown_members() {
        let ok: Result<EventProvenance, _> =
            serde_json::from_str(r#"{"kind":"synthetic","source":"runner","detail":"timeout"}"#);
        assert!(ok.is_ok());
        let bad: Result<EventProvenance, _> = serde_json::from_str(
            r#"{"kind":"synthetic","source":"runner","detail":"x","extra":1}"#,
        );
        assert!(bad.is_err());
    }

    #[test]
    fn counts_beyond_safe_range_rejected() {
        let bad: Result<SafeU64, _> = serde_json::from_str("9007199254740992");
        assert!(bad.is_err());
    }
}
