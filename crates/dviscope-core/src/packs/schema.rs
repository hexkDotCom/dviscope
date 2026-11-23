//! The pack source format `dviscope.rules/1.0` (strict YAML). See `docs/packs.md` for the
//! reference; every type here rejects unknown keys.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The format identifier every pack declares.
pub const FORMAT: &str = "dviscope.rules/1.0";

/// Precedence tier of a pack: project packs, then the detected simulator pack,
/// then `uvm`, `svunit` and `generic`. Project rules (suppressions, project patterns) sit
/// above every pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// A project's own pack (e.g. a custom report server).
    Project,
    /// A simulator pack (`questa`, `vcs`, `verilator`).
    Simulator,
    /// The `uvm` pack.
    Uvm,
    /// The `svunit` pack.
    Svunit,
    /// The `generic` pack.
    Generic,
}

/// A whole pack file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSource {
    /// Always `dviscope.rules/1.0`.
    pub format: String,
    /// Pack ID (`[a-z0-9-]+`).
    pub pack: String,
    /// Pack version (`MAJOR.MINOR.PATCH`).
    pub version: String,
    /// Precedence tier.
    pub tier: Tier,
    /// Simulator name for simulator packs (`questa`, `vcs`, `verilator`).
    #[serde(default)]
    pub simulator: Option<String>,
    /// Lines that identify the simulator (message forms, never vendor banners) for a
    /// simulator pack; for other packs, lines that show the pack's framework is in use.
    #[serde(default)]
    pub detect: Vec<String>,
    /// Line framing applied before every grammar once this simulator is selected.
    #[serde(default)]
    pub framing: Option<Framing>,
    /// Summary sections of other packs this pack replaces when it is active.
    #[serde(default)]
    pub replaces: Vec<String>,
    /// Whether the simulator's exit status carries meaning (informational for outcome).
    #[serde(default)]
    pub exit_code_meaningful: Option<bool>,
    /// Lines that end an open record (and are then re-fed).
    #[serde(default)]
    pub boundaries: Vec<String>,
    /// Record rules, in precedence order within the pack.
    #[serde(default)]
    pub records: Vec<RecordRule>,
    /// Counters read in the pre-pass.
    #[serde(default)]
    pub counters: Vec<CounterRule>,
    /// Verdict sources read in the pre-pass.
    #[serde(default)]
    pub verdicts: Vec<VerdictRule>,
    /// Completion markers read in the pre-pass.
    #[serde(default)]
    pub markers: Vec<MarkerRule>,
    /// Summary sections built from markers and counters.
    #[serde(default)]
    pub sections: Vec<SectionDecl>,
    /// Completion profiles (simulator packs) and the sections the pack adds when active.
    #[serde(default)]
    pub completion: Completion,
    /// Reconciliation of summary counters with extracted events.
    #[serde(default)]
    pub reconcile: Vec<ReconcileRule>,
    /// Default normalizers of the pack's records, in order.
    #[serde(default)]
    pub normalize: Vec<String>,
    /// Suppressions and project patterns (project packs only).
    #[serde(default)]
    pub rules: Vec<ProjectRule>,
    /// Structural self-tests on invented text.
    #[serde(default)]
    pub tests: Vec<SelfTest>,
}

/// Line framing.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Framing {
    /// Literal prefix removed from every line that carries it (spans stay on the raw line).
    pub strip_prefix: String,
}

/// A string or a list of strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    /// One.
    One(String),
    /// Many.
    Many(Vec<String>),
}

impl OneOrMany {
    /// As a slice-like vector.
    #[must_use]
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::One(s) => vec![s.clone()],
            Self::Many(v) => v.clone(),
        }
    }
}

impl Default for OneOrMany {
    fn default() -> Self {
        Self::Many(vec![])
    }
}

/// A value given literally or mapped from a capture.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Mapped {
    /// A literal value.
    Literal(String),
    /// `{from: group, map: {captured: value}, default: value}`.
    From(MapFrom),
}

/// Mapping from a capture.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapFrom {
    /// Capture name.
    pub from: String,
    /// Captured text to value.
    pub map: BTreeMap<String, String>,
    /// Value when the capture is missing or not in the map.
    #[serde(default)]
    pub default: Option<String>,
}

/// A record rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordRule {
    /// Rule ID, unique in the pack.
    pub id: String,
    /// Literal prefixes of the start line used for dispatch (`anchor: any` when absent).
    #[serde(default)]
    pub prefix: Option<OneOrMany>,
    /// Start line.
    pub start: String,
    /// Continuation lines.
    #[serde(default)]
    pub continuation: Option<Continuation>,
    /// What the record emits; absent: the record is claimed and dropped (ignore rule).
    #[serde(default)]
    pub emit: Option<Emit>,
}

/// When a continuation ends early.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Until {
    /// A blank line ends the record (not consumed).
    Blank,
    /// No early end other than boundaries and starts.
    Never,
}

/// Continuation lines of a record.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Continuation {
    /// Maximum continuation lines (≤ 200).
    pub max_lines: u32,
    /// Early end.
    #[serde(default = "until_never")]
    pub until: Until,
    /// Line matchers, tried in order.
    pub lines: Vec<LineMatcher>,
}

fn until_never() -> Until {
    Until::Never
}

/// A continuation line matcher.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineMatcher {
    /// Pattern.
    #[serde(rename = "match")]
    pub pattern: String,
    /// Whether its named groups become captures.
    #[serde(default)]
    pub capture: bool,
    /// Append the line (or its `text` group) to this field.
    #[serde(default)]
    pub append_to: Option<String>,
    /// Matches at most once per record.
    #[serde(default)]
    pub once: bool,
    /// Must match before anything else is offered (mandatory part, in order).
    #[serde(default)]
    pub mandatory: bool,
}

/// Source anchor declaration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorDecl {
    /// Capture holding the path.
    pub path: String,
    /// Capture holding the line.
    #[serde(default)]
    pub line: Option<String>,
    /// `full`, `truncated` or `auto` (a leading `..` means truncated).
    #[serde(default = "form_auto")]
    pub form: String,
}

fn form_auto() -> String {
    "auto".to_string()
}

/// Simulation time declaration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimTimeDecl {
    /// Capture with the value.
    pub value: String,
    /// Capture with the unit, or a literal unit with `unit_literal`.
    #[serde(default)]
    pub unit: Option<String>,
    /// A literal unit.
    #[serde(default)]
    pub unit_literal: Option<String>,
}

/// A typed field.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDecl {
    /// Field name.
    pub name: String,
    /// Capture or message-field pattern group it comes from (default: the name).
    #[serde(default)]
    pub from: Option<String>,
    /// `text`, `integer`, `sv_literal` or `time`.
    #[serde(default = "type_text", rename = "type")]
    pub kind: String,
}

fn type_text() -> String {
    "text".to_string()
}

/// A field parsed out of the message.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageField {
    /// Field name.
    pub name: String,
    /// Pattern with a group `v`.
    #[serde(rename = "match")]
    pub pattern: String,
    /// `text`, `integer`, `sv_literal` or `time`.
    #[serde(default = "type_text", rename = "type")]
    pub kind: String,
}

/// What a record emits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Emit {
    /// `uvm`, `simulator`, `assertion`, `svunit`, `display`, `project`.
    pub framework: String,
    /// Severity (`info`, `warning`, `error`, `fatal`), literal or mapped.
    pub severity: Mapped,
    /// Diagnostic ID template.
    pub diag_id: String,
    /// Checker ID template.
    #[serde(default)]
    pub checker_id: Option<String>,
    /// Checker scope template.
    #[serde(default)]
    pub checker_scope: Option<String>,
    /// Kind (`check`, `assertion`, `timeout`, `crash`, `build`, `x_z`, `usage`, `resource`,
    /// `license`, `other`), literal or mapped.
    #[serde(default)]
    pub kind: Option<Mapped>,
    /// Phase (`compile`, `elaborate`, `run`); default from the evidence subject.
    #[serde(default)]
    pub phase: Option<Mapped>,
    /// Family kind (`uvm-app`, `tool`, `assertion`, `build`); default from the framework.
    #[serde(default)]
    pub family: Option<String>,
    /// Message template.
    pub message: String,
    /// Source anchor.
    #[serde(default)]
    pub anchor: Option<AnchorDecl>,
    /// Simulation time.
    #[serde(default)]
    pub sim_time: Option<SimTimeDecl>,
    /// Hierarchical context path template.
    #[serde(default)]
    pub context: Option<String>,
    /// Captures that join the identity template.
    #[serde(default)]
    pub identity_fields: Vec<String>,
    /// Captures shown but never part of identity.
    #[serde(default)]
    pub display_fields: Vec<String>,
    /// Typed fields from captures.
    #[serde(default)]
    pub fields: Vec<FieldDecl>,
    /// Typed fields parsed out of the message.
    #[serde(default)]
    pub fields_from_message: Vec<MessageField>,
    /// Significance of typed fields (`verbatim`, `zero_vs_nonzero`, `x_vs_known`,
    /// `class:a|b|c`).
    #[serde(default)]
    pub significance: BTreeMap<String, String>,
    /// Normalizers for this rule (default: the pack's).
    #[serde(default)]
    pub normalize: Option<Vec<String>>,
    /// Extra normalizers for some diagnostic IDs only (opt-in folds such as `index_fold`).
    #[serde(default)]
    pub normalize_for: BTreeMap<String, Vec<String>>,
    /// The record is a fatal witness for early-fatal completion.
    #[serde(default)]
    pub fatal_witness: bool,
}

/// One value of a counter rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterValue {
    /// Key template.
    pub key: String,
    /// Capture with the number.
    pub from: String,
    /// Role (`failure_count`, `warning_count`, `success_count`, `info`), literal or mapped.
    pub role: Mapped,
    /// Diagnostic ID template whose failing buckets account for this count.
    #[serde(default)]
    pub explained_by: Option<String>,
    /// The keys a key template with captures can produce. Required before a reconciliation
    /// or section refers to such a key; a rendered key outside the list makes the log
    /// incomplete.
    #[serde(default)]
    pub keys: Option<Vec<String>>,
}

/// A counter rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterRule {
    /// Rule ID.
    pub id: String,
    /// Domain (`uvm_severity`, `uvm_by_id`, `sim_tool`, `checks`, `svunit`, `banner`,
    /// `project`).
    pub domain: String,
    /// Pattern.
    #[serde(rename = "match")]
    pub pattern: String,
    /// Values read from one line.
    pub values: Vec<CounterValue>,
    /// No rule may claim or suppress it.
    #[serde(default)]
    pub protected: bool,
    /// Only counted while this section is open.
    #[serde(default)]
    pub within: Option<String>,
}

/// A verdict source rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictRule {
    /// Rule ID.
    pub id: String,
    /// `banner`, `test_result`, `svunit_runner`, `sim_totals`.
    pub source: String,
    /// Pattern.
    #[serde(rename = "match")]
    pub pattern: String,
    /// `pass`, `fail`, `not_applicable`, literal or mapped.
    pub value: Mapped,
}

/// A completion marker.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarkerRule {
    /// Marker ID.
    pub id: String,
    /// Pattern.
    #[serde(rename = "match")]
    pub pattern: String,
    /// Sets the design-load state (`true` or `false`; `false` is sticky).
    #[serde(default)]
    pub design_loaded: Option<bool>,
    /// The marker is the simulator trailer (needed for early-fatal completion).
    #[serde(default)]
    pub trailer: bool,
    /// The marker is a fatal witness.
    #[serde(default)]
    pub fatal_witness: bool,
}

/// A summary section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionDecl {
    /// Section ID (e.g. `uvm_summary`).
    pub id: String,
    /// Marker that opens it.
    pub open: String,
    /// Counter keys (`domain:key`) or markers that must follow the opening.
    pub requires: Vec<String>,
    /// Verdict derived when the section is complete: fails if any of these counters
    /// (`domain:key`) is non-zero.
    #[serde(default)]
    pub verdict: Option<SectionVerdict>,
}

/// Verdict computed from a complete section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionVerdict {
    /// Verdict source kind (`uvm_summary`).
    pub source: String,
    /// Counters (`domain:key`) whose non-zero value means fail.
    pub fail_if_nonzero: Vec<String>,
}

/// Completion declarations.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    /// Profiles (simulator packs).
    #[serde(default)]
    pub profiles: Vec<ProfileDecl>,
    /// Sections required in any run where this pack is active (detected).
    #[serde(default)]
    pub requires_when_active: Vec<String>,
    /// Project packs: the console markers of a Verilator model with its own C++ main. They
    /// apply only to runs whose slot declares `extra.tool.main = "model"`; the declaration
    /// never selects the profile by itself.
    #[serde(default)]
    pub model_main: Option<ModelMainDecl>,
}

/// The console markers of a Verilator model with its own main (`verilator-model-main`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelMainDecl {
    /// The pack's marker of the model's start banner (exactly once, first).
    pub start: String,
    /// The pack's markers printed after `$finish`, in order (each exactly once); the last
    /// is the model's final line.
    pub trailer: Vec<String>,
}

/// How a completion profile is chosen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSelect {
    /// The first default profile of its subject is the simulator's profile.
    #[default]
    Default,
    /// Only a run declaring it selects it (a Verilator model with its own main).
    Declared,
}

/// A completion profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDecl {
    /// Profile name (`questa-run`).
    pub name: String,
    /// `build` or `simulation`.
    pub subject: String,
    /// Markers, counter rule IDs or sections required.
    pub requires: Vec<String>,
    /// Whether the design-load state must be known.
    #[serde(default)]
    pub design_loaded_known: bool,
    /// Whether a positive verdict source is required.
    #[serde(default)]
    pub verdict_required: bool,
    /// Whether early-fatal completion is allowed.
    #[serde(default)]
    pub early_fatal: bool,
    /// How the profile is chosen (`default` or `declared`).
    #[serde(default)]
    pub select: ProfileSelect,
}

/// A reconciliation equation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRule {
    /// Template name (`uvm_errors`, `questa_sim_errors`).
    pub template: String,
    /// Counters (`domain:key`) whose last values are summed.
    pub counters: Vec<String>,
    /// Population: events of these frameworks...
    pub frameworks: Vec<String>,
    /// ...and these observed severities (before suppression).
    pub severities: Vec<String>,
}

/// A project rule (project packs only).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRule {
    /// Rule ID.
    pub id: String,
    /// Rule version.
    pub version: String,
    /// `suppression` or `project_pattern`.
    pub kind: String,
    /// Owner.
    pub owner: String,
    /// Reason.
    pub reason: String,
    /// Suppression: `not_an_error` or `severity_override`.
    #[serde(default)]
    pub action: Option<String>,
    /// Suppression: severity after the override.
    #[serde(default)]
    pub severity: Option<String>,
    /// Suppression: diagnostic IDs it applies to (exact).
    #[serde(default)]
    pub diag_ids: Vec<String>,
    /// Suppression: message pattern it applies to.
    #[serde(default, rename = "match")]
    pub pattern: Option<String>,
    /// Project pattern: the record rule it defines.
    #[serde(default)]
    pub record: Option<RecordRule>,
    /// Project pattern: explicit failure indication (non-authoritative records only).
    #[serde(default)]
    pub fails_run: Option<bool>,
}

/// A structural self-test.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfTest {
    /// Test name.
    pub name: String,
    /// Invented input text.
    pub input: String,
    /// Simulator the run declares (default: detection).
    #[serde(default)]
    pub simulator: Option<String>,
    /// `simulation` (default) or `build`.
    #[serde(default)]
    pub subject: Option<String>,
    /// Expected events, in order (`diag_id@line`, optionally `!cut`).
    #[serde(default)]
    pub events: Vec<String>,
    /// Expected record cuts.
    #[serde(default)]
    pub record_cuts: Option<u32>,
    /// Expected completion state (`complete`, `incomplete`).
    #[serde(default)]
    pub completion: Option<String>,
}
