//! Expected sets: manifest chunks, seal, amend, marks.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical::Digest;
use crate::ids::ExternalKey;
use crate::values::DecimalInteger;

/// Simulator identity, part of build configuration.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Simulator {
    /// Vendor/tool, e.g. `questa`, `vcs`, `verilator`.
    pub vendor: String,
    /// Exact version string.
    pub version: String,
}

/// A build configuration (what is compiled and how).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    /// Simulator identity.
    pub simulator: Simulator,
    /// UVM version, when UVM is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uvm_version: Option<String>,
    /// Compile options, in order.
    #[serde(default)]
    pub options: Vec<String>,
    /// Defines (`NAME` or `NAME=VALUE`); duplicates are invalid.
    #[serde(default)]
    pub defines: Vec<String>,
    /// Digest of the file list, when the flow can supply it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_list_digest: Option<Digest>,
}

/// A build requirement reference: the source and the build configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuildReqRef {
    /// Source manifest the build compiles.
    pub source_manifest_ref: ExternalKey,
    /// Build configuration.
    pub build_config: BuildConfig,
}

/// Exact execution inputs of a slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecInputs {
    /// Test name.
    pub test: String,
    /// Seed as a decimal string.
    pub seed: DecimalInteger,
    /// Plusargs and run options, exactly as given and in order.
    #[serde(default)]
    pub plusargs: Vec<String>,
    /// Checking and simulator modes (e.g. `assertions: on`, `state: 4-state`).
    #[serde(default)]
    pub modes: BTreeMap<String, String>,
    /// Modes that belong to elaboration (e.g. `-voptargs`), used for elaboration groups.
    #[serde(default)]
    pub elaboration_modes: BTreeMap<String, String>,
    /// Namespaced extra inputs.
    #[serde(default)]
    pub extra: BTreeMap<String, BTreeMap<String, String>>,
}

/// Observed severity of a diagnostic.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
    /// Fatal.
    Fatal,
}

/// Expected verdict of a negative or error-path test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedVerdict {
    /// The test passes (possibly with expected diagnostics).
    Pass,
    /// The test fails with the expected diagnostics.
    Fail,
}

/// Expected count of a diagnostic: exact (`3`) or at least (`">=3"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ExpectedCount {
    /// Exactly this many.
    Exact(u32),
    /// At least, written `">=N"`.
    AtLeast(String),
}

/// One expected diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDiagnostic {
    /// Namespaced diagnostic ID, e.g. `uvm:REF_DONE`.
    pub diag_id: String,
    /// Observed severity.
    pub severity: Severity,
    /// Checker identity, when it must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checker_id: Option<String>,
    /// Normalized site (`file:line`), when it must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// Expected count.
    pub count: ExpectedCount,
}

/// Which extra diagnostics an expectation tolerates.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Extras {
    /// No other warning, error or fatal.
    #[default]
    None,
    /// Other warnings are allowed.
    WarningsAllowed,
}

/// Expected outcome of a slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    /// Expected verdict.
    pub verdict: ExpectedVerdict,
    /// Expected diagnostics; at least one when `verdict` is `fail`.
    #[serde(default)]
    pub diagnostics: Vec<ExpectedDiagnostic>,
    /// Extras policy.
    #[serde(default)]
    pub extras: Extras,
    /// Why the test is expected to behave so.
    pub reason: String,
}

/// One planned slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlotDecl {
    /// Producer key of the slot.
    pub slot_ref: ExternalKey,
    /// Exact execution inputs.
    pub exec_inputs: ExecInputs,
    /// Whether readiness requires it.
    pub required: bool,
    /// Build requirements the slot depends on.
    #[serde(default)]
    pub build_reqs: Vec<BuildReqRef>,
    /// Expected outcome (negative and error-path tests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<Expected>,
}

/// `PUT .../regressions/{r}/manifest/chunks/{n}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestChunk {
    /// Schema identifier.
    pub schema: String,
    /// Slots of this chunk.
    pub slots: Vec<SlotDecl>,
}

/// `POST .../manifest/seal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestSeal {
    /// Schema identifier.
    pub schema: String,
    /// Manifest revision being sealed.
    pub revision: u32,
    /// Number of slots in that revision.
    pub slot_count: u32,
    /// Manifest digest.
    pub manifest_digest: Digest,
}

/// A slot removed by an amendment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlotRemoval {
    /// The slot.
    pub slot_ref: ExternalKey,
    /// Why it is removed.
    pub reason: String,
}

/// `POST .../manifest/amend`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManifestAmend {
    /// Schema identifier.
    pub schema: String,
    /// New revision (current + 1).
    pub revision: u32,
    /// Added slots.
    #[serde(default)]
    pub add: Vec<SlotDecl>,
    /// Removed slots.
    #[serde(default)]
    pub remove: Vec<SlotRemoval>,
}

/// Declared state of slots that will not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MarkState {
    /// Cancelled by the runner.
    Cancelled,
    /// Skipped on purpose.
    Skipped,
}

/// `POST .../slots/mark`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SlotMark {
    /// Schema identifier.
    pub schema: String,
    /// The slots.
    pub slot_refs: Vec<ExternalKey>,
    /// Declared state.
    pub state: MarkState,
    /// Why.
    pub reason: String,
}
