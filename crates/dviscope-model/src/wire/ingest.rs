//! Ingest records: starts, build attempts, simulation attempts.

use serde::{Deserialize, Serialize};

use super::evidence::Evidence;
use super::manifest::{BuildReqRef, ExecInputs};
use crate::ids::ExternalKey;
use crate::values::{Measure, SafeU64, UtcTime};

/// Production or experiment (experiments are reserved; 0.1 rejects them).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Counts toward settlement and readiness.
    #[default]
    Production,
    /// Never counts; rejected with `E_NOT_SUPPORTED` in 0.1.
    Experiment,
}

/// How the supervised process ended (platform-neutral).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerminationKind {
    /// Exited on its own.
    Exited,
    /// Stopped by the runner's timeout.
    Timeout,
    /// Stopped by the runner for another reason.
    TerminatedByRunner,
    /// Stopped by something else (signal, OOM killer, user).
    TerminatedExternally,
    /// Ended by a fault (SIGSEGV, access violation, abort).
    Crash,
    /// The supervisor could not record how it ended.
    Unknown,
}

/// Termination facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Termination {
    /// Kind of termination.
    pub kind: TerminationKind,
    /// Exit code, when the process exited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// POSIX signal number, when one ended it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posix_signal: Option<i32>,
    /// Windows NTSTATUS / exception code, as `0x...`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_status: Option<String>,
}

/// What a CPU time figure covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CpuScope {
    /// The direct child only.
    Process,
    /// The child and the children it waited for (Linux `wait4`).
    ProcessAndWaitedChildren,
    /// The whole Windows Job Object.
    Job,
}

/// What a peak memory figure covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PeakScope {
    /// The largest single process of the supervised tree.
    LargestProcess,
}

/// Host facts, without identifying names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// Hash of the host name.
    pub name_hash: String,
    /// Site host class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// CPU model string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
}

/// Runner facts, measured by the supervisor (never by the log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Runner {
    /// How it ended.
    pub termination: Termination,
    /// Start (reported execution time).
    pub started_at: UtcTime,
    /// End; absent when termination is `unknown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<UtcTime>,
    /// Wall time from a monotonic clock, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_s: Option<Measure>,
    /// Timeout that applied, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_s: Option<Measure>,
    /// CPU time, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_s: Option<Measure>,
    /// What `cpu_s` covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_scope: Option<CpuScope>,
    /// Peak resident set of the largest single process, KiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_kb: Option<SafeU64>,
    /// What `peak_rss_kb` covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_scope: Option<PeakScope>,
    /// Host facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Host>,
}

/// Outcome as the producer reported it (one input of outcome derivation, never the outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportedOutcome {
    /// The producer believes it passed.
    Pass,
    /// The producer believes it failed.
    Fail,
    /// Tool or infrastructure error.
    Error,
}

/// Result part of a simulation attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptResult {
    /// Producer's view, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_reported: Option<ReportedOutcome>,
    /// Runner facts.
    pub runner: Runner,
}

/// Kind of artifact reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// A log file.
    Log,
    /// A waveform.
    Waveform,
    /// A coverage database or report.
    Coverage,
    /// Anything else.
    Other,
}

/// An artifact reference: never fetched, previewed or probed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    /// Kind.
    pub kind: ArtifactKind,
    /// Label shown in the UI.
    pub label: String,
    /// Location as given (URL or path).
    pub uri: String,
    /// Size, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<SafeU64>,
    /// Declared SHA-256 (hex), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// One ingest record (NDJSON line of `POST .../ingest`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IngestRecord {
    /// A simulation attempt was launched.
    AttemptStarted(AttemptStarted),
    /// A build attempt was launched.
    BuildStarted(BuildStarted),
    /// A build attempt's terminal report.
    BuildAttempt(Box<BuildAttempt>),
    /// A simulation attempt's terminal report.
    SimulationAttempt(Box<SimulationAttempt>),
}

/// `attempt_started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptStarted {
    /// Schema identifier.
    pub schema: String,
    /// Producer namespace.
    pub producer_id: ExternalKey,
    /// Regression.
    pub regression_ref: ExternalKey,
    /// Slot.
    pub slot_ref: ExternalKey,
    /// Attempt key.
    pub attempt_ref: ExternalKey,
    /// Runner-assigned order within the slot, allocated before launch.
    pub attempt_seq: u32,
    /// Build attempts used, one per build requirement of the slot.
    #[serde(default)]
    pub build_refs: Vec<ExternalKey>,
    /// Launch time.
    pub started_at: UtcTime,
    /// Production or experiment.
    #[serde(default)]
    pub purpose: Purpose,
    /// Experiment reference (reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experiment_ref: Option<ExternalKey>,
    /// Lineage of a rerun (reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerun_of: Option<ExternalKey>,
}

/// `build_started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuildStarted {
    /// Schema identifier.
    pub schema: String,
    /// Producer namespace.
    pub producer_id: ExternalKey,
    /// Build attempt key.
    pub build_ref: ExternalKey,
    /// The requirement it builds.
    pub build_req: BuildReqRef,
    /// Launch time.
    pub started_at: UtcTime,
    /// Production or experiment.
    #[serde(default)]
    pub purpose: Purpose,
    /// Experiment reference (reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experiment_ref: Option<ExternalKey>,
    /// Lineage of a rerun (reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerun_of: Option<ExternalKey>,
}

/// Build outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BuildOutcome {
    /// Built.
    Pass,
    /// Compile or elaboration failed.
    Fail,
    /// Tool or infrastructure error.
    Error,
}

/// Build phase reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BuildPhase {
    /// Compilation.
    Compile,
    /// Elaboration.
    Elaborate,
}

/// `build_attempt` terminal report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BuildAttempt {
    /// Schema identifier.
    pub schema: String,
    /// Producer namespace.
    pub producer_id: ExternalKey,
    /// Report revision (corrections), from 1.
    pub report_revision: u32,
    /// Build attempt key.
    pub build_ref: ExternalKey,
    /// The requirement it builds.
    pub build_req: BuildReqRef,
    /// Outcome as reported.
    pub outcome: BuildOutcome,
    /// Phase reached.
    pub phase_reached: BuildPhase,
    /// Runner facts.
    pub runner: Runner,
    /// Evidence from the build log.
    pub evidence: Evidence,
    /// Production or experiment.
    #[serde(default)]
    pub purpose: Purpose,
    /// Experiment reference (reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experiment_ref: Option<ExternalKey>,
    /// Lineage of a rerun (reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerun_of: Option<ExternalKey>,
}

/// `simulation_attempt` terminal report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SimulationAttempt {
    /// Schema identifier.
    pub schema: String,
    /// Producer namespace.
    pub producer_id: ExternalKey,
    /// Report key.
    pub report_id: ExternalKey,
    /// Report revision (corrections), from 1.
    pub report_revision: u32,
    /// Regression.
    pub regression_ref: ExternalKey,
    /// Slot.
    pub slot_ref: ExternalKey,
    /// Attempt key.
    pub attempt_ref: ExternalKey,
    /// Runner-assigned order within the slot.
    pub attempt_seq: u32,
    /// Build attempts actually used, one per build requirement.
    #[serde(default)]
    pub build_refs: Vec<ExternalKey>,
    /// Source manifest.
    pub source_manifest_ref: ExternalKey,
    /// Exact execution inputs.
    pub execution: ExecInputs,
    /// Result.
    pub result: AttemptResult,
    /// Evidence.
    pub evidence: Evidence,
    /// Artifact references.
    #[serde(default)]
    pub artifacts: Vec<ArtifactRef>,
    /// Production or experiment.
    #[serde(default)]
    pub purpose: Purpose,
    /// Experiment reference (reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experiment_ref: Option<ExternalKey>,
    /// Lineage of a rerun (reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerun_of: Option<ExternalKey>,
    /// Extension data.
    #[serde(default)]
    pub ext: super::Ext,
}
