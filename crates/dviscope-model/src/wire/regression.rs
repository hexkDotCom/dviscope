//! Regressions and source manifests.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::ExternalKey;
use crate::values::UtcTime;

/// What started a regression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    /// Scheduled nightly run.
    Nightly,
    /// A merge or pull request.
    MergeRequest,
    /// Started by a person.
    Manual,
    /// Anything else.
    Other,
}

/// The trigger of a regression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    /// Kind of trigger.
    pub kind: TriggerKind,
    /// Optional reference (e.g. merge request number), as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
}

/// A repository-qualified branch.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Branch {
    /// Project-registered repository name (never a URL).
    pub repository: String,
    /// Branch name.
    pub name: String,
}

/// `POST /api/v1/projects/{p}/regressions`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegressionCreate {
    /// Schema identifier (`dviscope.ingest/1.0-dev.N`).
    pub schema: String,
    /// Producer namespace.
    pub producer_id: ExternalKey,
    /// Producer key of the regression.
    pub regression_ref: ExternalKey,
    /// Suite name.
    pub suite: String,
    /// Repository-qualified branch.
    pub branch: Branch,
    /// The source manifest the regression runs.
    pub source_manifest_ref: ExternalKey,
    /// What started it.
    pub trigger: Trigger,
    /// When it started (execution time, reported).
    pub started_at: UtcTime,
    /// Free labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Links (CI run, scheduler job), never fetched.
    #[serde(default)]
    pub links: BTreeMap<String, String>,
    /// Extension data.
    #[serde(default)]
    pub ext: super::Ext,
}

/// One `(repository, revision)` of a source manifest.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SourceEntry {
    /// Project-registered repository name.
    pub repository: String,
    /// Revision (commit ID or equivalent).
    pub revision: String,
    /// Optional ancestry supplied by the flow (not part of the digest).
    #[serde(default)]
    pub ancestry: Vec<String>,
}

/// `POST /api/v1/projects/{p}/source-manifests`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceManifest {
    /// Schema identifier.
    pub schema: String,
    /// Producer namespace.
    pub producer_id: ExternalKey,
    /// Producer key of the manifest.
    pub source_manifest_ref: ExternalKey,
    /// Repositories and revisions.
    pub repositories: Vec<SourceEntry>,
}
