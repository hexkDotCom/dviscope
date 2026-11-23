//! `dviscope.checklist/1.0`: a feature checklist, authored in YAML by people.
//! Importing it creates an immutable checklist version; items are matched across versions
//! by `item_id`, and a changed `requires` or evidence digest is a new item revision.

use serde::{Deserialize, Serialize};

use crate::canonical::Digest;

/// Schema identifier of checklists (a user-authored file format).
pub const CHECKLIST: &str = "dviscope.checklist/1.0";

/// A checklist version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Checklist {
    /// `dviscope.checklist/1.0` (optional in files; checked when present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Stable checklist identifier.
    pub checklist_id: String,
    /// Title.
    pub title: String,
    /// Version label (each import of a new version is immutable).
    pub version: String,
    /// The feature it signs off.
    pub feature: String,
    /// Checklist owner.
    pub owner: String,
    /// Items.
    pub items: Vec<ChecklistItem>,
}

/// One requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChecklistItem {
    /// Stable item identifier (matched across versions).
    pub item_id: String,
    /// Title.
    pub title: String,
    /// Item owner (falls back to the checklist owner).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// What must have passed.
    pub requires: Requires,
    /// Where the item applies (default: everywhere).
    #[serde(default)]
    pub applies_to: AppliesTo,
    /// The evidence must be at most this many days old.
    pub freshness_days: u32,
    /// External evidence (declared, not verified in 0.1); needs an attestation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ExternalEvidence>,
}

/// Required tests and configurations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Requires {
    /// Test name globs (`*`, `?`).
    pub tests: Vec<String>,
    /// Configuration labels (simulator vendor, e.g. `questa`) or config digests
    /// (`sha256:…`); empty: any configuration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configs: Vec<String>,
    /// Distinct passing seeds needed per test and configuration (default 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_passing_seeds: Option<u32>,
}

/// Applicability.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppliesTo {
    /// Only this repository-qualified branch (`repo/name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Only branches of these repositories.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<String>,
}

/// A piece of external evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalEvidence {
    /// Name.
    pub name: String,
    /// Declared digest of the evidence.
    pub digest: Digest,
    /// Where a reviewer finds it (never fetched).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri_hint: Option<String>,
}
