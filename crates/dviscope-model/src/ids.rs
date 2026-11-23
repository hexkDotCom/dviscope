//! Server IDs (opaque, type-prefixed ULIDs) and producer-chosen external keys.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Validation error for IDs and keys.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct IdError(pub String);

macro_rules! server_id {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// The type prefix, e.g. `reg_`.
            pub const PREFIX: &'static str = $prefix;

            /// A new ID from a ULID supplied by the caller (core crates never read clocks).
            #[must_use]
            pub fn from_ulid(ulid: ulid::Ulid) -> Self {
                Self(format!("{}{}", $prefix, ulid))
            }

            /// The textual form.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(s: String) -> Result<Self, IdError> {
                let rest = s
                    .strip_prefix($prefix)
                    .ok_or_else(|| IdError(format!("expected an ID starting with {}", $prefix)))?;
                ulid::Ulid::from_string(rest)
                    .map_err(|_| IdError(format!("not a valid {} ID: {s}", $prefix)))?;
                Ok(Self(s))
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

server_id!(/// A project.
    ProjectId, "prj_");
server_id!(/// A regression (one invocation).
    RegressionId, "reg_");
server_id!(/// A planned slot of a regression.
    SlotId, "slt_");
server_id!(/// A simulation attempt.
    AttemptId, "att_");
server_id!(/// A build requirement.
    BuildReqId, "brq_");
server_id!(/// A build attempt.
    BuildAttemptId, "bat_");
server_id!(/// A signature.
    SignatureId, "sig_");
server_id!(/// A source manifest.
    SourceManifestId, "src_");
server_id!(/// An ingest receipt.
    ReceiptId, "rcp_");

/// A producer-chosen external key (`regression_ref`, `slot_ref`, ...): 1–200 characters of
/// `[A-Za-z0-9._:/@+-]`, unique within `(project, producer, kind)`.
#[derive(
    Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct ExternalKey(String);

impl ExternalKey {
    /// Maximum length in characters (all allowed characters are ASCII).
    pub const MAX_LEN: usize = 200;

    /// The textual form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ExternalKey {
    type Error = IdError;
    fn try_from(s: String) -> Result<Self, IdError> {
        if s.is_empty() || s.len() > Self::MAX_LEN {
            return Err(IdError(format!(
                "external key must be 1-{} characters",
                Self::MAX_LEN
            )));
        }
        if let Some(bad) = s.chars().find(|c| {
            !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '@' | '+' | '-'))
        }) {
            return Err(IdError(format!(
                "external key contains {bad:?}; allowed: A-Z a-z 0-9 . _ : / @ + -"
            )));
        }
        Ok(Self(s))
    }
}

impl TryFrom<&str> for ExternalKey {
    type Error = IdError;
    fn try_from(s: &str) -> Result<Self, IdError> {
        Self::try_from(s.to_string())
    }
}

impl From<ExternalKey> for String {
    fn from(k: ExternalKey) -> String {
        k.0
    }
}

impl fmt::Debug for ExternalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for ExternalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_id_round_trip_and_prefix_check() {
        let id = RegressionId::from_ulid(ulid::Ulid::from_parts(1, 2));
        assert!(id.as_str().starts_with("reg_"));
        assert_eq!(
            RegressionId::try_from(id.as_str().to_string()),
            Ok(id.clone())
        );
        assert!(RegressionId::try_from(id.as_str().replace("reg_", "att_")).is_err());
        assert!(RegressionId::try_from("reg_notaulid".to_string()).is_err());
    }

    #[test]
    fn external_key_rules() {
        assert!(ExternalKey::try_from("nightly-1842/slot-17/attempt-1").is_ok());
        assert!(ExternalKey::try_from("").is_err());
        assert!(ExternalKey::try_from("has space").is_err());
        assert!(ExternalKey::try_from("x".repeat(201)).is_err());
        assert!(ExternalKey::try_from("x".repeat(200)).is_ok());
    }
}
