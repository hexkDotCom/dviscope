//! The error registry: stable codes with HTTP status, retry disposition,
//! CLI exit code and recovery action. One table, used by server, CLI and docs.

use serde::{Deserialize, Serialize};

/// How a client should treat an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Retry {
    /// Permanent: do not retry the same request.
    No,
    /// Stop sending (credential problem) and alert.
    Stop,
    /// Retry later with back-off (honour `Retry-After`).
    Later,
}

macro_rules! registry {
    ($( $(#[$doc:meta])* $variant:ident => $code:literal, $http:literal, $retry:ident, $exit:literal, $action:literal; )*) => {
        /// A stable error code.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
        pub enum ErrorCode {
            $( $(#[$doc])* #[serde(rename = $code)] $variant, )*
        }

        impl ErrorCode {
            /// Every registered code, in registry order.
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant),*];

            /// The code as sent on the wire (`E_...`).
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self { $(ErrorCode::$variant => $code,)* }
            }

            /// HTTP status; 0 for client-only codes.
            #[must_use]
            pub fn http_status(self) -> u16 {
                match self { $(ErrorCode::$variant => $http,)* }
            }

            /// Retry disposition.
            #[must_use]
            pub fn retry(self) -> Retry {
                match self { $(ErrorCode::$variant => Retry::$retry,)* }
            }

            /// CLI exit code when this error ends a command.
            #[must_use]
            pub fn cli_exit(self) -> u8 {
                match self { $(ErrorCode::$variant => $exit,)* }
            }

            /// The recovery action shown to the user.
            #[must_use]
            pub fn recovery(self) -> &'static str {
                match self { $(ErrorCode::$variant => $action,)* }
            }
        }
    };
}

registry! {
    /// A field or record is invalid.
    Invalid => "E_INVALID", 400, No, 3, "fix the named field";
    /// The schema version is not the one this server accepts.
    SchemaVersion => "E_SCHEMA_VERSION", 400, No, 3, "use a client that matches the server's schema version";
    /// Missing or invalid credential.
    Unauthenticated => "E_UNAUTHENTICATED", 401, Stop, 3, "check the token";
    /// The credential lacks a scope or role.
    Forbidden => "E_FORBIDDEN", 403, Stop, 3, "check the token's scope or the user's role";
    /// The referenced object does not exist.
    NotFound => "E_NOT_FOUND", 404, No, 3, "check the reference";
    /// Same revision with a different payload.
    RevisionConflict => "E_REVISION_CONFLICT", 409, No, 3, "send the correction as a new revision";
    /// A newer revision exists.
    StaleRevision => "E_STALE_REVISION", 409, No, 3, "nothing to do: a newer revision exists";
    /// The edit was based on an older revision (`If-Match`); the response names the change.
    PreconditionFailed => "E_PRECONDITION_FAILED", 412, No, 3, "reload, then apply your change again";
    /// A retry whose exact inputs differ from the slot.
    RetryInputsDiffer => "E_RETRY_INPUTS_DIFFER", 409, No, 3, "declare another slot for different inputs";
    /// The data is past retention.
    Expired => "E_EXPIRED", 410, No, 3, "the regression is past retention";
    /// A replay older than the deduplication horizon.
    ReplayExpired => "E_REPLAY_EXPIRED", 410, No, 3, "the record is older than the deduplication horizon";
    /// A request or record exceeds a published limit.
    TooLarge => "E_TOO_LARGE", 413, No, 3, "split the batch or reduce the record";
    /// Well-formed but not processable.
    Unprocessable => "E_UNPROCESSABLE", 422, No, 3, "fix the record";
    /// A feature this version does not support.
    NotSupported => "E_NOT_SUPPORTED", 400, No, 3, "the feature is not available in this version";
    /// Cookie and bearer credentials in one request.
    MixedCredentials => "E_MIXED_CREDENTIALS", 400, No, 3, "send exactly one credential";
    /// Too many requests or bytes for this credential.
    RateLimited => "E_RATE_LIMITED", 429, Later, 4, "wait and retry (Retry-After)";
    /// Unexpected server error.
    Internal => "E_INTERNAL", 500, Later, 5, "report it with the correlation ID";
    /// Server temporarily unavailable or overloaded.
    Unavailable => "E_UNAVAILABLE", 503, Later, 4, "wait and retry";
    /// Server storage above its high-water mark.
    StorageFull => "E_STORAGE_FULL", 507, Later, 4, "free disk space on the server";
    /// Client refused a non-HTTPS URL before sending credentials.
    InsecureUrl => "E_INSECURE_URL", 0, No, 2, "use an https:// server URL";
}

/// The JSON body of every API error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    /// Stable code.
    pub code: ErrorCode,
    /// Human-readable message (never contains log text, tokens or paths).
    pub message: String,
    /// The offending field, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The offending record of a batch, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    /// Whether anything was committed before the error.
    pub committed: bool,
    /// Correlation ID for logs.
    pub correlation_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for c in ErrorCode::ALL {
            assert!(c.as_str().starts_with("E_"), "{}", c.as_str());
            assert!(seen.insert(c.as_str()), "duplicate {}", c.as_str());
            assert!(
                !c.recovery().trim().is_empty(),
                "{} has no recovery text",
                c.as_str()
            );
        }
    }

    #[test]
    fn serde_uses_wire_codes() {
        let s = serde_json::to_string(&ErrorCode::RetryInputsDiffer).unwrap_or_default();
        assert_eq!(s, "\"E_RETRY_INPUTS_DIFFER\"");
    }
}
