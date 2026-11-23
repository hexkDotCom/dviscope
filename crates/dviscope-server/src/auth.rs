//! Authentication and authorization: tokens, local accounts, sessions, and the
//! one `authorize(actor, action, object)` table. Unmapped actions are denied.

use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use dviscope_model::errors::ErrorCode;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Row as _};

use crate::error::AppError;

/// Every action a route maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Create a regression.
    RegressionCreate,
    /// Create a source manifest.
    SourceManifestCreate,
    /// Declare a manifest chunk.
    ManifestChunk,
    /// Seal the manifest.
    ManifestSeal,
    /// Amend the sealed manifest.
    ManifestAmend,
    /// Mark slots cancelled or skipped.
    SlotMark,
    /// Submit start and report records.
    IngestSubmit,
    /// Finish a regression.
    RegressionFinish,
    /// Read a regression and its slots.
    RegressionRead,
    /// Read a comparison.
    ComparisonRead,
    /// Edit a triage case.
    TriageWrite,
    /// Create or revoke an exception.
    ExceptionWrite,
    /// Evaluate readiness.
    ReadinessRead,
    /// Read the project's change feed.
    ChangesRead,
    /// Read the project's administration overview (members, token metadata, producers,
    /// pipelines); never secrets.
    AdminRead,
    /// Publish readiness (store publication receipts, record status updates).
    PublicationWrite,
    /// Read checklists and feature evaluations.
    ChecklistRead,
    /// Import checklists, attest and revoke.
    ChecklistWrite,
    /// Read the project's rules status: active pipeline, sample, activations.
    RulesRead,
    /// Upload activation samples and activate rules (project admins).
    RulesWrite,
    /// Read the project hierarchy (health dashboard).
    HierarchyRead,
    /// Import the project hierarchy (project admins).
    HierarchyWrite,
    /// Read regression health (dashboard).
    HealthRead,
}

/// Every action, for the route-matrix test.
pub const ALL_ACTIONS: &[Action] = &[
    Action::RegressionCreate,
    Action::SourceManifestCreate,
    Action::ManifestChunk,
    Action::ManifestSeal,
    Action::ManifestAmend,
    Action::SlotMark,
    Action::IngestSubmit,
    Action::RegressionFinish,
    Action::RegressionRead,
    Action::ComparisonRead,
    Action::TriageWrite,
    Action::ExceptionWrite,
    Action::ReadinessRead,
    Action::ChangesRead,
    Action::AdminRead,
    Action::PublicationWrite,
    Action::ChecklistRead,
    Action::ChecklistWrite,
    Action::RulesRead,
    Action::RulesWrite,
    Action::HierarchyRead,
    Action::HierarchyWrite,
    Action::HealthRead,
];

/// Project roles, ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Reads.
    Viewer,
    /// Triage.
    Triager,
    /// Administration.
    Admin,
}

impl Role {
    /// Parses a stored role name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "viewer" => Self::Viewer,
            "triager" => Self::Triager,
            "admin" => Self::Admin,
            _ => return None,
        })
    }
}

/// The policy table: the collector scope or the minimum role an action needs.
#[must_use]
pub fn policy(a: Action) -> (Option<&'static str>, Option<Role>) {
    match a {
        Action::RegressionCreate | Action::SourceManifestCreate => {
            (Some("regression:create"), None)
        }
        Action::ManifestChunk => (Some("manifest:declare"), None),
        Action::ManifestSeal => (Some("manifest:seal"), None),
        Action::ManifestAmend | Action::SlotMark => (Some("manifest:amend"), None),
        Action::IngestSubmit => (Some("ingest:submit"), None),
        Action::RegressionFinish => (Some("regression:finish"), None),
        Action::RegressionRead
        | Action::ComparisonRead
        | Action::ReadinessRead
        | Action::ChangesRead
        | Action::ChecklistRead
        | Action::RulesRead
        | Action::HierarchyRead
        | Action::HealthRead => (None, Some(Role::Viewer)),
        Action::TriageWrite | Action::PublicationWrite => (None, Some(Role::Triager)),
        Action::ExceptionWrite
        | Action::AdminRead
        | Action::ChecklistWrite
        | Action::RulesWrite
        | Action::HierarchyWrite => (None, Some(Role::Admin)),
    }
}

/// Scopes a collector token may carry.
pub const SCOPES: &[&str] = &[
    "regression:create",
    "manifest:declare",
    "manifest:seal",
    "manifest:amend",
    "ingest:submit",
    "regression:finish",
];

/// Who is acting.
#[derive(Debug, Clone)]
pub enum Actor {
    /// A collector token: one project, one producer, scopes.
    Collector {
        /// Token row.
        token_id: i64,
        /// Project.
        project_id: i64,
        /// Producer.
        producer_id: i64,
        /// Scopes.
        scopes: Vec<String>,
    },
    /// A user (personal token or browser session), with the current memberships.
    User {
        /// User.
        user_id: i64,
        /// Personal token, when one was used.
        token_id: Option<i64>,
        /// Memberships: project → role.
        roles: Vec<(i64, Role)>,
    },
}

impl Actor {
    /// The credential ID recorded with every report revision (B.17 quarantine).
    #[must_use]
    pub fn credential_id(&self) -> i64 {
        match self {
            Self::Collector { token_id, .. } => *token_id,
            Self::User {
                token_id, user_id, ..
            } => token_id.unwrap_or(-*user_id),
        }
    }
}

/// Decides whether `actor` may perform `action` on an object of `project_id`.
///
/// # Errors
/// 403 `E_FORBIDDEN` naming the missing scope or role.
pub fn authorize(actor: &Actor, action: Action, project_id: i64) -> Result<(), AppError> {
    let (scope, role) = policy(action);
    let ok = match actor {
        Actor::Collector {
            project_id: p,
            scopes,
            ..
        } => *p == project_id && scope.is_some_and(|s| scopes.iter().any(|x| x == s)),
        Actor::User { roles, .. } => {
            role.is_some_and(|need| roles.iter().any(|(p, r)| *p == project_id && *r >= need))
        }
    };
    if ok {
        Ok(())
    } else {
        let need = scope.map_or_else(
            || format!("role {:?}", role.unwrap_or(Role::Admin)),
            |s| format!("scope {s}"),
        );
        Err(AppError::new(
            ErrorCode::Forbidden,
            format!("this credential cannot do that here (needs {need})"),
        ))
    }
}

/// A new token: `dvis_` + 43 base64url characters (32 random bytes).
///
/// # Errors
/// The OS random source failed.
pub fn new_token() -> Result<String, AppError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AppError::internal("random source"))?;
    Ok(format!(
        "dvis_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    ))
}

/// SHA-256 of a token (what is stored).
#[must_use]
pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Resolves a bearer token to an actor (expired, revoked or unknown → 401).
///
/// # Errors
/// 401 `E_UNAUTHENTICATED`, or a database error.
pub async fn actor_from_token(db: &PgPool, token: &str) -> Result<Actor, AppError> {
    let unauth = || {
        AppError::new(
            ErrorCode::Unauthenticated,
            "unknown, expired or revoked token",
        )
    };
    if !token.starts_with("dvis_") || token.len() != 48 {
        return Err(unauth());
    }
    let row = sqlx::query(
        "SELECT t.id, t.kind, t.project_id, t.producer_id, t.user_id, t.scopes, u.disabled
           FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id
          WHERE t.hash = $1 AND t.revoked_at IS NULL AND t.expires_at > now()",
    )
    .bind(token_hash(token))
    .fetch_optional(db)
    .await?
    .ok_or_else(unauth)?;
    let token_id: i64 = row.get(0);
    let kind: String = row.get(1);
    if kind == "collector" {
        return Ok(Actor::Collector {
            token_id,
            project_id: row.get(2),
            producer_id: row.get(3),
            scopes: row.get(5),
        });
    }
    if row.get::<Option<bool>, _>(6).unwrap_or(true) {
        return Err(unauth());
    }
    let user_id: i64 = row.get(4);
    Ok(Actor::User {
        user_id,
        token_id: Some(token_id),
        roles: roles_of(db, user_id).await?,
    })
}

/// The current memberships of a user (a role change applies at once).
///
/// # Errors
/// Database errors.
pub async fn roles_of(db: &PgPool, user_id: i64) -> Result<Vec<(i64, Role)>, AppError> {
    let rows = sqlx::query("SELECT project_id, role FROM memberships WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| Role::parse(&r.get::<String, _>(1)).map(|role| (r.get(0), role)))
        .collect())
}

fn argon2() -> Argon2<'static> {
    // Argon2id, m = 19 MiB, t = 2, p = 1.
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19 * 1024, 2, 1, None).unwrap_or_default(),
    )
}

/// Hashes a password (length ≥ 12).
///
/// # Errors
/// Too short, or the hasher failed.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    if password.chars().count() < 12 {
        return Err(AppError::field(
            ErrorCode::Invalid,
            "a password has at least 12 characters",
            "password",
        ));
    }
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| AppError::internal("random source"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| AppError::internal("salt"))?;
    Ok(argon2()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AppError::internal("password hash"))?
        .to_string())
}

/// Verifies a password against a stored PHC string.
#[must_use]
pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| argon2().verify_password(password.as_bytes(), &h).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_have_the_documented_shape() {
        let t = new_token().unwrap_or_default();
        assert!(t.starts_with("dvis_") && t.len() == 48, "{t}");
    }

    #[test]
    fn collector_scopes_and_projects() {
        let c = Actor::Collector {
            token_id: 1,
            project_id: 7,
            producer_id: 2,
            scopes: vec!["ingest:submit".into()],
        };
        assert!(authorize(&c, Action::IngestSubmit, 7).is_ok());
        assert!(authorize(&c, Action::IngestSubmit, 8).is_err());
        assert!(authorize(&c, Action::ManifestSeal, 7).is_err());
        assert!(authorize(&c, Action::RegressionRead, 7).is_err());
        let u = Actor::User {
            user_id: 1,
            token_id: None,
            roles: vec![(7, Role::Viewer)],
        };
        assert!(authorize(&u, Action::RegressionRead, 7).is_ok());
        assert!(authorize(&u, Action::IngestSubmit, 7).is_err());
        // Every action has a policy entry.
        for a in ALL_ACTIONS {
            let (s, r) = policy(*a);
            assert!(s.is_some() || r.is_some(), "{a:?}");
        }
    }

    #[test]
    fn passwords() {
        assert!(hash_password("short").is_err());
        let h = hash_password("correct horse battery").unwrap_or_default();
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong horse battery", &h));
    }
}
