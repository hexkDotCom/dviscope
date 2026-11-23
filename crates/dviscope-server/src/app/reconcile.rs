//! Delivery reconciliation:
//! what the server holds for a producer's record identities and regressions, so a client
//! can compare its journal with it. Read-only; the caller's own producer only.

use dviscope_model::errors::ErrorCode;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row as _;

use super::App;
use crate::auth::Actor;
use crate::error::AppError;

/// The most identities one request may name.
pub const MAX_IDENTITIES: usize = 1000;
/// The most regressions one request may name.
pub const MAX_REGRESSIONS: usize = 100;

/// A reconciliation request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Record identities (receipt identities) to look up.
    #[serde(default)]
    pub identities: Vec<String>,
    /// Regression references whose slot counts to report.
    #[serde(default)]
    pub regressions: Vec<String>,
}

impl App {
    /// The receipts (every revision with its digest, or the retention tombstone) of the
    /// named identities, and the slot counts of the named regressions, for the collector's
    /// own producer.
    ///
    /// # Errors
    /// A non-collector actor, too many names, database errors.
    pub async fn reconcile(&self, actor: &Actor, req: &Request) -> Result<Value, AppError> {
        let Actor::Collector {
            project_id,
            producer_id,
            ..
        } = actor
        else {
            return Err(AppError::new(
                ErrorCode::Forbidden,
                "reconciliation is for collector tokens (their producer's records)",
            ));
        };
        if req.identities.len() > MAX_IDENTITIES || req.regressions.len() > MAX_REGRESSIONS {
            return Err(AppError::new(
                ErrorCode::TooLarge,
                format!(
                    "at most {MAX_IDENTITIES} identities and {MAX_REGRESSIONS} regressions per request"
                ),
            ));
        }
        let mut tx = self.snapshot().await?;
        let rows = sqlx::query(
            // A receipt's own digest first, then its aliases (an equivalent body under a
            // later compatible label): a collector matches any digest of its revision.
            "SELECT identity, revision, digest FROM (
                 SELECT identity, revision, digest, 0 AS k FROM receipts
                  WHERE project_id = $1 AND producer_id = $2 AND identity = ANY($3)
                 UNION ALL
                 SELECT identity, revision, digest, 1 FROM receipt_aliases
                  WHERE project_id = $1 AND producer_id = $2 AND identity = ANY($3)
             ) d ORDER BY identity, revision, k, digest",
        )
        .bind(project_id)
        .bind(producer_id)
        .bind(&req.identities)
        .fetch_all(&mut *tx)
        .await?;
        let expired = sqlx::query(
            "SELECT identity, max_revision FROM expired_receipts
              WHERE project_id = $1 AND producer_id = $2 AND identity = ANY($3)",
        )
        .bind(project_id)
        .bind(producer_id)
        .bind(&req.identities)
        .fetch_all(&mut *tx)
        .await?;
        let mut receipts = serde_json::Map::new();
        for r in &rows {
            let e = receipts
                .entry(r.get::<String, _>(0))
                .or_insert_with(|| json!({"revisions": [], "expired_max_revision": null}));
            if let Some(a) = e["revisions"].as_array_mut() {
                a.push(json!({"revision": r.get::<i32, _>(1), "digest": r.get::<String, _>(2)}));
            }
        }
        for r in &expired {
            let e = receipts
                .entry(r.get::<String, _>(0))
                .or_insert_with(|| json!({"revisions": [], "expired_max_revision": null}));
            e["expired_max_revision"] = json!(r.get::<i32, _>(1));
        }

        let mut regressions = vec![];
        for rref in &req.regressions {
            let row = sqlx::query(
                "SELECT r.state,
                        (SELECT count(*) FROM slots s
                          WHERE s.project_id = r.project_id AND s.regression_id = r.id
                            AND s.removed_revision IS NULL),
                        (SELECT count(DISTINCT a.slot_id) FROM attempts a JOIN slots s
                             ON s.project_id = a.project_id AND s.id = a.slot_id
                          WHERE s.project_id = r.project_id AND s.regression_id = r.id),
                        (SELECT count(DISTINCT a.slot_id) FROM attempts a JOIN slots s
                             ON s.project_id = a.project_id AND s.id = a.slot_id
                          WHERE s.project_id = r.project_id AND s.regression_id = r.id
                            AND EXISTS (SELECT 1 FROM attempt_facts f
                                         WHERE f.project_id = a.project_id AND f.attempt_id = a.id))
                   FROM regressions r
                  WHERE r.project_id = $1 AND r.producer_id = $2 AND r.ref = $3",
            )
            .bind(project_id)
            .bind(producer_id)
            .bind(rref)
            .fetch_optional(&mut *tx)
            .await?;
            let v = if let Some(r) = row {
                json!({"regression_ref": rref, "found": true, "expired": false,
                       "state": r.get::<String, _>(0),
                       "slots": r.get::<i64, _>(1),
                       "slots_started": r.get::<i64, _>(2),
                       "slots_reported": r.get::<i64, _>(3)})
            } else {
                let gone = sqlx::query(
                    "SELECT 1 FROM expired_regressions
                      WHERE project_id = $1 AND producer_id = $2 AND ref = $3",
                )
                .bind(project_id)
                .bind(producer_id)
                .bind(rref)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
                json!({"regression_ref": rref, "found": false, "expired": gone})
            };
            regressions.push(v);
        }
        tx.commit().await?;
        Ok(json!({"receipts": receipts, "regressions": regressions}))
    }
}
