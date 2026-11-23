//! A source manifest re-declared after a coordinated upgrade (its root schema
//! label bumped, content unchanged) is a duplicate, not a conflict. Only source manifests,
//! only their root label, only reviewed revisions; every other record stays strict.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_model::schema::DEV_REVISION;
use dviscope_server::app::{
    SOURCE_MANIFEST_COMPATIBLE, payload_digest, source_manifest_compat_digests,
};
use serde_json::{Value, json};

/// `v` with every `schema` label of the current revision set to the previous revision.
fn previous(v: &Value) -> Value {
    let (cur, prev) = (
        format!("/1.0-dev.{DEV_REVISION}"),
        format!("/1.0-dev.{}", DEV_REVISION - 1),
    );
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| {
                    let x = match (k.as_str(), x) {
                        ("schema", Value::String(s)) => json!(s.replace(&cur, &prev)),
                        _ => previous(x),
                    };
                    (k.clone(), x)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(previous).collect()),
        other => other.clone(),
    }
}

async fn set_receipt_digest(t: &TestDb, identity: &str, digest: &str) {
    // A consistent receipt from before: the column and the receipt's own digest.
    let n = sqlx::query(
        "UPDATE receipts SET digest = $2, receipt = jsonb_set(receipt, '{digest}', to_jsonb($2::text))
          WHERE identity = $1",
    )
        .bind(identity)
        .bind(digest)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .rows_affected();
    assert_eq!(n, 1, "{identity}");
}

#[tokio::test]
async fn the_same_source_manifest_after_a_schema_bump_is_a_duplicate() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let _ = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let body = source_manifest();
    ok(app.create_source_manifest(&c, &body).await);
    // As if received before the upgrade: the digest under the previous label.
    let old = payload_digest(&previous(&body)).unwrap_or_else(|e| panic!("{e:?}"));
    set_receipt_digest(&t, "source_manifest:sm1", &old).await;
    let r = app
        .create_source_manifest(&c, &body)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(r.duplicate, "{:?}", r.body);
    // The acknowledgement names the record sent, as the collector checks it (spool
    // receipt_matches): identity, the digest of the body sent, revision 1, a result, the
    // server's IDs.
    let sent = payload_digest(&body).unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(sent, old);
    assert_eq!(r.body["identity"], "source_manifest:sm1", "{}", r.body);
    assert_eq!(r.body["digest"], json!(sent), "{}", r.body);
    assert_eq!(r.body["revision"], 1, "{}", r.body);
    assert_eq!(r.body["result"], "duplicate", "{}", r.body);
    assert!(
        r.body["server_ids"]
            .as_object()
            .is_some_and(|m| !m.is_empty()),
        "{}",
        r.body
    );
    // The receipt keeps the digest it was received with (column and embedded), and the
    // digest sent is its alias: reconciliation lists both, the original first, so
    // collectors of either label match; the next declaration is a duplicate, one alias.
    let rec = || async {
        app.reconcile(
            &c,
            &dviscope_server::app::reconcile::Request {
                identities: vec!["source_manifest:sm1".into()],
                regressions: vec![],
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))
    };
    let stored: (String, String) = sqlx::query_as(
        "SELECT digest, receipt->>'digest' FROM receipts WHERE identity = 'source_manifest:sm1'",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stored, (old.clone(), old.clone()));
    let revs = |v: &Value| v["receipts"]["source_manifest:sm1"]["revisions"].clone();
    let want = json!([{"revision": 1, "digest": old}, {"revision": 1, "digest": sent}]);
    assert_eq!(revs(&rec().await), want);
    let again = app
        .create_source_manifest(&c, &body)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(again.duplicate);
    assert_eq!(again.body["digest"], json!(sent));
    assert_eq!(
        revs(&rec().await),
        want,
        "one alias, however often it is declared"
    );
    // Other content: still a conflict.
    let mut other = body.clone();
    other["repositories"][0]["revision"] = json!("def456");
    let e = app
        .create_source_manifest(&c, &other)
        .await
        .err()
        .unwrap_or_else(|| panic!("other content must conflict"));
    assert_eq!(e.code, ErrorCode::RevisionConflict, "{e:?}");
    // Deleting a receipt (retention) deletes its aliases.
    sqlx::query("DELETE FROM receipts WHERE identity = 'source_manifest:sm1'")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM receipt_aliases")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(left, 0);
    t.drop().await;
}

/// Any other record is compared exactly: an attempt received under the previous label
/// (whose rules may have differed) re-sent unchanged is a conflict, never acknowledged.
#[tokio::test]
async fn an_attempt_from_before_the_bump_is_never_a_duplicate() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let ev = passing();
    accept_pipeline(&t.pool, &ev).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    let rep = report("r1", "s1", "a1", 1, 1, &ev, &[]);
    ok(ingest(&app, &c, &rep).await);
    let old = payload_digest(&previous(&rep)).unwrap_or_else(|e| panic!("{e:?}"));
    set_receipt_digest(&t, "simulation_attempt:a1:r1", &old).await;
    let e = ingest(&app, &c, &rep)
        .await
        .err()
        .unwrap_or_else(|| panic!("an attempt must not be a cross-revision duplicate"));
    assert_eq!(e.code, ErrorCode::RevisionConflict, "{e:?}");
    // Nor under the source manifests' rule (only the root label set back).
    let mut root_only = rep.clone();
    root_only["schema"] = previous(&rep)["schema"].clone();
    let old = payload_digest(&root_only).unwrap_or_else(|e| panic!("{e:?}"));
    set_receipt_digest(&t, "simulation_attempt:a1:r1", &old).await;
    let e = ingest(&app, &c, &rep)
        .await
        .err()
        .unwrap_or_else(|| panic!("an attempt must not be a cross-revision duplicate"));
    assert_eq!(e.code, ErrorCode::RevisionConflict, "{e:?}");
    let _ = pid;
    t.drop().await;
}

#[test]
fn only_the_root_label_of_a_source_manifest_is_compared() {
    let body = source_manifest();
    let d = source_manifest_compat_digests(&body);
    let reviewed = SOURCE_MANIFEST_COMPATIBLE
        .iter()
        .filter(|k| **k < DEV_REVISION)
        .count();
    assert_eq!(d.len(), reviewed);
    assert!(d.contains(&payload_digest(&previous(&body)).unwrap_or_default()));
    // A nested `schema` string (an application value) is never relabelled.
    let mut nested = body.clone();
    nested["ext"] = json!({"schema": body["schema"].clone()});
    let mut nested_old = previous(&nested);
    nested_old["ext"]["schema"] = body["schema"].clone();
    assert!(
        source_manifest_compat_digests(&nested)
            .contains(&payload_digest(&nested_old).unwrap_or_default())
    );
    assert!(
        !source_manifest_compat_digests(&nested)
            .contains(&payload_digest(&previous(&nested)).unwrap_or_default())
    );
    // A body not labelled with this build's ingest schema: nothing.
    let mut other = body.clone();
    other["schema"] = json!("fp/1");
    assert!(source_manifest_compat_digests(&other).is_empty());
}
