//! Acceptance, feature mode at the app+DB
//! layer: candidate selection by execution time from the candidate index, no fallback to an
//! older pass, time trust, incomplete and expired candidates, seeds, freshness,
//! attestations bound to item revisions. Invented records only.

mod common;

use common::*;
use dviscope_model::wire::checklist::Checklist;
use dviscope_server::app::App;
use dviscope_server::app::checklists::AttestRequest;
use dviscope_server::auth::{Actor, Role};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

async fn user(t: &TestDb, name: &str, pid: i64, role: Role) -> Actor {
    let v = dviscope_server::admin::create_user(&t.pool, name, "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    Actor::User {
        user_id: v["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, role)],
    }
}

fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// A regression started at `started` with slots `(slot_ref, test, seed, passes?)`; each
/// slot with `Some(pass)` gets one report; finished (and sealed) when `finish`.
async fn reg(
    app: &App,
    c: &Actor,
    r: &str,
    start: OffsetDateTime,
    slots: &[(&str, &str, &str, Option<bool>)],
    finish: bool,
) {
    let _ = app.create_source_manifest(c, &source_manifest()).await;
    let mut body = regression(r);
    body["started_at"] = json!(ts(start));
    ok(app.create_regression(c, &body).await);
    let decls: Vec<Value> = slots
        .iter()
        .map(|(s, test, seed, _)| {
            json!({"slot_ref": s, "exec_inputs": {"test": test, "seed": seed}, "required": true})
        })
        .collect();
    ok(app.manifest_chunk(c, r, 1, &chunk(&decls)).await);
    ok(app.manifest_seal(c, r, &seal(&decls)).await);
    let (pass, fail) = (passing(), failing());
    for (i, (s, test, seed, result)) in slots.iter().enumerate() {
        let Some(p) = result else { continue };
        let a = format!("{r}-a{i}");
        ok(ingest(app, c, &started(r, s, &a, 1, &[])).await);
        let mut rep = report(r, s, &a, 1, 1, if *p { &pass } else { &fail }, &[]);
        rep["execution"] = json!({"test": test, "seed": seed});
        ok(ingest(app, c, &rep).await);
    }
    if finish {
        ok(app
            .finish(c, r, &json!({"kind": "finish", "regression_ref": r}))
            .await);
    }
}

fn item(id: &str, tests: &[&str], seeds: u32, days: u32) -> Value {
    json!({"item_id": id, "title": format!("{id} works"), "requires": {"tests": tests,
           "min_passing_seeds": seeds}, "freshness_days": days})
}

fn checklist(version: &str, items: Vec<Value>) -> Checklist {
    serde_json::from_value(
        json!({"schema": "dviscope.checklist/1.0", "checklist_id": "uart-fs",
        "title": "UART feature sign-off", "version": version, "feature": "uart", "owner": "Ana",
        "items": items}),
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

fn state<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["items"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["item_id"] == id))
        .unwrap_or_else(|| panic!("no item {id}: {v}"))
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one scenario, many oracles
async fn c16_feature_mode_and_c13_attestation_digest() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, token_id) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let admin = user(&t, "ada", pid, Role::Admin).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let day = Duration::days(1);
    // R1 (3 days ago): uart_tx seeds 1-3 pass; spi_x, gpio (seed 1), uart_rx pass.
    reg(
        &app,
        &c,
        "R1",
        now - 3 * day,
        &[
            ("tx1", "uart_tx", "1", Some(true)),
            ("tx2", "uart_tx", "2", Some(true)),
            ("tx3", "uart_tx", "3", Some(true)),
            ("spi", "spi_x", "1", Some(true)),
            ("gpio", "gpio", "1", Some(true)),
            ("rx", "uart_rx", "1", Some(true)),
        ],
        true,
    )
    .await;
    // R2 (2 days ago): uart_tx seed 2 fails.
    reg(
        &app,
        &c,
        "R2",
        now - 2 * day,
        &[
            ("tx1", "uart_tx", "1", Some(true)),
            ("tx2", "uart_tx", "2", Some(false)),
        ],
        true,
    )
    .await;
    // R0 ran 10 days ago, delivered after R2: never the candidate.
    reg(
        &app,
        &c,
        "R0",
        now - 10 * day,
        &[("tx1", "uart_tx", "1", Some(true))],
        true,
    )
    .await;
    // R3 (1 day ago): spi_x passes but the regression is not finished (incomplete).
    reg(
        &app,
        &c,
        "R3",
        now - day,
        &[("spi", "spi_x", "1", Some(true))],
        false,
    )
    .await;
    // Rskew claims to start 30 days in the future: time uncertain.
    reg(
        &app,
        &c,
        "Rskew",
        now + 30 * day,
        &[("i2c", "i2c", "1", Some(true))],
        true,
    )
    .await;

    let mut evidenced = item("rx", &["uart_rx"], 1, 30);
    evidenced["evidence"] =
        json!([{"name": "coverage", "digest": format!("sha256:{}", "a".repeat(64))}]);
    let v1 = checklist(
        "1",
        vec![
            item("tx", &["uart_*x"], 1, 30),
            item("spi", &["spi_*"], 1, 30),
            item("i2c", &["i2c"], 1, 30),
            item("gpio", &["gpio"], 2, 30),
            item("none", &["nope_*"], 1, 30),
            item("stale", &["gpio"], 1, 2),
            evidenced.clone(),
        ],
    );
    // Viewers cannot import; import is idempotent; another body under the same version is refused.
    assert!(app.import_checklist(&viewer(pid), "p1", &v1).await.is_err());
    let imp = app
        .import_checklist(&admin, "p1", &v1)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(imp["result"], "imported");
    let again = app
        .import_checklist(&admin, "p1", &v1)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(again["result"], "duplicate");
    let mut other = v1.clone();
    other.title = "changed".into();
    assert!(app.import_checklist(&admin, "p1", &other).await.is_err());

    let eval = |at: OffsetDateTime| {
        let app = app.clone();
        let v = viewer(pid);
        async move {
            app.evaluate_feature(&v, "p1", "uart-fs", None, "rtl/main", at)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"))
        }
    };
    let e = eval(now).await;
    // uart_*x matches uart_tx and uart_rx: uart_tx's candidate is R2 (newest by execution
    // time; R0 delivered later is older), seed 2 failed.
    let tx = state(&e, "tx");
    assert_eq!(tx["state"], "failed", "{tx}");
    let tx_pair = tx["pairs"]
        .as_array()
        .and_then(|p| p.iter().find(|x| x["test"] == "uart_tx"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(tx_pair["regression"], "R2", "{tx}");
    assert_eq!(state(&e, "spi")["state"], "missing");
    assert!(
        state(&e, "spi")["reasons"][0]
            .as_str()
            .unwrap_or("")
            .contains("candidate incomplete"),
        "{e}"
    );
    assert_eq!(state(&e, "i2c")["state"], "outdated");
    assert!(
        state(&e, "i2c")["reasons"][0]
            .as_str()
            .unwrap_or("")
            .contains("time uncertain")
    );
    assert_eq!(state(&e, "gpio")["state"], "missing");
    assert!(
        state(&e, "gpio")["reasons"][0]
            .as_str()
            .unwrap_or("")
            .contains("1/2 passing seeds")
    );
    assert_eq!(state(&e, "none")["state"], "missing");
    assert_eq!(state(&e, "stale")["state"], "outdated");
    assert_eq!(state(&e, "rx")["state"], "unreviewed");
    assert_eq!(e["ready"], false);
    assert_eq!(e["result"], "not ready");
    assert_eq!(
        state(&e, "rx")["owner"],
        "Ana",
        "owner falls back to the checklist owner"
    );

    // C13: an attestation in the same second changes the next digest.
    let rx = state(&e, "rx").clone();
    let req = AttestRequest {
        version: "1".into(),
        item_id: "rx".into(),
        item_revision: i32::try_from(rx["revision"].as_i64().unwrap_or(0)).unwrap_or(0),
        evidence_digest: rx["evidence_digest"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    };
    // A stale view (wrong revision) is refused.
    let mut stale = req.clone();
    stale.item_revision += 1;
    assert!(app.attest(&admin, "p1", "uart-fs", &stale).await.is_err());
    // Only admins attest.
    let tri = user(&t, "tim", pid, Role::Triager).await;
    assert!(app.attest(&tri, "p1", "uart-fs", &req).await.is_err());
    let att = app
        .attest(&admin, "p1", "uart-fs", &req)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let e2 = eval(now).await;
    assert_ne!(e2["digest"], e["digest"]);
    assert_eq!(state(&e2, "rx")["state"], "satisfied");
    assert!(state(&e2, "rx")["valid_until"].is_string());

    // A new version changing the evidence digest is a new item revision: unreviewed again.
    evidenced["evidence"] =
        json!([{"name": "coverage", "digest": format!("sha256:{}", "b".repeat(64))}]);
    let v2 = checklist("2", vec![item("tx", &["uart_*x"], 1, 30), evidenced]);
    let imp2 = app
        .import_checklist(&admin, "p1", &v2)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let rev = imp2["items"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["item_id"] == "rx"))
        .map(|x| x["revision"].clone());
    assert_eq!(rev, Some(json!(2)));
    let e3 = eval(now).await;
    assert_eq!(e3["checklist"]["version"], "2");
    assert_eq!(state(&e3, "rx")["state"], "unreviewed");
    // The old version still evaluates with its attestation.
    let old = app
        .evaluate_feature(&viewer(pid), "p1", "uart-fs", Some("1"), "rtl/main", now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(state(&old, "rx")["state"], "satisfied");
    // Revoking it makes it unreviewed.
    app.revoke_attestation(&admin, "p1", "uart-fs", att["id"].as_i64().unwrap_or(0))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let old = app
        .evaluate_feature(&viewer(pid), "p1", "uart-fs", Some("1"), "rtl/main", now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(state(&old, "rx")["state"], "unreviewed");

    // Another branch has no candidates.
    let other_branch = app
        .evaluate_feature(&viewer(pid), "p1", "uart-fs", Some("1"), "rtl/dev", now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(state(&other_branch, "tx")["state"], "missing");

    // R2's facts expire: the candidate stays R2 (missing, evidence expired), never R1.
    sqlx::query("UPDATE candidate_index SET state = 'expired' WHERE regression_ref = 'R2'")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let e4 = eval(now).await;
    let tx = state(&e4, "tx");
    assert_eq!(tx["state"], "missing", "{tx}");
    assert!(
        tx["reasons"]
            .to_string()
            .contains("evidence expired (regression R2)"),
        "{tx}"
    );
    // Deleted behaves the same.
    sqlx::query("UPDATE candidate_index SET state = 'deleted' WHERE regression_ref = 'R2'")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let e4d = eval(now).await;
    assert_eq!(state(&e4d, "tx")["state"], "missing", "{e4d}");
    sqlx::query("UPDATE candidate_index SET state = 'live' WHERE regression_ref = 'R2'")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // R2's credential is quarantined: insufficient, candidate still R2 (no fallback to R1).
    dviscope_server::admin::quarantine_token(&t.pool, token_id, &ts(now - Duration::hours(1)))
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let e5 = eval(now).await;
    let tx = state(&e5, "tx");
    assert_eq!(tx["state"], "insufficient", "{tx}");
    let tx_pair = tx["pairs"]
        .as_array()
        .and_then(|p| p.iter().find(|x| x["test"] == "uart_tx"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(tx_pair["regression"], "R2");
    t.drop().await;
}

/// R1 finding 13: receipt times backfilled from reported starts (migration 0012) are
/// replaced by the regression's first receipt time, or unknown when that receipt is gone.
#[tokio::test]
async fn legacy_receipt_times_are_trusted_or_unknown() {
    let Some(t) = TestDb::new_at(13).await else {
        return;
    };
    let app = t.app();
    let _pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    sealed(&app, &c, "keep", &[slot("s1")]).await;
    sealed(&app, &c, "gone", &[slot("s1")]).await;
    // As 0012 left legacy rows: received_at = the reported start (here in the future).
    for sql in [
        "UPDATE regressions SET started_at = now() + interval '30 days'",
        "UPDATE regressions SET received_at = started_at",
        "UPDATE candidate_index i SET started_at = r.started_at, received_at = r.started_at
           FROM regressions r WHERE r.id = i.regression_id",
        "DELETE FROM receipts WHERE identity = 'regression:gone'",
    ] {
        sqlx::query(sql)
            .execute(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    dviscope_server::db::migrate(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let rows: Vec<(String, Option<OffsetDateTime>, OffsetDateTime)> =
        sqlx::query_as("SELECT ref, received_at, started_at FROM regressions ORDER BY ref")
            .fetch_all(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rows[0].0, "gone");
    // No receipt left: the time stays unknown (uncertain, never fresh); a bound orders it.
    assert_eq!(rows[0].1, None, "{rows:?}");
    let bound: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT receipt_bound FROM regressions WHERE ref = 'gone'")
            .fetch_one(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    assert!(bound.is_some());
    let keep = rows[1].1.unwrap_or_else(|| panic!("receipt time"));
    assert!(
        keep < rows[1].2,
        "the server's receipt time, not the future start"
    );
    let idx: Vec<(String, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT regression_ref, received_at FROM candidate_index ORDER BY regression_ref",
    )
    .fetch_all(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(idx[0].1, None);
    assert_eq!(idx[1].1, Some(keep));
    t.drop().await;
}

/// R1 finding 6: a removal by a credential quarantined since before it keeps the newest
/// regression as the feature candidate (no older pass reappears).
#[tokio::test]
async fn quarantined_removal_keeps_the_newer_candidate() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c1, _) = collector(&t.pool).await;
    let (c2, tok2) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let admin = user(&t, "ada", pid, Role::Admin).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    reg(
        &app,
        &c1,
        "old",
        now - Duration::days(2),
        &[("x", "uart_tx", "1", Some(true))],
        true,
    )
    .await;
    // The newer regression declares uart_tx, then removes it (credential c2).
    reg(
        &app,
        &c2,
        "new",
        now - Duration::days(1),
        &[("x", "uart_tx", "1", None), ("y", "spi", "1", Some(true))],
        false,
    )
    .await;
    let since = OffsetDateTime::now_utc() - Duration::seconds(2);
    ok(app
        .manifest_amend(
            &c2,
            "new",
            &json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2,
                    "remove": [{"slot_ref": "x", "reason": "dropped"}]}),
        )
        .await);
    app.import_checklist(
        &admin,
        "p1",
        &checklist("1", vec![item("tx", &["uart_tx"], 1, 30)]),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let eval = || async {
        app.evaluate_feature(&viewer(pid), "p1", "uart-fs", None, "rtl/main", now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"))
    };
    // A valid removal: "new" no longer holds uart_tx; "old" is the candidate.
    let e = eval().await;
    assert_eq!(state(&e, "tx")["pairs"][0]["regression"], "old", "{e}");
    assert_eq!(state(&e, "tx")["state"], "satisfied");
    // The removing credential is quarantined since before the removal: "new" again.
    dviscope_server::admin::quarantine_token(&t.pool, tok2, &ts(since))
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let e = eval().await;
    assert_eq!(state(&e, "tx")["pairs"][0]["regression"], "new", "{e}");
    assert_ne!(state(&e, "tx")["state"], "satisfied");
    t.drop().await;
}

/// R2 finding 4: upgrading from schema 12 keeps legacy removals from counting under
/// quarantine: index rows deleted by earlier code are rebuilt (0015) and a removal without
/// a recorded credential (before 0013) does not count while any credential of the producer
/// is quarantined.
#[tokio::test]
async fn upgrade_restores_legacy_removals_under_quarantine() {
    let Some(t) = TestDb::new_at(12).await else {
        return;
    };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, token) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    reg(
        &app,
        &c,
        "old",
        now - Duration::days(2),
        &[("x", "uart_tx", "1", Some(true))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "new",
        now - Duration::days(1),
        &[("x", "uart_tx", "1", None), ("y", "spi", "1", Some(true))],
        false,
    )
    .await;
    // As the round-1 code left it: removal without provenance, index row deleted.
    for sql in [
        "UPDATE slots s SET removed_revision = 2 FROM regressions r
          WHERE r.id = s.regression_id AND r.ref = 'new' AND s.slot_ref = 'x'",
        "DELETE FROM candidate_index WHERE regression_ref = 'new' AND test = 'uart_tx'",
    ] {
        sqlx::query(sql)
            .execute(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    dviscope_server::db::migrate(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let admin = user(&t, "ada", pid, Role::Admin).await;
    app.import_checklist(
        &admin,
        "p1",
        &checklist("1", vec![item("tx", &["uart_tx"], 1, 30)]),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let eval = || async {
        app.evaluate_feature(&viewer(pid), "p1", "uart-fs", None, "rtl/main", now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"))
    };
    let e = eval().await;
    assert_eq!(state(&e, "tx")["pairs"][0]["regression"], "old", "{e}");
    dviscope_server::admin::quarantine_token(&t.pool, token, &ts(now - Duration::days(5)))
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let e = eval().await;
    assert_eq!(state(&e, "tx")["pairs"][0]["regression"], "new", "{e}");
    assert_ne!(state(&e, "tx")["state"], "satisfied");
    // The regression read restores the slot too.
    let r = read(&app, pid, "new").await;
    assert_eq!(r.header.planned, 2);
    t.drop().await;
}

/// R3 finding 2: a legacy regression whose receipt expired keeps an unknown receipt time
/// after upgrading (from schema 13): it is uncertain and never satisfies freshness, even
/// when its claimed start is recent.
#[tokio::test]
async fn upgraded_unknown_times_never_satisfy_freshness() {
    let Some(t) = TestDb::new_at(13).await else {
        return;
    };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    reg(
        &app,
        &c,
        "legacy",
        now - Duration::days(1),
        &[("x", "uart_tx", "1", Some(true))],
        true,
    )
    .await;
    for sql in [
        "UPDATE regressions SET received_at = started_at",
        "UPDATE candidate_index SET received_at = started_at",
        "DELETE FROM receipts WHERE identity = 'regression:legacy'",
    ] {
        sqlx::query(sql)
            .execute(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    dviscope_server::db::migrate(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let admin = user(&t, "ada", pid, Role::Admin).await;
    app.import_checklist(
        &admin,
        "p1",
        &checklist("1", vec![item("tx", &["uart_tx"], 1, 7)]),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let e = app
        .evaluate_feature(&viewer(pid), "p1", "uart-fs", None, "rtl/main", now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let tx = state(&e, "tx");
    assert_eq!(tx["state"], "outdated", "{e}");
    assert!(tx["reasons"].to_string().contains("time uncertain"), "{tx}");
    t.drop().await;
}

/// R4 finding 3: a slot declared after the upgrade on a legacy regression (unknown receipt
/// time) keeps the regression's bound, so a provably later passing run still replaces it.
#[tokio::test]
async fn late_slots_of_legacy_regressions_keep_their_bound() {
    let Some(t) = TestDb::new_at(13).await else {
        return;
    };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // An unfinished legacy regression (sealed, not finished), receipt gone.
    reg(
        &app,
        &c,
        "legacy",
        now - Duration::days(3),
        &[("y", "spi", "1", Some(true))],
        false,
    )
    .await;
    for sql in [
        "UPDATE regressions SET received_at = started_at",
        "UPDATE candidate_index SET received_at = started_at",
        "DELETE FROM receipts WHERE identity = 'regression:legacy'",
    ] {
        sqlx::query(sql)
            .execute(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    dviscope_server::db::migrate(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    // The upgrade happened a day ago (the bound is the migration time).
    for sql in [
        "UPDATE regressions SET receipt_bound = now() - interval '1 day' WHERE receipt_bound IS NOT NULL",
        "UPDATE candidate_index SET receipt_bound = now() - interval '1 day' WHERE receipt_bound IS NOT NULL",
    ] {
        sqlx::query(sql)
            .execute(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    }
    // A late declaration of uart_tx on the legacy regression (an amendment).
    let x =
        json!({"slot_ref": "x", "exec_inputs": {"test": "uart_tx", "seed": "1"}, "required": true});
    ok(app
        .manifest_amend(
            &c,
            "legacy",
            &json!({"schema": dviscope_model::schema::MANIFEST,
                                               "revision": 2, "add": [x]}),
        )
        .await);
    // A fresh regression, provably later (run after the upgrade), passes uart_tx.
    reg(
        &app,
        &c,
        "fresh",
        OffsetDateTime::now_utc(),
        &[("x", "uart_tx", "1", Some(true))],
        true,
    )
    .await;
    let admin = user(&t, "ada", pid, Role::Admin).await;
    app.import_checklist(
        &admin,
        "p1",
        &checklist("1", vec![item("tx", &["uart_tx"], 1, 7)]),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let e = app
        .evaluate_feature(
            &viewer(pid),
            "p1",
            "uart-fs",
            None,
            "rtl/main",
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let tx = state(&e, "tx");
    assert_eq!(tx["pairs"][0]["regression"], "fresh", "{e}");
    assert_eq!(tx["state"], "satisfied", "{e}");
    // R5 finding 1: the bound is in the permanent index, so it survives the legacy
    // regression's deletion by retention.
    let bounds: Vec<Option<OffsetDateTime>> = sqlx::query_scalar(
        "SELECT receipt_bound FROM candidate_index WHERE regression_ref = 'legacy' ORDER BY test",
    )
    .fetch_all(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(bounds.iter().all(Option::is_some), "{bounds:?}");
    dviscope_server::retention::run(
        &t.pool,
        OffsetDateTime::now_utc() + Duration::days(4000),
        dviscope_server::retention::Policy::default(),
        false,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let gone: i64 = sqlx::query_scalar("SELECT count(*) FROM regressions WHERE ref = 'legacy'")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(gone, 0, "retention deleted the legacy regression");
    let e = app
        .evaluate_feature(
            &viewer(pid),
            "p1",
            "uart-fs",
            None,
            "rtl/main",
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(state(&e, "tx")["pairs"][0]["regression"], "fresh", "{e}");
    t.drop().await;
}

/// R6 finding 3: a valid removal stays effective after retention deletes the removing
/// regression's slots (feature selection is retention-stable).
#[tokio::test]
async fn removals_survive_retention() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // R1 passes uart_tx; an unrelated failure keeps R1 for two years.
    reg(
        &app,
        &c,
        "R1",
        now - Duration::days(2),
        &[
            ("x", "uart_tx", "1", Some(true)),
            ("bad", "other", "1", Some(false)),
        ],
        true,
    )
    .await;
    // R2 declares uart_tx, removes it, and passes the rest (kept 90 days).
    reg(
        &app,
        &c,
        "R2",
        now - Duration::days(1),
        &[("x", "uart_tx", "1", None), ("y", "spi", "1", Some(true))],
        false,
    )
    .await;
    ok(app
        .manifest_amend(
            &c,
            "R2",
            &json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2,
                                           "remove": [{"slot_ref": "x", "reason": "dropped"}]}),
        )
        .await);
    ok(app
        .finish(&c, "R2", &json!({"kind": "finish", "regression_ref": "R2"}))
        .await);
    let admin = user(&t, "ada", pid, Role::Admin).await;
    app.import_checklist(
        &admin,
        "p1",
        &checklist("1", vec![item("tx", &["uart_tx"], 1, 30)]),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let eval = || async {
        app.evaluate_feature(&viewer(pid), "p1", "uart-fs", None, "rtl/main", now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"))
    };
    let e = eval().await;
    assert_eq!(state(&e, "tx")["pairs"][0]["regression"], "R1", "{e}");
    assert_eq!(state(&e, "tx")["state"], "satisfied");
    dviscope_server::retention::run(
        &t.pool,
        now + Duration::days(120),
        dviscope_server::retention::Policy::default(),
        false,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let r2: i64 = sqlx::query_scalar("SELECT count(*) FROM regressions WHERE ref = 'R2'")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r2, 0, "R2 expired");
    let e = eval().await;
    assert_eq!(state(&e, "tx")["pairs"][0]["regression"], "R1", "{e}");
    assert_eq!(state(&e, "tx")["state"], "satisfied", "{e}");
    t.drop().await;
}

/// R7 finding 1: when a test/configuration's slots were removed by several credentials,
/// quarantining any of them restores the candidate (each removal is kept), also after
/// retention.
#[tokio::test]
async fn every_removal_credential_counts() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c0, _) = collector(&t.pool).await;
    let (ca, tok_a) = collector(&t.pool).await;
    let (cb, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    reg(
        &app,
        &c0,
        "R1",
        now - Duration::days(2),
        &[
            ("x", "uart_tx", "1", Some(true)),
            ("bad", "other", "1", Some(false)),
        ],
        true,
    )
    .await;
    reg(
        &app,
        &c0,
        "R2",
        now - Duration::days(1),
        &[
            ("x1", "uart_tx", "1", None),
            ("x2", "uart_tx", "2", None),
            ("y", "spi", "1", Some(true)),
        ],
        false,
    )
    .await;
    let since = ts(OffsetDateTime::now_utc() - Duration::seconds(2));
    for (who, rev, slot) in [(&ca, 2, "x1"), (&cb, 3, "x2")] {
        ok(app
            .manifest_amend(
                who,
                "R2",
                &json!({"schema": dviscope_model::schema::MANIFEST,
                "revision": rev, "remove": [{"slot_ref": slot, "reason": "dropped"}]}),
            )
            .await);
    }
    ok(app
        .finish(
            &c0,
            "R2",
            &json!({"kind": "finish", "regression_ref": "R2"}),
        )
        .await);
    let admin = user(&t, "ada", pid, Role::Admin).await;
    app.import_checklist(
        &admin,
        "p1",
        &checklist("1", vec![item("tx", &["uart_tx"], 1, 30)]),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let eval = || async {
        app.evaluate_feature(&viewer(pid), "p1", "uart-fs", None, "rtl/main", now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"))
    };
    assert_eq!(state(&eval().await, "tx")["pairs"][0]["regression"], "R1");
    // The first remover is quarantined since before its removal: R2 is the candidate.
    dviscope_server::admin::quarantine_token(&t.pool, tok_a, &since)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let e = eval().await;
    assert_eq!(state(&e, "tx")["pairs"][0]["regression"], "R2", "{e}");
    assert_ne!(state(&e, "tx")["state"], "satisfied");
    dviscope_server::retention::run(
        &t.pool,
        now + Duration::days(120),
        dviscope_server::retention::Policy::default(),
        false,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let e = eval().await;
    assert_eq!(
        state(&e, "tx")["pairs"][0]["regression"],
        "R2",
        "after retention: {e}"
    );
    t.drop().await;
}

/// R17 finding 1: feature mode checks the authoritative attempts as merge readiness does.
/// Under strict policy a pass on an unproven build (its build report never came) is not a
/// passing seed, though a later attempt passes on a proven build; with both builds proven
/// the item is satisfied.
#[tokio::test]
async fn a_pass_on_an_unproven_build_is_not_a_passing_seed() {
    for prove_first in [false, true] {
        let Some(t) = TestDb::new().await else { return };
        let app = t.app();
        let pid = project(&t.pool).await;
        let (c, _) = collector(&t.pool).await;
        accept_pipeline(&t.pool, &passing()).await;
        let admin = user(&t, "ada", pid, Role::Admin).await;
        let now = OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let _ = app.create_source_manifest(&c, &source_manifest()).await;
        let mut body = regression("r1");
        body["started_at"] = json!(ts(now - Duration::days(1)));
        ok(app.create_regression(&c, &body).await);
        let decls = vec![
            json!({"slot_ref": "x", "exec_inputs": {"test": "uart_tx", "seed": "1"},
                                "required": true, "build_reqs": [build_req()]}),
        ];
        ok(app.manifest_chunk(&c, "r1", 1, &chunk(&decls)).await);
        ok(app.manifest_seal(&c, "r1", &seal(&decls)).await);
        ok(ingest(&app, &c, &build_started("b1")).await);
        if prove_first {
            ok(ingest(&app, &c, &build_report("b1", "pass")).await);
        }
        ok(ingest(&app, &c, &build_started("b2")).await);
        ok(ingest(&app, &c, &build_report("b2", "pass")).await);
        for (a, seq, b) in [("a1", 1, "b1"), ("a2", 2, "b2")] {
            ok(ingest(&app, &c, &started("r1", "x", a, seq, &[b])).await);
            let mut rep = report("r1", "x", a, seq, 1, &passing(), &[b]);
            rep["execution"] = json!({"test": "uart_tx", "seed": "1"});
            ok(ingest(&app, &c, &rep).await);
        }
        ok(app
            .finish(&c, "r1", &json!({"kind": "finish", "regression_ref": "r1"}))
            .await);
        app.import_checklist(
            &admin,
            "p1",
            &checklist("1", vec![item("tx", &["uart_tx"], 1, 30)]),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
        let e = app
            .evaluate_feature(&viewer(pid), "p1", "uart-fs", None, "rtl/main", now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        if prove_first {
            assert_eq!(state(&e, "tx")["state"], "satisfied", "{e}");
        } else {
            assert_ne!(state(&e, "tx")["state"], "satisfied", "{e}");
            assert_ne!(e["ready"], true, "{e}");
        }
        t.drop().await;
    }
}
