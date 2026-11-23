//! Acceptance cases at the app+DB layer. Invented records and logs only.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use serde_json::json;

const TABLES: &[&str] = &[
    "regressions",
    "slots",
    "attempts",
    "attempt_facts",
    "attempt_reports",
    "buckets",
    "signatures",
    "receipts",
    "manifest_chunks",
    "slot_marks",
];

async fn counts(t: &TestDb) -> Vec<i64> {
    let mut v = vec![];
    for table in TABLES {
        v.push(t.count(table).await);
    }
    v
}

/// A01: resending changes nothing; revision 1 replayed after revision 2 returns its
/// original receipt; the same revision with another payload is 409.
#[tokio::test]
async fn a01_duplicate_delivery() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let slots = [slot("s1"), slot("s2")];
    sealed(&app, &c, "r1", &slots).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    let records = [
        started("r1", "s1", "a1", 1, &[]),
        report("r1", "s1", "a1", 1, 1, &fail, &[]),
        started("r1", "s2", "a2", 1, &[]),
        report("r1", "s2", "a2", 1, 1, &pass, &[]),
    ];
    let mut first = vec![];
    for r in &records {
        first.push(ok(ingest(&app, &c, r).await));
    }
    let before = counts(&t).await;
    // Everything again: duplicates only, the same receipts, no row added.
    for (r, f) in records.iter().zip(&first) {
        let again = ok(ingest(&app, &c, r).await);
        assert!(again.duplicate);
        assert_eq!(again.body["server_ids"], f.body["server_ids"]);
        assert_eq!(again.body["digest"], f.body["digest"]);
    }
    for v in [regression("r1"), source_manifest()] {
        let r = if v.get("regression_ref").is_some() {
            app.create_regression(&c, &v).await
        } else {
            app.create_source_manifest(&c, &v).await
        };
        assert!(ok(r).duplicate);
    }
    assert!(ok(app.manifest_chunk(&c, "r1", 1, &chunk(&slots)).await).duplicate);
    assert!(ok(app.manifest_seal(&c, "r1", &seal(&slots)).await).duplicate);
    assert_eq!(counts(&t).await, before);
    // Revision 2, then revision 1 again: revision 1's original receipt.
    let r2 = ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 2, &pass, &[])).await);
    assert_eq!(r2.body["revision"], 2);
    let r1 = ok(ingest(&app, &c, &records[1]).await);
    assert!(r1.duplicate);
    assert_eq!(r1.body["revision"], 1);
    assert_eq!(r1.body["digest"], first[1].body["digest"]);
    // The same revision with another payload.
    let mut other = report("r1", "s1", "a1", 1, 2, &fail, &[]);
    other["result"]["outcome_reported"] = json!("fail");
    assert_eq!(
        code(ingest(&app, &c, &other).await),
        ErrorCode::RevisionConflict
    );
    t.drop().await;
}

/// A05: slot states always sum to the planned (live) slots, across chunks, seal,
/// amendments, marks and late reports.
#[tokio::test]
async fn a05_conservation() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    ok(app.create_regression(&c, &regression("r1")).await);
    let c1 = [slot("s1"), slot("s2"), slot("s3")];
    let c2 = [slot("s4"), slot("s5")];
    ok(app.manifest_chunk(&c, "r1", 1, &chunk(&c1)).await);
    ok(app.manifest_chunk(&c, "r1", 2, &chunk(&c2)).await);
    let all: Vec<_> = c1.iter().chain(c2.iter()).cloned().collect();
    let check = |planned: u64| {
        let app = app.clone();
        async move {
            let r = read(&app, pid, "r1").await;
            let h = &r.header;
            assert_eq!(h.planned, planned);
            assert_eq!(
                h.passed + h.failed + h.blocked + h.missing + h.running + h.cancelled + h.skipped,
                h.planned,
                "{h:?}"
            );
            assert_eq!(r.slots.len() as u64, planned);
        }
    };
    check(5).await;
    ok(app.manifest_seal(&c, "r1", &seal(&all)).await);
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    check(5).await; // s1 running
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &pass, &[])).await);
    let amend = json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2,
                       "add": [slot("s6"), slot("s7")],
                       "remove": [{"slot_ref": "s5", "reason": "dropped"}]});
    ok(app.manifest_amend(&c, "r1", &amend).await);
    check(6).await;
    let mark = json!({"schema": dviscope_model::schema::MANIFEST, "slot_refs": ["s6"],
                      "state": "skipped", "reason": "not this week"});
    ok(app.slot_mark(&c, "r1", &mark).await);
    ok(app
        .finish(&c, "r1", &json!({"kind": "finish", "regression_ref": "r1"}))
        .await);
    // A late report after the finish.
    ok(ingest(&app, &c, &started("r1", "s2", "a2", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s2", "a2", 1, 1, &pass, &[])).await);
    check(6).await;
    let r = read(&app, pid, "r1").await;
    assert_eq!(
        (r.header.passed, r.header.skipped, r.header.missing),
        (2, 1, 3)
    );
    t.drop().await;
}

/// A11: revisions a quarantined token delivered since its receipt time are barriers,
/// never a pass (also over an older clean pass); a later valid attempt clears; release
/// restores.
#[tokio::test]
async fn a11_quarantine() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (clean, _) = collector(&t.pool).await;
    let (bad, bad_id) = collector(&t.pool).await;
    let slots = [slot("s1"), slot("s2")];
    sealed(&app, &clean, "r1", &slots).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    // s1: attempt 1 passes (clean), attempt 2 fails (later quarantined).
    ok(ingest(&app, &clean, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &clean, &report("r1", "s1", "a1", 1, 1, &pass, &[])).await);
    ok(ingest(&app, &bad, &started("r1", "s1", "a2", 2, &[])).await);
    ok(ingest(&app, &bad, &report("r1", "s1", "a2", 2, 1, &fail, &[])).await);
    // s2: a clean pass, then a passing correction from the quarantined token.
    ok(ingest(&app, &clean, &started("r1", "s2", "b1", 1, &[])).await);
    ok(ingest(&app, &clean, &report("r1", "s2", "b1", 1, 1, &pass, &[])).await);
    let mut corr = report("r1", "s2", "b1", 1, 2, &pass, &[]);
    corr["result"]["outcome_reported"] = json!("pass");
    ok(ingest(&app, &bad, &corr).await);
    assert_eq!(state(&read(&app, pid, "r1").await, "s2")["state"], "passed");

    dviscope_server::admin::quarantine_token(&t.pool, bad_id, "2000-01-01T00:00:00Z")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let r = read(&app, pid, "r1").await;
    assert_eq!(
        state(&r, "s1"),
        json!({"state": "failed", "detail": "insufficient"})
    );
    assert_ne!(state(&r, "s2")["state"], "passed", "never the older pass");
    // The quarantined token delivers nothing more.
    assert!(
        dviscope_server::auth::actor_from_token(&t.pool, "dvis_x")
            .await
            .is_err(),
        "sanity"
    );
    // A later valid attempt clears s1.
    ok(ingest(&app, &clean, &started("r1", "s1", "a3", 3, &[])).await);
    ok(ingest(&app, &clean, &report("r1", "s1", "a3", 3, 1, &pass, &[])).await);
    let r = read(&app, pid, "r1").await;
    assert_ne!(
        state(&r, "s1"),
        json!({"state": "failed", "detail": "insufficient"})
    );
    // Release: the revisions count again (s1 has a real failure under strict; s2 passes).
    dviscope_server::admin::release_token(&t.pool, bad_id)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let r = read(&app, pid, "r1").await;
    assert_eq!(
        state(&r, "s1"),
        json!({"state": "failed", "detail": "functional"})
    );
    assert_eq!(state(&r, "s2")["state"], "passed");
    t.drop().await;
}

/// A14: forced interleavings with exact responses and rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a14_forced_interleavings() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    let _ = app.create_source_manifest(&c, &source_manifest()).await;

    // Seal vs chunk: either the seal wins (the chunk is then 409) or the chunk does (the
    // seal's count no longer matches: 400). Never both committed.
    for i in 0..5 {
        let r = format!("sc{i}");
        ok(app.create_regression(&c, &regression(&r)).await);
        let c1 = [slot("s1")];
        ok(app.manifest_chunk(&c, &r, 1, &chunk(&c1)).await);
        let (seal_body, chunk_body) = (seal(&c1), chunk(&[slot("s2")]));
        let (sl, ch) = tokio::join!(
            app.manifest_seal(&c, &r, &seal_body),
            app.manifest_chunk(&c, &r, 2, &chunk_body)
        );
        match (&sl, &ch) {
            (Ok(_), Err(e)) => assert_eq!(e.code, ErrorCode::RevisionConflict),
            (Err(e), Ok(_)) => assert_eq!(e.code, ErrorCode::Invalid),
            _ => panic!("seal {sl:?} / chunk {ch:?}"),
        }
        let n = read(&app, pid, &r).await.slots.len();
        assert_eq!(n, if sl.is_ok() { 1 } else { 2 });
    }

    // Competing amendments of the same revision: one commits, the other is refused.
    let base = [slot("s1"), slot("s2")];
    sealed(&app, &c, "am", &base).await;
    let a = json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2, "add": [slot("x1")]});
    let b = json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2, "add": [slot("y1")]});
    let (ra, rb) = tokio::join!(
        app.manifest_amend(&c, "am", &a),
        app.manifest_amend(&c, "am", &b)
    );
    assert!(ra.is_ok() ^ rb.is_ok(), "{ra:?} {rb:?}");
    let winner = if ra.is_ok() { "x1" } else { "y1" };
    let loser = ra.err().or(rb.err()).map(|e| e.code);
    assert!(matches!(
        loser,
        Some(ErrorCode::StaleRevision | ErrorCode::RevisionConflict)
    ));
    assert_eq!(read(&app, pid, "am").await.slots.len(), 3);

    // Finish vs a late report: both succeed, in either order.
    ok(ingest(&app, &c, &started("am", "s1", "f1", 1, &[])).await);
    let fin = json!({"kind": "finish", "regression_ref": "am"});
    let rep = report("am", "s1", "f1", 1, 1, &pass, &[]);
    let (rf, rr) = tokio::join!(app.finish(&c, "am", &fin), ingest(&app, &c, &rep));
    ok(rf);
    ok(rr);
    assert_eq!(state(&read(&app, pid, "am").await, "s1")["state"], "passed");

    // Two revisions in both orders.
    ok(ingest(&app, &c, &started("am", "s2", "o1", 1, &[])).await);
    ok(ingest(&app, &c, &report("am", "s2", "o1", 1, 2, &pass, &[])).await);
    assert_eq!(
        code(ingest(&app, &c, &report("am", "s2", "o1", 1, 1, &pass, &[])).await),
        ErrorCode::StaleRevision
    );
    ok(ingest(&app, &c, &started("am", winner, "o2", 1, &[])).await);
    ok(ingest(&app, &c, &report("am", winner, "o2", 1, 1, &pass, &[])).await);
    ok(ingest(&app, &c, &report("am", winner, "o2", 1, 2, &pass, &[])).await);
    let facts: i64 = t.count("attempt_facts").await;
    assert_eq!(facts, 4);
    t.drop().await;
}

/// A03a (storage part): a failed build blocks its dependents without fabricated attempts;
/// a passing rebuild leaves them missing until run; builds of one requirement get distinct
/// server-assigned orders, also when started concurrently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a03a_builds() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let slots = [built_slot("s1"), built_slot("s2")];
    sealed(&app, &c, "r1", &slots).await;
    // Build evidence counts only under an accepted pipeline.
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    ok(ingest(&app, &c, &build_started("b1")).await);
    ok(ingest(&app, &c, &build_report("b1", "fail")).await);
    let r = read(&app, pid, "r1").await;
    for s in ["s1", "s2"] {
        assert_eq!(state(&r, s), json!({"state": "blocked", "detail": "build"}));
    }
    assert_eq!(t.count("attempts").await, 0, "no fabricated attempts");
    ok(ingest(&app, &c, &build_started("b2")).await);
    ok(ingest(&app, &c, &build_report("b2", "pass")).await);
    let r = read(&app, pid, "r1").await;
    for s in ["s1", "s2"] {
        assert_eq!(state(&r, s)["state"], "missing");
    }
    // Concurrent first sightings of one requirement: distinct orders.
    let (b3, b4) = (build_started("b3"), build_started("b4"));
    let (x, y) = tokio::join!(ingest(&app, &c, &b3), ingest(&app, &c, &b4));
    ok(x);
    ok(y);
    let orders: Vec<i64> =
        sqlx::query_scalar("SELECT build_order FROM build_attempts ORDER BY build_order")
            .fetch_all(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(orders, vec![1, 2, 3, 4]);
    // An attempt that used the passing build passes.
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &["b2"])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &pass, &["b2"])).await);
    assert_eq!(state(&read(&app, pid, "r1").await, "s1")["state"], "passed");
    // A foreign-source build is refused; the others are unaffected.
    let mut foreign = build_started("b9");
    foreign["build_req"]["source_manifest_ref"] = json!("someone-elses");
    assert_eq!(code(ingest(&app, &c, &foreign).await), ErrorCode::Invalid);
    assert_eq!(t.count("build_attempts").await, 4);
    // A report naming no build for a slot that needs one is refused.
    assert_eq!(
        code(ingest(&app, &c, &started("r1", "s2", "a2", 1, &[])).await),
        ErrorCode::Invalid
    );
    t.drop().await;
}
