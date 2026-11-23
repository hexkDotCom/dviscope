//! Acceptance at the app+DB layer: merge readiness and decisions.
//! Invented records and logs only.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_server::app::App;
use dviscope_server::app::decisions::{
    BulkTriageItem, ExceptionRequest, MAX_BULK_TRIAGE, TriageEdit,
};
use dviscope_server::auth::{Actor, Role};
use serde_json::{Value, json};
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

async fn readiness(app: &App, pid: i64, r: &str, src: Option<&str>, now: OffsetDateTime) -> Value {
    app.read_readiness(&viewer(pid), "p1", r, src, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))
}

/// r1: s1 passes, s2 fails (one signature); sealed and finished.
async fn setup(t: &TestDb) -> (App, i64, Actor) {
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    for (s, a, ev) in [("s1", "a1", &pass), ("s2", "a2", &fail)] {
        ok(ingest(&app, &c, &started("r1", s, a, 1, &[])).await);
        ok(ingest(&app, &c, &report("r1", s, a, 1, 1, ev, &[])).await);
    }
    ok(app
        .finish(&c, "r1", &json!({"kind": "finish", "regression_ref": "r1"}))
        .await);
    (app, pid, c)
}

fn sig_of(v: &Value) -> i64 {
    v["blockers"][0]["signatures"][0].as_i64().unwrap_or(0)
}

/// A10, A13, A15 (exception part): an exception turns a covered failure into
/// accepted_with_exceptions until it expires; the verdict and digest change at
/// `valid_until`; any decision changes the next digest.
#[tokio::test]
async fn a10_a13_exceptions_and_expiry() {
    let Some(t) = TestDb::new().await else { return };
    let (app, pid, _) = setup(&t).await;
    let now = OffsetDateTime::now_utc();
    let v = readiness(&app, pid, "r1", None, now).await;
    assert_eq!(v["verdict"], "fail", "{v}");
    assert_eq!(v["blockers"][0]["kind"]["kind"], "failed");
    assert_eq!(v["blockers"][0]["exceptable"], true);
    let sig = sig_of(&v);
    assert!(sig > 0);
    // The log-free summary carries IDs and counts only.
    let summary = v["summary"].to_string();
    assert!(
        !summary.contains("expected 1 got 2") && !summary.contains("SB_MISMATCH"),
        "{summary}"
    );
    let admin = user(&t, "ada", pid, Role::Admin).await;
    let expires = now + Duration::days(10);
    let req = ExceptionRequest {
        signature: sig,
        branch: "rtl/main".into(),
        suite: "nightly".into(),
        reason: "known model gap, fix scheduled".into(),
        expires_at: expires
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    };
    // A viewer cannot add exceptions; 180 days is the limit.
    assert!(
        app.create_exception(&viewer(pid), "p1", &req, None, now)
            .await
            .is_err()
    );
    let mut long = req.clone();
    long.expires_at = (now + Duration::days(200))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    assert!(
        app.create_exception(&admin, "p1", &long, None, now)
            .await
            .is_err()
    );
    app.create_exception(&admin, "p1", &req, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let w = readiness(&app, pid, "r1", None, now).await;
    assert_eq!(w["verdict"], "accepted_with_exceptions", "{w}");
    assert!(w["valid_until"].is_string());
    assert_ne!(w["digest"], v["digest"]);
    // At valid_until the exception no longer applies: verdict and digest change.
    let later = readiness(&app, pid, "r1", None, expires + Duration::seconds(1)).await;
    assert_eq!(later["verdict"], "fail");
    assert_ne!(later["digest"], w["digest"]);
    // Superseding needs the reviewed revision (If-Match): a stale or missing one is 412.
    for stale in [None, Some(7)] {
        let e = app.create_exception(&admin, "p1", &req, stale, now).await;
        assert!(
            matches!(&e, Err(e) if e.code == ErrorCode::PreconditionFailed),
            "{e:?}"
        );
    }
    // Superseding creates revision 2 (one live exception per scope); revoking ends it.
    let h = app
        .create_exception(&admin, "p1", &req, Some(1), now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(h.revision, 2);
    let before = readiness(&app, pid, "r1", None, now).await;
    app.revoke_exception(&admin, "p1", h.id)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let after = readiness(&app, pid, "r1", None, now).await;
    assert_eq!(after["verdict"], "fail");
    // Revoke -> recreate -> a stale edit (R2 finding 5): revisions are never reused.
    let recreated = app
        .create_exception(&admin, "p1", &req, None, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(recreated.revision, 3);
    let stale = app.create_exception(&admin, "p1", &req, Some(2), now).await;
    assert!(
        matches!(&stale, Err(e) if e.code == ErrorCode::PreconditionFailed),
        "{stale:?}"
    );
    assert_ne!(after["change_seq"], before["change_seq"]);
    t.drop().await;
}

/// A04, closure and binding: missing and not-run required slots block (not exceptable),
/// optional ones do not; an open collection or another candidate is insufficient.
#[tokio::test]
async fn a04_obligations_and_closure() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let pass = passing();
    accept_pipeline(&t.pool, &pass).await;
    let mut opt = slot("s3");
    opt["required"] = json!(false);
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2"), opt]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &pass, &[])).await);
    let now = OffsetDateTime::now_utc();
    let v = readiness(&app, pid, "r1", None, now).await;
    assert_eq!(
        v["verdict"], "insufficient_evidence",
        "collection still open: {v}"
    );
    ok(app
        .finish(&c, "r1", &json!({"kind": "finish", "regression_ref": "r1"}))
        .await);
    let v = readiness(&app, pid, "r1", None, now).await;
    assert_eq!(v["verdict"], "fail");
    let kinds: Vec<String> = v["blockers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|b| format!("{}:{}", b["kind"]["kind"], b["slot"]))
        .collect();
    assert_eq!(
        kinds,
        vec!["\"missing\":\"s2\"".to_string()],
        "the optional slot does not block"
    );
    let mark = json!({"schema": dviscope_model::schema::MANIFEST, "slot_refs": ["s2"],
                      "state": "skipped", "reason": "license"});
    ok(app.slot_mark(&c, "r1", &mark).await);
    let v = readiness(&app, pid, "r1", None, now).await;
    assert_eq!(v["blockers"][0]["kind"]["kind"], "required_not_run");
    assert_eq!(v["blockers"][0]["exceptable"], false);
    // Another candidate's source digest: insufficient evidence.
    let v = readiness(&app, pid, "r1", Some("sha256:0000"), now).await;
    assert_eq!(v["verdict"], "insufficient_evidence");
    t.drop().await;
}

/// Triage: revisions with If-Match; a stale base gets 412 naming the change; the change
/// feed lists every decision.
#[tokio::test]
async fn triage_revisions_and_change_feed() {
    let Some(t) = TestDb::new().await else { return };
    let (app, pid, _) = setup(&t).await;
    let sig = sig_of(&readiness(&app, pid, "r1", None, OffsetDateTime::now_utc()).await);
    let ana = user(&t, "ana", pid, Role::Triager).await;
    let bo = user(&t, "bo", pid, Role::Triager).await;
    let edit = |owner: &str| TriageEdit {
        state: "open".into(),
        owner: Some(owner.into()),
        notes: "looks like the scoreboard model".into(),
        bug_urls: vec!["https://bugs.example/1".into()],
    };
    let h = app
        .set_triage(&ana, "p1", sig, "rtl/main", None, &edit("Ana"))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(h.revision, 1);
    let h2 = app
        .set_triage(&bo, "p1", sig, "rtl/main", Some(1), &edit("Bo"))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(h2.revision, 2);
    let e = app
        .set_triage(&ana, "p1", sig, "rtl/main", Some(1), &edit("Ana"))
        .await
        .err()
        .unwrap_or_else(|| panic!("a stale base must fail"));
    assert_eq!(e.code, ErrorCode::PreconditionFailed);
    assert!(
        e.message.contains("bo") && e.message.contains("Bo"),
        "{}",
        e.message
    );
    // A viewer cannot triage; notes and URLs are bounded.
    assert!(
        app.set_triage(&viewer(pid), "p1", sig, "rtl/main", Some(2), &edit("x"))
            .await
            .is_err()
    );
    let mut bad = edit("Bo");
    bad.bug_urls = vec!["javascript:alert(1)".into()];
    assert!(
        app.set_triage(&bo, "p1", sig, "rtl/main", Some(2), &bad)
            .await
            .is_err()
    );
    // The owner shows in the readiness summary.
    let v = readiness(&app, pid, "r1", None, OffsetDateTime::now_utc()).await;
    assert_eq!(
        v["summary"]["blockers"][0]["owner"], "Bo",
        "{}",
        v["summary"]
    );
    // Two triage changes in the feed (evidence changes of the setup are there too).
    let feed = app
        .changes_since(&viewer(pid), "p1", 0)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let triage: Vec<i64> = feed["changes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|c| c["kind"].as_str().is_some_and(|k| k.starts_with("triage")))
                .filter_map(|c| c["seq"].as_i64())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(triage.len(), 2, "{feed}");
    // Since the first one: only the second.
    let feed = app
        .changes_since(&viewer(pid), "p1", triage[0])
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(feed["changes"].as_array().map_or(0, Vec::len), 1, "{feed}");
    t.drop().await;
}

/// Bulk triage: one decision for several signatures in one transaction. Each item carries
/// its own base revision; a stale base, an unknown or repeated signature, an empty or too
/// large request and a viewer are refused and write nothing; the change feed names every
/// case; comparison rows carry the diagnostic and the triage head revision.
#[tokio::test]
async fn bulk_triage_all_or_nothing() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let (ea, eb, ec) = (
        failing_ids(&["BULK_A"]),
        failing_ids(&["BULK_B"]),
        failing_ids(&["BULK_C"]),
    );
    accept_pipeline(&t.pool, &ea).await;
    sealed(&app, &c, "rb", &[slot("s1"), slot("s2"), slot("s3")]).await;
    for (s, a, ev) in [("s1", "a1", &ea), ("s2", "a2", &eb), ("s3", "a3", &ec)] {
        ok(ingest(&app, &c, &started("rb", s, a, 1, &[])).await);
        ok(ingest(&app, &c, &report("rb", s, a, 1, 1, ev, &[])).await);
    }
    ok(app
        .finish(&c, "rb", &json!({"kind": "finish", "regression_ref": "rb"}))
        .await);
    let rows = |cmp: &dviscope_server::app::read::ComparisonRead| -> Vec<(String, i64, Option<i32>, Option<String>)> {
        let mut v: Vec<_> = cmp
            .decisions
            .values()
            .map(|d| (d.diag_id.clone().unwrap_or_default(), d.number.unwrap_or(0), d.triage_revision, d.owner.clone()))
            .collect();
        v.sort();
        v
    };
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "rb", Some("none"), None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let r0 = rows(&cmp);
    assert_eq!(
        r0.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        ["uvm:BULK_A", "uvm:BULK_B", "uvm:BULK_C"],
        "{r0:?}"
    );
    let (na, nb, nc) = (r0[0].1, r0[1].1, r0[2].1);
    let ana = user(&t, "ana", pid, Role::Triager).await;
    let edit = |owner: &str| TriageEdit {
        state: "open".into(),
        owner: Some(owner.into()),
        notes: "byte lanes".into(),
        bug_urls: vec![],
    };
    // B already has a case (revision 1).
    app.set_triage(&ana, "p1", nb, "rtl/main", None, &edit("Bo"))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let item = |number: i64, if_match: Option<i32>| BulkTriageItem { number, if_match };
    let revisions = t.count("triage_revisions").await;
    let (history, changes) = (t.count("history").await, t.count("changes").await);
    let refused = |r: Result<Vec<_>, dviscope_server::error::AppError>| {
        r.err().unwrap_or_else(|| panic!("must be refused"))
    };
    // A stale base on one item: 412 naming it, nothing written (A stays without a case).
    let e = refused(
        app.set_triage_bulk(
            &ana,
            "p1",
            "rtl/main",
            &[item(na, None), item(nb, Some(7)), item(nc, Some(0))],
            &edit("Ana"),
        )
        .await,
    );
    assert_eq!(e.code, ErrorCode::PreconditionFailed);
    assert!(
        e.message.contains(&format!("signature #{nb}")),
        "{}",
        e.message
    );
    // A case that exists needs its revision; an item without one is stale too.
    let e = refused(
        app.set_triage_bulk(
            &ana,
            "p1",
            "rtl/main",
            &[item(na, None), item(nb, None)],
            &edit("Ana"),
        )
        .await,
    );
    assert_eq!(e.code, ErrorCode::PreconditionFailed, "{}", e.message);
    // Unknown, repeated, empty, too many; a viewer; an invalid edit.
    let e = refused(
        app.set_triage_bulk(
            &ana,
            "p1",
            "rtl/main",
            &[item(na, None), item(999_999, None)],
            &edit("Ana"),
        )
        .await,
    );
    assert_eq!(e.code, ErrorCode::Invalid, "{}", e.message);
    let e = refused(
        app.set_triage_bulk(
            &ana,
            "p1",
            "rtl/main",
            &[item(na, None), item(na, None)],
            &edit("Ana"),
        )
        .await,
    );
    assert!(e.message.contains("twice"), "{}", e.message);
    assert_eq!(
        refused(
            app.set_triage_bulk(&ana, "p1", "rtl/main", &[], &edit("Ana"))
                .await
        )
        .code,
        ErrorCode::Invalid
    );
    let many: Vec<BulkTriageItem> = (1..=i64::try_from(MAX_BULK_TRIAGE).unwrap_or(0) + 1)
        .map(|n| item(n, None))
        .collect();
    // Refused for its size, before any signature is looked up.
    let e = refused(
        app.set_triage_bulk(&ana, "p1", "rtl/main", &many, &edit("Ana"))
            .await,
    );
    assert!(
        e.message
            .contains(&format!("between 1 and {MAX_BULK_TRIAGE}")),
        "{}",
        e.message
    );
    // A viewer is refused (HTTP 403).
    assert_eq!(
        refused(
            app.set_triage_bulk(
                &viewer(pid),
                "p1",
                "rtl/main",
                &[item(na, None)],
                &edit("Ana")
            )
            .await
        )
        .code,
        ErrorCode::Forbidden
    );
    let mut bad = edit("Ana");
    bad.state = "fixed".into();
    assert!(
        app.set_triage_bulk(&ana, "p1", "rtl/main", &[item(na, None)], &bad)
            .await
            .is_err()
    );
    assert_eq!(
        t.count("triage_revisions").await,
        revisions,
        "nothing written by a refused request"
    );
    assert_eq!(
        (t.count("history").await, t.count("changes").await),
        (history, changes),
        "no history or change of a refused request"
    );
    let seq_before = app
        .changes_since(&viewer(pid), "p1", 0)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))["change_seq"]
        .as_i64()
        .unwrap_or(0);
    // The real one: A and C new (revision 1), B edited from revision 1 to 2.
    let heads = app
        .set_triage_bulk(
            &ana,
            "p1",
            "rtl/main",
            &[item(nc, Some(0)), item(nb, Some(1)), item(na, None)],
            &edit("Ana"),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut got: Vec<(i64, i32)> = heads.iter().map(|h| (h.signature, h.revision)).collect();
    got.sort_unstable();
    let mut want = vec![(na, 1), (nb, 2), (nc, 1)];
    want.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(t.count("triage_revisions").await, revisions + 3);
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "rb", Some("none"), None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    for r in rows(&cmp) {
        assert_eq!(r.3.as_deref(), Some("Ana"), "{r:?}");
        assert_eq!(r.2, Some(if r.1 == nb { 2 } else { 1 }), "{r:?}");
    }
    // One change per case.
    let feed = app
        .changes_since(&viewer(pid), "p1", seq_before)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let objects: Vec<&str> = feed["changes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["object"].as_str())
        .collect();
    assert_eq!(objects.len(), 3, "{feed}");
    assert!(objects.iter().all(|o| o.starts_with("triage:")), "{feed}");
    // A second bulk on a stale view of B fails as a whole (A is not touched again).
    let e = refused(
        app.set_triage_bulk(
            &ana,
            "p1",
            "rtl/main",
            &[item(na, Some(1)), item(nb, Some(1))],
            &edit("Cy"),
        )
        .await,
    );
    assert_eq!(e.code, ErrorCode::PreconditionFailed);
    assert_eq!(t.count("triage_revisions").await, revisions + 3);
    t.drop().await;
}

/// Bulk triage takes the project counter only after every case scope, as the single path
/// does: while a single edit holds case B (and will take the counter next), a bulk request
/// over A and B waits on B without holding the counter, so the single edit completes and
/// then the bulk does (no deadlock).
#[tokio::test]
async fn bulk_triage_takes_the_project_counter_after_every_case() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let (ea, eb) = (failing_ids(&["RACE_A"]), failing_ids(&["RACE_B"]));
    accept_pipeline(&t.pool, &ea).await;
    sealed(&app, &c, "rr", &[slot("s1"), slot("s2")]).await;
    for (s, a, ev) in [("s1", "a1", &ea), ("s2", "a2", &eb)] {
        ok(ingest(&app, &c, &started("rr", s, a, 1, &[])).await);
        ok(ingest(&app, &c, &report("rr", s, a, 1, 1, ev, &[])).await);
    }
    let numbers: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT number, id, diag_id FROM signatures WHERE project_id = $1 ORDER BY diag_id",
    )
    .bind(pid)
    .fetch_all(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(numbers.len(), 2, "{numbers:?}");
    let (na, nb, sid_b) = (numbers[0].0, numbers[1].0, numbers[1].1);
    let heads: i64 = sqlx::query_scalar("SELECT count(*) FROM project_heads WHERE project_id = $1")
        .bind(pid)
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        heads, 1,
        "the counter row exists (the setup changed the project)"
    );
    // A single edit of B, part way: it holds B's scope.
    let mut single = t.pool.begin().await.unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 11))")
        .bind(format!("triage/{pid}/{sid_b}/rtl/main"))
        .execute(&mut *single)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let ana = user(&t, "ana", pid, Role::Triager).await;
    let edit = TriageEdit {
        state: "open".into(),
        owner: Some("Ana".into()),
        notes: String::new(),
        bug_urls: vec![],
    };
    let bulk = {
        let app = app.clone();
        let (ana, edit) = (ana.clone(), edit.clone());
        tokio::spawn(async move {
            app.set_triage_bulk(
                &ana,
                "p1",
                "rtl/main",
                &[
                    BulkTriageItem {
                        number: na,
                        if_match: None,
                    },
                    BulkTriageItem {
                        number: nb,
                        if_match: None,
                    },
                ],
                &edit,
            )
            .await
        })
    };
    // Wait until the bulk request waits on B's scope (it has written A by then): an ungranted
    // advisory lock on exactly B's key, in this database.
    let key = format!("triage/{pid}/{sid_b}/rtl/main");
    let mut waiting = false;
    for _ in 0..200 {
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks l
              WHERE l.locktype = 'advisory' AND NOT l.granted AND l.objsubid = 1
                AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
                AND ((l.classid::bigint << 32) | l.objid::bigint) = hashtextextended($1, 11)",
        )
        .bind(&key)
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        if n > 0 {
            waiting = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(waiting, "the bulk request never waited on B");
    // The single edit now takes the counter: free, because the bulk has not taken it yet.
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *single)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("UPDATE project_heads SET change_seq = change_seq WHERE project_id = $1")
        .bind(pid)
        .execute(&mut *single)
        .await
        .unwrap_or_else(|e| panic!("the single edit could not take the counter: {e}"));
    single.commit().await.unwrap_or_else(|e| panic!("{e}"));
    let heads = bulk
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("the bulk request failed: {e:?}"));
    assert_eq!(heads.len(), 2);
    t.drop().await;
}

/// Browse reads: the regression list pages with a cursor; a signature shows where it
/// occurs and its decisions; an attempt shows its revisions, buckets and evidence while the
/// payload is retained, and says so once it expired.
#[tokio::test]
async fn browse_reads() {
    let Some(t) = TestDb::new().await else { return };
    let (app, pid, c) = setup(&t).await;
    for i in 0..3 {
        sealed(&app, &c, &format!("x{i}"), &[slot("s1")]).await;
    }
    let v = viewer(pid);
    let page = app
        .list_regressions(&v, "p1", None, Some(2))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(page["regressions"].as_array().map_or(0, Vec::len), 2);
    let next = page["next"].as_str().map(str::to_string);
    assert!(next.is_some());
    let rest = app
        .list_regressions(&v, "p1", next.as_deref(), Some(10))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(rest["regressions"].as_array().map_or(0, Vec::len), 2);
    assert!(rest["next"].is_null());
    let projects = app
        .list_projects(&v)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(projects["projects"][0]["name"], "p1");
    assert!(
        app.list_projects(&c).await.is_err(),
        "not for collector tokens"
    );

    let sig = sig_of(&readiness(&app, pid, "r1", None, OffsetDateTime::now_utc()).await);
    let d = app
        .signature_detail(&v, "p1", sig)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(d["occurrences"].as_array().map_or(0, Vec::len), 1);
    assert_eq!(d["occurrences"][0]["slot"], "s2");
    assert!(
        d["note"]
            .as_str()
            .is_some_and(|n| n.contains("root cause not established"))
    );

    let a = app
        .attempt_detail(&v, "p1", "r1", "s2", 1, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(a["revisions"][0]["effective"], "failed");
    assert!(
        a["buckets"]
            .as_array()
            .is_some_and(|b| b.iter().any(|x| x["signature"] == sig))
    );
    assert!(a["evidence"]["excerpt"].is_object());
    sqlx::raw_sql("DELETE FROM attempt_reports")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let a = app
        .attempt_detail(&v, "p1", "r1", "s2", 1, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(a["evidence"].is_null());
    assert_eq!(
        a["evidence_note"],
        "Excerpt expired; triage history retained"
    );
    assert_eq!(
        a["revisions"][0]["effective"], "failed",
        "facts outlive payloads"
    );
    t.drop().await;
}

/// Triage pages: row disposition and the finish card follow triage and
/// exceptions; the exception preview reports its impact without storing anything; the
/// green proof card names each accepted required slot's attempt; the repair list names
/// missing slots with their reason and recovery, without paths.
#[tokio::test]
async fn dispositions_preview_proof_and_repair_list() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2"), slot("s3")]).await;
    for (s, a, ev) in [("s1", "a1", &pass), ("s2", "a2", &fail)] {
        ok(ingest(&app, &c, &started("r1", s, a, 1, &[])).await);
        ok(ingest(&app, &c, &report("r1", s, a, 1, 1, ev, &[])).await);
    }
    ok(app
        .finish(&c, "r1", &json!({"kind": "finish", "regression_ref": "r1"}))
        .await);
    let v = viewer(pid);
    let now = OffsetDateTime::now_utc();
    let disposition = |c: &dviscope_server::app::read::ComparisonRead| {
        let row = &c.comparison.rows[0];
        c.decisions[row.signature.as_str()].disposition
    };

    // Untriaged: needs a decision; s3 missing blocks too.
    let c0 = app
        .read_comparison(&v, "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(disposition(&c0), "needs_decision");
    assert_eq!(c0.finish["needs_decision"], 1);
    assert_eq!(c0.finish["missing_results"], 1);
    let sig = c0.decisions[c0.comparison.rows[0].signature.as_str()]
        .number
        .unwrap_or(0);

    // Assigned once an owner is set.
    let ana = user(&t, "ana", pid, Role::Triager).await;
    let edit = TriageEdit {
        state: "open".into(),
        owner: Some("Ana".into()),
        notes: "\nscoreboard model gap\nmore".into(),
        bug_urls: vec!["https://bugs.example/7".into()],
    };
    app.set_triage(&ana, "p1", sig, "rtl/main", None, &edit)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let c1 = app
        .read_comparison(&v, "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let d1 = &c1.decisions[c1.comparison.rows[0].signature.as_str()];
    assert_eq!(d1.disposition, "assigned");
    assert_eq!(d1.latest_note.as_deref(), Some("scoreboard model gap"));
    assert_eq!(d1.bug_url.as_deref(), Some("https://bugs.example/7"));

    // Preview: covers s2, s3 stays missing (verdict stays fail), nothing stored.
    let expires = (now + Duration::days(30))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let p = app
        .preview_exception(
            &v,
            "p1",
            "r1",
            None,
            dviscope_server::app::readiness::ExceptionPreview {
                signature: sig,
                expires_at: expires.clone(),
            },
            now,
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(p["covers_slots"], json!(["s2"]), "{p}");
    assert_eq!(p["stay_blocked_slots"], json!([]), "{p}");
    assert_eq!(p["not_exceptable"], false);
    assert_eq!(
        p["scope"],
        json!({"branch": "rtl/main", "suite": "nightly"})
    );
    assert_eq!(p["verdict_before"], "fail");
    assert_eq!(p["verdict_after"], "fail", "s3 is still missing: {p}");
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM exceptions")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stored, 0);
    // An unknown signature is 404.
    let missing = app
        .preview_exception(
            &v,
            "p1",
            "r1",
            None,
            dviscope_server::app::readiness::ExceptionPreview {
                signature: 999_999,
                expires_at: expires.clone(),
            },
            now,
        )
        .await;
    assert!(matches!(missing, Err(e) if e.code == ErrorCode::NotFound));

    // Covered once an exception exists; the proof card shows s1's accepting attempt.
    let admin = user(&t, "ada", pid, Role::Admin).await;
    app.create_exception(
        &admin,
        "p1",
        &ExceptionRequest {
            signature: sig,
            branch: "rtl/main".into(),
            suite: "nightly".into(),
            reason: "known gap".into(),
            expires_at: expires,
        },
        None,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let c2 = app
        .read_comparison(&v, "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(disposition(&c2), "covered");
    assert_eq!(c2.finish["covered"], 1);
    assert_eq!(c2.finish["blocking_groups"], 0);
    let r = readiness(&app, pid, "r1", None, now).await;
    let proof = r["proof"].as_array().cloned().unwrap_or_default();
    let s1 = proof
        .iter()
        .find(|x| x["slot"] == "s1")
        .cloned()
        .unwrap_or_default();
    assert_eq!(s1["attempt_seq"], 1, "{r}");
    assert_eq!(s1["retry"], false);
    let s2 = proof
        .iter()
        .find(|x| x["slot"] == "s2")
        .cloned()
        .unwrap_or_default();
    assert_eq!(s2["exceptions"], json!([sig]), "{r}");
    assert!(
        proof.iter().all(|x| x["slot"] != "s3"),
        "s3 is blocked: {r}"
    );

    // Repair list: s3, no report received; the text has no paths.
    let rl = app
        .repair_list(&v, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let slots = rl["groups"][0]["slots"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(slots.len(), 1, "{rl}");
    assert_eq!(slots[0]["slot"], "s3");
    assert_eq!(slots[0]["reason"], "No report received");
    let text = rl["text"].as_str().unwrap_or_default();
    assert!(
        text.contains("s3") && text.contains("spool flush"),
        "{text}"
    );

    // Started without a report (a collector that may have stopped): listed as running.
    ok(ingest(&app, &c, &started("r1", "s3", "a3", 1, &[])).await);
    let rl = app
        .repair_list(&v, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        rl["groups"][0]["slots"][0]["reason"], "Attempt started; no report yet",
        "{rl}"
    );
    // A report under a pipeline that is not accepted is received but not eligible.
    ok(ingest(&app, &c, &report("r1", "s3", "a3", 1, 1, &pass, &[])).await);
    sqlx::query("DELETE FROM pipelines")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let rl = app
        .repair_list(&v, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        rl["text"]
            .as_str()
            .unwrap_or_default()
            .contains("s3 (t_s3), required: Report received; not eligible: pipeline"),
        "{rl}"
    );
    // Withdrawn: the report is rejected (a settlement barrier) and listed as such.
    dviscope_server::admin::set_pipeline(&t.pool, "p1", pass.pipeline_digest.as_str(), "withdrawn")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let rl = app
        .repair_list(&v, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let reasons: Vec<String> = rl["groups"][0]["slots"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|s| {
            format!(
                "{}={}",
                s["slot"].as_str().unwrap_or(""),
                s["reason"].as_str().unwrap_or("")
            )
        })
        .collect();
    assert!(
        reasons.contains(
            &"s3=Report received; rejected: evidence from a withdrawn pipeline".to_string()
        ),
        "{reasons:?}"
    );
    t.drop().await;
}

/// Admin overview (read-only): members, collector-token metadata without secrets,
/// producers with their assurance profile, pipelines; admins only.
#[tokio::test]
async fn admin_overview_is_metadata_for_admins() {
    let Some(t) = TestDb::new().await else { return };
    let (app, pid, _) = setup(&t).await;
    let admin = user(&t, "ada", pid, Role::Admin).await;
    let tri = user(&t, "tim", pid, Role::Triager).await;
    dviscope_server::admin::set_member(&t.pool, "p1", "ada", "admin")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    for who in [&tri, &viewer(pid)] {
        let e = app.admin_overview(who, "p1").await;
        assert!(matches!(e, Err(e) if e.code == ErrorCode::Forbidden));
    }
    let v = app
        .admin_overview(&admin, "p1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let text = v.to_string();
    assert!(!text.contains("hash") && !text.contains("dvis_"), "{text}");
    assert_eq!(v["tokens"][0]["state"], "active", "{v}");
    assert!(
        v["members"]
            .as_array()
            .is_some_and(|m| m.iter().any(|x| x["username"] == "ada"))
    );
    let p = &v["producers"][0];
    assert_eq!(
        p["assurance"][0], "Counting available (sealed expected sets)",
        "{v}"
    );
    assert_eq!(
        p["assurance"][1],
        "Build provenance missing (no build attempts)"
    );
    assert_eq!(
        p["assurance"][2],
        "Merge gating available (source manifests)"
    );
    assert_eq!(v["pipelines"][0]["state"], "accepted");
    t.drop().await;
}

/// A23 (server side): publishing refreshes an unchanged status or stores a new receipt;
/// the host's acceptance retires what it replaced; the receipt stays readable after a
/// correction and after its exception expires, next to the current evaluation; a status is
/// green only for a passing verdict; retirement is explicit.
#[tokio::test]
async fn a23_publication_receipts() {
    use dviscope_server::app::publications::{Posted, PublishRequest, Retire, Target};
    let Some(t) = TestDb::new().await else { return };
    let (app, pid, _) = setup(&t).await;
    let tri = user(&t, "tim", pid, Role::Triager).await;
    let now = OffsetDateTime::now_utc();
    let first = readiness(&app, pid, "r1", None, now).await;
    let src = first["summary"]["candidate"]["source_digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let req = PublishRequest {
        regression: "r1".into(),
        producer: None,
        expect_source: src.clone(),
        target: Target {
            repository: "hexkDotCom/dviscope-dev".into(),
            commit: "a".repeat(40),
            context: "dviscope/merge".into(),
        },
    };
    // Viewers cannot publish; targets are validated.
    let e = app.publish(&viewer(pid), "p1", &req, now).await;
    assert!(matches!(e, Err(e) if e.code == ErrorCode::Forbidden));
    let mut bad = req.clone();
    bad.target.commit = "nothex".into();
    let e = app.publish(&tri, "p1", &bad, now).await;
    assert!(matches!(e, Err(e) if e.code == ErrorCode::Invalid));

    // First publication: a failing verdict is a failure status, to post.
    let p1 = app
        .publish(&tri, "p1", &req, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(p1["action"], "post", "{p1}");
    let r1 = &p1["receipt"];
    let d1 = r1["digest"].as_str().unwrap_or_default().to_string();
    assert_eq!(r1["status"]["state"], "failure");
    assert_eq!(
        r1["producer"], "pilot",
        "receipts name their producer: {r1}"
    );
    assert!(
        r1["status"]["description"]
            .as_str()
            .unwrap_or("")
            .starts_with("Fail as of ")
    );
    // Undated: monitored for 14 days.
    let mu = OffsetDateTime::parse(
        r1["monitor_until"].as_str().unwrap_or(""),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!((mu - now - Duration::days(14)).abs() < Duration::seconds(2));
    let wrong = app
        .mark_posted(
            &tri,
            "p1",
            &d1,
            &Posted {
                state: "success".into(),
            },
            now,
        )
        .await;
    assert!(
        wrong.is_err(),
        "a failing receipt is never posted as success"
    );
    app.mark_posted(
        &tri,
        "p1",
        &d1,
        &Posted {
            state: "failure".into(),
        },
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));

    // Same basis an hour later: a refresh, no new receipt.
    let later = now + Duration::hours(1);
    let p2 = app
        .publish(&tri, "p1", &req, later)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(p2["action"], "unchanged", "{p2}");
    assert_eq!(p2["receipt"]["digest"], d1.as_str());
    assert!(p2["receipt"]["last_refresh_at"].is_string());

    // An exception: a new receipt (success, monitored until it expires); posting it
    // retires the first.
    let admin = user(&t, "ada", pid, Role::Admin).await;
    let sig = first["blockers"][0]["signatures"][0].as_i64().unwrap_or(0);
    let expires = now + Duration::days(20);
    app.create_exception(
        &admin,
        "p1",
        &ExceptionRequest {
            signature: sig,
            branch: "rtl/main".into(),
            suite: "nightly".into(),
            reason: "known gap".into(),
            expires_at: expires
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        },
        None,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let p3 = app
        .publish(&tri, "p1", &req, later)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(p3["action"], "post");
    let d3 = p3["receipt"]["digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_ne!(d3, d1);
    assert_eq!(p3["receipt"]["status"]["state"], "success");
    assert_eq!(p3["receipt"]["monitor_until"], p3["receipt"]["valid_until"]);
    let open = app
        .open_publications(&tri, "p1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        open["publications"].as_array().map_or(0, Vec::len),
        2,
        "{open}"
    );
    app.mark_posted(
        &tri,
        "p1",
        &d3,
        &Posted {
            state: "success".into(),
        },
        later,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let open = app
        .open_publications(&tri, "p1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        open["publications"].as_array().map_or(0, Vec::len),
        1,
        "{open}"
    );
    // Fence (R1 finding 3): the older receipt can no longer be recorded as posted.
    let fenced = app
        .mark_posted(
            &tri,
            "p1",
            &d1,
            &Posted {
                state: "failure".into(),
            },
            later,
        )
        .await;
    assert!(
        matches!(&fenced, Err(e) if e.code == ErrorCode::StaleRevision),
        "{fenced:?}"
    );

    // The first receipt stays readable, retired as superseded, next to the current
    // evaluation (accepted with exceptions).
    let r = app
        .read_receipt(&viewer(pid), "p1", &d1, later)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r["receipt"]["retired_reason"], "superseded");
    assert_eq!(r["receipt"]["summary"]["verdict"], "fail");
    assert_eq!(
        r["current"]["summary"]["verdict"],
        "accepted_with_exceptions"
    );

    // Day 20: the exception expires; re-publishing gives a failure again, never a lingering
    // success; the success receipt shows the current fail.
    let day21 = expires + Duration::seconds(1);
    let p4 = app
        .publish(&tri, "p1", &req, day21)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(p4["action"], "post");
    assert_eq!(p4["receipt"]["status"]["state"], "failure");
    let r = app
        .read_receipt(&viewer(pid), "p1", &d3, day21)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        r["receipt"]["summary"]["verdict"],
        "accepted_with_exceptions"
    );
    assert_eq!(r["current"]["summary"]["verdict"], "fail");

    // Another candidate: insufficient evidence is pending, not success.
    let mut other = req.clone();
    other.expect_source = format!("sha256:{}", "0".repeat(64));
    other.target.commit = "b".repeat(40);
    let p5 = app
        .publish(&tri, "p1", &other, day21)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(p5["receipt"]["status"]["state"], "pending", "{p5}");

    // Retirement is explicit and idempotent.
    let d5 = p5["receipt"]["digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let bad = app
        .retire_publication(
            &tri,
            "p1",
            &d5,
            &Retire {
                reason: "whatever".into(),
            },
            day21,
        )
        .await;
    assert!(bad.is_err());
    for _ in 0..2 {
        let x = app
            .retire_publication(
                &tri,
                "p1",
                &d5,
                &Retire {
                    reason: "monitoring_ended".into(),
                },
                day21,
            )
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(x["retired_reason"], "monitoring_ended");
    }
    t.drop().await;
}

/// A03b (app part): slots blocked by a failed build show as one comparison row (no
/// fabricated attempts, no signature), with its own next action.
#[tokio::test]
async fn a03b_build_group_row() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let slots: Vec<serde_json::Value> = (0..25).map(|i| built_slot(&format!("s{i:02}"))).collect();
    sealed(&app, &c, "r1", &slots).await;
    ok(ingest(&app, &c, &build_started("b1")).await);
    ok(ingest(&app, &c, &build_report("b1", "fail")).await);
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        cmp.comparison.header.blocked, 25,
        "{:?}",
        cmp.comparison.header
    );
    assert_eq!(cmp.comparison.rows.len(), 1, "{:?}", cmp.comparison.rows);
    let row = &cmp.comparison.rows[0];
    assert_eq!(row.group, Some("build"));
    assert_eq!(row.failed_slots, 25);
    assert_eq!(row.failing_attempts, 0);
    let d = &cmp.decisions[row.signature.as_str()];
    assert_eq!(d.number, None);
    assert_eq!(
        d.next_action,
        "fix the build and rebuild, then run its tests"
    );
    assert_eq!(cmp.comparison.header.signatures, 0);
    t.drop().await;
}

/// R3 finding 4: the open-publications inventory pages completely (every target reachable
/// beyond the first page).
#[tokio::test]
async fn open_publications_page_through_every_target() {
    use dviscope_server::app::publications::{OPEN_PAGE, PublishRequest, Target};
    let Some(t) = TestDb::new().await else { return };
    let (app, pid, _) = setup(&t).await;
    let tri = user(&t, "tim", pid, Role::Triager).await;
    let now = OffsetDateTime::now_utc();
    let src = readiness(&app, pid, "r1", None, now).await["summary"]["candidate"]["source_digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let n = OPEN_PAGE + 3;
    for i in 0..n {
        let req = PublishRequest {
            regression: "r1".into(),
            producer: None,
            expect_source: src.clone(),
            target: Target {
                repository: "o/r".into(),
                commit: format!("{i:040x}"),
                context: "dviscope/merge".into(),
            },
        };
        app.publish(
            &tri,
            "p1",
            &req,
            now + Duration::seconds(i64::try_from(i).unwrap_or(0)),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut after: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = app
            .open_publications(&tri, "p1", after.as_deref())
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        pages += 1;
        for p in page["publications"].as_array().cloned().unwrap_or_default() {
            assert!(seen.insert(p["target"]["commit"].as_str().unwrap_or("").to_string()));
        }
        match page["next"].as_str() {
            Some(c) => after = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(seen.len(), n);
    assert_eq!(pages, 2);
    t.drop().await;
}

/// R17 finding 2: targets compare without case (as GitHub compares them): an older receipt
/// of a case variant is fenced once a newer receipt of the target is posted.
#[tokio::test]
async fn publication_targets_compare_without_case() {
    use dviscope_server::app::publications::{Posted, PublishRequest, Target};
    let Some(t) = TestDb::new().await else { return };
    let (app, pid, _) = setup(&t).await;
    let tri = user(&t, "tim", pid, Role::Triager).await;
    let now = OffsetDateTime::now_utc();
    let first = readiness(&app, pid, "r1", None, now).await;
    let src = first["summary"]["candidate"]["source_digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let req = |repository: &str, commit: String, context: &str| PublishRequest {
        regression: "r1".into(),
        producer: None,
        expect_source: src.clone(),
        target: Target {
            repository: repository.into(),
            commit,
            context: context.into(),
        },
    };
    let variant = req("HexkDotCom/DVIScope-dev", "A".repeat(40), "DVIScope/Merge");
    let plain = req("hexkDotCom/dviscope-dev", "a".repeat(40), "dviscope/merge");
    let old = app
        .publish(&tri, "p1", &variant, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let d_old = old["receipt"]["digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let later = now + Duration::minutes(5);
    let new = app
        .publish(&tri, "p1", &plain, later)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let d_new = new["receipt"]["digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_ne!(d_old, d_new);
    let state = new["receipt"]["status"]["state"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    app.mark_posted(
        &tri,
        "p1",
        &d_new,
        &Posted {
            state: state.clone(),
        },
        later,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let fenced = app
        .mark_posted(&tri, "p1", &d_old, &Posted { state }, later)
        .await;
    assert!(
        matches!(&fenced, Err(e) if e.code == ErrorCode::StaleRevision),
        "{fenced:?}"
    );
    t.drop().await;
}
