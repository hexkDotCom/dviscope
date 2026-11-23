//! Regression health dashboard (server): hierarchy import (validation, revisions, rights,
//! maintenance), health reads (own streams and child roll-ups, linked streams counted once,
//! unassigned streams, trends, retained runner metrics, overdue, payload expiry) and the
//! stream history. Invented records only.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_model::wire::evidence::Evidence;
use dviscope_model::wire::hierarchy::{Hierarchy, StreamRef};
use dviscope_server::app::App;
use dviscope_server::auth::{Actor, Role};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

fn admin(pid: i64) -> Actor {
    Actor::User {
        user_id: 1,
        token_id: None,
        roles: vec![(pid, Role::Admin)],
    }
}

/// One slot: its test, and `None` (no report), `Some(None)` (pass) or `Some(Some(id))`
/// (fails with that UVM ID).
type SlotSpec<'a> = (&'a str, Option<Option<&'a str>>);

fn fail_with(id: &str) -> Evidence {
    failing_ids(&[id])
}

/// A regression of suite `suite` started at `start`, finished when `finish`. Reports carry
/// runner metrics (wall 60 s, CPU 50 s per slot, scope `job`).
#[allow(clippy::too_many_arguments)]
async fn reg(
    app: &App,
    c: &Actor,
    r: &str,
    suite: &str,
    start: OffsetDateTime,
    slots: &[SlotSpec<'_>],
    finish: bool,
) {
    let _ = app.create_source_manifest(c, &source_manifest()).await;
    let mut body = regression(r);
    body["suite"] = json!(suite);
    body["started_at"] = json!(ts(start));
    ok(app.create_regression(c, &body).await);
    let decls: Vec<Value> = slots
        .iter()
        .map(|(s, _)| json!({"slot_ref": s, "exec_inputs": {"test": format!("t_{s}"), "seed": "1"}, "required": true}))
        .collect();
    ok(app.manifest_chunk(c, r, 1, &chunk(&decls)).await);
    ok(app.manifest_seal(c, r, &seal(&decls)).await);
    for (i, (s, result)) in slots.iter().enumerate() {
        let Some(result) = result else { continue };
        let a = format!("{r}-a{i}");
        let mut st = started(r, s, &a, 1, &[]);
        st["started_at"] = json!(ts(start + Duration::minutes(1)));
        ok(ingest(app, c, &st).await);
        let ev = match result {
            None => passing(),
            Some(id) => fail_with(id),
        };
        let mut rep = report(r, s, &a, 1, 1, &ev, &[]);
        rep["result"]["runner"]["started_at"] = json!(ts(start + Duration::minutes(1)));
        rep["result"]["runner"]["finished_at"] = json!(ts(
            start + Duration::minutes(2 + i64::try_from(i).unwrap_or(0))
        ));
        rep["result"]["runner"]["wall_s"] = json!("60");
        rep["result"]["runner"]["cpu_s"] = json!("50");
        rep["result"]["runner"]["cpu_scope"] = json!("job");
        ok(ingest(app, c, &rep).await);
    }
    if finish {
        ok(app
            .finish(c, r, &json!({"kind": "finish", "regression_ref": r}))
            .await);
    }
}

fn tree(v: Value) -> Hierarchy {
    serde_json::from_value(v).unwrap_or_else(|e| panic!("{e}"))
}

fn soc() -> Hierarchy {
    tree(json!({
        "nodes": [{"path": "soc", "title": "Demo SoC"}, {"path": "soc/cpu_ss"},
                  {"path": "soc/cpu_ss/dma"}, {"path": "soc/dsp_ss"}],
        "streams": [
            {"node": "soc/cpu_ss", "producer": "pilot", "suite": "cpu", "branch": "rtl/main",
             "cadence": "nightly"},
            {"node": "soc/cpu_ss/dma", "producer": "pilot", "suite": "dma", "branch": "rtl/main"}
        ],
        "links": [{"node": "soc/dsp_ss",
                   "stream": {"producer": "pilot", "suite": "dma", "branch": "rtl/main"}}]
    }))
}

async fn health(app: &App, pid: i64, area: Option<&str>, now: OffsetDateTime) -> Value {
    app.read_health(&viewer(pid), "p1", area, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))
}

fn row<'a>(page: &'a Value, suite: &str) -> &'a Value {
    page["own"]
        .as_array()
        .and_then(|a| a.iter().find(|r| r["stream"]["suite"] == suite))
        .unwrap_or_else(|| panic!("no row {suite} in {page}"))
}

fn child<'a>(page: &'a Value, path: &str) -> &'a Value {
    page["children"]
        .as_array()
        .and_then(|a| a.iter().find(|r| r["path"] == path))
        .unwrap_or_else(|| panic!("no child {path} in {page}"))
}

#[tokio::test]
async fn import_validates_versions_and_is_admin_only() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    // Viewers and collectors may not import.
    let e = app
        .import_hierarchy(&viewer(pid), "p1", &soc())
        .await
        .err()
        .map(|e| e.code);
    assert_eq!(e, Some(ErrorCode::Forbidden));
    let (c, _) = collector(&t.pool).await;
    assert!(app.import_hierarchy(&c, "p1", &soc()).await.is_err());
    assert!(
        app.read_health(&c, "p1", None, OffsetDateTime::now_utc())
            .await
            .is_err()
    );
    // A located file problem and an unknown producer.
    let mut bad = soc();
    bad.streams[1].node = "soc/nowhere".into();
    let e = app
        .import_hierarchy(&admin(pid), "p1", &bad)
        .await
        .err()
        .unwrap_or_else(|| panic!("accepted"));
    assert_eq!(
        (e.code, e.field.as_deref()),
        (ErrorCode::Invalid, Some("streams[1].node"))
    );
    let mut ghost = soc();
    ghost.streams[0].producer = "ghost".into();
    let e = app
        .import_hierarchy(&admin(pid), "p1", &ghost)
        .await
        .err()
        .unwrap_or_else(|| panic!("accepted"));
    assert_eq!(e.field.as_deref(), Some("streams[0].producer"));
    // A → duplicate → B → A: revisions 1, 1 (no-op), 2, 3.
    let a = app
        .import_hierarchy(&admin(pid), "p1", &soc())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        (a["revision"].as_i64(), a["result"].as_str()),
        (Some(1), Some("imported"))
    );
    let d = app
        .import_hierarchy(&admin(pid), "p1", &soc())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        (d["revision"].as_i64(), d["result"].as_str()),
        (Some(1), Some("duplicate"))
    );
    let mut b = soc();
    b.links.clear();
    let r2 = app
        .import_hierarchy(&admin(pid), "p1", &b)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r2["revision"].as_i64(), Some(2));
    let r3 = app
        .import_hierarchy(&admin(pid), "p1", &soc())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        r3["revision"].as_i64(),
        Some(3),
        "A after B is a new revision"
    );
    let cur = app
        .read_hierarchy(&viewer(pid), "p1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(cur["revision"].as_i64(), Some(3));
    assert_eq!(cur["hierarchy"]["links"].as_array().map(Vec::len), Some(1));
    // Audited, one row per effective import.
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit WHERE action = 'hierarchy.import'")
            .fetch_one(&t.pool)
            .await
            .unwrap_or(0);
    assert_eq!(audits, 3);
    // Maintenance refuses the import, also an identical one.
    dviscope_server::backup::set_maintenance(&t.pool, true, "test")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let e = app
        .import_hierarchy(&admin(pid), "p1", &soc())
        .await
        .err()
        .map(|e| e.code);
    assert_eq!(e, Some(ErrorCode::Unavailable));
    t.drop().await;
}

#[tokio::test]
async fn health_rolls_up_each_stream_once() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let day = Duration::days(1);
    // cpu: night 1 clean, night 2 a new signature on a slot that passed before.
    reg(
        &app,
        &c,
        "cpu-1",
        "cpu",
        now - day * 2,
        &[("a", Some(None)), ("b", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "cpu-2",
        "cpu",
        now - day,
        &[("a", Some(Some("NEW_BUG"))), ("b", Some(None))],
        true,
    )
    .await;
    // dma: two clean nights. io: never in the hierarchy (unassigned).
    reg(
        &app,
        &c,
        "dma-1",
        "dma",
        now - day * 2,
        &[("x", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "dma-2",
        "dma",
        now - day,
        &[("x", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "io-1",
        "io",
        now - day,
        &[("z", Some(Some("IO_BUG")))],
        true,
    )
    .await;

    // Without a hierarchy every stream is the project's own.
    let flat = health(&app, pid, None, now).await;
    assert_eq!(flat["own"].as_array().map(Vec::len), Some(3), "{flat}");
    assert_eq!(flat["hierarchy_revision"], Value::Null);

    app.import_hierarchy(&admin(pid), "p1", &soc())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let top = health(&app, pid, None, now).await;
    // Children: the root and the unassigned streams.
    let socn = child(&top, "soc");
    let un = child(&top, "~unassigned");
    assert_eq!(un["own_streams"], 1);
    // dma is linked under dsp_ss too, yet counted once: 2 streams in soc.
    assert_eq!(socn["health"]["streams"], 2, "{socn}");
    assert_eq!(socn["health"]["counts"]["required"], 3);
    assert_eq!(socn["health"]["trend"], "red");
    assert_eq!(socn["health"]["signatures"]["new"], 1);
    // The project KPI covers soc and unassigned: 3 distinct streams.
    assert_eq!(top["kpi"]["streams"], 3);

    let cpu = health(&app, pid, Some("soc/cpu_ss"), now).await;
    assert_eq!(cpu["node"]["breadcrumb"][0]["path"], "soc");
    let r = row(&cpu, "cpu");
    assert_eq!(r["trend"], "red", "{r}");
    assert!(
        r["worse"]
            .as_array()
            .is_some_and(|w| w.contains(&json!("new_signatures")))
    );
    assert_eq!(r["verdict"], "fail");
    assert_eq!(r["baseline_verdict"], "pass");
    assert_eq!(r["pass_rate"], 50.0);
    assert_eq!(r["pass_rate_delta_pts"], -50.0);
    assert_eq!(r["signatures"]["undecided"], 1);
    // Retained runner metrics: 2 slots × 50 s CPU, scope job, complete; delta 0.
    assert_eq!(r["cost"]["cpu_s"], 100.0);
    assert_eq!(r["cost"]["cpu_scope"], "job");
    assert_eq!(r["deltas"]["cpu_s"], 0.0);
    assert_eq!(r["cost"]["machine_s"], 120.0);
    assert_eq!(r["cadence_hours"], 24);
    assert_eq!(r["overdue"], false);
    assert!(
        r["overdue_at"].is_string(),
        "the overdue deadline is the next refresh point"
    );
    assert_eq!(cpu["valid_until"], r["overdue_at"]);
    // Own (cpu) and child (dma) both shown on the subsystem.
    assert_eq!(child(&cpu, "soc/cpu_ss/dma")["health"]["trend"], "green");

    let dsp = health(&app, pid, Some("soc/dsp_ss"), now).await;
    let linked = row(&dsp, "dma");
    assert_eq!(linked["home"], false);
    assert_eq!(linked["shared_from"], "soc/cpu_ss/dma");

    // Overdue once the nightly cadence and grace (24 h + 6 h) passed since the start.
    let later = health(
        &app,
        pid,
        Some("soc/cpu_ss"),
        now - day + Duration::hours(30),
    )
    .await;
    assert_eq!(row(&later, "cpu")["overdue"], true);
    let at_soc = health(&app, pid, None, now - day + Duration::hours(30)).await;
    assert_eq!(child(&at_soc, "soc")["health"]["grey"]["overdue"], 1);

    // Payload expiry leaves the page unchanged (metrics and facts are retained).
    sqlx::query("DELETE FROM attempt_reports")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let again = health(&app, pid, Some("soc/cpu_ss"), now).await;
    assert_eq!(again["own"], cpu["own"]);

    // An unknown area.
    let e = app
        .read_health(&viewer(pid), "p1", Some("soc/nope"), now)
        .await
        .err()
        .map(|e| e.code);
    assert_eq!(e, Some(ErrorCode::NotFound));
    t.drop().await;
}

#[tokio::test]
async fn running_and_never_seen_streams_stay_grey() {
    let Some(t) = TestDb::new().await else { return };
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
        "cpu-1",
        "cpu",
        now - Duration::hours(2),
        &[("a", Some(None)), ("b", None)],
        false,
    )
    .await;
    app.import_hierarchy(&admin(pid), "p1", &soc())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let page = health(&app, pid, Some("soc/cpu_ss"), now).await;
    let r = row(&page, "cpu");
    assert_eq!(r["trend"], "running");
    assert_eq!(r["latest"]["state"], "sealed");
    // dma never ran: no data, never overdue.
    let dma = health(&app, pid, Some("soc/cpu_ss/dma"), now).await;
    let d = row(&dma, "dma");
    assert_eq!(
        (d["trend"].as_str(), d["overdue"].as_bool()),
        (Some("no_data"), Some(false))
    );
    assert_eq!(d["latest"], Value::Null);
    let n = child(&page, "soc/cpu_ss/dma");
    assert_eq!(n["health"]["trend"], Value::Null, "grey only: no colour");
    assert_eq!(n["health"]["grey"]["no_data"], 1);
    t.drop().await;
}

#[tokio::test]
async fn history_compares_each_regression_with_its_predecessor() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let day = Duration::days(1);
    reg(
        &app,
        &c,
        "n1",
        "cpu",
        now - day * 4,
        &[("a", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "n2",
        "cpu",
        now - day * 3,
        &[("a", Some(Some("BUG_A")))],
        true,
    )
    .await;
    // n3 never finished: it is nobody's predecessor.
    reg(
        &app,
        &c,
        "n3",
        "cpu",
        now - day * 2,
        &[("a", Some(Some("BUG_A")))],
        false,
    )
    .await;
    reg(&app, &c, "n4", "cpu", now - day, &[("a", Some(None))], true).await;
    let s = StreamRef {
        producer: "pilot".into(),
        suite: "cpu".into(),
        branch: "rtl/main".into(),
    };
    let h = app
        .read_health_history(&viewer(pid), "p1", &s, 3, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let rows = h["regressions"].as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["latest"]["ref"], "n4");
    assert_eq!(rows[0]["baseline"], "n2", "the unfinished n3 is skipped");
    assert_eq!(rows[0]["signatures"]["no_longer_observed"], 1);
    assert_eq!(rows[0]["verdict"], "pass");
    assert_eq!(rows[0]["baseline_verdict"], "fail");
    assert_eq!(rows[0]["trend"], "green");
    assert_eq!(rows[1]["latest"]["ref"], "n3");
    assert_eq!(rows[1]["trend"], "running");
    assert_eq!(rows[2]["latest"]["ref"], "n2");
    assert_eq!(rows[2]["baseline"], "n1", "predecessor outside the window");
    assert_eq!(rows[2]["signatures"]["new"], 1);
    assert_eq!(rows[2]["signatures"]["undecided"], 1);
    assert_eq!(rows[2]["trend"], "red");
    assert!(h["watermark"].is_i64());
    assert_eq!(
        h["valid_until"],
        Value::Null,
        "no exception, no cadence: no expiry"
    );
    t.drop().await;
}

#[tokio::test]
async fn budgets_refuse_and_the_deadline_answers_unavailable() {
    use dviscope_server::app::health::Limits;
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let day = Duration::days(1);
    reg(
        &app,
        &c,
        "a-1",
        "cpu",
        now - day * 2,
        &[("a", Some(Some("X"))), ("b", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "a-2",
        "cpu",
        now - day,
        &[("a", Some(Some("X"))), ("b", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "d-1",
        "dma",
        now - day,
        &[("x", Some(None))],
        true,
    )
    .await;
    let v = viewer(pid);
    let read = |lim: Limits| {
        let app = &app;
        let v = &v;
        async move {
            app.read_health_with(v, "p1", None, now, &lim)
                .await
                .err()
                .map(|e| (e.code, e.message))
        }
    };
    // Exactly at each limit: answered. One below: refused, naming what was exceeded.
    // This page loads cpu (2 regressions: 4 slots, 4 attempts, 4 revisions, 2 failing
    // buckets) and dma (1 regression: 1 slot).
    let exact = Limits {
        streams: 2,
        slots: 5,
        attempts: 5,
        fact_revisions: 5,
        buckets: 2,
        ..Limits::default()
    };
    assert_eq!(read(exact).await, None);
    for (lim, what) in [
        (
            Limits {
                streams: 1,
                ..exact
            },
            "streams",
        ),
        (Limits { slots: 4, ..exact }, "slots"),
        (
            Limits {
                attempts: 4,
                ..exact
            },
            "attempts",
        ),
        (
            Limits {
                fact_revisions: 4,
                ..exact
            },
            "report revisions",
        ),
        (
            Limits {
                buckets: 1,
                ..exact
            },
            "diagnostic buckets",
        ),
    ] {
        let (code, msg) = read(lim)
            .await
            .unwrap_or_else(|| panic!("{what} not refused"));
        assert_eq!(code, ErrorCode::TooLarge, "{what}");
        assert!(msg.contains(what), "{what}: {msg}");
    }
    // History is budgeted too, including the predecessor outside its window.
    let s = StreamRef {
        producer: "pilot".into(),
        suite: "cpu".into(),
        branch: "rtl/main".into(),
    };
    let h = app
        .read_health_history_with(&v, "p1", &s, 1, now, &Limits { slots: 3, ..exact })
        .await
        .err()
        .map(|e| e.code);
    assert_eq!(
        h,
        Some(ErrorCode::TooLarge),
        "1 row + its predecessor = 4 slots"
    );
    // The deadline: an exhausted one answers unavailable (retryable), nothing written.
    let d = read(Limits {
        deadline: std::time::Duration::ZERO,
        ..exact
    })
    .await;
    assert_eq!(d.map(|x| x.0), Some(ErrorCode::Unavailable));
    t.drop().await;
}

#[tokio::test]
async fn exception_expiry_bounds_validity_and_changes_the_next_read() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let day = Duration::days(1);
    reg(
        &app,
        &c,
        "cpu-1",
        "cpu",
        now - day * 2,
        &[("a", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "cpu-2",
        "cpu",
        now - day,
        &[("a", Some(Some("NEW_BUG")))],
        true,
    )
    .await;
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "cpu-2", None, Some("pilot"))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let number = cmp
        .decisions
        .values()
        .find_map(|d| d.number)
        .unwrap_or_else(|| panic!("no signature number"));
    let expires = now + Duration::hours(2);
    let ann = dviscope_server::admin::create_user(&t.pool, "ann", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    dviscope_server::admin::set_member(&t.pool, "p1", "ann", "admin")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let ann = Actor::User {
        user_id: ann["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, Role::Admin)],
    };
    app.create_exception(
        &ann,
        "p1",
        &dviscope_server::app::decisions::ExceptionRequest {
            signature: number,
            branch: "rtl/main".into(),
            suite: "cpu".into(),
            reason: "known, fix in flight".into(),
            expires_at: ts(expires),
        },
        None,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let before = health(&app, pid, None, now).await;
    let r = row(&before, "cpu");
    assert_eq!(r["verdict"], "accepted_with_exceptions", "{r}");
    assert_eq!(r["signatures"]["undecided"], 0, "covered");
    assert_eq!(
        before["valid_until"],
        json!(ts(expires)),
        "the exception's expiry"
    );
    // After the expiry (no write in between) the same data reads differently.
    let after = health(&app, pid, None, expires + Duration::minutes(1)).await;
    let r = row(&after, "cpu");
    assert_eq!(r["verdict"], "fail");
    assert_eq!(r["signatures"]["undecided"], 1);
    assert_eq!(after["valid_until"], Value::Null);
    t.drop().await;
}

#[tokio::test]
async fn changes_after_finish_reach_the_next_read() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, token_id) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    reg(
        &app,
        &c,
        "cpu-1",
        "cpu",
        now - Duration::days(1),
        &[("a", Some(None)), ("b", None)],
        true,
    )
    .await;
    let r0 = row(&health(&app, pid, None, now).await, "cpu").clone();
    assert_eq!(
        (
            r0["counts"]["passed"].as_i64(),
            r0["counts"]["missing"].as_i64()
        ),
        (Some(1), Some(1))
    );
    // A late report after finish.
    ok(ingest(&app, &c, &started("cpu-1", "b", "late", 1, &[])).await);
    ok(ingest(
        &app,
        &c,
        &report("cpu-1", "b", "late", 1, 1, &passing(), &[]),
    )
    .await);
    let r1 = row(&health(&app, pid, None, now).await, "cpu").clone();
    assert_eq!(
        (
            r1["counts"]["passed"].as_i64(),
            r1["counts"]["missing"].as_i64()
        ),
        (Some(2), Some(0))
    );
    // Its credential quarantined: its reports no longer count.
    dviscope_server::admin::quarantine_token(&t.pool, token_id, &ts(now - Duration::days(30)))
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let r2 = row(&health(&app, pid, None, now).await, "cpu").clone();
    assert_eq!(r2["counts"]["passed"], 0, "{r2}");
    // Released, then the pipeline withdrawn: again nothing counts.
    dviscope_server::admin::release_token(&t.pool, token_id)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        row(&health(&app, pid, None, now).await, "cpu")["counts"]["passed"],
        2
    );
    dviscope_server::admin::set_pipeline(
        &t.pool,
        "p1",
        passing().pipeline_digest.as_str(),
        "withdrawn",
    )
    .await
    .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(
        row(&health(&app, pid, None, now).await, "cpu")["counts"]["passed"],
        0
    );
    t.drop().await;
}

/// Benchmark (ignored; run in release on the Linux suite and record the numbers in the
/// notes). The project page over: 12 balanced streams (latest + predecessor × 1,000 slots,
/// half failing with two diagnostics), a stream of 500 built slots sharing 100 build
/// attempts (×2 regressions), a slot with 1,000 quarantined attempts and one clearing retry,
/// and a regression with 5,000 distinct signatures; then one history read.
#[tokio::test]
#[ignore = "benchmark: run explicitly"]
#[allow(clippy::too_many_lines)]
async fn health_benchmark() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let two = failing_ids(&["BENCH_A", "BENCH_B", "BENCH_C", "BENCH_D"]);
    let t0 = std::time::Instant::now();
    let new_reg = |r: String, suite: String, start: OffsetDateTime, decls: Vec<Value>| {
        let (app, c) = (&app, &c);
        async move {
            let _ = app.create_source_manifest(c, &source_manifest()).await;
            let mut body = regression(&r);
            body["suite"] = json!(suite);
            body["started_at"] = json!(ts(start));
            ok(app.create_regression(c, &body).await);
            ok(app.manifest_chunk(c, &r, 1, &chunk(&decls)).await);
            ok(app.manifest_seal(c, &r, &seal(&decls)).await);
        }
    };
    let decl = |s: &str| json!({"slot_ref": s, "exec_inputs": {"test": format!("t_{s}"), "seed": "1"}, "required": true});
    let mut slots_total = 0usize;
    // Balanced.
    for k in 0..12 {
        for (n, start) in [(1, now - Duration::days(2)), (2, now - Duration::days(1))] {
            let r = format!("s{k}-n{n}");
            let decls: Vec<Value> = (0..1000).map(|i| decl(&format!("t{i}"))).collect();
            new_reg(r.clone(), format!("suite-{k}"), start, decls).await;
            for i in 0..1000 {
                let s = format!("t{i}");
                let a = format!("{r}-{i}");
                ok(ingest(&app, &c, &started(&r, &s, &a, 1, &[])).await);
                let ev = if i % 2 == 0 { passing() } else { two.clone() };
                ok(ingest(&app, &c, &report(&r, &s, &a, 1, 1, &ev, &[])).await);
            }
            ok(app
                .finish(&c, &r, &json!({"kind": "finish", "regression_ref": r}))
                .await);
            slots_total += 1000;
        }
    }
    // Shared builds: 100 build attempts of one requirement, 500 built slots per regression.
    for b in 0..100 {
        let b = format!("bb{b}");
        ok(ingest(&app, &c, &build_started(&b)).await);
        ok(ingest(&app, &c, &build_report(&b, "pass")).await);
    }
    for (n, start) in [(1, now - Duration::days(2)), (2, now - Duration::days(1))] {
        let r = format!("built-n{n}");
        let decls: Vec<Value> = (0..500).map(|i| built_slot(&format!("u{i}"))).collect();
        new_reg(r.clone(), "built".into(), start, decls).await;
        for i in 0..500 {
            let s = format!("u{i}");
            let a = format!("{r}-{i}");
            ok(ingest(&app, &c, &started(&r, &s, &a, 1, &["bb99"])).await);
            ok(ingest(&app, &c, &report(&r, &s, &a, 1, 1, &passing(), &["bb99"])).await);
        }
        ok(app
            .finish(&c, &r, &json!({"kind": "finish", "regression_ref": r}))
            .await);
        slots_total += 500;
    }
    // Quarantine skew: 1,000 attempts by a credential quarantined later, then a clearing
    // retry by another credential.
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let bad = dviscope_server::admin::issue_token(&t.pool, "p1", "pilot", &scopes, 1, "bad")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let bad_actor =
        dviscope_server::auth::actor_from_token(&t.pool, bad["token"].as_str().unwrap_or(""))
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
    new_reg(
        "skew".into(),
        "skewed".into(),
        now - Duration::hours(3),
        vec![decl("r")],
    )
    .await;
    for seq in 1..=1000u32 {
        let a = format!("skew-{seq}");
        ok(ingest(&app, &bad_actor, &started("skew", "r", &a, seq, &[])).await);
        ok(ingest(
            &app,
            &bad_actor,
            &report("skew", "r", &a, seq, 1, &two, &[]),
        )
        .await);
    }
    dviscope_server::admin::quarantine_token(
        &t.pool,
        bad["token_id"].as_i64().unwrap_or(0),
        &ts(now - Duration::days(30)),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:#}"));
    ok(ingest(&app, &c, &started("skew", "r", "skew-ok", 1001, &[])).await);
    ok(ingest(
        &app,
        &c,
        &report("skew", "r", "skew-ok", 1001, 1, &passing(), &[]),
    )
    .await);
    ok(app
        .finish(
            &c,
            "skew",
            &json!({"kind": "finish", "regression_ref": "skew"}),
        )
        .await);
    slots_total += 1;
    // 5,000 distinct signatures.
    let decls: Vec<Value> = (0..5000).map(|i| decl(&format!("v{i}"))).collect();
    new_reg(
        "sigs".into(),
        "many-signatures".into(),
        now - Duration::hours(2),
        decls,
    )
    .await;
    for i in 0..5000 {
        let s = format!("v{i}");
        let a = format!("sigs-{i}");
        ok(ingest(&app, &c, &started("sigs", &s, &a, 1, &[])).await);
        let ev = failing_ids(&[&format!("SIG_{i}")]);
        ok(ingest(&app, &c, &report("sigs", &s, &a, 1, 1, &ev, &[])).await);
    }
    ok(app
        .finish(
            &c,
            "sigs",
            &json!({"kind": "finish", "regression_ref": "sigs"}),
        )
        .await);
    slots_total += 5000;
    eprintln!("populated {slots_total} slots in {:?}", t0.elapsed());
    let mut times = vec![];
    for _ in 0..5 {
        let t1 = std::time::Instant::now();
        let p = health(&app, pid, None, now).await;
        times.push(t1.elapsed());
        assert_eq!(p["kpi"]["streams"], 15);
    }
    times.sort();
    let budget: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM slots), (SELECT count(*) FROM attempts),
                (SELECT count(*) FROM buckets b JOIN attempts a ON a.project_id = b.project_id
                    AND a.id = b.attempt_id AND a.head_revision = b.report_revision)",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    eprintln!(
        "project page (15 streams; {} slots, {} attempts, {} head buckets): p50 {:?}, max {:?}",
        budget.0, budget.1, budget.2, times[2], times[4]
    );
    // The agreed thresholds for accepted work near the default limits.
    assert!(
        times[2] < std::time::Duration::from_secs(2),
        "p50 {:?}",
        times[2]
    );
    assert!(
        times[4] < std::time::Duration::from_secs(5),
        "max {:?}",
        times[4]
    );
    let s = StreamRef {
        producer: "pilot".into(),
        suite: "suite-0".into(),
        branch: "rtl/main".into(),
    };
    let t2 = std::time::Instant::now();
    let h = app
        .read_health_history(&viewer(pid), "p1", &s, 30, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    eprintln!("history (2 rows × 1,000 slots): {:?}", t2.elapsed());
    assert_eq!(h["regressions"].as_array().map(Vec::len), Some(2));
    t.drop().await;
}

#[tokio::test]
async fn build_budgets_count_what_settlement_reads() {
    use dviscope_server::app::health::Limits;
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // Two built slots of one requirement, two build attempts of it (the second with a
    // corrected report revision): 2 distinct builds, 4 slot-build pairs, 3 build revisions.
    sealed(&app, &c, "bld-1", &[built_slot("s1"), built_slot("s2")]).await;
    for b in ["b1", "b2"] {
        ok(ingest(&app, &c, &build_started(b)).await);
        ok(ingest(&app, &c, &build_report(b, "pass")).await);
    }
    let mut corrected = build_report("b2", "pass");
    corrected["report_revision"] = json!(2);
    let _ = ingest(&app, &c, &corrected).await;
    for (s, a) in [("s1", "x1"), ("s2", "x2")] {
        ok(ingest(&app, &c, &started("bld-1", s, a, 1, &["b2"])).await);
        ok(ingest(&app, &c, &report("bld-1", s, a, 1, 1, &passing(), &["b2"])).await);
    }
    finish(&app, &c, "bld-1").await;
    let v = viewer(pid);
    let base = Limits {
        streams: 1,
        slots: 2,
        attempts: 2,
        buckets: 0,
        builds: 2,
        build_pairs: 4,
        build_refs: 2,
        ..Limits::default()
    };
    let rev = |lim: Limits| {
        let (app, v) = (&app, &v);
        async move {
            app.read_health_with(v, "p1", None, now, &lim)
                .await
                .err()
                .map(|e| (e.code, e.message))
        }
    };
    let revisions: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM attempt_facts) + (SELECT count(*) FROM build_facts)",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap_or(0);
    let exact = Limits {
        fact_revisions: revisions,
        ..base
    };
    assert_eq!(rev(exact).await, None, "exactly at every limit");
    for (lim, what) in [
        (Limits { builds: 1, ..exact }, "build attempts"),
        (
            Limits {
                build_pairs: 3,
                ..exact
            },
            "slot-build pairs",
        ),
        (
            Limits {
                fact_revisions: revisions - 1,
                ..exact
            },
            "report revisions",
        ),
        (
            Limits {
                build_refs: 1,
                ..exact
            },
            "build references",
        ),
    ] {
        let (code, msg) = rev(lim)
            .await
            .unwrap_or_else(|| panic!("{what} not refused"));
        assert_eq!(code, ErrorCode::TooLarge, "{what}");
        assert!(msg.contains(what), "{what}: {msg}");
    }
    t.drop().await;
}

#[tokio::test]
async fn expiries_that_change_dispositions_or_the_predecessor_bound_validity() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let day = Duration::days(1);
    let ann = dviscope_server::admin::create_user(&t.pool, "ann", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    dviscope_server::admin::set_member(&t.pool, "p1", "ann", "admin")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let ann = Actor::User {
        user_id: ann["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, Role::Admin)],
    };
    let except =
        |regression: &'static str, id: &'static str, suite: &'static str, until: OffsetDateTime| {
            let (app, ann) = (&app, &ann);
            async move {
                let cmp = app
                    .read_comparison(&viewer(pid), "p1", regression, None, Some("pilot"))
                    .await
                    .unwrap_or_else(|e| panic!("{e:?}"));
                // The row whose slots fail with `id`.
                let fp = cmp
                    .comparison
                    .rows
                    .iter()
                    .find(|r| r.preview.iter().any(|s| s == id))
                    .map(|r| r.signature.to_string())
                    .unwrap_or_else(|| panic!("no row for {id}"));
                let number = cmp.decisions[&fp]
                    .number
                    .unwrap_or_else(|| panic!("no number"));
                app.create_exception(
                    ann,
                    "p1",
                    &dviscope_server::app::decisions::ExceptionRequest {
                        signature: number,
                        branch: "rtl/main".into(),
                        suite: suite.into(),
                        reason: "known".into(),
                        expires_at: ts(until),
                    },
                    None,
                    now,
                )
                .await
                .unwrap_or_else(|e| panic!("{e:?}"));
            }
        };
    // Disposition only: two failing signatures; one excepted. Readiness stays "fail" (the
    // other blocks) before and after the expiry, but `undecided` changes.
    reg(
        &app,
        &c,
        "d-1",
        "disp",
        now - day,
        &[("a", Some(Some("ONE"))), ("b", Some(Some("TWO")))],
        true,
    )
    .await;
    let e1 = now + Duration::hours(3);
    except("d-1", "a", "disp", e1).await;
    // Predecessor only: the predecessor's failure excepted (it read as accepted with
    // exceptions); the latest fails anew. After the expiry the predecessor reads "fail",
    // so the latest is no longer worse by readiness.
    reg(
        &app,
        &c,
        "p-1",
        "pred",
        now - day * 2,
        &[("a", Some(Some("OLD")))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "p-2",
        "pred",
        now - day,
        &[("a", Some(None)), ("z", Some(Some("NEWER")))],
        true,
    )
    .await;
    let e2 = now + Duration::hours(2);
    except("p-1", "a", "pred", e2).await;

    let page = health(&app, pid, None, now).await;
    let d = row(&page, "disp");
    assert_eq!(
        (d["verdict"].as_str(), d["signatures"]["undecided"].as_i64()),
        (Some("fail"), Some(1))
    );
    let p = row(&page, "pred");
    assert_eq!(p["baseline_verdict"], "accepted_with_exceptions", "{p}");
    assert!(
        p["worse"]
            .as_array()
            .is_some_and(|w| w.contains(&json!("readiness")))
    );
    assert_eq!(
        page["valid_until"],
        json!(ts(e2)),
        "the earliest expiry shown"
    );

    let later = health(&app, pid, None, e1 + Duration::minutes(1)).await;
    let d = row(&later, "disp");
    assert_eq!(
        (d["verdict"].as_str(), d["signatures"]["undecided"].as_i64()),
        (Some("fail"), Some(2))
    );
    let p = row(&later, "pred");
    assert_eq!(p["baseline_verdict"], "fail");
    assert!(
        !p["worse"]
            .as_array()
            .is_some_and(|w| w.contains(&json!("readiness")))
    );

    // History carries the same deadlines.
    let s = StreamRef {
        producer: "pilot".into(),
        suite: "pred".into(),
        branch: "rtl/main".into(),
    };
    let h = app
        .read_health_history(&viewer(pid), "p1", &s, 5, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(h["valid_until"], json!(ts(e2)));
    t.drop().await;
}

#[tokio::test]
async fn metrics_follow_the_deciding_attempt_and_the_head_revision() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    let mut body = regression("m-1");
    body["suite"] = json!("metrics");
    body["started_at"] = json!(ts(now - Duration::hours(5)));
    ok(app.create_regression(&c, &body).await);
    let decl = vec![
        json!({"slot_ref": "s", "exec_inputs": {"test": "t_s", "seed": "1"}, "required": true}),
    ];
    ok(app.manifest_chunk(&c, "m-1", 1, &chunk(&decl)).await);
    ok(app.manifest_seal(&c, "m-1", &seal(&decl)).await);
    let rep = |a: &str, seq: u32, rev: u32, ev: &Evidence, cpu: &str, end_min: i64| {
        let mut r = report("m-1", "s", a, seq, rev, ev, &[]);
        r["report_id"] = json!(format!("{a}:r{rev}"));
        r["result"]["runner"]["started_at"] = json!(ts(now - Duration::hours(4)));
        r["result"]["runner"]["finished_at"] =
            json!(ts(now - Duration::hours(4) + Duration::minutes(end_min)));
        r["result"]["runner"]["wall_s"] = json!("60");
        r["result"]["runner"]["cpu_s"] = json!(cpu);
        r["result"]["runner"]["cpu_scope"] = json!("job");
        r
    };
    // Attempt 1 fails (CPU 10, later corrected to revision 2 with CPU 20); attempt 2 (a
    // retry) passes with CPU 99. Under the strict policy the failure decides.
    ok(ingest(&app, &c, &started("m-1", "s", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &rep("a1", 1, 1, &fail_with("BAD"), "10", 10)).await);
    let _ = ingest(&app, &c, &rep("a1", 1, 2, &fail_with("BAD"), "20", 10)).await;
    ok(ingest(&app, &c, &started("m-1", "s", "a2", 2, &[])).await);
    ok(ingest(&app, &c, &rep("a2", 2, 1, &passing(), "99", 50)).await);
    finish(&app, &c, "m-1").await;
    let r = row(&health(&app, pid, None, now).await, "metrics").clone();
    assert_eq!(r["counts"]["failed"], 1, "strict: the failure decides: {r}");
    assert_eq!(r["cost"]["cpu_s"], 20.0, "deciding attempt, head revision");
    // The latest observed end is over every terminal attempt (the retry ended later).
    assert_eq!(
        r["cost"]["last_end"],
        json!(ts(now - Duration::hours(4) + Duration::minutes(50)))
    );
    t.drop().await;
}

#[tokio::test]
async fn retention_removal_keeps_the_page_whole() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let day = Duration::days(1);
    reg(
        &app,
        &c,
        "old",
        "ret",
        now - day * 200,
        &[("a", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "mid",
        "ret",
        now - day * 2,
        &[("a", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "new",
        "ret",
        now - day,
        &[("a", Some(None))],
        true,
    )
    .await;
    // Retention ages a regression by its end: the old one ended 200 days ago.
    sqlx::query("UPDATE regressions SET finished_at = started_at WHERE ref = 'old'")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let metrics_before: i64 = sqlx::query_scalar("SELECT count(*) FROM attempt_metrics")
        .fetch_one(&t.pool)
        .await
        .unwrap_or(0);
    let p = dviscope_server::retention::Policy::default();
    dviscope_server::retention::run(&t.pool, now, p, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // The old all-pass regression's facts are gone, its metrics with them (cascade).
    let metrics_after: i64 = sqlx::query_scalar("SELECT count(*) FROM attempt_metrics")
        .fetch_one(&t.pool)
        .await
        .unwrap_or(0);
    assert_eq!(metrics_after, metrics_before - 1);
    let r = row(&health(&app, pid, None, now).await, "ret").clone();
    assert_eq!(
        (r["latest"]["ref"].as_str(), r["baseline"].as_str()),
        (Some("new"), Some("mid"))
    );
    let s = StreamRef {
        producer: "pilot".into(),
        suite: "ret".into(),
        branch: "rtl/main".into(),
    };
    let h = app
        .read_health_history(&viewer(pid), "p1", &s, 30, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        h["regressions"].as_array().map(Vec::len),
        Some(2),
        "only retained regressions"
    );
    t.drop().await;
}

#[tokio::test]
async fn history_shows_the_streams_cadence_and_overdue_latest() {
    let Some(t) = TestDb::new().await else { return };
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
        "cpu-1",
        "cpu",
        now - Duration::days(3),
        &[("a", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "cpu-2",
        "cpu",
        now - Duration::days(2),
        &[("a", Some(None))],
        true,
    )
    .await;
    app.import_hierarchy(&admin(pid), "p1", &soc())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let s = StreamRef {
        producer: "pilot".into(),
        suite: "cpu".into(),
        branch: "rtl/main".into(),
    };
    let h = app
        .read_health_history(&viewer(pid), "p1", &s, 5, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(h["cadence_hours"], 24);
    assert_eq!(h["home"], "soc/cpu_ss");
    assert_eq!(h["regressions"][0]["overdue"], true, "2 days > 24 h + 6 h");
    assert_eq!(
        h["regressions"][1]["overdue"], false,
        "only the latest can be overdue"
    );
    // Before the deadline, the deadline bounds the history's validity.
    let early = now - Duration::days(2) + Duration::hours(1);
    let h = app
        .read_health_history(&viewer(pid), "p1", &s, 5, early)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        h["valid_until"],
        json!(ts(now - Duration::days(2) + Duration::hours(30)))
    );
    t.drop().await;
}

#[tokio::test]
async fn an_unused_exception_expiring_changes_the_disposition_and_bounds_validity() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // One slot failing with two signatures: an exception on ONE cannot accept the slot
    // (TWO stays uncovered), so readiness never uses it.
    let both = failing_ids(&["ONE", "TWO"]);
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    let mut body = regression("u-1");
    body["suite"] = json!("unused");
    body["started_at"] = json!(ts(now - Duration::hours(6)));
    ok(app.create_regression(&c, &body).await);
    let decl = vec![
        json!({"slot_ref": "a", "exec_inputs": {"test": "t_a", "seed": "1"}, "required": true}),
    ];
    ok(app.manifest_chunk(&c, "u-1", 1, &chunk(&decl)).await);
    ok(app.manifest_seal(&c, "u-1", &seal(&decl)).await);
    ok(ingest(&app, &c, &started("u-1", "a", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("u-1", "a", "a1", 1, 1, &both, &[])).await);
    finish(&app, &c, "u-1").await;
    let ann = dviscope_server::admin::create_user(&t.pool, "ann", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    dviscope_server::admin::set_member(&t.pool, "p1", "ann", "admin")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let ann = Actor::User {
        user_id: ann["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, Role::Admin)],
    };
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "u-1", None, Some("pilot"))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    // ONE: an owner (assigned) and a live exception that cannot accept the slot.
    let one = cmp
        .decisions
        .values()
        .filter_map(|d| d.number)
        .min()
        .unwrap_or_else(|| panic!("no signature"));
    app.set_triage(
        &ann,
        "p1",
        one,
        "rtl/main",
        None,
        &dviscope_server::app::decisions::TriageEdit {
            state: "open".into(),
            owner: Some("ann".into()),
            notes: String::new(),
            bug_urls: vec![],
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let expires = now + Duration::hours(2);
    app.create_exception(
        &ann,
        "p1",
        &dviscope_server::app::decisions::ExceptionRequest {
            signature: one,
            branch: "rtl/main".into(),
            suite: "unused".into(),
            reason: "one is known".into(),
            expires_at: ts(expires),
        },
        None,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let before = health(&app, pid, None, now).await;
    let r = row(&before, "unused");
    assert_eq!(r["verdict"], "fail", "the exception is not used: {r}");
    assert_eq!(
        r["signatures"]["undecided"], 2,
        "the ineffective exception needs a decision"
    );
    assert_eq!(
        before["valid_until"],
        json!(ts(expires)),
        "an unused exception still bounds it"
    );
    let s = StreamRef {
        producer: "pilot".into(),
        suite: "unused".into(),
        branch: "rtl/main".into(),
    };
    let h = app
        .read_health_history(&viewer(pid), "p1", &s, 5, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(h["valid_until"], json!(ts(expires)));
    // After the expiry: ONE is merely assigned (owner, no exception), readiness unchanged.
    let after = health(&app, pid, None, expires + Duration::minutes(1)).await;
    let r = row(&after, "unused");
    assert_eq!(r["verdict"], "fail");
    assert_eq!(r["signatures"]["undecided"], 1);
    t.drop().await;
}

#[tokio::test]
async fn declared_requirements_without_builds_are_budgeted() {
    use dviscope_server::app::health::Limits;
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // Three built slots declared, no build and no attempt yet.
    sealed(
        &app,
        &c,
        "decl-1",
        &[built_slot("s1"), built_slot("s2"), built_slot("s3")],
    )
    .await;
    let v = viewer(pid);
    let read = |lim: Limits| {
        let (app, v) = (&app, &v);
        async move {
            app.read_health_with(v, "p1", None, now, &lim)
                .await
                .err()
                .map(|e| (e.code, e.message))
        }
    };
    assert_eq!(
        read(Limits {
            requirements: 3,
            ..Limits::default()
        })
        .await,
        None
    );
    let (code, msg) = read(Limits {
        requirements: 2,
        ..Limits::default()
    })
    .await
    .unwrap_or_else(|| panic!("not refused"));
    assert_eq!(code, ErrorCode::TooLarge);
    assert!(msg.contains("declared build requirements"), "{msg}");
    t.drop().await;
}

#[tokio::test]
async fn many_links_to_one_stream_share_one_rollup_and_are_budgeted() {
    use dviscope_server::app::health::Limits;
    let Some(t) = TestDb::new().await else { return };
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
        "x-1",
        "shared",
        now - Duration::days(2),
        &[("a", Some(None)), ("b", Some(None))],
        true,
    )
    .await;
    reg(
        &app,
        &c,
        "x-2",
        "shared",
        now - Duration::days(1),
        &[("a", Some(Some("S1"))), ("b", Some(Some("S2")))],
        true,
    )
    .await;
    // A root with 300 children: the stream's home in the first, linked in the others.
    let mut nodes = vec![json!({"path": "r"})];
    let mut links = vec![];
    for i in 0..300 {
        nodes.push(json!({"path": format!("r/c{i}")}));
        if i > 0 {
            links.push(json!({"node": format!("r/c{i}"),
                              "stream": {"producer": "pilot", "suite": "shared", "branch": "rtl/main"}}));
        }
    }
    let h = tree(json!({
        "nodes": nodes,
        "streams": [{"node": "r/c0", "producer": "pilot", "suite": "shared", "branch": "rtl/main"}],
        "links": links,
    }));
    app.import_hierarchy(&admin(pid), "p1", &h)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let page = health(&app, pid, Some("r"), now).await;
    let kids = page["children"].as_array().cloned().unwrap_or_default();
    assert_eq!(kids.len(), 300);
    assert!(
        kids.iter().all(|k| k["health"] == kids[0]["health"]),
        "one shared roll-up"
    );
    assert_eq!(kids[0]["health"]["signatures"]["new"], 2);
    // The work is the KPI's entries plus ONE child set (not 300): with the stream's
    // entries E, a limit of 2E answers and 2E - 1 is refused.
    let e = {
        let r = row(&health(&app, pid, Some("r/c0"), now).await, "shared").clone();
        let sg = &r["signatures"];
        [
            "all",
            "new",
            "unknown",
            "persistent",
            "no_longer_observed",
            "config_not_run",
            "undecided",
        ]
        .iter()
        .map(|k| sg[k].as_i64().unwrap_or(0))
        .sum::<i64>()
    };
    let ok_lim = Limits {
        rollup_entries: 2 * e,
        ..Limits::default()
    };
    assert!(
        app.read_health_with(&viewer(pid), "p1", Some("r"), now, &ok_lim)
            .await
            .is_ok()
    );
    let low = Limits {
        rollup_entries: 2 * e - 1,
        ..Limits::default()
    };
    let err = app
        .read_health_with(&viewer(pid), "p1", Some("r"), now, &low)
        .await
        .err()
        .map(|e| e.code);
    assert_eq!(err, Some(ErrorCode::TooLarge));
    t.drop().await;
}

#[tokio::test]
async fn shared_build_history_is_counted_per_regression_that_reads_it() {
    use dviscope_server::app::health::Limits;
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // One build with three report revisions, read by two regressions of one stream (the
    // latest and its predecessor, both loaded by the page).
    let _ = app.create_source_manifest(&c, &source_manifest()).await;
    ok(ingest(&app, &c, &build_started("b1")).await);
    for rev in 1..=3 {
        let mut r = build_report("b1", "pass");
        r["report_revision"] = json!(rev);
        let _ = ingest(&app, &c, &r).await;
    }
    let build_revisions: i64 = sqlx::query_scalar("SELECT count(*) FROM build_facts")
        .fetch_one(&t.pool)
        .await
        .unwrap_or(0);
    assert!(build_revisions >= 2, "{build_revisions}");
    for (r, start) in [
        ("sb-1", now - Duration::days(2)),
        ("sb-2", now - Duration::days(1)),
    ] {
        let _ = app.create_source_manifest(&c, &source_manifest()).await;
        let mut body = regression(r);
        body["started_at"] = json!(ts(start));
        ok(app.create_regression(&c, &body).await);
        let decls = [built_slot("s1")];
        ok(app.manifest_chunk(&c, r, 1, &chunk(&decls)).await);
        ok(app.manifest_seal(&c, r, &seal(&decls)).await);
        finish(&app, &c, r).await;
    }
    // No attempts: every report revision of the page is a build revision, read twice.
    let read = |n: i64| {
        let app = &app;
        async move {
            app.read_health_with(
                &viewer(pid),
                "p1",
                None,
                now,
                &Limits {
                    fact_revisions: n,
                    ..Limits::default()
                },
            )
            .await
            .err()
            .map(|e| (e.code, e.message))
        }
    };
    assert_eq!(
        read(2 * build_revisions).await,
        None,
        "exactly at the limit"
    );
    let (code, msg) = read(2 * build_revisions - 1)
        .await
        .unwrap_or_else(|| panic!("not refused"));
    assert_eq!(code, ErrorCode::TooLarge);
    assert!(msg.contains("report revisions"), "{msg}");
    t.drop().await;
}

/// The demo SoC (`dviscope-server demo --soc`) tells its story on the dashboard.
/// A sealed regression with these slots (`(slot, required)`, test `t_<slot>`), no results;
/// sealed only when `seal`.
async fn declared(
    app: &App,
    c: &Actor,
    r: &str,
    suite: &str,
    start: OffsetDateTime,
    slots: &[(&str, bool)],
    seal_it: bool,
) {
    let _ = app.create_source_manifest(c, &source_manifest()).await;
    let mut body = regression(r);
    body["suite"] = json!(suite);
    body["started_at"] = json!(ts(start));
    ok(app.create_regression(c, &body).await);
    let decls: Vec<Value> = slots
        .iter()
        .map(|(s, req)| json!({"slot_ref": s, "exec_inputs": {"test": format!("t_{s}"), "seed": "1"}, "required": req}))
        .collect();
    ok(app.manifest_chunk(c, r, 1, &chunk(&decls)).await);
    if seal_it {
        ok(app.manifest_seal(c, r, &seal(&decls)).await);
    }
}

/// Test growth: per UTC day, each stream's latest sealed regression by the day's end (one
/// from before the period carries forward; one starting exactly at midnight belongs to that
/// day; one superseded the same day is never read), required runs summed, distinct required
/// tests counted once across streams; removed and optional slots and unsealed regressions do
/// not count; a non-UTC clock gives the same days; the node's subtree, the project (every
/// stream) and Unassigned; both budgets exact, each refusal from its own check.
#[tokio::test]
async fn growth_counts_tests_per_day_and_carries_streams_forward() {
    use dviscope_server::app::health::Limits;
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    app.import_hierarchy(&admin(pid), "p1", &soc())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    // A fixed clock in the past: the read is at 01:01 UTC of a day that has begun for sure
    // (at least two hours ago), and every regression of a day starts at 00:01.
    let wall = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let base =
        (wall - Duration::hours(2)).replace_time(time::Time::MIDNIGHT) + Duration::minutes(1);
    let now = base + Duration::hours(1);
    let day = Duration::days(1);
    declared(
        &app,
        &c,
        "cpu-0",
        "cpu",
        base - day * 10,
        &[("a", true), ("b", true)],
        true,
    )
    .await;
    // Unsealed before the period: never dma's value on the first day.
    declared(
        &app,
        &c,
        "dma-0",
        "dma",
        base - day * 8,
        &[("y", true)],
        false,
    )
    .await;
    // Exactly at midnight: day 1, not day 0.
    declared(
        &app,
        &c,
        "dma-1",
        "dma",
        base - day * 3 - Duration::minutes(1),
        &[("a", true), ("x", true)],
        true,
    )
    .await;
    declared(
        &app,
        &c,
        "cpu-1",
        "cpu",
        base - day * 2,
        &[("a", true), ("b", true), ("c", true)],
        true,
    )
    .await;
    // c is removed again: cpu-1 has two required tests (and three slot rows).
    ok(app
        .manifest_amend(
            &c,
            "cpu-1",
            &json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2, "add": [],
                    "remove": [{"slot_ref": "c", "reason": "dropped"}]}),
        )
        .await);
    // Superseded the same day by cpu-2: never a day's winner, never read.
    let ten: Vec<(String, bool)> = (0..10).map(|k| (format!("z{k}"), true)).collect();
    let ten: Vec<(&str, bool)> = ten.iter().map(|(s, r)| (s.as_str(), *r)).collect();
    declared(
        &app,
        &c,
        "cpu-2a",
        "cpu",
        base - day - Duration::seconds(30),
        &ten,
        true,
    )
    .await;
    declared(&app, &c, "cpu-2", "cpu", base - day, &[("a", true)], true).await;
    declared(&app, &c, "io-1", "io", base - day, &[("q", true)], true).await;
    declared(
        &app,
        &c,
        "dma-2",
        "dma",
        base,
        &[("a", true), ("opt", false)],
        true,
    )
    .await;
    declared(
        &app,
        &c,
        "cpu-3",
        "cpu",
        base,
        &[("a", true), ("b", true), ("c", true), ("d", true)],
        false,
    )
    .await;
    let growth = |area: Option<&'static str>, days: i64, lim: Limits, at: OffsetDateTime| {
        let app = app.clone();
        async move {
            app.read_health_growth_with(&viewer(pid), "p1", area, days, at, &lim)
                .await
        }
    };
    let series = |v: &Value| -> Vec<(i64, i64, i64)> {
        v["days"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|d| {
                (
                    d["required_runs"].as_i64().unwrap_or(-1),
                    d["tests"].as_i64().unwrap_or(-1),
                    d["streams"].as_i64().unwrap_or(-1),
                )
            })
            .collect()
    };
    let want5 = vec![(2, 2, 1), (4, 3, 2), (4, 3, 2), (3, 2, 2), (2, 1, 2)];
    let soc5 = growth(Some("soc"), 5, Limits::default(), now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(series(&soc5), want5, "{soc5}");
    let dates: Vec<&str> = soc5["days"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| d["date"].as_str())
        .collect();
    let (first, last) = (
        (now - Duration::days(4)).date().to_string(),
        now.date().to_string(),
    );
    assert_eq!(dates.first().copied(), Some(first.as_str()));
    assert_eq!(dates.last().copied(), Some(last.as_str()));
    // The same instant on clocks whose local date differs from the UTC date (01:01 UTC is the
    // previous day at -05:00): the same UTC days.
    for (h, label) in [(5, "+05:00"), (-5, "-05:00")] {
        let at = now.to_offset(time::UtcOffset::from_hms(h, 0, 0).unwrap_or(time::UtcOffset::UTC));
        let v = growth(Some("soc"), 5, Limits::default(), at)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(v["days"], soc5["days"], "{label}");
    }
    assert_ne!(
        now.to_offset(time::UtcOffset::from_hms(-5, 0, 0).unwrap_or(time::UtcOffset::UTC))
            .date(),
        now.date(),
        "the -05:00 clock is on another date"
    );
    // The project has every stream (io is unassigned); Unassigned only io.
    let all = growth(None, 2, Limits::default(), now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(series(&all), vec![(4, 3, 3), (3, 2, 3)], "{all}");
    let un = growth(Some("~unassigned"), 2, Limits::default(), now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(series(&un), vec![(1, 1, 1), (1, 1, 1)], "{un}");
    // A lower node: dma is linked under dsp_ss too.
    let dsp = growth(Some("soc/dsp_ss"), 1, Limits::default(), now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(series(&dsp), vec![(1, 1, 1)], "{dsp}");
    // Refusals.
    let refused = |r: Result<Value, dviscope_server::error::AppError>| {
        r.err()
            .map(|e| (e.code, e.message))
            .unwrap_or_else(|| panic!("must be refused"))
    };
    assert_eq!(
        refused(growth(Some("soc"), 0, Limits::default(), now).await).0,
        ErrorCode::Invalid
    );
    assert_eq!(
        refused(growth(Some("soc"), 367, Limits::default(), now).await).0,
        ErrorCode::Invalid
    );
    assert_eq!(
        refused(growth(Some("nope"), 5, Limits::default(), now).await).0,
        ErrorCode::NotFound
    );
    // soc over 5 days: 6 candidates (cpu-0 from before, cpu-2a superseded); the winners have
    // 10 slot rows (cpu-2a's 10 never read); the five distinct sets scan 2 + 4 + 5 + 3 + 3.
    let exact = Limits {
        growth_regressions: 6,
        growth_slots: 17,
        ..Limits::default()
    };
    assert!(growth(Some("soc"), 5, exact, now).await.is_ok());
    // Seven days: the first three share one set (cpu-0 only), scanned once.
    let soc7 = growth(Some("soc"), 7, exact, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        series(&soc7)[..3],
        [(2, 2, 1), (2, 2, 1), (2, 2, 1)],
        "{soc7}"
    );
    let e = refused(
        growth(
            Some("soc"),
            5,
            Limits {
                growth_regressions: 5,
                ..exact
            },
            now,
        )
        .await,
    );
    assert_eq!(e.0, ErrorCode::TooLarge);
    assert!(e.1.contains("more than 5 regressions"), "{}", e.1);
    let e = refused(
        growth(
            Some("soc"),
            5,
            Limits {
                growth_slots: 16,
                ..exact
            },
            now,
        )
        .await,
    );
    assert_eq!(e.0, ErrorCode::TooLarge);
    assert!(e.1.contains("scan 17 slots"), "{}", e.1);
    // Fewer than the winners' rows: refused by the bounded count, before any slot is read.
    let e = refused(
        growth(
            Some("soc"),
            5,
            Limits {
                growth_slots: 9,
                ..exact
            },
            now,
        )
        .await,
    );
    assert!(e.1.contains("have more than 9 slots"), "{}", e.1);
    assert!(
        growth(
            Some("soc"),
            5,
            Limits {
                growth_slots: 10,
                ..exact
            },
            now
        )
        .await
        .is_err_and(|e| e.message.contains("scan"))
    );
    assert_eq!(
        refused(
            growth(
                Some("soc"),
                5,
                Limits {
                    streams: 1,
                    ..exact
                },
                now
            )
            .await
        )
        .0,
        ErrorCode::TooLarge
    );
    t.drop().await;
}

/// The growth candidates are found through the sealed-stream index: 20,000 unsealed
/// regressions of the stream and 20,000 sealed ones of another producer's 50 streams in the
/// period are never visited (both arms use the index; neither the table nor the date index
/// is scanned).
#[tokio::test]
async fn growth_candidates_use_the_sealed_stream_index() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    declared(
        &app,
        &c,
        "cpu-0",
        "cpu",
        now - Duration::days(30),
        &[("a", true)],
        true,
    )
    .await;
    sqlx::query(
        "INSERT INTO regressions (project_id, producer_id, ref, digest, body, suite,
                                  branch_repository, branch_name, source_manifest_ref, started_at)
         SELECT project_id, producer_id, ref || '-u' || g, digest, body, suite,
                branch_repository, branch_name, source_manifest_ref,
                $2::timestamptz + g * interval '15 seconds'
           FROM regressions, generate_series(1, 20000) g WHERE project_id = $1 AND ref = 'cpu-0'",
    )
    .bind(pid)
    .bind(now - Duration::days(6))
    .execute(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    // Another producer's sealed regressions over 50 suites of the branch, interleaved in time.
    dviscope_server::admin::create_producer(&t.pool, "p1", "other")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    sqlx::query(
        "INSERT INTO regressions (project_id, producer_id, ref, digest, body, suite,
                                  branch_repository, branch_name, source_manifest_ref, started_at,
                                  sealed, state)
         SELECT r.project_id, p.id, r.ref || '-o' || g, r.digest, r.body, r.suite || '-' || (g % 50),
                r.branch_repository, r.branch_name, r.source_manifest_ref,
                $2::timestamptz + g * interval '15 seconds' + interval '7 seconds', true, 'sealed'
           FROM regressions r JOIN producers p ON p.project_id = r.project_id AND p.name = 'other',
                generate_series(1, 20000) g
          WHERE r.project_id = $1 AND r.ref = 'cpu-0'",
    )
    .bind(pid)
    .bind(now - Duration::days(6))
    .execute(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("ANALYZE regressions")
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let (producer, suite, repo, branch): (i64, String, String, String) = sqlx::query_as(
        "SELECT producer_id, suite, branch_repository, branch_name FROM regressions
          WHERE project_id = $1 AND ref = 'cpu-0'",
    )
    .bind(pid)
    .fetch_one(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    // The listing and the bounded count: both arms (the period and the top-1 lookup before
    // it) go through the index, and nothing scans the table.
    let q = dviscope_server::app::health::GROWTH_CANDIDATES;
    for (what, sql) in [
        ("listing", format!("EXPLAIN {q}")),
        (
            "count",
            format!("EXPLAIN SELECT count(*) FROM (SELECT 1 FROM ({q}) y LIMIT 20001) x"),
        ),
    ] {
        let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(pid)
            .bind(vec![producer])
            .bind(vec![suite.clone()])
            .bind(vec![repo.clone()])
            .bind(vec![branch.clone()])
            .bind(now - Duration::days(7))
            .bind(now)
            .fetch_all(&t.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let plan = plan.join("\n");
        assert!(
            plan.matches("regressions_stream_sealed").count() >= 2,
            "{what}: {plan}"
        );
        assert!(!plan.contains("Seq Scan on regressions"), "{what}: {plan}");
        assert!(!plan.contains("regressions_age"), "{what}: {plan}");
        // Unsealed rows are not in the index at all: nothing filters them out row by row.
        assert!(!plan.contains("Filter: sealed"), "{what}: {plan}");
    }
    t.drop().await;
}

#[tokio::test]
async fn demo_soc_tells_its_story() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let out = dviscope_server::demo_soc::generate(&t.pool, "demo-soc", now)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(out["regressions"], 8 * 14 + 2);
    let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'demo-soc'")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let v = viewer(pid);
    let read = |area: Option<&'static str>| {
        let (app, v) = (&app, &v);
        async move {
            app.read_health(v, "demo-soc", area, now)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"))
        }
    };
    let soc = read(Some("soc")).await;
    assert_eq!(soc["kpi"]["streams"], 9, "dma counted once");
    let ss = |p: &str| child(&soc, p)["health"].clone();
    // cpu_ss: the assigned dma failure persists (no worse), core-questa still running.
    assert_eq!(ss("soc/cpu_ss")["trend"], "yellow", "{}", ss("soc/cpu_ss"));
    assert_eq!(ss("soc/cpu_ss")["grey"]["running"], 1);
    // dsp_ss: a new overflow in mac_array.
    assert_eq!(ss("soc/dsp_ss")["trend"], "red");
    // io_ss: results missing on the last night.
    assert_eq!(ss("soc/io_ss")["trend"], "red");
    // periph_ss: clean but overdue.
    assert_eq!(ss("soc/periph_ss")["trend"], "green");
    assert_eq!(ss("soc/periph_ss")["grey"]["overdue"], 1);
    let core = read(Some("soc/cpu_ss/core")).await;
    let vcs = row(&core, "core-vcs");
    assert_eq!(vcs["trend"], "green");
    assert_eq!(
        vcs["signatures"]["no_longer_observed"], 0,
        "fixed two nights ago"
    );
    let questa = row(&core, "core-questa");
    assert_eq!(questa["trend"], "running");
    assert_eq!(
        questa["counts"]["running"], 3,
        "three attempts still in progress"
    );
    assert_ne!(questa["verdict"], "pass");
    let dsp_dma = read(Some("soc/dsp_ss/dma")).await;
    assert_eq!(
        row(&dsp_dma, "dma-nightly")["shared_from"],
        "soc/cpu_ss/dma"
    );
    assert_eq!(
        row(&dsp_dma, "dma-nightly")["signatures"]["undecided"],
        0,
        "assigned"
    );
    // fft lost three tests last night: the Tests change shows it, the trend does not.
    let fft = read(Some("soc/dsp_ss/fft")).await;
    let f = row(&fft, "fft-nightly");
    assert_eq!(
        (
            f["counts"]["required"].as_i64(),
            f["baseline_counts"]["required"].as_i64()
        ),
        (Some(5), Some(8)),
        "{f}"
    );
    let mac = read(Some("soc/dsp_ss/mac_array")).await;
    assert_eq!(row(&mac, "mac-nightly")["signatures"]["new"], 1);
    assert_eq!(row(&mac, "mac-nightly")["counts"]["failed"], 2);
    // Exact counts: the assigned dma failure still fails readiness; two I/O results missing.
    let dma = row(&read(Some("soc/cpu_ss/dma")).await, "dma-nightly").clone();
    assert_eq!(
        (dma["counts"]["failed"].as_i64(), dma["verdict"].as_str()),
        (Some(1), Some("fail"))
    );
    let io = row(&read(Some("soc/io_ss")).await, "io_ss-nightly").clone();
    assert_eq!(
        (
            io["counts"]["missing"].as_i64(),
            io["counts"]["passed"].as_i64()
        ),
        (Some(2), Some(8))
    );
    // The generator's credential is not left usable; a second run is refused.
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_tokens WHERE revoked_at IS NULL AND expires_at > now()",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap_or(-1);
    assert_eq!(live, 0);
    assert!(
        dviscope_server::demo_soc::generate(&t.pool, "demo-soc", now)
            .await
            .is_err()
    );
    // The fixed hazard shows in core-vcs history as no longer observed on night 13.
    let s = StreamRef {
        producer: "demo-runner".into(),
        suite: "core-vcs".into(),
        branch: "soc-rtl/main".into(),
    };
    let h = app
        .read_health_history(&v, "demo-soc", &s, 5, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(h["regressions"][1]["latest"]["ref"], "core-vcs-n13");
    assert_eq!(h["regressions"][1]["signatures"]["no_longer_observed"], 1);
    t.drop().await;
}

/// A demo generation that fails part-way still revokes its collector token.
#[tokio::test]
async fn a_failed_demo_generation_leaves_no_usable_token() {
    let Some(t) = TestDb::new().await else { return };
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // The decisions author's name is taken: generation fails after the regressions.
    dviscope_server::admin::create_user(&t.pool, "x-soc-demo", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    dviscope_server::admin::create_user(&t.pool, "x-demo", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert!(
        dviscope_server::demo_soc::generate(&t.pool, "x-soc", now)
            .await
            .is_err()
    );
    assert!(
        dviscope_server::demo::generate(&t.pool, "x", now)
            .await
            .is_err()
    );
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM api_tokens WHERE revoked_at IS NULL AND expires_at > now()",
    )
    .fetch_one(&t.pool)
    .await
    .unwrap_or(-1);
    assert_eq!(live, 0, "both generators revoked their tokens");
    t.drop().await;
}
