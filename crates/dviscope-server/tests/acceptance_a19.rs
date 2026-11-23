//! A19: retention under a controlled clock.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_server::retention::{self, Policy};
use serde_json::json;
use time::{Duration, OffsetDateTime};

fn at(days: i64) -> OffsetDateTime {
    // Records start 2026-11-08T01:00:00Z; the clock runs from there.
    OffsetDateTime::parse(
        "2026-11-08T01:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap_or_else(|e| panic!("{e}"))
        + Duration::days(days)
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one aged dataset, step by step
async fn a19_retention() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, &pass).await;
    // "clean": all pass. "red": one failure. Both use build b1.
    let slots = [built_slot("s1"), built_slot("s2")];
    for r in ["clean", "red"] {
        sealed(&app, &c, r, &slots).await;
        if r == "clean" {
            ok(ingest(&app, &c, &build_started("b1")).await);
        }
        for (s, ev) in [
            ("s1", &pass),
            ("s2", if r == "red" { &fail } else { &pass }),
        ] {
            let a = format!("{r}-{s}");
            ok(ingest(&app, &c, &started(r, s, &a, 1, &["b1"])).await);
            ok(ingest(&app, &c, &report(r, s, &a, 1, 1, ev, &["b1"])).await);
        }
        ok(app
            .finish(&c, r, &json!({"kind": "finish", "regression_ref": r}))
            .await);
    }
    ok(ingest(&app, &c, &build_report("b1", "pass")).await);
    // Ages count from the regression's end: pin it to the controlled clock's origin.
    sqlx::query("UPDATE regressions SET finished_at = $1")
        .bind(at(0))
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("UPDATE receipts SET received_at = $1")
        .bind(at(0))
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    sqlx::query("UPDATE build_attempts SET started_at = $1")
        .bind(at(0))
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let v = viewer(pid);
    let cmp = |r: &'static str| {
        let app = app.clone();
        let v = v.clone();
        async move {
            let c = app
                .read_comparison(&v, "p1", r, Some("none"), None)
                .await
                .unwrap_or_else(|e| panic!("{e:?}"))
                .comparison;
            serde_json::to_value(c).unwrap_or_default()
        }
    };
    let red_before = cmp("red").await;
    let p = Policy::default();

    // Day 10: nothing. A dry run at day 40 reports the clean payloads and changes nothing.
    assert_eq!(
        retention::run(&t.pool, at(10), p, false)
            .await
            .map(|r| r.payloads)
            .ok(),
        Some(0)
    );
    let dry = retention::run(&t.pool, at(40), p, true)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((dry.payloads, dry.regressions), (2, 0));
    assert_eq!(t.count("attempt_reports").await, 4);

    // Day 40: the clean payloads expire; answers do not change.
    let r = retention::run(&t.pool, at(40), p, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.payloads, 2);
    assert_eq!(t.count("attempt_reports").await, 2);
    assert_eq!(
        state(&read(&app, pid, "clean").await, "s1")["state"],
        "passed"
    );
    // A correction after payload expiry is accepted (new facts and payload).
    ok(ingest(
        &app,
        &c,
        &report("clean", "s1", "clean-s1", 1, 2, &pass, &["b1"]),
    )
    .await);
    assert_eq!(t.count("attempt_reports").await, 3);

    // Day 100: the red payloads expire too; the comparison is unchanged.
    let r = retention::run(&t.pool, at(100), p, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        r.regressions, 1,
        "the clean regression's facts expire at 90 days"
    );
    assert_eq!(cmp("red").await, red_before);
    // A correction for the expired regression: 410 E_EXPIRED; nothing resurrected.
    let late = report("clean", "s2", "clean-s2", 1, 2, &pass, &["b1"]);
    assert_eq!(code(ingest(&app, &c, &late).await), ErrorCode::Expired);
    assert!(app.read_regression(&v, "p1", "clean", None).await.is_err());
    // The shared build stays while the red regression references it.
    assert_eq!(t.count("build_attempts").await, 1);

    // Day 130: receipts past the horizon; an old replay is 410 E_REPLAY_EXPIRED.
    let r = retention::run(&t.pool, at(130), p, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(r.receipts > 0);
    let replay = report("red", "s1", "red-s1", 1, 1, &pass, &["b1"]);
    assert_eq!(
        code(ingest(&app, &c, &replay).await),
        ErrorCode::ReplayExpired
    );
    assert_eq!(
        code(app.create_regression(&c, &regression("clean")).await),
        ErrorCode::ReplayExpired,
        "an expired regression is never created again"
    );

    // Day 800: the red facts expire; the unreferenced build goes with them.
    let r = retention::run(&t.pool, at(800), p, false)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((r.regressions, r.builds), (1, 1));
    for table in [
        "regressions",
        "slots",
        "attempts",
        "attempt_facts",
        "buckets",
        "build_attempts",
    ] {
        assert_eq!(t.count(table).await, 0, "{table}");
    }
    t.drop().await;
}
