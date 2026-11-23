//! The "bad nightly" demo dataset: a separate project with three nightlies of
//! invented records, the last of which has every kind of trouble a triager meets — a
//! repeated failure signature (with a triage case), a failure whose exception has expired,
//! a missing result and slots blocked by a failed build. Written through the same app
//! paths as real collectors; nothing in it comes from a real simulation.

use anyhow::{Context as _, Result, bail};
use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::packs::shipped;
use dviscope_model::canonical::digest_of;
use dviscope_model::schema::{INGEST, MANIFEST};
use dviscope_model::wire::evidence::Evidence;
use dviscope_model::wire::manifest::SlotDecl;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::app::decisions::{ExceptionRequest, TriageEdit};
use crate::app::ingest::LineResult;
use crate::app::{App, Receipt};
use crate::auth::{Actor, Role};

const PRODUCER: &str = "demo-runner";
const SOURCE: &str = "demo-sm";

pub(crate) fn ts(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

fn evidence(body: &str, errors: u32, fatals: u32) -> Result<Evidence> {
    let text = format!(
        "{body}--- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    {errors}\nUVM_FATAL :    {fatals}\n$finish at simulation time 100\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n"
    );
    let p = shipped::default_pipeline()?;
    let mut o = ExtractOptions::simulation("sim.log");
    o.simulator = Some("vcs".into());
    Ok(extract_bytes(&p, o, text.as_bytes()).0)
}

/// The demo's passing evidence (shared by the demo datasets).
pub(crate) fn demo_pass() -> Result<Evidence> {
    evidence("UVM_INFO @ 1: top [HELLO] all transactions matched\n", 0, 0)
}

/// The demo's failing evidence (a scoreboard mismatch; shared by the demo datasets).
pub(crate) fn demo_mismatch() -> Result<Evidence> {
    evidence(
        "UVM_ERROR @ 5000: uvm_test_top.env.sb [SB_MISMATCH] expected 0x1f got 0x0f\n",
        1,
        0,
    )
}

fn build_req() -> Value {
    json!({"source_manifest_ref": SOURCE,
           "build_config": {"simulator": {"vendor": "vcs", "version": "demo"}}})
}

fn slot(test: &str, built: bool) -> Value {
    let mut v =
        json!({"slot_ref": test, "exec_inputs": {"test": test, "seed": "1"}, "required": true});
    if built {
        v["build_reqs"] = json!([build_req()]);
    }
    v
}

pub(crate) fn check(
    r: std::result::Result<Receipt, crate::error::AppError>,
    what: &str,
) -> Result<()> {
    r.map(|_| ())
        .map_err(|e| anyhow::anyhow!("{what}: {}", e.message))
}

pub(crate) async fn ingest(app: &App, c: &Actor, v: &Value, what: &str) -> Result<()> {
    match app.ingest_line(c, v).await {
        LineResult::Ok(_) => Ok(()),
        LineResult::Rejected(e) => bail!("{what}: {}", e.message),
    }
}

/// What one slot does in a nightly.
#[derive(Clone, Copy)]
enum Run {
    Pass,
    Mismatch,
    Timeout,
    Missing,
}

/// Creates the demo project `project` and its data as of `now`; refuses an existing
/// project. Returns what was created.
///
/// # Errors
/// An existing project, or any write that fails (the data are then partial: drop the
/// project's database or use another name).
#[allow(clippy::too_many_lines)] // one scripted story
pub async fn generate(db: &PgPool, project: &str, now: OffsetDateTime) -> Result<Value> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM projects WHERE name = $1)")
        .bind(project)
        .fetch_one(db)
        .await?;
    if exists {
        bail!("project {project} exists: the demo is created in a new project");
    }
    crate::admin::create_project(db, project, "strict").await?;
    crate::admin::create_producer(db, project, PRODUCER).await?;
    let pipeline = shipped::default_pipeline()?.digest;
    crate::admin::set_pipeline(db, project, pipeline.as_str(), "accepted").await?;
    let scopes: Vec<String> = crate::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let tok =
        crate::admin::issue_token(db, project, PRODUCER, &scopes, 1, "demo generator").await?;
    let out = populate(db, project, now, tok["token"].as_str().unwrap_or_default()).await;
    // The generator's credential is never left usable, also when generation failed; a
    // failed revocation is reported, never hidden behind the generation error.
    let revoked = crate::admin::revoke_token(db, tok["token_id"].as_i64().unwrap_or(0)).await;
    match (out, revoked) {
        (Ok(v), Ok(_)) => Ok(v),
        (Ok(_), Err(r)) => Err(r.context("revoking the demo generator's token")),
        (Err(e), Ok(_)) => Err(e),
        (Err(e), Err(r)) => Err(e.context(format!(
            "revoking the demo generator's token failed too: {r:#}"
        ))),
    }
}

#[allow(clippy::too_many_lines)] // one scripted story
async fn populate(db: &PgPool, project: &str, now: OffsetDateTime, token: &str) -> Result<Value> {
    crate::app::fail::point("demo_generator").map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let c = crate::auth::actor_from_token(db, token)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let c = &c;
    let app = App { db: db.clone() };
    let pass = demo_pass()?;
    let mismatch = demo_mismatch()?;
    let timeout = evidence(
        "UVM_FATAL @ 90000: uvm_test_top [WATCHDOG] test did not finish in time\n",
        0,
        1,
    )?;

    check(
        app.create_source_manifest(
            c,
            &json!({"schema": INGEST, "producer_id": PRODUCER, "source_manifest_ref": SOURCE,
                    "repositories": [{"repository": "demo-rtl", "revision": "0000demo"}]}),
        )
        .await,
        "source manifest",
    )?;

    // Three nightlies, oldest first. The last one is the bad nightly.
    let tests = [
        "uart_tx",
        "uart_rx",
        "spi_basic",
        "dma_burst",
        "dma_chain",
        "irq_storm",
    ];
    let plans: [(&str, [Run; 6], bool); 3] = [
        ("nightly-1", [Run::Pass; 6], false),
        (
            "nightly-2",
            [
                Run::Pass,
                Run::Mismatch,
                Run::Pass,
                Run::Pass,
                Run::Pass,
                Run::Pass,
            ],
            false,
        ),
        (
            "nightly-3",
            [
                Run::Pass,
                Run::Mismatch,
                Run::Missing,
                Run::Pass,
                Run::Pass,
                Run::Timeout,
            ],
            true,
        ),
    ];
    let mut regressions = vec![];
    for (i, (name, runs, bad_build)) in plans.iter().enumerate() {
        let back = i64::try_from(plans.len() - i).unwrap_or(1);
        let start = now - Duration::days(back) - Duration::hours(6);
        let slots: Vec<Value> = tests
            .iter()
            .enumerate()
            .map(|(k, t)| slot(t, *bad_build && (k == 3 || k == 4)))
            .collect();
        check(
            app.create_regression(
                c,
                &json!({"schema": INGEST, "producer_id": PRODUCER, "regression_ref": name,
                        "suite": "nightly", "branch": {"repository": "demo-rtl", "name": "main"},
                        "source_manifest_ref": SOURCE, "trigger": {"kind": "nightly"},
                        "started_at": ts(start)}),
            )
            .await,
            "regression",
        )?;
        check(
            app.manifest_chunk(c, name, 1, &json!({"schema": MANIFEST, "slots": slots}))
                .await,
            "manifest",
        )?;
        let mut decls: Vec<SlotDecl> = slots
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<std::result::Result<_, _>>()?;
        decls.sort_by(|a, b| a.slot_ref.as_str().cmp(b.slot_ref.as_str()));
        check(
            app.manifest_seal(
                c,
                name,
                &json!({"schema": MANIFEST, "revision": 1, "slot_count": decls.len(),
                        "manifest_digest": digest_of(&decls)?}),
            )
            .await,
            "seal",
        )?;
        if *bad_build {
            // The build the DMA tests need fails: their slots are blocked, never run.
            let b = format!("{name}-build");
            let (bs, bf) = (start + Duration::minutes(1), start + Duration::minutes(9));
            ingest(
                &app,
                c,
                &json!({"kind": "build_started", "schema": INGEST, "producer_id": PRODUCER,
                        "build_ref": b, "build_req": build_req(), "started_at": ts(bs)}),
                "build start",
            )
            .await?;
            ingest(
                &app,
                c,
                &json!({"kind": "build_attempt", "schema": INGEST, "producer_id": PRODUCER,
                        "report_revision": 1, "build_ref": b, "build_req": build_req(),
                        "outcome": "fail", "phase_reached": "compile",
                        "runner": {"termination": {"kind": "exited", "exit_code": 1},
                                   "started_at": ts(bs), "finished_at": ts(bf)},
                        "evidence": pass}),
                "build report",
            )
            .await?;
        }
        for (k, (t, run)) in tests.iter().zip(runs.iter()).enumerate() {
            if *bad_build && (k == 3 || k == 4) {
                continue;
            }
            let ev = match run {
                Run::Missing => continue,
                Run::Pass => &pass,
                Run::Mismatch => &mismatch,
                Run::Timeout => &timeout,
            };
            let a = format!("{name}-{t}-1");
            let off = i64::try_from(k).unwrap_or(0);
            let (s0, s1) = (
                start + Duration::minutes(10 + off * 5),
                start + Duration::minutes(14 + off * 5),
            );
            ingest(
                &app,
                c,
                &json!({"kind": "attempt_started", "schema": INGEST, "producer_id": PRODUCER,
                        "regression_ref": name, "slot_ref": t, "attempt_ref": a,
                        "attempt_seq": 1, "build_refs": [], "started_at": ts(s0)}),
                "attempt start",
            )
            .await?;
            ingest(
                &app,
                c,
                &json!({"kind": "simulation_attempt", "schema": INGEST, "producer_id": PRODUCER,
                        "report_id": format!("{a}:r1"), "report_revision": 1,
                        "regression_ref": name, "slot_ref": t, "attempt_ref": a,
                        "attempt_seq": 1, "source_manifest_ref": SOURCE, "build_refs": [],
                        "execution": {"test": t, "seed": "1"},
                        "result": {"runner": {"termination": {"kind": "exited", "exit_code": 0},
                                              "started_at": ts(s0), "finished_at": ts(s1)}},
                        "evidence": ev}),
                "attempt report",
            )
            .await?;
        }
        check(
            app.finish(c, name, &json!({"kind": "finish", "regression_ref": name}))
                .await,
            "finish",
        )?;
        regressions.push(*name);
    }

    // Decisions by a demo user with no usable password (it only authors them).
    let mut pw = [0u8; 24];
    getrandom::fill(&mut pw).map_err(|e| anyhow::anyhow!("{e}"))?;
    let user = format!("{project}-demo");
    let u = crate::admin::create_user(db, &user, &hex::encode(pw)).await?;
    crate::admin::set_member(db, project, &user, "admin").await?;
    let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = $1")
        .bind(project)
        .fetch_one(db)
        .await?;
    let admin = Actor::User {
        user_id: u["id"].as_i64().unwrap_or(0),
        token_id: None,
        roles: vec![(pid, Role::Admin)],
    };
    let v = app
        .read_readiness(&admin, project, "nightly-3", None, None, now)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message))?;
    let sig_of = |slot: &str| {
        v["blockers"]
            .as_array()
            .and_then(|a| a.iter().find(|b| b["slot"] == slot))
            .and_then(|b| b["signatures"][0].as_i64())
            .with_context(|| format!("no failure signature for {slot}"))
    };
    let repeated = sig_of("uart_rx")?;
    let expired = sig_of("irq_storm")?;
    app.set_triage(
        &admin,
        project,
        repeated,
        "demo-rtl/main",
        None,
        &TriageEdit {
            state: "open".into(),
            owner: Some(user.clone()),
            notes: "Scoreboard mismatch since nightly-2; tracked as DEMO-1.".into(),
            bug_urls: vec!["https://bugs.example.invalid/DEMO-1".into()],
        },
    )
    .await
    .map_err(|e| anyhow::anyhow!("triage: {}", e.message))?;
    // An exception granted three weeks ago for two weeks: expired a week ago.
    let granted = now - Duration::days(21);
    app.create_exception(
        &admin,
        project,
        &ExceptionRequest {
            signature: expired,
            branch: "demo-rtl/main".into(),
            suite: "nightly".into(),
            reason: "watchdog too tight for the slow IRQ model (expired)".into(),
            expires_at: ts(granted + Duration::days(14)),
        },
        None,
        granted,
    )
    .await
    .map_err(|e| anyhow::anyhow!("exception: {}", e.message))?;

    Ok(json!({
        "project": project,
        "producer": PRODUCER,
        "regressions": regressions,
        "bad_nightly": "nightly-3",
        "decisions_author": user,
        "story": {
            "uart_rx": "failure repeated since nightly-2 (triage case DEMO-1)",
            "spi_basic": "no result (missing)",
            "dma_burst": "blocked by the failed build",
            "dma_chain": "blocked by the failed build",
            "irq_storm": "failure whose exception expired",
        },
    }))
}
