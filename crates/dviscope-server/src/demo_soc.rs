//! The "demo SoC" dataset: a small system-on-chip hierarchy with stub regressions for the
//! health dashboard — subsystems with their own regressions and blocks, one with blocks
//! only, one with its own regression only, a block shared by two subsystems and an overdue
//! weekly regression, over 14 invented nights. Written through the same app paths as real
//! collectors; nothing in it comes from a real simulation and no log text is invented:
//! failures are structural variants of the bad-nightly demo's evidence.

use anyhow::{Result, bail};
use dviscope_model::canonical::{Digest, digest_of};
use dviscope_model::schema::{INGEST, MANIFEST};
use dviscope_model::wire::evidence::Evidence;
use dviscope_model::wire::hierarchy::Hierarchy;
use dviscope_model::wire::manifest::SlotDecl;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use crate::app::App;
use crate::app::decisions::TriageEdit;
use crate::auth::{Actor, Role};
use crate::demo::{check, demo_mismatch, demo_pass, ingest, ts};

const PRODUCER: &str = "demo-runner";
const SOURCE: &str = "demo-soc-sm";
const NIGHTS: i64 = 14;
const BRANCH: &str = "soc-rtl/main";

/// Evidence failing with one signature `id`: the demo's failing evidence with its diagnostic
/// ID and family fingerprint rewritten (a structural variant, no new log text).
fn failing_as(base: &Evidence, id: &str) -> Result<Evidence> {
    let mut v = serde_json::to_value(base)?;
    let fp = Digest::of_bytes(format!("demo-soc-family/{id}").as_bytes());
    for (list, key) in [("buckets", "family"), ("families", "fingerprint")] {
        for x in v[list].as_array_mut().into_iter().flatten() {
            x[key] = json!(fp);
            x["diag_id"] = json!(format!("uvm:{id}"));
            if list == "buckets" {
                x["checker_id"] = json!(id);
            }
        }
    }
    for e in v["events"].as_array_mut().into_iter().flatten() {
        e["diag_id"] = json!(format!("uvm:{id}"));
        e["checker_id"] = json!(id);
    }
    Ok(serde_json::from_value(v)?)
}

/// One stream of the demo: its suite, home node, slots per night, cadence, and what fails.
struct Stream {
    suite: &'static str,
    node: &'static str,
    slots: usize,
    weekly: bool,
    /// (failing signature, slot index, first night, last night) — nights 1..=14.
    failures: &'static [(&'static str, usize, i64, i64)],
    /// Slots left without a result on the last night.
    missing_last: usize,
    /// The last night is still running (not finished).
    running_last: bool,
    /// Tests dropped from the run list on the last night (a trimmed list).
    dropped_last: usize,
}

const STREAMS: &[Stream] = &[
    Stream {
        suite: "cpu_ss-nightly",
        node: "soc/cpu_ss",
        slots: 12,
        weekly: false,
        failures: &[],
        missing_last: 0,
        running_last: false,
        dropped_last: 0,
    },
    Stream {
        suite: "core-vcs",
        node: "soc/cpu_ss/core",
        slots: 16,
        weekly: false,
        // A hazard bug appears on night 9 and is fixed on night 13.
        failures: &[
            ("CORE_LSU_HAZARD", 3, 9, 12),
            ("CORE_LSU_HAZARD", 7, 10, 12),
        ],
        missing_last: 0,
        running_last: false,
        dropped_last: 0,
    },
    Stream {
        suite: "core-questa",
        node: "soc/cpu_ss/core",
        slots: 16,
        weekly: false,
        failures: &[],
        missing_last: 0,
        running_last: true,
        dropped_last: 0,
    },
    Stream {
        suite: "l2cache-nightly",
        node: "soc/cpu_ss/l2cache",
        slots: 10,
        weekly: false,
        failures: &[],
        missing_last: 0,
        running_last: false,
        dropped_last: 0,
    },
    Stream {
        suite: "dma-nightly",
        node: "soc/cpu_ss/dma",
        slots: 8,
        weekly: false,
        // A known, assigned descriptor-alignment failure since night 4.
        failures: &[("DMA_DESC_ALIGN", 2, 4, 14)],
        missing_last: 0,
        running_last: false,
        dropped_last: 0,
    },
    Stream {
        suite: "mac-nightly",
        node: "soc/dsp_ss/mac_array",
        slots: 12,
        weekly: false,
        // A new overflow on the last night: worse than yesterday.
        failures: &[("MAC_OVERFLOW", 5, 14, 14), ("MAC_OVERFLOW", 9, 14, 14)],
        missing_last: 0,
        running_last: false,
        dropped_last: 0,
    },
    Stream {
        suite: "fft-nightly",
        node: "soc/dsp_ss/fft",
        slots: 8,
        weekly: false,
        failures: &[],
        missing_last: 0,
        running_last: false,
        // Three tests fell out of its run list last night.
        dropped_last: 3,
    },
    Stream {
        suite: "io_ss-nightly",
        node: "soc/io_ss",
        slots: 10,
        weekly: false,
        failures: &[],
        // Two results never arrived last night.
        missing_last: 2,
        running_last: false,
        dropped_last: 0,
    },
    Stream {
        suite: "periph_ss-weekly",
        node: "soc/periph_ss",
        slots: 6,
        weekly: true,
        failures: &[],
        missing_last: 0,
        running_last: false,
        dropped_last: 0,
    },
];

fn hierarchy() -> Result<Hierarchy> {
    let mut streams: Vec<Value> = STREAMS
        .iter()
        .map(|s| {
            json!({"node": s.node, "producer": PRODUCER, "suite": s.suite, "branch": BRANCH,
                   "cadence": if s.weekly { "weekly" } else { "nightly" }})
        })
        .collect();
    streams.sort_by_key(|v| v["suite"].as_str().map(str::to_string));
    Ok(serde_json::from_value(json!({
        "nodes": [
            {"path": "soc", "title": "Demo SoC"},
            {"path": "soc/cpu_ss", "title": "CPU subsystem"},
            {"path": "soc/cpu_ss/core", "title": "core"},
            {"path": "soc/cpu_ss/l2cache", "title": "l2cache"},
            {"path": "soc/cpu_ss/dma", "title": "dma"},
            {"path": "soc/dsp_ss", "title": "DSP subsystem"},
            {"path": "soc/dsp_ss/mac_array", "title": "mac_array"},
            {"path": "soc/dsp_ss/fft", "title": "fft"},
            {"path": "soc/dsp_ss/dma", "title": "dma (shared)"},
            {"path": "soc/io_ss", "title": "I/O subsystem"},
            {"path": "soc/periph_ss", "title": "Peripheral subsystem"},
        ],
        "streams": streams,
        "links": [{"node": "soc/dsp_ss/dma",
                   "stream": {"producer": PRODUCER, "suite": "dma-nightly", "branch": BRANCH}}],
    }))?)
}

/// Creates the demo SoC project `project` as of `now`; refuses an existing project.
///
/// # Errors
/// An existing project, or any write that fails (the data are then partial: use another
/// name).
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
    let pipeline = dviscope_core::packs::shipped::default_pipeline()?.digest;
    crate::admin::set_pipeline(db, project, pipeline.as_str(), "accepted").await?;
    let scopes: Vec<String> = crate::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let tok =
        crate::admin::issue_token(db, project, PRODUCER, &scopes, 1, "demo-soc generator").await?;
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
    // The bad-nightly demo's evidence; failures are structural variants of its mismatch.
    let pass = demo_pass()?;
    let base_fail = demo_mismatch()?;
    check(
        app.create_source_manifest(
            c,
            &json!({"schema": INGEST, "producer_id": PRODUCER, "source_manifest_ref": SOURCE,
                    "repositories": [{"repository": "soc-rtl", "revision": "0000demo"}]}),
        )
        .await,
        "source manifest",
    )?;
    let mut created = 0usize;
    for s in STREAMS {
        // Weekly: two runs, 17 and 10 days ago (so the stream is overdue now).
        let nights: Vec<i64> = if s.weekly {
            vec![1, 8]
        } else {
            (1..=NIGHTS).collect()
        };
        for &n in &nights {
            let reg = format!("{}-n{n:02}", s.suite);
            let back = if s.weekly { 18 - n } else { NIGHTS + 1 - n };
            let start = now - Duration::days(back) - Duration::hours(2);
            let last = n == *nights.last().unwrap_or(&n);
            // Tests are added as the project goes (up to three fewer on the first nights);
            // a trimmed run list drops some on the last night.
            let count = if last {
                s.slots - s.dropped_last
            } else if s.weekly {
                s.slots
            } else {
                s.slots - usize::try_from((NIGHTS - n) / 4).unwrap_or(0)
            };
            let slots: Vec<Value> = (0..count)
                .map(|k| {
                    let t = format!("{}_t{k:02}", s.suite.split('-').next().unwrap_or("t"));
                    json!({"slot_ref": t, "exec_inputs": {"test": t, "seed": "1"}, "required": true})
                })
                .collect();
            check(
                app.create_regression(
                    c,
                    &json!({"schema": INGEST, "producer_id": PRODUCER, "regression_ref": reg,
                            "suite": s.suite, "branch": {"repository": "soc-rtl", "name": "main"},
                            "source_manifest_ref": SOURCE, "trigger": {"kind": "nightly"},
                            "started_at": ts(start)}),
                )
                .await,
                "regression",
            )?;
            check(
                app.manifest_chunk(c, &reg, 1, &json!({"schema": MANIFEST, "slots": slots}))
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
                    &reg,
                    &json!({"schema": MANIFEST, "revision": 1, "slot_count": decls.len(),
                            "manifest_digest": digest_of(&decls)?}),
                )
                .await,
                "seal",
            )?;
            for (k, v) in slots.iter().enumerate() {
                if last && k >= count - s.missing_last {
                    continue;
                }
                let t = v["slot_ref"].as_str().unwrap_or_default();
                let failing = s
                    .failures
                    .iter()
                    .find(|(_, slot, from, to)| *slot == k && (*from..=*to).contains(&n));
                let ev = match failing {
                    Some((id, ..)) => failing_as(&base_fail, id)?,
                    None => pass.clone(),
                };
                let a = format!("{reg}-{t}-1");
                let off = i64::try_from(k).unwrap_or(0);
                let (s0, s1) = (
                    start + Duration::minutes(5 + off * 3),
                    start + Duration::minutes(7 + off * 3),
                );
                ingest(
                    &app,
                    c,
                    &json!({"kind": "attempt_started", "schema": INGEST, "producer_id": PRODUCER,
                            "regression_ref": reg, "slot_ref": t, "attempt_ref": a,
                            "attempt_seq": 1, "build_refs": [], "started_at": ts(s0)}),
                    "attempt start",
                )
                .await?;
                if last && s.running_last && k + 3 >= count {
                    continue; // still running: started, no report yet
                }
                ingest(
                    &app,
                    c,
                    &json!({"kind": "simulation_attempt", "schema": INGEST, "producer_id": PRODUCER,
                            "report_id": format!("{a}:r1"), "report_revision": 1,
                            "regression_ref": reg, "slot_ref": t, "attempt_ref": a,
                            "attempt_seq": 1, "source_manifest_ref": SOURCE, "build_refs": [],
                            "execution": {"test": t, "seed": "1"},
                            "result": {"runner": {"termination": {"kind": "exited", "exit_code": 0},
                                                  "started_at": ts(s0), "finished_at": ts(s1),
                                                  "wall_s": "120", "cpu_s": "110", "cpu_scope": "job"}},
                            "evidence": ev}),
                    "attempt report",
                )
                .await?;
            }
            if !(last && s.running_last) {
                check(
                    app.finish(c, &reg, &json!({"kind": "finish", "regression_ref": reg}))
                        .await,
                    "finish",
                )?;
            }
            created += 1;
        }
    }

    // The hierarchy and one triage decision, by a demo user with no usable password.
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
    app.import_hierarchy(&admin, project, &hierarchy()?)
        .await
        .map_err(|e| anyhow::anyhow!("hierarchy: {}", e.message))?;
    let cmp = app
        .read_comparison(
            &admin,
            project,
            &format!("dma-nightly-n{NIGHTS:02}"),
            None,
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message))?;
    if let Some(number) = cmp.decisions.values().find_map(|d| d.number) {
        app.set_triage(
            &admin,
            project,
            number,
            BRANCH,
            None,
            &TriageEdit {
                state: "open".into(),
                owner: Some(user.clone()),
                notes: "Descriptor alignment since night 4; tracked as DEMO-7.".into(),
                bug_urls: vec!["https://bugs.example.invalid/DEMO-7".into()],
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("triage: {}", e.message))?;
    }
    Ok(json!({
        "project": project,
        "producer": PRODUCER,
        "regressions": created,
        "hierarchy": "soc: cpu_ss (own + core, l2cache, dma), dsp_ss (mac_array, fft, dma shared), io_ss (own only), periph_ss (weekly, overdue)",
        "decisions_author": user,
        "story": {
            "core": "a hazard failed nights 9-12 and was fixed on night 13; core-questa's last night is still running (three attempts in progress)",
            "dma": "a known failure since night 4, assigned (DEMO-7); shared by cpu_ss and dsp_ss",
            "mac_array": "a new overflow on the last night (worse)",
            "io_ss": "two results missing on the last night",
            "periph_ss": "weekly, last run 10 days ago (overdue)",
            "fft": "three tests dropped from its run list on the last night (Tests column)",
            "tests": "tests added over the first nights (Test growth)",
        },
    }))
}
