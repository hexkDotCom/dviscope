//! Shared helpers of the database tests: a throwaway database per test, provisioning,
//! invented records and evidence.

#![allow(dead_code)] // each test binary uses a part

use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::packs::shipped;
use dviscope_model::canonical::digest_of;
use dviscope_model::errors::ErrorCode;
use dviscope_model::schema::{INGEST, MANIFEST};
use dviscope_model::wire::evidence::Evidence;
use dviscope_model::wire::manifest::SlotDecl;
use dviscope_server::app::ingest::LineResult;
use dviscope_server::app::read::RegressionRead;
use dviscope_server::app::{App, Receipt};
use dviscope_server::auth::{Actor, Role};
use dviscope_server::db;
use dviscope_server::error::AppError;
use serde_json::{Value, json};
use sqlx::{PgPool, Row as _};

pub struct TestDb {
    pub pool: PgPool,
    admin_url: String,
    name: String,
}

impl TestDb {
    /// The database's URL (for client tools such as pg_dump).
    pub fn url(&self) -> String {
        let (base, _) = self
            .admin_url
            .rsplit_once('/')
            .unwrap_or((&self.admin_url, ""));
        format!("{base}/{}", self.name)
    }

    pub async fn new() -> Option<Self> {
        Self::new_at(i32::MAX).await
    }

    /// A database migrated up to `upto` (an earlier release, for upgrade tests).
    pub async fn new_at(upto: i32) -> Option<Self> {
        let Ok(url) = std::env::var("DVISCOPE_TEST_DATABASE_URL") else {
            // CI sets DVISCOPE_REQUIRE_TEST_DB: a missing database fails the run there, never a
            // silent skip.
            assert!(
                std::env::var_os("DVISCOPE_REQUIRE_TEST_DB").is_none(),
                "DVISCOPE_REQUIRE_TEST_DB is set but DVISCOPE_TEST_DATABASE_URL is not"
            );
            eprintln!("skipped: DVISCOPE_TEST_DATABASE_URL is not set");
            return None;
        };
        let admin = db::connect(&url, 2, 30_000)
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        let mut b = [0u8; 6];
        getrandom::fill(&mut b).unwrap_or_else(|e| panic!("{e}"));
        let name = format!("dvs_a_{}", hex::encode(b));
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        admin.close().await;
        let (base, _) = url.rsplit_once('/').unwrap_or((&url, ""));
        let pool = db::connect(&format!("{base}/{name}"), 16, 30_000)
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        db::migrate_to(&pool, upto)
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        Some(Self {
            pool,
            admin_url: url,
            name,
        })
    }

    pub fn app(&self) -> App {
        App {
            db: self.pool.clone(),
        }
    }

    pub async fn count(&self, table: &str) -> i64 {
        sqlx::query(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
            .get(0)
    }

    pub async fn drop(self) {
        self.pool.close().await;
        if let Ok(admin) = db::connect(&self.admin_url, 1, 30_000).await {
            let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE {} WITH (FORCE)",
                self.name
            )))
            .execute(&admin)
            .await;
            admin.close().await;
        }
    }
}

/// Project `p1` (policy `strict`) with producer `pilot`; returns its ID.
pub async fn project(pool: &PgPool) -> i64 {
    dviscope_server::admin::create_project(pool, "p1", "strict")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    dviscope_server::admin::create_producer(pool, "p1", "pilot")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    sqlx::query("SELECT id FROM projects WHERE name = 'p1'")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .get(0)
}

/// A collector of `pilot` with every scope; returns the actor and its token ID.
pub async fn collector(pool: &PgPool) -> (Actor, i64) {
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let t = dviscope_server::admin::issue_token(pool, "p1", "pilot", &scopes, 1, "t")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let actor = dviscope_server::auth::actor_from_token(pool, t["token"].as_str().unwrap_or(""))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    (actor, t["token_id"].as_i64().unwrap_or(0))
}

pub fn viewer(project_id: i64) -> Actor {
    Actor::User {
        user_id: 1,
        token_id: None,
        roles: vec![(project_id, Role::Viewer)],
    }
}

pub fn ok(r: Result<Receipt, AppError>) -> Receipt {
    r.unwrap_or_else(|e| panic!("{e:?}"))
}

pub fn code(r: Result<Receipt, AppError>) -> ErrorCode {
    match r {
        Ok(r) => panic!("expected an error, got {:?}", r.body),
        Err(e) => e.code,
    }
}

pub fn source_manifest() -> Value {
    json!({"schema": INGEST, "producer_id": "pilot", "source_manifest_ref": "sm1",
           "repositories": [{"repository": "rtl", "revision": "abc123"}]})
}

pub fn regression(r: &str) -> Value {
    json!({"schema": INGEST, "producer_id": "pilot", "regression_ref": r, "suite": "nightly",
           "branch": {"repository": "rtl", "name": "main"}, "source_manifest_ref": "sm1",
           "trigger": {"kind": "nightly"}, "started_at": "2026-11-08T01:00:00Z"})
}

pub fn build_req() -> Value {
    json!({"source_manifest_ref": "sm1",
           "build_config": {"simulator": {"vendor": "vcs", "version": "x"}}})
}

pub fn slot(s: &str) -> Value {
    json!({"slot_ref": s, "exec_inputs": {"test": format!("t_{s}"), "seed": "1"}, "required": true})
}

pub fn built_slot(s: &str) -> Value {
    let mut v = slot(s);
    v["build_reqs"] = json!([build_req()]);
    v
}

pub fn chunk(slots: &[Value]) -> Value {
    json!({"schema": MANIFEST, "slots": slots})
}

pub fn seal(slots: &[Value]) -> Value {
    let mut decls: Vec<SlotDecl> = slots
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{e}")))
        .collect();
    decls.sort_by(|a, b| a.slot_ref.as_str().cmp(b.slot_ref.as_str()));
    let d = digest_of(&decls).unwrap_or_else(|e| panic!("{e}"));
    json!({"schema": MANIFEST, "revision": 1, "slot_count": decls.len(), "manifest_digest": d})
}

/// A sealed regression `r` with `slots` in one chunk (the source manifest created once).
pub async fn sealed(app: &App, c: &Actor, r: &str, slots: &[Value]) {
    let _ = app.create_source_manifest(c, &source_manifest()).await;
    ok(app.create_regression(c, &regression(r)).await);
    ok(app.manifest_chunk(c, r, 1, &chunk(slots)).await);
    ok(app.manifest_seal(c, r, &seal(slots)).await);
}

fn evidence(body: &str, errors: u32) -> Evidence {
    let text = format!(
        "{body}--- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    {errors}\nUVM_FATAL :    0\n$finish at simulation time 100\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n"
    );
    let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
    let mut o = ExtractOptions::simulation("sim.log");
    o.simulator = Some("vcs".into());
    extract_bytes(&p, o, text.as_bytes()).0
}

pub fn passing() -> Evidence {
    evidence("UVM_INFO @ 1: top [HELLO] hi\n", 0)
}

pub fn failing() -> Evidence {
    evidence(
        "UVM_ERROR @ 5: uvm_test_top.env.sb [SB_MISMATCH] expected 1 got 2\n",
        1,
    )
}

/// A Questa run that stopped in elaboration (`vopt`, design not loaded: complete through
/// the early-fatal profile): blocked when the slot has a build.
/// Evidence failing with one distinct signature per ID: a structural fixture (fixture class
/// 2) derived from the shared failing evidence by rewriting its diagnostic IDs and family
/// fingerprints; no log text is written.
pub fn failing_ids(ids: &[&str]) -> Evidence {
    let mut v = serde_json::to_value(failing()).unwrap_or_else(|e| panic!("{e}"));
    let bucket = v["buckets"][0].clone();
    let family = v["families"][0].clone();
    let event = v["events"][0].clone();
    let (mut buckets, mut families, mut events) = (vec![], vec![], vec![]);
    for (k, id) in ids.iter().enumerate() {
        let fp = dviscope_model::canonical::Digest::of_bytes(
            format!("structural-family/{id}").as_bytes(),
        );
        let ord = k + 1;
        let mut b = bucket.clone();
        b["diag_id"] = json!(format!("uvm:{id}"));
        b["checker_id"] = json!(id);
        b["family"] = json!(fp);
        b["first_ordinal"] = json!(ord);
        b["example_ordinal"] = json!(ord);
        let mut f = family.clone();
        f["fingerprint"] = json!(fp);
        f["diag_id"] = json!(format!("uvm:{id}"));
        f["buckets"] = json!([k]);
        let mut e = event.clone();
        e["ordinal"] = json!(ord);
        e["diag_id"] = json!(format!("uvm:{id}"));
        e["checker_id"] = json!(id);
        buckets.push(b);
        families.push(f);
        events.push(e);
    }
    let n = ids.len().to_string();
    v["buckets"] = json!(buckets);
    v["families"] = json!(families);
    v["events"] = json!(events);
    for c in v["counters"].as_array_mut().into_iter().flatten() {
        if c["key"] == "UVM_ERROR" {
            c["value"] = json!(n);
        }
    }
    for r in v["reconciliation"].as_array_mut().into_iter().flatten() {
        r["counted"] = json!(n);
        r["extracted"] = json!(n);
    }
    serde_json::from_value(v).unwrap_or_else(|e| panic!("{e}"))
}

pub fn elaboration_failure() -> Evidence {
    let text = [
        "** Error: (vopt-2912) design.sv(4): Unresolved reference to 'missing_mod'.",
        "Error loading design",
        "Errors: 1, Warnings: 0",
        "End time: 01:06:00 on Nov 08,2026, Elapsed time: 0:00:01",
        "",
    ]
    .join(
        "
",
    );
    let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
    let mut o = ExtractOptions::simulation("sim.log");
    o.simulator = Some("questa".into());
    extract_bytes(&p, o, text.as_bytes()).0
}

/// The operator's finish of regression `r`.
pub async fn finish(app: &App, c: &Actor, r: &str) {
    ok(app
        .finish(c, r, &json!({"kind": "finish", "regression_ref": r}))
        .await);
}

pub async fn accept_pipeline(pool: &PgPool, ev: &Evidence) {
    dviscope_server::admin::set_pipeline(pool, "p1", ev.pipeline_digest.as_str(), "accepted")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
}

pub fn started(r: &str, s: &str, a: &str, seq: u32, builds: &[&str]) -> Value {
    json!({"kind": "attempt_started", "schema": INGEST, "producer_id": "pilot",
           "regression_ref": r, "slot_ref": s, "attempt_ref": a, "attempt_seq": seq,
           "build_refs": builds, "started_at": "2026-11-08T01:05:00Z"})
}

pub fn report(
    r: &str,
    s: &str,
    a: &str,
    seq: u32,
    rev: u32,
    ev: &Evidence,
    builds: &[&str],
) -> Value {
    json!({"kind": "simulation_attempt", "schema": INGEST, "producer_id": "pilot",
           "report_id": format!("{a}:r1"), "report_revision": rev, "regression_ref": r,
           "slot_ref": s, "attempt_ref": a, "attempt_seq": seq, "source_manifest_ref": "sm1",
           "build_refs": builds,
           "execution": {"test": format!("t_{s}"), "seed": "1"},
           "result": {"runner": {"termination": {"kind": "exited", "exit_code": 0},
                                 "started_at": "2026-11-08T01:05:00Z",
                                 "finished_at": "2026-11-08T01:06:00Z"}},
           "evidence": ev})
}

pub fn build_started(b: &str) -> Value {
    json!({"kind": "build_started", "schema": INGEST, "producer_id": "pilot", "build_ref": b,
           "build_req": build_req(), "started_at": "2026-11-08T01:00:00Z"})
}

pub fn build_report(b: &str, outcome: &str) -> Value {
    json!({"kind": "build_attempt", "schema": INGEST, "producer_id": "pilot", "report_revision": 1,
           "build_ref": b, "build_req": build_req(), "outcome": outcome, "phase_reached": "compile",
           "runner": {"termination": {"kind": "exited", "exit_code": if outcome == "pass" { 0 } else { 1 }},
                      "started_at": "2026-11-08T01:00:00Z", "finished_at": "2026-11-08T01:01:00Z"},
           "evidence": passing()})
}

pub async fn ingest(app: &App, actor: &Actor, v: &Value) -> Result<Receipt, AppError> {
    match app.ingest_line(actor, v).await {
        LineResult::Ok(r) => Ok(r),
        LineResult::Rejected(e) => Err(e),
    }
}

pub async fn read(app: &App, project_id: i64, r: &str) -> RegressionRead {
    app.read_regression(&viewer(project_id), "p1", r, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))
}

/// `{state, detail?}` of a slot.
pub fn state(read: &RegressionRead, s: &str) -> Value {
    let row = read
        .slots
        .iter()
        .find(|x| x.slot_ref == s)
        .unwrap_or_else(|| panic!("no slot {s}"));
    let v = serde_json::to_value(row).unwrap_or_default();
    json!({"state": v["state"], "detail": v["detail"]})
}
