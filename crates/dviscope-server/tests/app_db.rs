//! Application operations against PostgreSQL.
//! Each test creates its own throwaway database from `DVISCOPE_TEST_DATABASE_URL` and drops
//! it afterwards; without that variable the tests are skipped (reported on stderr). All
//! records and logs are invented.

use dviscope_core::extract::{ExtractOptions, extract_bytes};
use dviscope_core::packs::shipped;
use dviscope_model::canonical::digest_of;
use dviscope_model::errors::ErrorCode;
use dviscope_model::schema::{INGEST, MANIFEST};
use dviscope_model::wire::evidence::Evidence;
use dviscope_model::wire::manifest::SlotDecl;
use dviscope_server::app::ingest::LineResult;
use dviscope_server::app::{App, Receipt};
use dviscope_server::auth::{Actor, Role};
use dviscope_server::db;
use dviscope_server::error::AppError;
use serde_json::{Value, json};
use sqlx::{PgPool, Row as _};

struct TestDb {
    pool: PgPool,
    admin_url: String,
    name: String,
}

impl TestDb {
    async fn new() -> Option<Self> {
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
        let name = format!("dvs_t_{}", hex::encode(b));
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        admin.close().await;
        let (base, _) = url.rsplit_once('/').unwrap_or((&url, ""));
        let pool = db::connect(&format!("{base}/{name}"), 8, 30_000)
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        db::migrate(&pool).await.unwrap_or_else(|e| panic!("{e:#}"));
        Some(Self {
            pool,
            admin_url: url,
            name,
        })
    }

    async fn drop(self) {
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

/// A project with one producer and a collector token with every scope.
async fn provision(pool: &PgPool, project: &str, producer: &str) -> (i64, Actor) {
    let pid: i64 = sqlx::query("INSERT INTO projects (name) VALUES ($1) RETURNING id")
        .bind(project)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .get(0);
    let prod: i64 =
        sqlx::query("INSERT INTO producers (project_id, name) VALUES ($1, $2) RETURNING id")
            .bind(pid)
            .bind(producer)
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
            .get(0);
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let tok = dviscope_server::auth::new_token().unwrap_or_else(|e| panic!("{e:?}"));
    let tid: i64 = sqlx::query(
        "INSERT INTO api_tokens (hash, kind, project_id, producer_id, scopes, expires_at)
         VALUES ($1, 'collector', $2, $3, $4, now() + interval '1 day') RETURNING id",
    )
    .bind(dviscope_server::auth::token_hash(&tok))
    .bind(pid)
    .bind(prod)
    .bind(&scopes)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"))
    .get(0);
    let actor = dviscope_server::auth::actor_from_token(pool, &tok)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(actor, Actor::Collector { token_id, .. } if token_id == tid));
    (pid, actor)
}

fn viewer(project_id: i64) -> Actor {
    Actor::User {
        user_id: 1,
        token_id: None,
        roles: vec![(project_id, Role::Viewer)],
    }
}

fn ok(r: Result<Receipt, AppError>) -> Receipt {
    r.unwrap_or_else(|e| panic!("{e:?}"))
}

fn code(r: Result<Receipt, AppError>) -> ErrorCode {
    match r {
        Ok(r) => panic!("expected an error, got {:?}", r.body),
        Err(e) => e.code,
    }
}

fn source_manifest() -> Value {
    json!({"schema": INGEST, "producer_id": "pilot", "source_manifest_ref": "sm1",
           "repositories": [{"repository": "rtl", "revision": "abc123"}]})
}

fn regression(r: &str, suite: &str) -> Value {
    json!({"schema": INGEST, "producer_id": "pilot", "regression_ref": r, "suite": suite,
           "branch": {"repository": "rtl", "name": "main"}, "source_manifest_ref": "sm1",
           "trigger": {"kind": "nightly"}, "started_at": "2026-11-08T01:00:00Z"})
}

fn slot(s: &str, test: &str) -> Value {
    json!({"slot_ref": s, "exec_inputs": {"test": test, "seed": "1"}, "required": true})
}

fn chunk(slots: &[Value]) -> Value {
    json!({"schema": MANIFEST, "slots": slots})
}

fn seal(slots: &[Value]) -> Value {
    let mut decls: Vec<SlotDecl> = slots
        .iter()
        .map(|v| serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{e}")))
        .collect();
    decls.sort_by(|a, b| a.slot_ref.as_str().cmp(b.slot_ref.as_str()));
    let d = digest_of(&decls).unwrap_or_else(|e| panic!("{e}"));
    json!({"schema": MANIFEST, "revision": 1, "slot_count": decls.len(), "manifest_digest": d})
}

/// A complete VCS-style UVM run in the shipped packs' message forms.
fn evidence(body: &str, errors: u32) -> Evidence {
    let text = format!(
        "{body}--- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    {errors}\nUVM_FATAL :    0\n$finish at simulation time 100\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n"
    );
    let p = shipped::default_pipeline().unwrap_or_else(|e| panic!("{e}"));
    let mut o = ExtractOptions::simulation("sim.log");
    o.simulator = Some("vcs".into());
    extract_bytes(&p, o, text.as_bytes()).0
}

fn passing() -> Evidence {
    evidence("UVM_INFO @ 1: top [HELLO] hi\n", 0)
}

fn failing() -> Evidence {
    evidence(
        "UVM_ERROR @ 5: uvm_test_top.env.sb [SB_MISMATCH] expected 1 got 2\n",
        1,
    )
}

fn started(r: &str, s: &str, a: &str, seq: u32) -> Value {
    json!({"kind": "attempt_started", "schema": INGEST, "producer_id": "pilot",
           "regression_ref": r, "slot_ref": s, "attempt_ref": a, "attempt_seq": seq,
           "started_at": "2026-11-08T01:05:00Z"})
}

fn report(r: &str, s: &str, a: &str, seq: u32, rev: u32, ev: &Evidence) -> Value {
    json!({"kind": "simulation_attempt", "schema": INGEST, "producer_id": "pilot",
           "report_id": format!("{a}:r1"), "report_revision": rev, "regression_ref": r,
           "slot_ref": s, "attempt_ref": a, "attempt_seq": seq, "source_manifest_ref": "sm1",
           "execution": {"test": format!("t{}", &s[1..]), "seed": "1"},
           "result": {"runner": {"termination": {"kind": "exited", "exit_code": 0},
                                 "started_at": "2026-11-08T01:05:00Z",
                                 "finished_at": "2026-11-08T01:06:00Z"}},
           "evidence": ev})
}

async fn ingest(app: &App, actor: &Actor, v: &Value) -> Result<Receipt, AppError> {
    match app.ingest_line(actor, v).await {
        LineResult::Ok(r) => Ok(r),
        LineResult::Rejected(e) => Err(e),
    }
}

async fn accept_pipeline(pool: &PgPool, project: i64, ev: &Evidence) {
    sqlx::query(
        "INSERT INTO pipelines (project_id, digest, state) VALUES ($1, $2, 'accepted')
         ON CONFLICT (project_id, digest) DO UPDATE SET state = 'accepted'",
    )
    .bind(project)
    .bind(ev.pipeline_digest.as_str())
    .execute(pool)
    .await
    .unwrap_or_else(|e| panic!("{e}"));
}

/// A sealed regression `r` with the given slots.
async fn sealed(app: &App, actor: &Actor, r: &str, slots: &[Value]) {
    let _ = app.create_source_manifest(actor, &source_manifest()).await;
    ok(app
        .create_regression(actor, &regression(r, "nightly"))
        .await);
    ok(app.manifest_chunk(actor, r, 1, &chunk(slots)).await);
    ok(app.manifest_seal(actor, r, &seal(slots)).await);
}

fn state(read: &dviscope_server::app::read::RegressionRead, s: &str) -> Value {
    let row = read
        .slots
        .iter()
        .find(|x| x.slot_ref == s)
        .unwrap_or_else(|| panic!("no slot {s}"));
    serde_json::to_value(row).unwrap_or_default()
}

#[tokio::test]
async fn migrations_are_idempotent_and_ready() {
    let Some(t) = TestDb::new().await else { return };
    assert!(db::migrate(&t.pool).await.unwrap_or_default().is_empty());
    assert!(db::schema_ready(&t.pool).await.unwrap_or(false));
    t.drop().await;
}

#[tokio::test]
async fn manifest_state_table() {
    let Some(t) = TestDb::new().await else { return };
    let app = App { db: t.pool.clone() };
    let (_, c) = provision(&t.pool, "p1", "pilot").await;

    // Creation: committed, replayed as a duplicate, other content is a conflict.
    let sm = ok(app.create_source_manifest(&c, &source_manifest()).await);
    assert_eq!(sm.body["result"], "committed");
    assert!(ok(app.create_source_manifest(&c, &source_manifest()).await).duplicate);
    let mut unknown = regression("r0", "nightly");
    unknown["source_manifest_ref"] = json!("nope");
    assert_eq!(
        code(app.create_regression(&c, &unknown).await),
        ErrorCode::Invalid
    );
    let r = ok(app
        .create_regression(&c, &regression("r1", "nightly"))
        .await);
    assert_eq!(r.body["identity"], "regression:r1");
    let again = ok(app
        .create_regression(&c, &regression("r1", "nightly"))
        .await);
    assert!(again.duplicate);
    assert_eq!(again.body["server_ids"], r.body["server_ids"]);
    assert_eq!(
        code(app.create_regression(&c, &regression("r1", "weekly")).await),
        ErrorCode::RevisionConflict
    );

    // Chunks while unsealed: replay, replacement, a slot in two chunks.
    let c1 = chunk(&[slot("s1", "t1"), slot("s2", "t2")]);
    ok(app.manifest_chunk(&c, "r1", 1, &c1).await);
    assert!(ok(app.manifest_chunk(&c, "r1", 1, &c1).await).duplicate);
    let c1b = chunk(&[slot("s1", "t1"), slot("s3", "t3")]);
    let rep = ok(app.manifest_chunk(&c, "r1", 1, &c1b).await);
    assert!(!rep.duplicate);
    assert_eq!(
        code(
            app.manifest_chunk(&c, "r1", 2, &chunk(&[slot("s1", "t1")]))
                .await
        ),
        ErrorCode::Invalid
    );
    assert_eq!(
        code(
            app.manifest_chunk(&c, "r1", 2, &chunk(&[slot("s4", "t"), slot("s4", "t")]))
                .await
        ),
        ErrorCode::Invalid
    );

    // Seal: count and digest checked inside the lock.
    let live = [slot("s1", "t1"), slot("s3", "t3")];
    let mut wrong = seal(&live);
    wrong["slot_count"] = json!(3);
    let e = app.manifest_seal(&c, "r1", &wrong).await.err();
    assert_eq!(
        e.map(|e| (e.code, e.field)),
        Some((ErrorCode::Invalid, Some("slot_count".into())))
    );
    let mut wrong = seal(&live);
    wrong["manifest_digest"] = seal(&[slot("s1", "t1")])["manifest_digest"].clone();
    assert_eq!(
        code(app.manifest_seal(&c, "r1", &wrong).await),
        ErrorCode::Invalid
    );
    // Not sealed yet: amendments and marks are refused.
    let amend = json!({"schema": MANIFEST, "revision": 2, "add": [slot("s4", "t4")],
                       "remove": [{"slot_ref": "s3", "reason": "dropped"}]});
    assert_eq!(
        code(app.manifest_amend(&c, "r1", &amend).await),
        ErrorCode::RevisionConflict
    );
    ok(app.manifest_seal(&c, "r1", &seal(&live)).await);
    assert!(ok(app.manifest_seal(&c, "r1", &seal(&live)).await).duplicate);
    assert_eq!(
        code(
            app.manifest_chunk(&c, "r1", 2, &chunk(&[slot("s9", "t")]))
                .await
        ),
        ErrorCode::RevisionConflict
    );

    // Amendments: next revision only; a slot with attempts cannot be removed.
    let mut skip = amend.clone();
    skip["revision"] = json!(3);
    assert_eq!(
        code(app.manifest_amend(&c, "r1", &skip).await),
        ErrorCode::Invalid
    );
    ok(ingest(&app, &c, &started("r1", "s1", "a1", 1)).await);
    let bad = json!({"schema": MANIFEST, "revision": 2,
                     "remove": [{"slot_ref": "s1", "reason": "x"}]});
    assert_eq!(
        code(app.manifest_amend(&c, "r1", &bad).await),
        ErrorCode::RevisionConflict
    );
    ok(app.manifest_amend(&c, "r1", &amend).await);
    assert!(ok(app.manifest_amend(&c, "r1", &amend).await).duplicate);
    assert_eq!(
        code(ingest(&app, &c, &started("r1", "s3", "a3", 1)).await),
        ErrorCode::Invalid,
        "a removed slot is not declared"
    );

    // Marks and finish.
    let mark = json!({"schema": MANIFEST, "slot_refs": ["s4"], "state": "skipped", "reason": "no licence"});
    ok(app.slot_mark(&c, "r1", &mark).await);
    assert!(ok(app.slot_mark(&c, "r1", &mark).await).duplicate);
    let fin = json!({"kind": "finish", "regression_ref": "r1"});
    ok(app.finish(&c, "r1", &fin).await);
    assert!(ok(app.finish(&c, "r1", &fin).await).duplicate);
    // Late marks are allowed; structural changes are not.
    let late =
        json!({"schema": MANIFEST, "slot_refs": ["s1"], "state": "cancelled", "reason": "late"});
    ok(app.slot_mark(&c, "r1", &late).await);
    let amend3 = json!({"schema": MANIFEST, "revision": 3, "add": [slot("s5", "t5")]});
    assert_eq!(
        code(app.manifest_amend(&c, "r1", &amend3).await),
        ErrorCode::RevisionConflict
    );

    // Another producer's records and a reader's token are refused.
    let mut other = regression("r2", "nightly");
    other["producer_id"] = json!("someone-else");
    assert_eq!(
        code(app.create_regression(&c, &other).await),
        ErrorCode::Forbidden
    );
    assert_eq!(
        code(
            app.create_regression(&viewer(1), &regression("r2", "nightly"))
                .await
        ),
        ErrorCode::Forbidden
    );
    t.drop().await;
}

#[tokio::test]
async fn ingest_derives_and_settles_on_the_server() {
    let Some(t) = TestDb::new().await else { return };
    let app = App { db: t.pool.clone() };
    let (pid, c) = provision(&t.pool, "p1", "pilot").await;
    let slots = [slot("s1", "t1"), slot("s2", "t2"), slot("s3", "t3")];
    sealed(&app, &c, "r1", &slots).await;
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, pid, &pass).await;

    for (s, a, ev) in [("s1", "a1", &pass), ("s2", "a2", &fail)] {
        ok(ingest(&app, &c, &started("r1", s, a, 1)).await);
        let rec = report("r1", s, a, 1, 1, ev);
        let first = ok(ingest(&app, &c, &rec).await);
        assert_eq!(first.body["identity"], format!("simulation_attempt:{a}:r1"));
        // A replay is the original receipt, with no second effect.
        let again = ok(ingest(&app, &c, &rec).await);
        assert!(again.duplicate);
        assert_eq!(again.body["server_ids"], first.body["server_ids"]);
    }
    let facts: i64 = sqlx::query("SELECT count(*) FROM attempt_facts")
        .fetch_one(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .get(0);
    assert_eq!(facts, 2);

    // Same revision, other content: conflict. The producer's claim never decides.
    let mut forged = report("r1", "s2", "a2", 1, 1, &pass);
    forged["result"]["outcome_reported"] = json!("pass");
    assert_eq!(
        code(ingest(&app, &c, &forged).await),
        ErrorCode::RevisionConflict
    );

    let v = viewer(pid);
    let read = app
        .read_regression(&v, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(state(&read, "s1")["state"], "passed");
    assert_eq!(state(&read, "s2")["state"], "failed");
    assert_eq!(state(&read, "s3")["state"], "missing");
    assert_eq!(
        (read.header.passed, read.header.failed, read.header.missing),
        (1, 1, 1)
    );

    // Comparison without a baseline: one signature row for the failing slot.
    let read = app
        .read_comparison(&v, "p1", "r1", None, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let cmp = &read.comparison;
    assert_eq!(cmp.rows.len(), 1, "{cmp:?}");
    assert_eq!(cmp.rows[0].failed_slots, 1);
    // Each row's signature has its project number (the UI links by it).
    let n: i64 = sqlx::query_scalar("SELECT number FROM signatures WHERE fingerprint = $1")
        .bind(cmp.rows[0].signature.as_str())
        .fetch_one(&app.db)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let d = &read.decisions[cmp.rows[0].signature.as_str()];
    assert_eq!(d.number, Some(n));
    assert_eq!(d.disposition, "needs_decision");
    assert_eq!(read.finish["groups"], 1);

    // A correction (revision 2) supersedes; an unseen lower revision is then stale.
    ok(ingest(&app, &c, &report("r1", "s2", "a2", 1, 2, &pass)).await);
    let read = app
        .read_regression(&v, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(state(&read, "s2")["state"], "passed");
    assert!(ok(ingest(&app, &c, &report("r1", "s2", "a2", 1, 1, &fail)).await).duplicate);

    // Withdrawing the pipeline is a barrier: nothing classified under it passes.
    sqlx::query("UPDATE pipelines SET state = 'withdrawn' WHERE project_id = $1")
        .bind(pid)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let read = app
        .read_regression(&v, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(
        state(&read, "s1")["state"],
        "passed",
        "{:?}",
        state(&read, "s1")
    );
    // A pipeline the project never accepted makes the attempt ineligible.
    sqlx::query("DELETE FROM pipelines WHERE project_id = $1")
        .bind(pid)
        .execute(&t.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let read = app
        .read_regression(&v, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_ne!(state(&read, "s1")["state"], "passed");

    // Readers: a collector token or a user without a role here is refused.
    assert!(app.read_regression(&c, "p1", "r1", None).await.is_err());
    assert!(
        app.read_regression(&viewer(pid + 100), "p1", "r1", None)
            .await
            .is_err()
    );
    t.drop().await;
}

#[tokio::test]
async fn comparison_against_a_baseline() {
    let Some(t) = TestDb::new().await else { return };
    let app = App { db: t.pool.clone() };
    let (pid, c) = provision(&t.pool, "p1", "pilot").await;
    let slots = [slot("s1", "t1"), slot("s2", "t2")];
    let (pass, fail) = (passing(), failing());
    accept_pipeline(&t.pool, pid, &pass).await;
    // Baseline: both pass. Current: s2 fails with a new signature.
    for (r, s2) in [("base", &pass), ("cur", &fail)] {
        sealed(&app, &c, r, &slots).await;
        for (s, ev) in [("s1", &pass), ("s2", s2)] {
            let a = format!("{r}-{s}");
            ok(ingest(&app, &c, &started(r, s, &a, 1)).await);
            ok(ingest(&app, &c, &report(r, s, &a, 1, 1, ev)).await);
        }
    }
    let cmp = app
        .read_comparison(&viewer(pid), "p1", "cur", Some("base"), None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"))
        .comparison;
    assert_eq!(cmp.rows.len(), 1, "{cmp:?}");
    let row = serde_json::to_value(&cmp.rows[0]).unwrap_or_default();
    assert_eq!(row["baseline"], "absent_from_baseline", "{row}");
    assert_eq!(cmp.header.failed, 1);
    t.drop().await;
}
