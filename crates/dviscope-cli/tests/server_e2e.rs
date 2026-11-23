//! End to end through the real collector and server: `dviscope`
//! journals a regression, runs two attempts (a fake simulator copies an invented log) and
//! flushes over TLS to `dviscope-server` on PostgreSQL; a crash after the server commits
//! and before the outcome is written loses and duplicates nothing; the server's settled
//! states match. Skipped without `DVISCOPE_TEST_DATABASE_URL`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use dviscope_cli::tls;
use dviscope_server::auth::{Actor, Role};
use dviscope_server::config::{DatabaseConfig, ServerConfig, TlsConfig};
use dviscope_server::{admin, db};
use serde_json::{Value, json};
use sqlx::Row as _;

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

fn s(p: &Path) -> &str {
    p.to_str().unwrap_or_default()
}

fn write(p: &Path, v: &Value) -> PathBuf {
    std::fs::write(p, v.to_string()).unwrap_or_else(|e| panic!("{e}"));
    p.to_path_buf()
}

struct Cli {
    env: Vec<(String, String)>,
}

impl Cli {
    fn run(&self, args: &[&str], crash: Option<&str>) -> Output {
        let mut c = Command::new(BIN);
        c.args(args);
        for (k, v) in &self.env {
            c.env(k, v);
        }
        match crash {
            Some(p) => c.env("DVISCOPE_TEST_CRASH_POINT", p),
            None => c.env_remove("DVISCOPE_TEST_CRASH_POINT"),
        };
        c.output().unwrap_or_else(|e| panic!("{e}"))
    }

    fn ok(&self, args: &[&str]) -> Value {
        let o = self.run(args, None);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        serde_json::from_slice(&o.stdout).unwrap_or(Value::Null)
    }
}

fn vcs_log(body: &str, errors: u32) -> String {
    format!(
        "{body}--- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    {errors}\nUVM_FATAL :    0\n$finish at simulation time 100\nCPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n"
    )
}

/// A provisioned throwaway database, a TLS server on it, and a collector configured for
/// it; `None` without `DVISCOPE_TEST_DATABASE_URL`.
#[allow(clippy::too_many_lines)]
async fn setup(tag: &str) -> Option<Ctx> {
    let Ok(admin_url) = std::env::var("DVISCOPE_TEST_DATABASE_URL") else {
        // CI sets DVISCOPE_REQUIRE_TEST_DB: a missing database fails the run there, never a
        // silent skip.
        assert!(
            std::env::var_os("DVISCOPE_REQUIRE_TEST_DB").is_none(),
            "DVISCOPE_REQUIRE_TEST_DB is set but DVISCOPE_TEST_DATABASE_URL is not"
        );
        eprintln!("skipped: DVISCOPE_TEST_DATABASE_URL is not set");
        return None;
    };
    let d = std::env::temp_dir().join(format!("dviscope-srv-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();

    // A throwaway database, migrated and provisioned.
    let adm = db::connect(&admin_url, 1, 30_000)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let name = format!("dvs_e_{tag}_{}", std::process::id());
    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
    )))
    .execute(&adm)
    .await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&adm)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let (base, _) = admin_url.rsplit_once('/').unwrap_or((&admin_url, ""));
    let db_url = format!("{base}/{name}");
    let pool = db::connect(&db_url, 4, 30_000)
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    db::migrate(&pool).await.unwrap_or_else(|e| panic!("{e:#}"));
    admin::create_project(&pool, "p1", "strict")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    admin::create_producer(&pool, "p1", "pilot")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let scopes: Vec<String> = dviscope_server::auth::SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let tok = admin::issue_token(&pool, "p1", "pilot", &scopes, 1, "e2e")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let digest = dviscope_core::packs::shipped::default_pipeline()
        .unwrap_or_else(|e| panic!("{e}"))
        .digest;
    admin::set_pipeline(&pool, "p1", digest.as_str(), "accepted")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));

    // The server, over TLS with a local CA.
    let paths = tls::TlsPaths::new(&d.join("ca"), &d.join("server"));
    tls::init(
        &paths,
        time::OffsetDateTime::now_utc(),
        &tls::PrivatePolicy {
            allow_any_location: true,
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let url_file = d.join("db.url");
    std::fs::write(&url_file, &db_url).ok();
    let cfg = Arc::new(ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap_or_else(|e| panic!("{e}")),
        public_origin: "https://127.0.0.1:8443".into(),
        tls: TlsConfig {
            cert_file: paths.server_cert.clone(),
            key_file: paths.server_key.clone(),
        },
        database: Some(DatabaseConfig {
            url_file: Some(url_file),
            pool_size: 4,
            statement_timeout_ms: 30_000,
        }),
        ui_dir: None,
        request_body_timeout_s: 60,
    });
    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = dviscope_server::serve(cfg, h).await {
            eprintln!("server: {e:#}");
        }
    });
    let addr = handle
        .listening()
        .await
        .unwrap_or_else(|| panic!("server did not start"));
    let token_file = d.join("token");
    std::fs::write(&token_file, tok["token"].as_str().unwrap_or_default()).ok();
    let cli = Cli {
        env: vec![
            (
                "DVISCOPE_SERVER_URL".into(),
                format!("https://127.0.0.1:{}", addr.port()),
            ),
            ("DVISCOPE_CA_FILE".into(), s(&paths.ca_cert).into()),
            ("DVISCOPE_TOKEN_FILE".into(), s(&token_file).into()),
            ("DVISCOPE_STATE_DIR".into(), s(&d.join("state")).into()),
        ],
    };

    Some(Ctx {
        d,
        cli,
        pool,
        adm,
        name,
        handle,
    })
}

struct Ctx {
    d: PathBuf,
    cli: Cli,
    pool: sqlx::PgPool,
    adm: sqlx::PgPool,
    name: String,
    handle: axum_server::Handle,
}

impl Ctx {
    async fn close(self) {
        self.handle.shutdown();
        self.pool.close().await;
        let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.name
        )))
        .execute(&self.adm)
        .await;
        // The directory holds the test database URL and a token: removed.
        let _ = std::fs::remove_dir_all(&self.d);
    }

    /// Journals source manifest `sm1` and regression `r` with `slots` (one chunk), sealed.
    fn regression(&self, j: &Path, r: &str, slots: &[Value]) {
        let (cli, d) = (&self.cli, &self.d);
        let sm = write(
            &d.join("sm.json"),
            &json!({"schema": dviscope_model::schema::INGEST,
            "producer_id": "pilot", "source_manifest_ref": "sm1",
            "repositories": [{"repository": "rtl", "revision": "abc123"}]}),
        );
        cli.ok(&["source-manifest", "--journal", s(j), "--body", s(&sm)]);
        let reg = write(
            &d.join(format!("{r}.reg.json")),
            &json!({"schema": dviscope_model::schema::INGEST,
            "producer_id": "pilot", "regression_ref": r, "suite": "nightly",
            "branch": {"repository": "rtl", "name": "main"}, "source_manifest_ref": "sm1",
            "trigger": {"kind": "nightly"}, "started_at": "2026-11-08T01:00:00Z"}),
        );
        cli.ok(&["regression", "create", "--journal", s(j), "--body", s(&reg)]);
        let chunk = write(
            &d.join(format!("{r}.chunk.json")),
            &json!({"schema": dviscope_model::schema::MANIFEST, "slots": slots}),
        );
        cli.ok(&[
            "manifest",
            "declare",
            "--journal",
            s(j),
            "--regression",
            r,
            "--chunk",
            "1",
            "--body",
            s(&chunk),
        ]);
    }

    /// One attempt whose fake simulator copies `src` into its log.
    fn attempt(&self, j: &Path, r: &str, a: &str, slot: &str, src: &Path) -> Value {
        let launch = write(
            &self.d.join(format!("{a}.launch.json")),
            &json!({
            "producer_id": "pilot", "regression_ref": r, "slot_ref": slot,
            "attempt_ref": a, "source_manifest_ref": "sm1",
            "execution": {"test": "t", "seed": "1"}}),
        );
        let log = self.d.join(format!("{a}.log"));
        self.cli.ok(&[
            "run",
            "--journal",
            s(j),
            "--launch",
            s(&launch),
            "--log",
            s(&log),
            "--simulator",
            "vcs",
            "--",
            BIN,
            "__tree",
            "--children",
            "0",
            "--sleep",
            "0",
            "--copy",
            s(src),
            s(&log),
        ])
    }
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)] // one scenario, step by step
async fn collection_end_to_end_with_a_crash_after_commit() {
    let Some(ctx) = setup("crash").await else {
        return;
    };
    let (d, cli, pool) = (&ctx.d, &ctx.cli, &ctx.pool);
    // The regression, journalled.
    let j = d.join("journal");
    cli.ok(&["journal", "init", "--dir", s(&j), "--id", "j1"]);
    let sm = write(
        &d.join("sm.json"),
        &json!({"schema": dviscope_model::schema::INGEST,
        "producer_id": "pilot", "source_manifest_ref": "sm1",
        "repositories": [{"repository": "rtl", "revision": "abc123"}]}),
    );
    cli.ok(&["source-manifest", "--journal", s(&j), "--body", s(&sm)]);
    let reg = write(
        &d.join("reg.json"),
        &json!({"schema": dviscope_model::schema::INGEST,
        "producer_id": "pilot", "regression_ref": "r1", "suite": "nightly",
        "branch": {"repository": "rtl", "name": "main"}, "source_manifest_ref": "sm1",
        "trigger": {"kind": "nightly"}, "started_at": "2026-11-08T01:00:00Z"}),
    );
    cli.ok(&[
        "regression",
        "create",
        "--journal",
        s(&j),
        "--body",
        s(&reg),
    ]);
    let slots: Vec<Value> = ["s1", "s2", "s3"]
        .iter()
        .map(
            |x| json!({"slot_ref": x, "exec_inputs": {"test": "t", "seed": "1"}, "required": true}),
        )
        .collect();
    let chunk = write(
        &d.join("chunk.json"),
        &json!({"schema": dviscope_model::schema::MANIFEST, "slots": slots}),
    );
    cli.ok(&[
        "manifest",
        "declare",
        "--journal",
        s(&j),
        "--regression",
        "r1",
        "--chunk",
        "1",
        "--body",
        s(&chunk),
    ]);
    cli.ok(&["manifest", "seal", "--journal", s(&j), "--regression", "r1"]);

    // Two attempts: the fake simulator copies an invented log into place.
    std::fs::write(
        d.join("pass.txt"),
        vcs_log("UVM_INFO @ 1: top [HELLO] hi\n", 0),
    )
    .ok();
    std::fs::write(
        d.join("fail.txt"),
        vcs_log(
            "UVM_ERROR @ 5: uvm_test_top.env.sb [SB_MISMATCH] expected 1 got 2\n",
            1,
        ),
    )
    .ok();
    for (a, slot, src) in [("a1", "s1", "pass.txt"), ("a2", "s2", "fail.txt")] {
        let launch = write(
            &d.join(format!("{a}.launch.json")),
            &json!({
            "producer_id": "pilot", "regression_ref": "r1", "slot_ref": slot,
            "attempt_ref": a, "source_manifest_ref": "sm1",
            "execution": {"test": "t", "seed": "1"}}),
        );
        let log = d.join(format!("{a}.log"));
        cli.ok(&[
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&launch),
            "--log",
            s(&log),
            "--simulator",
            "vcs",
            "--",
            BIN,
            "__tree",
            "--children",
            "0",
            "--sleep",
            "0",
            "--copy",
            s(&d.join(src)),
            s(&log),
        ]);
    }

    // Flush; the client dies after the server committed, before writing the outcome.
    let o = cli.run(&["spool", "flush", "--dir", s(&j)], Some("after_receipt"));
    assert_eq!(
        o.status.code(),
        Some(86),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let f = cli.ok(&["spool", "flush", "--dir", s(&j)]);
    assert_eq!(f["pending"], 0, "{f}");
    assert_eq!(f["rejected"], 0, "{f}");

    // Exactly one effect per record.
    let n = |q: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(q)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .get::<i64, _>(0)
        }
    };
    assert_eq!(n("SELECT count(*) FROM attempts").await, 2);
    assert_eq!(n("SELECT count(*) FROM attempt_facts").await, 2);
    assert_eq!(n("SELECT count(*) FROM slots").await, 3);
    assert_eq!(n("SELECT count(*) FROM receipts").await, 8);

    // The server settles what the collector reported.
    let app = dviscope_server::app::App { db: pool.clone() };
    let pid: i64 = sqlx::query("SELECT id FROM projects WHERE name = 'p1'")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .get(0);
    let viewer = Actor::User {
        user_id: 1,
        token_id: None,
        roles: vec![(pid, Role::Viewer)],
    };
    let read = app
        .read_regression(&viewer, "p1", "r1", None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let state = |slot: &str| {
        read.slots
            .iter()
            .find(|x| x.slot_ref == slot)
            .map(|x| serde_json::to_value(x).unwrap_or_default()["state"].clone())
            .unwrap_or_default()
    };
    assert_eq!(state("s1"), "passed");
    assert_eq!(state("s2"), "failed");
    assert_eq!(state("s3"), "missing");

    // Close, finish, deliver: the regression is finished on the server.
    cli.ok(&["journal", "close", "--dir", s(&j)]);
    cli.ok(&["journal", "finish", "--dir", s(&j), "--regression", "r1"]);
    let f = cli.ok(&["spool", "flush", "--dir", s(&j)]);
    assert_eq!(f["pending"], 0, "{f}");
    let st: String = sqlx::query("SELECT state FROM regressions")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .get(0);
    assert_eq!(st, "finished");

    // `dviscope verdict` with a viewer's personal token: s2 failed and s3 is missing, so
    // the verdict is fail (exit 10); the log-free summary is written before exiting.
    admin::create_user(pool, "vera", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    admin::set_member(pool, "p1", "vera", "viewer")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let pt = admin::issue_personal_token(pool, "vera", 1, "ci")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let vtok = d.join("vera.token");
    std::fs::write(&vtok, pt["token"].as_str().unwrap_or_default()).ok();
    let mut viewer_cli = Cli {
        env: cli.env.clone(),
    };
    for (k, v) in &mut viewer_cli.env {
        if k == "DVISCOPE_TOKEN_FILE" {
            *v = s(&vtok).into();
        }
    }
    let summary = d.join("summary.json");
    // Unbound merge gating is refused (2), and the summary says why.
    let o = viewer_cli.run(
        &[
            "verdict",
            "--project",
            "p1",
            "--regression",
            "r1",
            "--summary-file",
            s(&summary),
        ],
        None,
    );
    assert_eq!(o.status.code(), Some(2));
    let sum: Value =
        serde_json::from_slice(&std::fs::read(&summary).unwrap_or_default()).unwrap_or(Value::Null);
    assert!(
        sum["no_verdict"]
            .as_str()
            .unwrap_or("")
            .contains("--expect-source"),
        "{sum}"
    );
    // The candidate's source digest, as `dviscope source digest` computes it.
    let o = viewer_cli.run(&["source", "digest", "--rev", "rtl=abc123"], None);
    let src: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    let digest = src["source_digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(digest.starts_with("sha256:"), "{src}");
    let o = viewer_cli.run(
        &[
            "verdict",
            "--project",
            "p1",
            "--regression",
            "r1",
            "--expect-source",
            &digest,
            "--summary-file",
            s(&summary),
        ],
        None,
    );
    assert_eq!(
        o.status.code(),
        Some(10),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let sum: Value =
        serde_json::from_slice(&std::fs::read(&summary).unwrap_or_default()).unwrap_or(Value::Null);
    assert_eq!(sum["verdict"], "fail", "{sum}");
    assert_eq!(sum["counts"]["planned"], 3);
    assert_eq!(sum["candidate"]["bound"], true, "{sum}");
    assert!(!sum.to_string().contains("SB_MISMATCH"), "log-free: {sum}");
    // The collector token is not a reader: rejected (3), and the summary says so.
    let o = cli.run(
        &[
            "verdict",
            "--project",
            "p1",
            "--regression",
            "r1",
            "--expect-source",
            &digest,
            "--summary-file",
            s(&summary),
        ],
        None,
    );
    assert_eq!(o.status.code(), Some(3));
    let sum: Value =
        serde_json::from_slice(&std::fs::read(&summary).unwrap_or_default()).unwrap_or(Value::Null);
    assert!(
        sum["verdict"].is_null() && sum["no_verdict"].is_string(),
        "{sum}"
    );

    // No server there: unreachable (4), never a pass.
    for (k, v) in &mut viewer_cli.env {
        if k == "DVISCOPE_SERVER_URL" {
            *v = "https://127.0.0.1:1".into();
        }
    }
    let args = [
        "verdict",
        "--project",
        "p1",
        "--regression",
        "r1",
        "--expect-source",
        &digest,
        "--summary-file",
        s(&summary),
    ];
    let o = viewer_cli.run(&args, None);
    assert_eq!(o.status.code(), Some(4));
    let sum: Value =
        serde_json::from_slice(&std::fs::read(&summary).unwrap_or_default()).unwrap_or(Value::Null);
    assert!(sum["verdict"].is_null(), "{sum}");

    ctx.close().await;
}

/// A21 (CLI part): a manifest chunk the server rejects blocks the reports that depend on
/// it, while another regression in the same journal flows.
#[tokio::test(flavor = "multi_thread")]
async fn a21_a_rejected_chunk_blocks_only_its_regression() {
    let Some(ctx) = setup("a21").await else {
        return;
    };
    let j = ctx.d.join("journal");
    ctx.cli
        .ok(&["journal", "init", "--dir", s(&j), "--id", "j1"]);
    let good =
        [json!({"slot_ref": "s1", "exec_inputs": {"test": "t", "seed": "1"}, "required": true})];
    // The same slot twice in one chunk: valid JSON, refused by the server (400).
    let bad = [good[0].clone(), good[0].clone()];
    ctx.regression(&j, "ok", &good);
    ctx.regression(&j, "bad", &bad);
    std::fs::write(
        ctx.d.join("pass.txt"),
        vcs_log("UVM_INFO @ 1: top [HELLO] hi\n", 0),
    )
    .ok();
    let src = ctx.d.join("pass.txt");
    ctx.attempt(&j, "ok", "ok-a1", "s1", &src);
    ctx.attempt(&j, "bad", "bad-a1", "s1", &src);
    let f = ctx.cli.ok(&["spool", "flush", "--dir", s(&j)]);
    assert_eq!(f["rejected"], 1, "{f}");
    assert_eq!(
        f["blocked"], 2,
        "the bad regression's start and report: {f}"
    );
    assert_eq!(f["pending"], 0, "{f}");
    let st = ctx.cli.ok(&["journal", "status", "--dir", s(&j)]);
    let by_id = |id: &str| {
        st["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["identity"] == id)
            .map(|e| e["state"].clone())
            .unwrap_or_default()
    };
    assert_eq!(by_id("manifest_chunk:bad/1"), "rejected");
    assert_eq!(by_id("attempt_started:bad-a1"), "blocked_by_dependency");
    assert_eq!(by_id("simulation_attempt:ok-a1:r1"), "committed");
    let facts: i64 = sqlx::query_scalar("SELECT count(*) FROM attempt_facts")
        .fetch_one(&ctx.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(facts, 1);
    ctx.close().await;
}

/// `sample upload` (chunked, resumable) and `rules import` through
/// the real binary: no sample → refused; a failing check is never sent (exit 3); a passing
/// one activates, and a collector's `--pack` extraction names the activated digest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn sample_upload_and_rules_import() {
    let Some(ctx) = setup("rules").await else {
        return;
    };
    // A project admin with a personal token.
    admin::create_user(&ctx.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    admin::set_member(&ctx.pool, "p1", "ada", "admin")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let t = admin::issue_personal_token(&ctx.pool, "ada", 1, "e2e")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let admin_token = ctx.d.join("admin.token");
    std::fs::write(&admin_token, t["token"].as_str().unwrap_or_default()).ok();
    let mut cli = Cli {
        env: ctx.cli.env.clone(),
    };
    for (k, v) in &mut cli.env {
        if k == "DVISCOPE_TOKEN_FILE" {
            *v = s(&admin_token).into();
        }
    }
    // The sample: a failing case, and a 5 MiB case (two chunks).
    let dir = ctx.d.join("sample");
    std::fs::create_dir_all(&dir).ok();
    std::fs::write(dir.join("serious.log"), "ERROR: serious\n").ok();
    write(
        &dir.join("serious.expect.json"),
        &json!({"format": "dviscope.expect/1", "simulator": "vcs",
                "failures": {"display:error": 1}, "must_survive": ["display:error"]}),
    );
    std::fs::write(
        dir.join("big.log"),
        "INFO: steady\n".repeat(5 * 1024 * 1024 / 13),
    )
    .ok();
    write(
        &dir.join("big.expect.json"),
        &json!({"format": "dviscope.expect/1", "simulator": "vcs"}),
    );
    let pack = |name: &str, diag: &str| {
        let p = ctx.d.join(format!("{name}.yaml"));
        std::fs::write(
            &p,
            format!(
                "format: dviscope.rules/1.0\npack: {name}\nversion: 1.0.0\ntier: project\nrules:\n  - {{id: q, version: 1.0.0, kind: suppression, owner: o, reason: r, action: not_an_error,\n     diag_ids: ['{diag}']}}\n"
            ),
        )
        .ok();
        p
    };
    let (quiet, harmless) = (
        pack("quiet", "display:error"),
        pack("harmless", "proj:never"),
    );
    let import = |p: &Path| {
        cli.run(
            &[
                "rules",
                "import",
                "--project",
                "p1",
                "--sample",
                s(&dir),
                "--pack",
                s(p),
            ],
            None,
        )
    };

    // No sample on the server yet: refused before any check is sent.
    let o = import(&harmless);
    assert_eq!(
        o.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );

    // Upload, then again (nothing to send the second time).
    let up = cli.ok(&["sample", "upload", "--project", "p1", "--dir", s(&dir)]);
    assert_eq!(up["cases"], 2, "{up}");
    assert_eq!(up["uploaded"], 2);
    let again = cli.ok(&["sample", "upload", "--project", "p1", "--dir", s(&dir)]);
    assert_eq!(again["already_uploaded"], 2, "{again}");
    assert_eq!(again["sample"], up["sample"]);

    // A lost must-survive failure: exit 3, nothing activated.
    let o = import(&quiet);
    assert_eq!(o.status.code(), Some(3));
    let out: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(out["activated"], false, "{out}");
    let accepted: i64 = sqlx::query_scalar("SELECT count(*) FROM pipelines")
        .fetch_one(&ctx.pool)
        .await
        .unwrap_or(0);
    assert_eq!(accepted, 1, "only the default pipeline");

    // A passing check activates; a collector extracting with the same --pack names it.
    let o = import(&harmless);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(out["activated"], true, "{out}");
    let activated = out["activation"]["new_pipeline"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let ev = cli.ok(&[
        "extract",
        "--pack",
        s(&harmless),
        s(&dir.join("serious.log")),
    ]);
    assert_eq!(ev["pipeline_digest"], activated.as_str());
    let state: String = sqlx::query_scalar("SELECT state FROM pipelines WHERE digest = $1")
        .bind(&activated)
        .fetch_one(&ctx.pool)
        .await
        .unwrap_or_default();
    assert_eq!(state, "accepted");
    ctx.close().await;
}

/// `import folder` previews, then submits a regression whose expected
/// set is the CSV (a row without a log is missing); a second import adds nothing; logs are
/// confined to the root (symlink escape, root-prefix collision, FIFO refused, never hangs).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn import_folder_preview_submit_and_confinement() {
    let Some(ctx) = setup("import").await else {
        return;
    };
    let root = ctx.d.join("runs");
    std::fs::create_dir_all(root.join("t")).ok();
    std::fs::write(
        root.join("t/pass.log"),
        vcs_log("UVM_INFO @ 1: top [HELLO] hi\n", 0),
    )
    .ok();
    std::fs::write(
        root.join("t/fail.log"),
        vcs_log(
            "UVM_ERROR @ 5: uvm_test_top.env.sb [SB_MISMATCH] expected 1 got 2\n",
            1,
        ),
    )
    .ok();
    let csv = ctx.d.join("runs.csv");
    std::fs::write(
        &csv,
        "slot,test,seed,log,exit_code,started_at,finished_at\r\n\
         s1,t_pass,1,t/pass.log,0,2026-11-08T01:00:00Z,2026-11-08T01:01:00Z\r\n\
         s2,t_fail,2,t/fail.log,0,2026-11-08T01:00:00Z,2026-11-08T01:02:00Z\r\n\
         s3,t_gone,3,,,,\r\n",
    )
    .ok();
    let args = |extra: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = [
            "import",
            "folder",
            "--root",
            s(&root),
            "--manifest",
            s(&csv),
            "--regression",
            "imported-1",
            "--producer",
            "pilot",
            "--repository",
            "rtl",
            "--branch",
            "main",
            "--revision",
            "abc123",
            "--simulator",
            "vcs",
        ]
        .iter()
        .map(|x| (*x).to_string())
        .collect();
        v.extend(extra.iter().map(|x| (*x).to_string()));
        v
    };
    let run = |extra: &[&str]| {
        let a = args(extra);
        let r: Vec<&str> = a.iter().map(String::as_str).collect();
        ctx.cli.run(&r, None)
    };
    // Preview: nothing journalled, counts and examples.
    let o = run(&[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let p: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(p["rows"], 3, "{p}");
    assert_eq!(p["with_log"], 2);
    assert_eq!(p["expected_without_log"], 1);
    assert_eq!(p["completeness"], "Expected jobs known (3 rows)");
    assert_eq!(p["examples"]["passing"]["slot"], "s1");
    assert_eq!(p["examples"]["failing"]["slot"], "s2");
    assert!(p.get("journalled_attempts").is_none());
    // Submit.
    let journal = ctx.d.join("state").join("import-1");
    let o = run(&["--submit", "--journal", s(&journal)]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(out["journalled_attempts"], 2, "{out}");
    // No scratch files beside the journal (r3 finding 2).
    let extra: Vec<String> = std::fs::read_dir(journal.parent().unwrap_or(&journal))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    assert!(extra.is_empty(), "{extra:?}");
    assert_eq!(out["delivery"]["runs"]["rejected"], 0, "{out}");
    assert_eq!(out["delivery"]["finish"]["rejected"], 0, "{out}");
    let states = || async {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT s.slot_ref, r.state FROM slots s JOIN regressions r ON r.id = s.regression_id
              WHERE r.ref = 'imported-1' ORDER BY s.slot_ref",
        )
        .fetch_all(&ctx.pool)
        .await
        .unwrap_or_default();
        let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM attempts")
            .fetch_one(&ctx.pool)
            .await
            .unwrap_or(-1);
        (rows, attempts)
    };
    let (rows, attempts) = states().await;
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows.iter().all(|(_, st)| st == "finished"), "{rows:?}");
    assert_eq!(attempts, 2);
    // A second import (same journal, then a fresh one) adds nothing.
    let o = run(&["--submit", "--journal", s(&journal)]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let again: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(again["journalled_attempts"], 0, "{again}");
    let o = run(&[
        "--submit",
        "--journal",
        s(&ctx.d.join("state").join("import-2")),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(states().await.1, 2, "no new attempts");

    // Confinement (Unix fixtures): an escaping symlink, a root-prefix sibling reached
    // through a symlink, and a FIFO are unreadable (never followed, never blocking).
    #[cfg(unix)]
    {
        let outside = ctx.d.join("secret.log");
        std::fs::write(&outside, "UVM_ERROR @ 1: x [Y] z\n").ok();
        let sibling = ctx.d.join("runs2");
        std::fs::create_dir_all(&sibling).ok();
        std::fs::write(sibling.join("a.log"), "x\n").ok();
        std::os::unix::fs::symlink(&outside, root.join("escape.log")).ok();
        std::os::unix::fs::symlink(&sibling, root.join("sib")).ok();
        let fifo = root.join("pipe.log");
        let _ = std::process::Command::new("mkfifo").arg(&fifo).status();
        let csv2 = ctx.d.join("runs2.csv");
        std::fs::write(
            &csv2,
            "slot,test,seed,log,exit_code\nq1,t,1,escape.log,0\nq2,t,2,sib/a.log,0\nq3,t,3,pipe.log,0\n",
        )
        .ok();
        let started = std::time::Instant::now();
        let o = ctx.cli.run(
            &[
                "import",
                "folder",
                "--root",
                s(&root),
                "--manifest",
                s(&csv2),
                "--regression",
                "imported-2",
                "--producer",
                "pilot",
                "--repository",
                "rtl",
                "--branch",
                "main",
                "--revision",
                "abc123",
            ],
            None,
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "never blocks"
        );
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let p: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
        let bad: Vec<&str> = p["unreadable"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x["slot"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(bad, ["q1", "q2", "q3"], "{p}");
        // Submitting with unreadable logs is refused.
        let o = ctx.cli.run(
            &[
                "import",
                "folder",
                "--root",
                s(&root),
                "--manifest",
                s(&csv2),
                "--regression",
                "imported-2",
                "--producer",
                "pilot",
                "--repository",
                "rtl",
                "--branch",
                "main",
                "--revision",
                "abc123",
                "--submit",
                "--journal",
                s(&ctx.d.join("state").join("import-3")),
            ],
            None,
        );
        assert_eq!(o.status.code(), Some(3));
    }
    ctx.close().await;
}

/// A24 (CLI part, B.18): `doctor --assurance PROJECT` prints each producer's profile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_prints_the_assurance_profile() {
    let Some(ctx) = setup("assure").await else {
        return;
    };
    admin::create_user(&ctx.pool, "ada", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    admin::set_member(&ctx.pool, "p1", "ada", "admin")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let t = admin::issue_personal_token(&ctx.pool, "ada", 1, "e2e")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let admin_token = ctx.d.join("admin.token");
    std::fs::write(&admin_token, t["token"].as_str().unwrap_or_default()).ok();
    let mut cli = Cli {
        env: ctx.cli.env.clone(),
    };
    for (k, v) in &mut cli.env {
        if k == "DVISCOPE_TOKEN_FILE" {
            *v = s(&admin_token).into();
        }
    }
    let r = cli.ok(&["doctor", "--server", "--assurance", "p1"]);
    let a = &r["assurance"][0];
    assert_eq!(a["producer"], "pilot", "{r}");
    assert_eq!(
        a["profile"][0], "Counting unavailable (no sealed expected set yet)",
        "{r}"
    );
    // A collector token cannot read it (admins only): the doctor says so and fails.
    let o = ctx.cli.run(&["doctor", "--assurance", "p1"], None);
    assert_eq!(o.status.code(), Some(4));
    ctx.close().await;
}

/// `verdict --wait-processed --deadline` waits only while
/// waiting can change the answer (the collection is open); `--publish-receipt` stores a
/// receipt of the evaluation; `spool flush --wait committed --deadline` retries until the
/// deadline and then exits 4 with records pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn verdict_waits_publishes_and_flush_waits() {
    let Some(ctx) = setup("wait").await else {
        return;
    };
    let (d, cli) = (&ctx.d, &ctx.cli);
    let j = d.join("journal");
    cli.ok(&["journal", "init", "--dir", s(&j), "--id", "w1"]);
    let sm = write(
        &d.join("sm.json"),
        &json!({"schema": dviscope_model::schema::INGEST,
        "producer_id": "pilot", "source_manifest_ref": "sm1",
        "repositories": [{"repository": "rtl", "revision": "abc123"}]}),
    );
    cli.ok(&["source-manifest", "--journal", s(&j), "--body", s(&sm)]);
    let reg = write(
        &d.join("reg.json"),
        &json!({"schema": dviscope_model::schema::INGEST,
        "producer_id": "pilot", "regression_ref": "w1", "suite": "nightly",
        "branch": {"repository": "rtl", "name": "main"}, "source_manifest_ref": "sm1",
        "trigger": {"kind": "nightly"}, "started_at": "2026-11-08T01:00:00Z"}),
    );
    cli.ok(&[
        "regression",
        "create",
        "--journal",
        s(&j),
        "--body",
        s(&reg),
    ]);
    let chunk = write(
        &d.join("chunk.json"),
        &json!({"schema": dviscope_model::schema::MANIFEST, "slots": [
            {"slot_ref": "s1", "exec_inputs": {"test": "t", "seed": "1"}, "required": true}]}),
    );
    cli.ok(&[
        "manifest",
        "declare",
        "--journal",
        s(&j),
        "--regression",
        "w1",
        "--chunk",
        "1",
        "--body",
        s(&chunk),
    ]);
    cli.ok(&["manifest", "seal", "--journal", s(&j), "--regression", "w1"]);
    cli.ok(&[
        "spool",
        "flush",
        "--dir",
        s(&j),
        "--wait",
        "committed",
        "--deadline",
        "30s",
    ]);
    // A triager's personal token for verdicts and receipts.
    admin::create_user(&ctx.pool, "tim", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    admin::set_member(&ctx.pool, "p1", "tim", "triager")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let t = admin::issue_personal_token(&ctx.pool, "tim", 1, "e2e")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let tok = d.join("tim.token");
    std::fs::write(&tok, t["token"].as_str().unwrap_or_default()).ok();
    let mut tim = Cli {
        env: cli.env.clone(),
    };
    for (k, v) in &mut tim.env {
        if k == "DVISCOPE_TOKEN_FILE" {
            *v = s(&tok).into();
        }
    }
    let summary = d.join("summary.json");
    let verdict = |extra: &[&str]| {
        let mut a = vec![
            "verdict",
            "--project",
            "p1",
            "--regression",
            "w1",
            "--expect-source",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--summary",
            "json",
            "--summary-file",
            s(&summary),
        ];
        a.extend_from_slice(extra);
        let started = std::time::Instant::now();
        let o = tim.run(&a, None);
        (o.status.code(), started.elapsed())
    };
    // Open collection: without waiting, at once; with waiting, until the deadline.
    let (code, took) = verdict(&[]);
    assert_eq!(code, Some(11));
    assert!(took < std::time::Duration::from_secs(5));
    let (code, took) = verdict(&["--wait-processed", "--deadline", "3s", "--poll", "1s"]);
    assert_eq!(code, Some(11));
    assert!(
        took >= std::time::Duration::from_millis(2500),
        "it waited: {took:?}"
    );
    // A rejection while waiting is the answer, never the earlier one (r5 finding 2): the
    // token is revoked during the wait.
    let mut child = std::process::Command::new(BIN);
    child.args([
        "verdict",
        "--project",
        "p1",
        "--regression",
        "w1",
        "--expect-source",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "--wait-processed",
        "--deadline",
        "30s",
        "--poll",
        "1s",
    ]);
    for (k, v) in &tim.env {
        child.env(k, v);
    }
    let started = std::time::Instant::now();
    let mut child = child.spawn().unwrap_or_else(|e| panic!("{e}"));
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    admin::revoke_token(&ctx.pool, t["token_id"].as_i64().unwrap_or(0))
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    let status = child.wait().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        status.code(),
        Some(3),
        "the rejection, not the earlier answer"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
    let t = admin::issue_personal_token(&ctx.pool, "tim", 1, "e2e2")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    std::fs::write(&tok, t["token"].as_str().unwrap_or_default()).ok();
    // Finished: nothing to wait for any more (the missing slot does not settle by
    // waiting), so the answer comes at once.
    cli.ok(&["journal", "close", "--dir", s(&j)]);
    cli.ok(&["journal", "finish", "--dir", s(&j), "--regression", "w1"]);
    cli.ok(&["spool", "flush", "--dir", s(&j)]);
    let (code, took) = verdict(&["--wait-processed", "--deadline", "60s", "--poll", "1s"]);
    assert_eq!(code, Some(11), "the missing slot is insufficient evidence");
    assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    // A publication receipt of the evaluation.
    let (code, _) = verdict(&[
        "--publish-receipt",
        "--target-repository",
        "hexkDotCom/dviscope-dev",
        "--target-commit",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]);
    assert_eq!(code, Some(11));
    let out: Value =
        serde_json::from_slice(&std::fs::read(&summary).unwrap_or_default()).unwrap_or(Value::Null);
    assert_eq!(out["publication"]["action"], "post", "{out}");
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM publication_receipts")
        .fetch_one(&ctx.pool)
        .await
        .unwrap_or(-1);
    assert_eq!(receipts, 1);
    // The command's verdict and summary are the receipt's own evaluation (r1 finding 7).
    let stored: Value = sqlx::query_scalar("SELECT summary FROM publication_receipts")
        .fetch_one(&ctx.pool)
        .await
        .unwrap_or(Value::Null);
    assert_eq!(
        out["summary"]["evaluated_at"], stored["evaluated_at"],
        "{out}"
    );
    assert_eq!(out["verdict"], stored["verdict"]);
    // One evaluation only: nothing of the earlier one remains (r2 finding 4).
    let mut keys: Vec<&String> = out
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    keys.sort();
    assert_eq!(keys, ["publication", "summary", "verdict"], "{out}");
    // --publish-receipt without a target is a usage error.
    let (code, _) = verdict(&["--publish-receipt"]);
    assert_eq!(code, Some(2));

    // flush --wait committed against an unreachable server: retries, then exit 4.
    let j2 = d.join("journal2");
    cli.ok(&["journal", "init", "--dir", s(&j2), "--id", "w2"]);
    let mut sm2 = sm.clone();
    sm2.set_file_name("sm2.json");
    write(
        &sm2,
        &json!({"schema": dviscope_model::schema::INGEST,
        "producer_id": "pilot", "source_manifest_ref": "sm2", "repositories": []}),
    );
    cli.ok(&["source-manifest", "--journal", s(&j2), "--body", s(&sm2)]);
    let mut down = Cli {
        env: cli.env.clone(),
    };
    for (k, v) in &mut down.env {
        if k == "DVISCOPE_SERVER_URL" {
            *v = "https://127.0.0.1:9".into();
        }
    }
    let started = std::time::Instant::now();
    let o = down.run(
        &[
            "spool",
            "flush",
            "--dir",
            s(&j2),
            "--wait",
            "committed",
            "--deadline",
            "3s",
        ],
        None,
    );
    assert_eq!(
        o.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(2500));
    ctx.close().await;
}

/// B.19: `doctor --server --pilot` checks the state location and privacy, the token file,
/// CA trust and the clock offset; a token file others can read fails it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doctor_pilot_checks() {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(ctx) = setup("pilot").await else {
        return;
    };
    let state = ctx.d.join("state");
    std::fs::create_dir_all(&state).ok();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).ok();
    let token = ctx.d.join("token");
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).ok();
    let r = ctx.cli.ok(&["doctor", "--server", "--pilot"]);
    let check = |r: &Value, name: &str| {
        r["checks"]
            .as_array()
            .and_then(|a| a.iter().find(|c| c["check"] == name).cloned())
            .unwrap_or_else(|| panic!("no check {name}: {r}"))
    };
    for name in [
        "state_location",
        "state_private",
        "token_file",
        "process_identity",
        "clock_offset_s",
        "ca_trust",
    ] {
        assert_eq!(check(&r, name)["ok"], true, "{name}: {r}");
    }
    assert!(
        check(&r, "clock_offset_s")["detail"]
            .as_i64()
            .is_some_and(|o| o.abs() <= 5)
    );
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).ok();
    let o = ctx.cli.run(&["doctor", "--server", "--pilot"], None);
    assert_eq!(o.status.code(), Some(4));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(check(&r, "token_file")["ok"], false, "{r}");
    ctx.close().await;
}

/// `journal reconcile` and `doctor --reconcile` compare the journal with the
/// server's receipts and slot counts, changing nothing: agreement exits 0; a record not yet
/// delivered, or one the server no longer holds (as after restoring an older backup), is
/// named and exits 10 (doctor: 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn journal_reconcile_names_what_the_server_lacks() {
    let Some(ctx) = setup("recon").await else {
        return;
    };
    let (d, cli) = (&ctx.d, &ctx.cli);
    let j = d.join("journal");
    cli.ok(&["journal", "init", "--dir", s(&j), "--id", "rc1"]);
    let slot = |n: &str| json!({"slot_ref": n, "exec_inputs": {"test": "t", "seed": "1"}, "required": true});
    ctx.regression(&j, "rc", &[slot("s1"), slot("s2")]);
    cli.ok(&["manifest", "seal", "--journal", s(&j), "--regression", "rc"]);
    let src = d.join("pass.log");
    std::fs::write(&src, vcs_log("UVM_INFO @ 1: top [HELLO] hi\n", 0)).ok();
    ctx.attempt(&j, "rc", "a1", "s1", &src);
    let flush = || {
        cli.ok(&[
            "spool",
            "flush",
            "--dir",
            s(&j),
            "--wait",
            "committed",
            "--deadline",
            "30s",
        ])
    };
    flush();

    // Agreement.
    let r = cli.ok(&["journal", "reconcile", "--dir", s(&j)]);
    assert_eq!(r["ok"], true, "{r}");
    assert!(r["confirmed"].as_u64().unwrap_or(0) >= 5, "{r}");
    let reg = &r["regressions"][0];
    assert_eq!(reg["regression_ref"], "rc", "{r}");
    assert_eq!(reg["journal_slots_started"], 1, "{r}");
    assert_eq!(reg["journal_slots_reported"], 1, "{r}");
    assert_eq!(reg["server"]["slots"], 2, "{r}");
    assert_eq!(reg["server"]["slots_started"], 1, "{r}");
    assert_eq!(reg["server"]["slots_reported"], 1, "{r}");
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM receipts")
        .fetch_one(&ctx.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // A record not yet delivered.
    ctx.attempt(&j, "rc", "a2", "s2", &src);
    let o = cli.run(&["journal", "reconcile", "--dir", s(&j)], None);
    assert_eq!(o.status.code(), Some(10));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    let undelivered = r["undelivered"].to_string();
    assert!(undelivered.contains("attempt_started:a2"), "{r}");
    // Reconciliation changed nothing on the server.
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM receipts")
        .fetch_one(&ctx.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(after, before);
    flush();
    assert_eq!(
        cli.ok(&["journal", "reconcile", "--dir", s(&j)])["ok"],
        true
    );

    // The server lost a committed record (as after restoring an older backup).
    sqlx::query("DELETE FROM receipts WHERE identity = 'attempt_started:a1'")
        .execute(&ctx.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let o = cli.run(&["journal", "reconcile", "--dir", s(&j)], None);
    assert_eq!(o.status.code(), Some(10));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(r["lost"][0]["at"]["identity"], "attempt_started:a1", "{r}");
    assert_eq!(r["lost"].as_array().map(Vec::len), Some(1), "{r}");
    // The doctor reports the same and fails.
    let o = cli.run(&["doctor", "--reconcile", s(&j)], None);
    assert_eq!(o.status.code(), Some(4));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(r["ok"], false, "{r}");
    assert_eq!(
        r["reconcile"][0]["result"]["lost"][0]["at"]["identity"], "attempt_started:a1",
        "{r}"
    );
    ctx.close().await;
}
