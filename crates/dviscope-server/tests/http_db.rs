//! The HTTP API against PostgreSQL: the route matrix (every route × credential kind),
//! mixed credentials, NDJSON ingest and its bounds, and browser sessions (Origin, CSRF,
//! throttle). Plain HTTP on a loopback port (TLS is covered by `tls_e2e`). Skipped without
//! `DVISCOPE_TEST_DATABASE_URL`; each test uses its own throwaway database.

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use dviscope_model::schema::{INGEST, MANIFEST};
use dviscope_server::config::{ServerConfig, TlsConfig};
use dviscope_server::{admin, app::App, db, http};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};

const ORIGIN: &str = "https://127.0.0.1:8443";

struct Env {
    base: String,
    pool: sqlx::PgPool,
    admin_url: String,
    name: String,
}

impl Env {
    async fn new() -> Option<Self> {
        Self::new_with(60).await
    }

    async fn new_with(body_timeout_s: u64) -> Option<Self> {
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
        let adm = db::connect(&url, 1, 30_000)
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        let mut b = [0u8; 6];
        getrandom::fill(&mut b).unwrap_or_else(|e| panic!("{e}"));
        let name = format!("dvs_h_{}", hex::encode(b));
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&adm)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        adm.close().await;
        let (base_url, _) = url.rsplit_once('/').unwrap_or((&url, ""));
        let pool = db::connect(&format!("{base_url}/{name}"), 8, 30_000)
            .await
            .unwrap_or_else(|e| panic!("{e:#}"));
        db::migrate(&pool).await.unwrap_or_else(|e| panic!("{e:#}"));
        let cfg = Arc::new(ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap_or_else(|e| panic!("{e}")),
            public_origin: ORIGIN.into(),
            tls: TlsConfig {
                cert_file: "unused".into(),
                key_file: "unused".into(),
            },
            database: None,
            ui_dir: None,
            request_body_timeout_s: body_timeout_s,
        });
        let router = dviscope_server::api::router_with(cfg, Some(App { db: pool.clone() }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        Some(Self {
            base: format!("http://{addr}"),
            pool,
            admin_url: url,
            name,
        })
    }

    async fn drop(self) {
        self.pool.close().await;
        if let Ok(adm) = db::connect(&self.admin_url, 1, 30_000).await {
            let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE {} WITH (FORCE)",
                self.name
            )))
            .execute(&adm)
            .await;
            adm.close().await;
        }
    }
}

fn client() -> Client {
    Client::builder().build().unwrap_or_else(|e| panic!("{e}"))
}

async fn token(pool: &sqlx::PgPool, scopes: &[&str]) -> String {
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    let t = admin::issue_token(pool, "p1", "pilot", &scopes, 30, "test")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    t["token"].as_str().unwrap_or_default().to_string()
}

async fn setup(pool: &sqlx::PgPool) {
    admin::create_project(pool, "p1", "strict")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    admin::create_producer(pool, "p1", "pilot")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    admin::create_user(pool, "vera", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
    admin::set_member(pool, "p1", "vera", "viewer")
        .await
        .unwrap_or_else(|e| panic!("{e:#}"));
}

fn path(p: &str) -> String {
    p.replace("{ref}", "r1")
        .replace("{n}", "1")
        .replace("{project}", "p1")
        .replace("{signature}", "1")
        .replace("{id}", "1")
        .replace("{slot}", "s1")
        .replace("{seq}", "1")
}

async fn send(
    c: &Client,
    base: &str,
    method: &str,
    p: &str,
    bearer: Option<&str>,
    cookie: Option<&str>,
    body: &str,
) -> (StatusCode, Value) {
    let m = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let mut r = c
        .request(m, format!("{base}{}", path(p)))
        .body(body.to_string());
    if let Some(t) = bearer {
        r = r.bearer_auth(t);
    }
    if let Some(k) = cookie {
        r = r.header("cookie", format!("{}={k}", http::SESSION_COOKIE));
    }
    let res = r.send().await.unwrap_or_else(|e| panic!("{e}"));
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

#[tokio::test]
async fn route_matrix_and_credentials() {
    let Some(e) = Env::new().await else { return };
    setup(&e.pool).await;
    let c = client();
    let none = token(&e.pool, &[]).await;
    let all = token(&e.pool, dviscope_server::auth::SCOPES).await;
    for (method, p, action) in http::ROUTES {
        let Some(action) = action else { continue };
        // No credential: 401 before anything else.
        let (s, _) = send(&c, &e.base, method, p, None, None, "{}").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {p}");
        // Both credentials: 400 E_MIXED_CREDENTIALS.
        let (s, b) = send(&c, &e.base, method, p, Some(&all), Some("x"), "{}").await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{method} {p}");
        assert_eq!(b["code"], "E_MIXED_CREDENTIALS");
        // An unknown token: 401.
        let (s, _) = send(&c, &e.base, method, p, Some("dvis_nope"), None, "{}").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {p}");
        let (scope, _) = dviscope_server::auth::policy(*action);
        if scope.is_some() {
            // A collector without the scope: 403, whatever the body.
            let body = if *p == "/api/v1/ingest" {
                format!(
                    "{}\n",
                    json!({"kind": "attempt_started", "schema": INGEST,
                    "producer_id": "pilot", "regression_ref": "r1", "slot_ref": "s1",
                    "attempt_ref": "a1", "attempt_seq": 1, "started_at": "2026-11-08T01:00:00Z"})
                )
            } else {
                regression_body("r1")
            };
            let (s, b) = send(&c, &e.base, method, p, Some(&none), None, &body).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{method} {p}: {b}");
            // Decided before the body is read: a garbage body is still 403.
            let (s, _) = send(&c, &e.base, method, p, Some(&none), None, "{").await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{method} {p}");
        } else {
            // Reads: a collector token is denied.
            let (s, _) = send(&c, &e.base, method, p, Some(&all), None, "").await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{method} {p}");
        }
    }
    e.drop().await;
}

fn regression_body(r: &str) -> String {
    json!({"schema": INGEST, "producer_id": "pilot", "regression_ref": r, "suite": "nightly",
           "branch": {"repository": "rtl", "name": "main"}, "source_manifest_ref": "sm1",
           "trigger": {"kind": "nightly"}, "started_at": "2026-11-08T01:00:00Z"})
    .to_string()
}

#[tokio::test]
async fn collection_over_http() {
    let Some(e) = Env::new().await else { return };
    setup(&e.pool).await;
    let c = client();
    let t = token(&e.pool, dviscope_server::auth::SCOPES).await;
    let sm = json!({"schema": INGEST, "producer_id": "pilot", "source_manifest_ref": "sm1",
                    "repositories": [{"repository": "rtl", "revision": "abc"}]})
    .to_string();
    let (s, b) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/source-manifests",
        Some(&t),
        None,
        &sm,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let (s, b) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/source-manifests",
        Some(&t),
        None,
        &sm,
    )
    .await;
    assert_eq!(
        (s, b["result"].as_str()),
        (StatusCode::OK, Some("duplicate"))
    );
    let (s, _) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/regressions",
        Some(&t),
        None,
        &regression_body("r1"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let slots =
        json!([{"slot_ref": "s1", "exec_inputs": {"test": "t1", "seed": "1"}, "required": true}]);
    let chunk = json!({"schema": MANIFEST, "slots": slots}).to_string();
    let (s, b) = send(
        &c,
        &e.base,
        "PUT",
        "/api/v1/regressions/{ref}/manifest/chunks/{n}",
        Some(&t),
        None,
        &chunk,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let decls: Vec<dviscope_model::wire::manifest::SlotDecl> =
        serde_json::from_value(slots).unwrap_or_default();
    let digest = dviscope_model::canonical::digest_of(&decls).unwrap_or_else(|e| panic!("{e}"));
    let seal =
        json!({"schema": MANIFEST, "revision": 1, "slot_count": 1, "manifest_digest": digest})
            .to_string();
    let (s, b) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/regressions/{ref}/manifest/seal",
        Some(&t),
        None,
        &seal,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    // A bad body is a 400 with the error registry shape.
    let (s, b) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/regressions/{ref}/manifest/seal",
        Some(&t),
        None,
        "{",
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(b["code"], "E_INVALID");
    assert_eq!(b["committed"], false);

    // NDJSON: lines fail independently.
    let start = json!({"kind": "attempt_started", "schema": INGEST, "producer_id": "pilot",
        "regression_ref": "r1", "slot_ref": "s1", "attempt_ref": "a1", "attempt_seq": 1,
        "started_at": "2026-11-08T01:00:00Z"});
    let undeclared = json!({"kind": "attempt_started", "schema": INGEST, "producer_id": "pilot",
        "regression_ref": "r1", "slot_ref": "nope", "attempt_ref": "a2", "attempt_seq": 1,
        "started_at": "2026-11-08T01:00:00Z"});
    let batch = format!("{start}\nnot json\n{undeclared}\n{start}\n");
    let (s, b) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/ingest",
        Some(&t),
        None,
        &batch,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let lines: Vec<Value> = b
        .as_str()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let results: Vec<&str> = lines.iter().filter_map(|l| l["result"].as_str()).collect();
    assert_eq!(
        results,
        ["committed", "rejected", "rejected", "duplicate"],
        "{lines:?}"
    );
    assert_eq!(lines[2]["error"]["field"], "slot_ref");

    // gzip within bounds is accepted; beyond the ratio, 413.
    let gz = |raw: &[u8]| {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(raw).unwrap_or_else(|e| panic!("{e}"));
        enc.finish().unwrap_or_default()
    };
    let res = c
        .post(format!("{}/api/v1/ingest", e.base))
        .bearer_auth(&t)
        .header("content-encoding", "gzip")
        .body(gz(format!("{start}\n").as_bytes()))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(res.status(), StatusCode::OK);
    let bomb = vec![b' '; 4 * 1024 * 1024];
    let res = c
        .post(format!("{}/api/v1/ingest", e.base))
        .bearer_auth(&t)
        .header("content-encoding", "gzip")
        .body(gz(&bomb))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Too many records in one batch: 413, nothing committed.
    let many = format!("{start}\n").repeat(1_001);
    let (s, b) = send(&c, &e.base, "POST", "/api/v1/ingest", Some(&t), None, &many).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{b}");
    e.drop().await;
}

#[tokio::test]
async fn browser_sessions() {
    let Some(e) = Env::new().await else { return };
    setup(&e.pool).await;
    let c = client();
    let login = |origin: &'static str, pw: &'static str| {
        c.post(format!("{}/api/v1/session", e.base))
            .header("origin", origin)
            .json(&json!({"username": "vera", "password": pw}))
            .send()
    };
    // The Origin is checked on login.
    let r = login("https://evil.example", "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = login(ORIGIN, "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let set = r
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(set.contains("HttpOnly") && set.contains("Secure") && set.contains("SameSite=Lax"));
    let sid = set
        .split(';')
        .next()
        .and_then(|kv| kv.split_once('='))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    let csrf = r
        .headers()
        .get(http::CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    // Reads with the session (a missing regression is a 404, so the session counted).
    let (s, _) = send(
        &c,
        &e.base,
        "GET",
        "/api/v1/projects/{project}/regressions/{ref}",
        None,
        Some(&sid),
        "",
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A viewer may not triage, in bulk either: 403 with CSRF and Origin in order.
    let r = c
        .post(format!(
            "{}/api/v1/projects/p1/triage?branch=rtl%2Fmain",
            e.base
        ))
        .header("cookie", format!("{}={sid}", http::SESSION_COOKIE))
        .header(http::CSRF_HEADER, &csrf)
        .header("origin", ORIGIN)
        .json(&json!({"signatures": [{"number": 1}], "state": "open", "notes": "", "bug_urls": []}))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // Logout without CSRF or Origin is refused; with both it ends the session.
    let (s, _) = send(
        &c,
        &e.base,
        "DELETE",
        "/api/v1/session",
        None,
        Some(&sid),
        "",
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let r = c
        .delete(format!("{}/api/v1/session", e.base))
        .header("cookie", format!("{}={sid}", http::SESSION_COOKIE))
        .header(http::CSRF_HEADER, &csrf)
        .header("origin", ORIGIN)
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let (s, _) = send(
        &c,
        &e.base,
        "GET",
        "/api/v1/projects/{project}/regressions/{ref}",
        None,
        Some(&sid),
        "",
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Five failures lock the account for the window, even with the right password next.
    for _ in 0..5 {
        let r = login(ORIGIN, "wrong horse battery")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }
    let r = login(ORIGIN, "correct horse battery")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers().contains_key("retry-after"));
    e.drop().await;
}

/// A burst of concurrent guesses cannot pass the
/// throttle together; a body without a declared length is refused before it is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r1_9_10_bounds_hold_under_concurrency() {
    let Some(e) = Env::new().await else { return };
    setup(&e.pool).await;
    let c = client();
    let mut tasks = vec![];
    for _ in 0..15 {
        let c = c.clone();
        let url = format!("{}/api/v1/session", e.base);
        tasks.push(tokio::spawn(async move {
            c.post(url)
                .header("origin", ORIGIN)
                .json(&json!({"username": "vera", "password": "wrong horse battery"}))
                .send()
                .await
                .map(|r| r.status())
        }));
    }
    let mut checked = 0;
    for t in tasks {
        if let Ok(Ok(s)) = t.await {
            if s == StatusCode::UNAUTHORIZED {
                checked += 1;
            } else {
                assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }
    assert!(checked <= 5, "{checked} guesses were checked");
    // A streamed body (chunked, no Content-Length) is refused before it is read.
    let t = token(&e.pool, dviscope_server::auth::SCOPES).await;
    let addr = e.base.trim_start_matches("http://").to_string();
    let status = tokio::task::spawn_blocking(move || {
        use std::io::{Read as _, Write as _};
        let mut s = std::net::TcpStream::connect(&addr).unwrap_or_else(|e| panic!("{e}"));
        let req = format!(
            "POST /api/v1/regressions HTTP/1.1
Host: {addr}
Authorization: Bearer {t}
             Transfer-Encoding: chunked
Connection: close

2
{{}}
0

"
        );
        s.write_all(req.as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out.lines().next().unwrap_or_default().to_string()
    })
    .await
    .unwrap_or_default();
    assert!(status.contains(" 400 "), "{status}");
    e.drop().await;
}

/// Maintenance mode refuses every write (503) whatever the credential,
/// keeps reads, and /readyz says so; turned off, writes are served again.
#[tokio::test]
async fn maintenance_mode_refuses_writes() {
    let Some(e) = Env::new().await else { return };
    setup(&e.pool).await;
    let c = client();
    let all = token(&e.pool, dviscope_server::auth::SCOPES).await;
    dviscope_server::backup::set_maintenance(&e.pool, true, "test")
        .await
        .unwrap_or_else(|x| panic!("{x:#}"));
    let (s, b) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/regressions",
        Some(&all),
        None,
        "{}",
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["code"], "E_UNAVAILABLE");
    let (s, _) = send(
        &c,
        &e.base,
        "GET",
        "/api/v1/projects/p1/regressions",
        Some(&all),
        None,
        "",
    )
    .await;
    assert_ne!(s, StatusCode::SERVICE_UNAVAILABLE, "reads stay possible");
    let r = c
        .get(format!("{}/readyz", e.base))
        .send()
        .await
        .unwrap_or_else(|x| panic!("{x}"));
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.text().await.unwrap_or_default(), "maintenance");
    dviscope_server::backup::set_maintenance(&e.pool, false, "")
        .await
        .unwrap_or_else(|x| panic!("{x:#}"));
    let (s, _) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/regressions",
        Some(&all),
        None,
        "{}",
    )
    .await;
    assert_ne!(s, StatusCode::SERVICE_UNAVAILABLE);
}

/// Security fixture: compressed bombs and encodings. A large bomb is refused (413)
/// without being decoded beyond the limit; gzip inside gzip decodes one layer only; an
/// unsupported or stacked `Content-Encoding` is refused, never read as identity.
#[tokio::test]
async fn compressed_bombs_and_encodings_are_refused() {
    let Some(e) = Env::new().await else { return };
    setup(&e.pool).await;
    let c = client();
    let t = token(&e.pool, &["ingest:submit"]).await;
    let gz = |raw: &[u8]| {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(raw).unwrap_or_else(|e| panic!("{e}"));
        enc.finish().unwrap_or_default()
    };
    let post = |enc: Option<&'static str>, body: Vec<u8>| {
        let mut r = c
            .post(format!("{}/api/v1/ingest", e.base))
            .bearer_auth(&t)
            .body(body);
        if let Some(v) = enc {
            r = r.header("content-encoding", v);
        }
        async move {
            let res = r.send().await.unwrap_or_else(|e| panic!("{e}"));
            let s = res.status();
            (s, res.text().await.unwrap_or_default())
        }
    };
    // 256 MiB of zeros in about 256 KiB.
    let bomb = gz(&vec![0u8; 256 * 1024 * 1024]);
    assert!(bomb.len() < 1024 * 1024);
    let started = std::time::Instant::now();
    let (s, b) = post(Some("gzip"), bomb.clone()).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{b}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    // A bomb inside gzip: one layer is decoded (within the ratio, or refused by it), and
    // what it yields is not a batch.
    let (s, b) = post(Some("gzip"), gz(&gz(&vec![b' '; 8 * 1024 * 1024]))).await;
    assert!(
        matches!(s, StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE),
        "{s}: {b}"
    );
    // Stacked, unknown or other encodings are refused.
    for enc in ["gzip, gzip", "br", "deflate", "x-gzip", "zstd"] {
        let (s, b) = post(Some(enc), bomb.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{enc}: {b}");
        assert!(b.contains("Content-Encoding"), "{enc}: {b}");
    }
    // Several Content-Encoding fields are a stacked encoding too.
    let res = c
        .post(format!("{}/api/v1/ingest", e.base))
        .bearer_auth(&t)
        .header("content-encoding", "identity")
        .header("content-encoding", "gzip")
        .body(bomb.clone())
        .send()
        .await
        .unwrap_or_else(|x| panic!("{x}"));
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        res.text()
            .await
            .unwrap_or_default()
            .contains("Content-Encoding")
    );
    // `identity` and none are plain bodies.
    let (s, b) = post(Some("identity"), b"\n".to_vec()).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let receipts: i64 = sqlx::query_scalar("SELECT count(*) FROM receipts")
        .fetch_one(&e.pool)
        .await
        .unwrap_or_else(|x| panic!("{x}"));
    assert_eq!(receipts, 0, "nothing committed");
    e.drop().await;
}

/// Login bodies are small, unencoded and reserve from their own budget,
/// and every body arrives within the deadline: withheld logins never starve authenticated
/// requests, and release their reservation at the deadline.
#[tokio::test]
async fn p2_withheld_login_bodies_never_starve_requests() {
    let Some(e) = Env::new_with(1).await else {
        return;
    };
    setup(&e.pool).await;
    let c = client();
    let addr = e.base.trim_start_matches("http://").to_string();
    let login = || {
        c.post(format!("{}/api/v1/session", e.base))
            .header("origin", ORIGIN)
            .json(&json!({"username": "vera", "password": "wrong horse battery"}))
            .send()
    };
    // Size and encoding.
    let big = c
        .post(format!("{}/api/v1/session", e.base))
        .header("origin", ORIGIN)
        .body("x".repeat(http::MAX_LOGIN_BODY_BYTES + 1))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(big.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let gz = c
        .post(format!("{}/api/v1/session", e.base))
        .header("origin", ORIGIN)
        .header("content-encoding", "gzip")
        .body("x")
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(gz.status(), StatusCode::BAD_REQUEST);
    // Fill the login budget with declared, withheld bodies.
    let n = http::MAX_LOGIN_IN_FLIGHT_BYTES / http::MAX_LOGIN_BODY_BYTES;
    let mut held = vec![];
    for _ in 0..n {
        use std::io::Write as _;
        let mut s = std::net::TcpStream::connect(&addr).unwrap_or_else(|e| panic!("{e}"));
        let req = format!(
            "POST /api/v1/session HTTP/1.1\r\nHost: {addr}\r\nOrigin: {ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            http::MAX_LOGIN_BODY_BYTES
        );
        s.write_all(req.as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
        held.push(s);
    }
    // Let the server read every request's headers and reserve for its body.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // The server has reserved for them: one more login is busy...
    let mut busy = false;
    for _ in 0..50 {
        let r = login().await.unwrap_or_else(|e| panic!("{e}"));
        if r.status() == StatusCode::SERVICE_UNAVAILABLE {
            busy = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(busy, "the login budget is bounded");
    // ...while an authenticated write still has its budget.
    let t = token(&e.pool, dviscope_server::auth::SCOPES).await;
    let (st, v) = send(
        &c,
        &e.base,
        "POST",
        "/api/v1/source-manifests",
        Some(&t),
        None,
        &json!({"schema": dviscope_model::schema::INGEST, "producer_id": "pilot",
                "source_manifest_ref": "sm1", "repositories": [{"repository": "rtl", "revision": "a"}]})
        .to_string(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    // After the deadline the withheld logins are answered and their reservation released.
    tokio::time::sleep(std::time::Duration::from_millis(1600)).await;
    let r = login().await.unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(held);
    e.drop().await;
}

/// Once an address is over its limit, rotating usernames records nothing
/// more; usernames are bounded; expired windows are forgotten.
#[tokio::test]
async fn p3_the_login_throttle_never_grows_unbounded() {
    let Some(e) = Env::new().await else { return };
    setup(&e.pool).await;
    let c = client();
    sqlx::query("INSERT INTO login_throttle (key, failures, window_start) VALUES ('user:old', 3, now() - interval '1 hour')")
        .execute(&e.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let attempt = |user: String| {
        c.post(format!("{}/api/v1/session", e.base))
            .header("origin", ORIGIN)
            .json(&json!({"username": user, "password": "wrong"}))
            .send()
    };
    let long = attempt("u".repeat(65))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(long.status(), StatusCode::BAD_REQUEST);
    for i in 0..40 {
        let _ = attempt(format!("nobody{i}")).await;
    }
    let users: i64 =
        sqlx::query_scalar("SELECT count(*) FROM login_throttle WHERE key LIKE 'user:%'")
            .fetch_one(&e.pool)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    // The address allows 20 attempts per window: no username row after that, and the
    // expired row is gone.
    assert_eq!(users, 20, "username rows");
    let old: i64 = sqlx::query_scalar("SELECT count(*) FROM login_throttle WHERE key = 'user:old'")
        .fetch_one(&e.pool)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(old, 0);
    e.drop().await;
}
