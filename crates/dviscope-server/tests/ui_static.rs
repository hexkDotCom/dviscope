//! Web UI hosting from `ui_dir`: files, app-route fallback, traversal, API isolation, cache
//! and security headers. Plain HTTP on a loopback port; no database needed.

use std::path::PathBuf;
use std::sync::Arc;

use dviscope_server::config::{ServerConfig, TlsConfig};
use reqwest::{Client, StatusCode};

fn tmp(tag: &str) -> PathBuf {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).unwrap_or_else(|e| panic!("{e}"));
    let d = std::env::temp_dir().join(format!("dvs-ui-{tag}-{}", hex::encode(b)));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

async fn start(ui_dir: Option<PathBuf>) -> String {
    let cfg = Arc::new(ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap_or_else(|e| panic!("{e}")),
        public_origin: "https://127.0.0.1:8443".into(),
        tls: TlsConfig {
            cert_file: "unused".into(),
            key_file: "unused".into(),
        },
        database: None,
        ui_dir,
        request_body_timeout_s: 60,
    });
    let router = dviscope_server::api::router(cfg);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}")
}

/// A built UI under `<base>/dist`, with a file beside it that must never be served.
fn fixture() -> (PathBuf, PathBuf) {
    let base = tmp("site");
    let dist = base.join("dist");
    std::fs::create_dir_all(dist.join("assets")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(
        dist.join("index.html"),
        "<!doctype html><div id=root></div>",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(dist.join("assets").join("index-abc.js"), "console.log(1)")
        .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(base.join("secret.txt"), "outside").unwrap_or_else(|e| panic!("{e}"));
    (base, dist)
}

#[tokio::test]
async fn serves_files_and_app_routes() {
    let (base, dist) = fixture();
    let url = start(Some(dist)).await;
    let c = Client::new();

    let r = c
        .get(format!("{url}/"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::OK);
    let h = r.headers().clone();
    assert_eq!(h["content-type"], "text/html; charset=utf-8");
    assert_eq!(h["cache-control"], "no-cache");
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap_or("")
            .contains("script-src 'self'")
    );
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert!(r.text().await.unwrap_or_default().contains("id=root"));

    let r = c
        .get(format!("{url}/assets/index-abc.js"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );
    assert!(
        r.headers()["cache-control"]
            .to_str()
            .unwrap_or("")
            .contains("immutable")
    );

    // App routes get the app; missing files with an extension do not.
    for route in ["/p/alpha/r/nightly-7", "/login", "/p/alpha/signatures/12"] {
        let r = c
            .get(format!("{url}{route}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.status(), StatusCode::OK, "{route}");
        assert!(
            r.text().await.unwrap_or_default().contains("id=root"),
            "{route}"
        );
    }
    let r = c
        .get(format!("{url}/assets/missing.js"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // HEAD answers without a body.
    let r = c
        .head(format!("{url}/"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::OK);
    std::fs::remove_dir_all(base).ok();
}

#[tokio::test]
async fn never_serves_outside_ui_dir_or_for_the_api() {
    let (base, dist) = fixture();
    #[cfg(unix)]
    std::os::unix::fs::symlink(base.join("secret.txt"), dist.join("link.txt"))
        .unwrap_or_else(|e| panic!("{e}"));
    let url = start(Some(dist)).await;
    let c = Client::new();
    // reqwest normalizes `..` in URLs, so encoded and raw variants are sent as written.
    for path in [
        "/%2e%2e/secret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt",
        "/..%2fsecret.txt",
        "/.hidden",
        "/assets\\..\\..\\secret.txt",
        "/link.txt",
    ] {
        let r = c
            .get(format!("{url}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let body = r.text().await.unwrap_or_default();
        assert!(
            !body.contains("outside"),
            "{path} leaked a file outside ui_dir"
        );
    }
    // Unknown API paths are API 404s, never the app.
    for path in ["/api/v1/nope", "/api"] {
        let r = c
            .get(format!("{url}{path}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(
            !r.text().await.unwrap_or_default().contains("id=root"),
            "{path}"
        );
    }
    // Only reads are served.
    let r = c
        .post(format!("{url}/"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    std::fs::remove_dir_all(base).ok();
}

#[tokio::test]
async fn no_ui_without_ui_dir() {
    let url = start(None).await;
    let r = Client::new()
        .get(format!("{url}/"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

/// The stylesheet's colour contract (jsdom applies no CSS, so the rules are checked here):
/// KPI labels never recolour the badges in the tiles, an exception never reads as green and
/// insufficient evidence has no colour.
#[test]
fn colour_rules_of_the_stylesheet() {
    let css = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/src/style.css"),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let compact: String = css.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !compact.contains(".kpis span {"),
        "a rule for every span in the KPI tiles"
    );
    assert!(compact.contains(".kpis .kpi-label {"));
    assert!(compact.contains(".verdict-accepted_with_exceptions { color: var(--warn); }"));
    assert!(compact.contains(".verdict-insufficient_evidence { color: var(--muted); }"));
    assert!(compact.contains(".hb-yellow { color: var(--warn); }"));
}
