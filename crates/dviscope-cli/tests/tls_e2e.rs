//! End to end: `tls init` certificates, a real TLS server, `doctor --server`.

use std::collections::BTreeMap;
use std::sync::Arc;

use dviscope_cli::config::{CliConfig, Overrides};
use dviscope_cli::{doctor, tls};
use dviscope_server::config::{ServerConfig, TlsConfig};

fn any() -> tls::PrivatePolicy {
    tls::PrivatePolicy {
        allow_any_location: true,
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

async fn start(paths: &tls::TlsPaths) -> (axum_server::Handle, std::net::SocketAddr) {
    let cfg = Arc::new(ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap_or_else(|e| panic!("{e}")),
        public_origin: "https://127.0.0.1:8443".into(),
        tls: TlsConfig {
            cert_file: paths.server_cert.clone(),
            key_file: paths.server_key.clone(),
        },
        database: None,
        ui_dir: None,
        request_body_timeout_s: 60,
    });
    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        let _ = dviscope_server::serve(cfg, h).await;
    });
    let addr = handle
        .listening()
        .await
        .unwrap_or_else(|| panic!("server did not start"));
    (handle, addr)
}

fn cli_config(url: String, ca: Option<std::path::PathBuf>, state: &std::path::Path) -> CliConfig {
    let mut env = BTreeMap::new();
    env.insert(
        "DVISCOPE_STATE_DIR".to_string(),
        state.display().to_string(),
    );
    CliConfig::resolve(
        &env,
        &Overrides {
            server_url: Some(url),
            ca_file: ca,
            state_dir: None,
        },
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

#[tokio::test]
async fn doctor_reaches_server_with_local_ca_only() {
    let dir = tmp("doctor");
    let paths = tls::TlsPaths::new(&dir.join("ca"), &dir.join("server"));
    tls::init(&paths, time::OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
    let (handle, addr) = start(&paths).await;
    let url = format!("https://127.0.0.1:{}", addr.port());

    // With the local CA: every check passes and capabilities come back.
    let (report, ok) = doctor::run(
        &cli_config(url.clone(), Some(paths.ca_cert.clone()), &dir),
        true,
    )
    .await;
    assert!(ok, "{report:#}");
    assert!(report.to_string().contains("dviscope.ingest/1.0-dev.3"));

    // Without it: the TLS handshake must fail (no trust-on-first-use).
    let (_, ok) = doctor::run(&cli_config(url, None, &dir), true).await;
    assert!(!ok);

    // Plain HTTP is refused before any request.
    let (report, ok) = doctor::run(
        &cli_config(format!("http://127.0.0.1:{}", addr.port()), None, &dir),
        true,
    )
    .await;
    assert!(!ok);
    assert!(report.to_string().contains("E_INSECURE_URL"));

    handle.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn renewed_leaf_is_trusted_by_the_same_ca() {
    let dir = tmp("renew");
    let paths = tls::TlsPaths::new(&dir.join("ca"), &dir.join("server"));
    tls::init(&paths, time::OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
    tls::renew(&paths, time::OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
    let (handle, addr) = start(&paths).await;
    let url = format!("https://127.0.0.1:{}", addr.port());
    let (report, ok) = doctor::run(&cli_config(url, Some(paths.ca_cert.clone()), &dir), true).await;
    assert!(ok, "{report:#}");
    handle.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn expired_leaf_is_rejected_and_renew_recovers() {
    let dir = tmp("expired");
    let paths = tls::TlsPaths::new(&dir.join("ca"), &dir.join("server"));
    // Issued 400 days ago: the leaf (365 days) has expired, the CA (3650 days) has not.
    let past = time::OffsetDateTime::now_utc() - time::Duration::days(400);
    tls::init(&paths, past, &any()).unwrap_or_else(|e| panic!("{e}"));
    let (handle, addr) = start(&paths).await;
    let url = format!("https://127.0.0.1:{}", addr.port());
    let (report, ok) = doctor::run(
        &cli_config(url.clone(), Some(paths.ca_cert.clone()), &dir),
        true,
    )
    .await;
    assert!(!ok, "an expired leaf must be rejected: {report:#}");
    assert!(
        report.to_string().to_lowercase().contains("expired"),
        "{report:#}"
    );
    handle.shutdown();

    // Recovery: renew (same CA) and restart.
    tls::renew(&paths, time::OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
    let (handle, addr) = start(&paths).await;
    let url = format!("https://127.0.0.1:{}", addr.port());
    let (report, ok) = doctor::run(&cli_config(url, Some(paths.ca_cert.clone()), &dir), true).await;
    assert!(ok, "{report:#}");
    handle.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn security_headers_present() {
    let dir = tmp("headers");
    let paths = tls::TlsPaths::new(&dir.join("ca"), &dir.join("server"));
    tls::init(&paths, time::OffsetDateTime::now_utc(), &any()).unwrap_or_else(|e| panic!("{e}"));
    let (handle, addr) = start(&paths).await;
    let client = dviscope_cli::client::build(
        &format!("https://127.0.0.1:{}", addr.port()),
        Some(&paths.ca_cert),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let res = client
        .get(format!("https://127.0.0.1:{}/healthz", addr.port()))
        .send()
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let h = res.headers();
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap_or("")
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert!(h.contains_key("strict-transport-security"));
    handle.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}
