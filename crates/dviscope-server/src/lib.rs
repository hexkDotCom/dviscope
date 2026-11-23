//! DVIScope server: HTTPS API, ingest, readiness, decisions and the web UI.
//!
//! Layering: `api` handlers decode and call one application operation; `app`
//! owns authorization, transactions, history and audit; `db` takes the operation's
//! transaction.

/// SQL condition (slot alias `s`): the slot's removal does not count — its credential is
/// quarantined since before it, or (a removal from before migration 0013, credential
/// unknown) any credential of the regression's producer is quarantined.
macro_rules! removal_untrusted {
    () => {
        "(EXISTS (SELECT 1 FROM api_tokens q WHERE q.id = s.removed_by
                    AND q.quarantined_since IS NOT NULL AND s.removed_at >= q.quarantined_since)
          OR (s.removed_by IS NULL AND EXISTS (
                SELECT 1 FROM regressions rr JOIN api_tokens q ON q.producer_id = rr.producer_id
                 WHERE rr.project_id = s.project_id AND rr.id = s.regression_id
                   AND q.quarantined_since IS NOT NULL)))"
    };
}

pub mod admin;
pub mod api;
pub mod app;
pub mod auth;
pub mod backup;
pub mod config;
pub mod db;
pub mod demo;
pub mod demo_soc;
pub mod error;
pub mod http;
pub mod retention;
pub mod ui;

use std::sync::Arc;

use anyhow::Context as _;
use axum_server::tls_rustls::RustlsConfig;

pub use config::ServerConfig;

/// Builds the TLS configuration from the configured PEM files.
///
/// # Errors
/// Unreadable or invalid certificate or key.
pub async fn tls_config(cfg: &ServerConfig) -> anyhow::Result<RustlsConfig> {
    // The ring provider is the only one compiled in; install it as the process default.
    let _ = rustls::crypto::ring::default_provider().install_default();
    RustlsConfig::from_pem_file(&cfg.tls.cert_file, &cfg.tls.key_file)
        .await
        .with_context(|| {
            format!(
                "loading TLS files {} / {}",
                cfg.tls.cert_file.display(),
                cfg.tls.key_file.display()
            )
        })
}

/// Runs the server until the handle is shut down.
///
/// # Errors
/// TLS or bind failures.
pub async fn serve(cfg: Arc<ServerConfig>, handle: axum_server::Handle) -> anyhow::Result<()> {
    let tls = tls_config(&cfg).await?;
    let app = match &cfg.database {
        Some(d) => {
            let env: Vec<(String, String)> = std::env::vars().collect();
            let pool = db::connect(&d.url(&env)?, d.pool_size, d.statement_timeout_ms).await?;
            if !db::schema_ready(&pool).await? {
                anyhow::bail!(
                    "the database schema is not this version's: run `dviscope-server migrate`"
                );
            }
            Some(app::App { db: pool })
        }
        None => None,
    };
    let router = api::router_with(cfg.clone(), app);
    axum_server::bind_rustls(cfg.listen, tls)
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .await
        .context("server stopped with an error")
}
