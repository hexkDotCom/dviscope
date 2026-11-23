//! `dviscope-server` binary: thin wrapper over the library.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use dviscope_server::ServerConfig;

#[derive(Debug, Parser)]
#[command(name = "dviscope-server", version, about = "DVIScope server")]
struct Cli {
    /// Configuration file (TOML).
    #[arg(
        long,
        env = "DVISCOPE_SERVER_CONFIG",
        default_value = "dviscope-server.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server (default).
    Run,
    /// Validate the configuration and TLS files, then exit.
    Check,
    /// Apply pending database migrations (exclusive advisory lock), then exit.
    Migrate,
    /// Apply retention: expire payloads, then facts, then receipts.
    Retention {
        /// Report what would be removed (each regression), change nothing.
        #[arg(long, visible_alias = "preview")]
        dry_run: bool,
        /// The clock (RFC 3339; default: now). For tests and previews.
        #[arg(long, conflicts_with = "every")]
        now: Option<String>,
        /// Keep running: apply retention every N hours (the compose `retention` service
        /// uses 24). Skipped, not failed, while the server is in maintenance.
        #[arg(long, value_name = "HOURS", value_parser = clap::value_parser!(u32).range(1..=168))]
        every: Option<u32>,
    },
    /// Provisioning (audited).
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Write a backup: a private pg_dump archive and its manifest of conservation values.
    Backup {
        /// The archive to create (its manifest is written beside it).
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Restore an archive into the configured database; maintenance on, sessions deleted,
    /// tokens disabled until re-enabled or rotated.
    Restore {
        /// The archive.
        archive: std::path::PathBuf,
    },
    /// Compare the restored database with the archive's manifest (counts, readiness).
    RestoreVerify {
        /// The archive.
        archive: std::path::PathBuf,
    },
    /// Create the "bad nightly" demo project (invented records: a repeated failure, an
    /// expired exception, a missing result, a failed build). Refuses an existing project.
    Demo {
        /// The new project's name (default `demo`, or `demo-soc` with `--soc`).
        #[arg(long)]
        project: Option<String>,
        /// The demo SoC instead: a hierarchy of subsystems and blocks with 14 nights of
        /// stub regressions, for the health dashboard.
        #[arg(long)]
        soc: bool,
        /// An existing user to make a member (viewer) of the demo project.
        #[arg(long)]
        member: Option<String>,
    },
    /// Maintenance mode: writes refused.
    Maintenance {
        /// `on` or `off`.
        state: String,
        /// Why (recorded in the audit log).
        #[arg(long, default_value = "")]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
enum AdminAction {
    /// Create a project.
    CreateProject {
        /// Project name (lower-case letters, digits, '-', '_').
        #[arg(long)]
        name: String,
        /// Retry policy: strict or retry-pass-accepted.
        #[arg(long, default_value = "strict")]
        policy: String,
    },
    /// Create a producer namespace in a project.
    CreateProducer {
        /// Project.
        #[arg(long)]
        project: String,
        /// Producer name (the `producer_id` of its records).
        #[arg(long)]
        name: String,
    },
    /// Issue a collector token, written to a new owner-only file (never printed).
    IssueToken {
        /// Project.
        #[arg(long)]
        project: String,
        /// Producer.
        #[arg(long)]
        producer: String,
        /// Scopes (repeatable); default: every collector scope.
        #[arg(long = "scope")]
        scopes: Vec<String>,
        /// Days until expiry (at most a year).
        #[arg(long, default_value_t = 365)]
        days: u32,
        /// Label shown in listings.
        #[arg(long, default_value = "")]
        label: String,
        /// File the token is written to (created, owner-only; never printed).
        #[arg(long)]
        out: PathBuf,
    },
    /// Issue a personal token for a user, written to a new owner-only file (never printed;
    /// acts with the user's roles).
    IssuePersonalToken {
        /// User name.
        #[arg(long)]
        username: String,
        /// Days until expiry (at most a year).
        #[arg(long, default_value_t = 90)]
        days: u32,
        /// Label shown in listings.
        #[arg(long, default_value = "")]
        label: String,
        /// File the token is written to (created, owner-only; never printed).
        #[arg(long)]
        out: PathBuf,
    },
    /// Re-enable a token a restore disabled (after checking it was not leaked).
    ReenableToken {
        /// Token ID.
        #[arg(long)]
        id: i64,
    },
    /// Revoke a token.
    RevokeToken {
        /// Token ID.
        #[arg(long)]
        id: i64,
    },
    /// Quarantine a token from a receipt time on (and revoke it).
    QuarantineToken {
        /// Token ID.
        #[arg(long)]
        id: i64,
        /// RFC 3339 time: revisions received since then are barriers.
        #[arg(long)]
        since: String,
    },
    /// Release a token's quarantine (it stays revoked).
    ReleaseToken {
        /// Token ID.
        #[arg(long)]
        id: i64,
    },
    /// Accept a pipeline digest for a project.
    AcceptPipeline {
        /// Project.
        #[arg(long)]
        project: String,
        /// Pipeline digest (`sha256:...`, from `dviscope rules check`).
        #[arg(long)]
        digest: String,
    },
    /// Withdraw an accepted pipeline (its results stop settling).
    WithdrawPipeline {
        /// Project.
        #[arg(long)]
        project: String,
        /// Pipeline digest.
        #[arg(long)]
        digest: String,
    },
    /// Create a local user; the password is read from a file or standard input.
    CreateUser {
        /// User name.
        #[arg(long)]
        username: String,
        /// File holding the password (default: standard input).
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
    /// Set a user's role in a project (viewer, triager, admin).
    SetMember {
        /// Project.
        #[arg(long)]
        project: String,
        /// User name.
        #[arg(long)]
        username: String,
        /// Role.
        #[arg(long)]
        role: String,
    },
}

/// Command output goes to stdout as JSON (logs go to stderr).
/// The retention service: one run every `hours`, as of the clock at each run. A run is
/// skipped (logged) while the schema is not this version's or the server is in
/// maintenance; a failed run is logged and retried at the next tick (never a crash loop).
async fn retention_loop(db: &sqlx::PgPool, dry_run: bool, hours: u32) -> anyhow::Result<()> {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(u64::from(hours) * 3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
        match dviscope_server::db::schema_ready(db).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!("retention skipped: the database schema is not this version's");
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "retention skipped: database unavailable");
                continue;
            }
        }
        if !dry_run
            && dviscope_server::backup::maintenance_on(db)
                .await
                .unwrap_or(true)
        {
            tracing::warn!("retention skipped: maintenance");
            continue;
        }
        match dviscope_server::retention::run(
            db,
            time::OffsetDateTime::now_utc(),
            dviscope_server::retention::Policy::default(),
            dry_run,
        )
        .await
        {
            Ok(r) => tracing::info!(
                payloads = r.payloads,
                regressions = r.regressions,
                builds = r.builds,
                receipts = r.receipts,
                dry_run = r.dry_run,
                "retention run"
            ),
            Err(e) => tracing::warn!(error = %e, "retention run failed; retried at the next tick"),
        }
    }
}

fn print_json(v: &serde_json::Value) -> anyhow::Result<()> {
    use std::io::Write as _;
    writeln!(std::io::stdout(), "{}", serde_json::to_string_pretty(v)?)?;
    Ok(())
}

async fn pool(cfg: &ServerConfig, env: &[(String, String)]) -> anyhow::Result<sqlx::PgPool> {
    let d = cfg
        .database
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no [database] section in the configuration"))?;
    dviscope_server::db::connect(&d.url(env)?, 2, d.statement_timeout_ms).await
}

fn database_url(cfg: &ServerConfig, env: &[(String, String)]) -> anyhow::Result<String> {
    let d = cfg
        .database
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no [database] section in the configuration"))?;
    Ok(d.url(env)?)
}

async fn admin(cfg: &ServerConfig, env: &[(String, String)], a: AdminAction) -> anyhow::Result<()> {
    use dviscope_server::admin as ad;
    let db = pool(cfg, env).await?;
    if !dviscope_server::db::schema_ready(&db).await? {
        anyhow::bail!("the database schema is not this version's: run `dviscope-server migrate`");
    }
    // In maintenance (a restored or frozen database) only credential recovery runs:
    // replacing, re-enabling, revoking or quarantining tokens. Everything else would change
    // the data being verified.
    let recovery = matches!(
        a,
        AdminAction::IssueToken { .. }
            | AdminAction::IssuePersonalToken { .. }
            | AdminAction::ReenableToken { .. }
            | AdminAction::RevokeToken { .. }
            | AdminAction::QuarantineToken { .. }
            | AdminAction::ReleaseToken { .. }
    );
    if !recovery && dviscope_server::backup::maintenance_on(&db).await? {
        anyhow::bail!(
            "the server is in maintenance: only token recovery commands run (issue, re-enable, \
             revoke, quarantine, release); end it with `dviscope-server maintenance off`"
        );
    }
    let out = match a {
        AdminAction::CreateProject { name, policy } => {
            ad::create_project(&db, &name, &policy).await?
        }
        AdminAction::CreateProducer { project, name } => {
            ad::create_producer(&db, &project, &name).await?
        }
        AdminAction::IssueToken {
            project,
            producer,
            scopes,
            days,
            label,
            out,
        } => {
            // Checked before issuing: a refused destination leaves no unused live token.
            token_destination(&out)?;
            let scopes = if scopes.is_empty() {
                dviscope_server::auth::SCOPES
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                scopes
            };
            write_token(
                &out,
                ad::issue_token(&db, &project, &producer, &scopes, days, &label).await?,
            )?
        }
        AdminAction::RevokeToken { id } => ad::revoke_token(&db, id).await?,
        AdminAction::ReenableToken { id } => {
            dviscope_server::backup::reenable_token(&db, id).await?
        }
        AdminAction::IssuePersonalToken {
            username,
            days,
            label,
            out,
        } => {
            token_destination(&out)?;
            write_token(
                &out,
                ad::issue_personal_token(&db, &username, days, &label).await?,
            )?
        }
        AdminAction::QuarantineToken { id, since } => ad::quarantine_token(&db, id, &since).await?,
        AdminAction::ReleaseToken { id } => ad::release_token(&db, id).await?,
        AdminAction::AcceptPipeline { project, digest } => {
            ad::set_pipeline(&db, &project, &digest, "accepted").await?
        }
        AdminAction::WithdrawPipeline { project, digest } => {
            ad::set_pipeline(&db, &project, &digest, "withdrawn").await?
        }
        AdminAction::CreateUser {
            username,
            password_file,
        } => {
            let password = match password_file {
                Some(f) => std::fs::read_to_string(&f)?,
                None => {
                    let mut s = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                    s
                }
            };
            ad::create_user(&db, &username, password.trim_end_matches(['\r', '\n'])).await?
        }
        AdminAction::SetMember {
            project,
            username,
            role,
        } => ad::set_member(&db, &project, &username, &role).await?,
    };
    print_json(&out)?;
    Ok(())
}

/// A token file is written owner-only: on a Linux host, off a Windows drive (checked before
/// issuing, so a refused destination leaves no unused live token).
fn token_destination(path: &std::path::Path) -> anyhow::Result<()> {
    if cfg!(windows) {
        anyhow::bail!(
            "a token file is written on a Linux host, where file modes make it owner-only"
        );
    }
    dviscope_server::backup::check_protected_location(path, "a token")
}

/// Writes an issued token to `path` (created, never overwritten; owner-only on Unix) and
/// returns the issuance record without it: a secret never reaches standard output, a
/// terminal recording or a provisioning log.
fn write_token(
    path: &std::path::Path,
    mut issued: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    use std::io::Write as _;
    let token = issued
        .as_object_mut()
        .and_then(|m| m.remove("token"))
        .and_then(|t| t.as_str().map(str::to_string))
        .ok_or_else(|| anyhow::anyhow!("the issuance returned no token"))?;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| {
        anyhow::anyhow!(
            "{}: {e} (the token is written to a new file; the issued token is unused, revoke it)",
            path.display()
        )
    })?;
    f.write_all(format!("{token}\n").as_bytes())?;
    f.sync_all()?;
    issued["token_file"] = serde_json::json!(path.display().to_string());
    Ok(issued)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    let env: Vec<(String, String)> = std::env::vars().collect();
    let cfg = Arc::new(ServerConfig::load(&cli.config, &env)?);
    match cli.command.unwrap_or(Command::Run) {
        Command::Check => {
            dviscope_server::tls_config(&cfg).await?;
            tracing::info!(listen = %cfg.listen, origin = %cfg.public_origin, "configuration valid");
            Ok(())
        }
        Command::Migrate => {
            let db = pool(&cfg, &env).await?;
            let applied = dviscope_server::db::migrate(&db).await?;
            tracing::info!(?applied, "migrations applied");
            print_json(&serde_json::json!({"applied": applied}))?;
            Ok(())
        }
        Command::Admin { action } => admin(&cfg, &env, action).await,
        Command::Backup { out } => {
            let url = database_url(&cfg, &env)?;
            // Before connecting: a URL backup cannot use is refused first.
            dviscope_server::backup::pg_env(&url)?;
            let db = pool(&cfg, &env).await?;
            let m =
                dviscope_server::backup::backup(&db, &url, &out, time::OffsetDateTime::now_utc())
                    .await?;
            print_json(&serde_json::json!({
                "archive": out.display().to_string(),
                "created_at": m.created_at, "tables": m.counts.len(),
                "readiness_recorded": m.readiness.len(), "sha256": m.dump_sha256,
            }))?;
            Ok(())
        }
        Command::Restore { archive } => {
            let url = database_url(&cfg, &env)?;
            print_json(&dviscope_server::backup::restore(&url, &archive).await?)?;
            Ok(())
        }
        Command::RestoreVerify { archive } => {
            let db = pool(&cfg, &env).await?;
            let r = dviscope_server::backup::verify(&db, &archive).await?;
            print_json(&r)?;
            if r["ok"] != true {
                anyhow::bail!("the restored database differs from the backup");
            }
            Ok(())
        }
        Command::Demo {
            project,
            soc,
            member,
        } => {
            let project = project.unwrap_or_else(|| if soc { "demo-soc" } else { "demo" }.into());
            let db = pool(&cfg, &env).await?;
            if !dviscope_server::db::schema_ready(&db).await? {
                anyhow::bail!(
                    "the database schema is not this version's: run `dviscope-server migrate`"
                );
            }
            if dviscope_server::backup::maintenance_on(&db).await? {
                anyhow::bail!("the server is in maintenance: no demo data is written");
            }
            let now = time::OffsetDateTime::now_utc();
            let mut out = if soc {
                dviscope_server::demo_soc::generate(&db, &project, now).await?
            } else {
                dviscope_server::demo::generate(&db, &project, now).await?
            };
            if let Some(u) = member {
                out["member"] =
                    dviscope_server::admin::set_member(&db, &project, &u, "viewer").await?;
            }
            print_json(&out)?;
            Ok(())
        }
        Command::Maintenance { state, reason } => {
            let db = pool(&cfg, &env).await?;
            let on = match state.as_str() {
                "on" => true,
                "off" => false,
                _ => anyhow::bail!("maintenance on|off"),
            };
            print_json(&dviscope_server::backup::set_maintenance(&db, on, &reason).await?)?;
            Ok(())
        }
        Command::Retention {
            dry_run,
            now,
            every,
        } => {
            let db = pool(&cfg, &env).await?;
            if let Some(hours) = every {
                return retention_loop(&db, dry_run, hours).await;
            }
            if !dviscope_server::db::schema_ready(&db).await? {
                anyhow::bail!(
                    "the database schema is not this version's: run `dviscope-server migrate`"
                );
            }
            if !dry_run && dviscope_server::backup::maintenance_on(&db).await? {
                anyhow::bail!(
                    "the server is in maintenance: retention changes nothing until `maintenance off`"
                );
            }
            let now = match now {
                Some(t) => {
                    time::OffsetDateTime::parse(&t, &time::format_description::well_known::Rfc3339)?
                }
                None => time::OffsetDateTime::now_utc(),
            };
            let rep = dviscope_server::retention::run(
                &db,
                now,
                dviscope_server::retention::Policy::default(),
                dry_run,
            )
            .await?;
            print_json(&serde_json::to_value(&rep)?)?;
            Ok(())
        }
        Command::Run => {
            let handle = axum_server::Handle::new();
            let shutdown = handle.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
            tracing::info!(listen = %cfg.listen, origin = %cfg.public_origin, "starting");
            dviscope_server::serve(cfg, handle).await
        }
    }
}
