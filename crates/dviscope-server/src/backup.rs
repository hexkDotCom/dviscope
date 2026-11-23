//! Backup and safe restore. `backup` writes a private `pg_dump` custom
//! archive and a manifest of conservation values: row counts per table and the readiness
//! of recent finished regressions, evaluated at the backup time. `restore` loads an
//! archive, then turns maintenance on (writes refused), deletes sessions and disables every
//! token until it is re-enabled or rotated. `verify` recomputes the conservation values in
//! the restored database and compares them with the manifest.
//!
//! The database password never appears on a command line: the client tools get the
//! connection through `PG*` environment variables. Nothing here prints log text or secrets.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row as _};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Manifest format.
pub const MANIFEST_FORMAT: &str = "dviscope.backup/1";
/// Finished regressions whose readiness the manifest records.
const READINESS_SAMPLE: i64 = 20;
/// Tables not conserved across a restore (rewritten by the restore itself).
const NOT_CONSERVED: &[&str] = &[
    "sessions",
    "maintenance",
    "audit",
    "login_throttle",
    "restore_disabled_tokens",
];

/// One recorded readiness evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessFixture {
    /// Project name.
    pub project: String,
    /// Regression reference.
    pub regression: String,
    /// Producer name.
    pub producer: String,
    /// Verdict.
    pub verdict: String,
    /// Evaluation digest.
    pub digest: String,
}

/// A backup's manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Always `dviscope.backup/1`.
    pub format: String,
    /// The backup time (readiness is evaluated at it, also when verifying).
    pub created_at: String,
    /// The schema version (latest migration).
    pub schema_version: i32,
    /// SHA-256 (hex) of the archive.
    pub dump_sha256: String,
    /// Row counts of conserved tables.
    pub counts: BTreeMap<String, i64>,
    /// Readiness of recent finished regressions.
    pub readiness: Vec<ReadinessFixture>,
    /// The major version of the `pg_dump` that wrote the archive (a `pg_restore` at least
    /// as new reads it); 0 when unknown.
    #[serde(default)]
    pub pg_dump_major: u32,
}

/// The `PG*` environment for a `postgres://` URL (no secret on a command line).
///
/// It addresses the database the server's own connection does: the settings are those SQLx
/// resolves for this URL in this process (`db::connect` parses it the same way), environment
/// defaults included, so an omitted port, host, user or database is the same for both
/// (an inherited `PGPORT` cannot point the checks at one database and the dump or restore at
/// another). Checked before anything connects or is written.
///
/// # Errors
/// Not a `postgres://` URL, or a query parameter other than `sslmode`.
pub fn pg_env(url: &str) -> Result<Vec<(String, String)>> {
    let u = url::Url::parse(url).context("the database URL is not a URL")?;
    if !matches!(u.scheme(), "postgres" | "postgresql") {
        bail!("the database URL is not postgres://");
    }
    // A query parameter changes how the server's connection resolves (`dbname`, `host`,
    // `options`, ...): only `sslmode` is accepted, so the URL stays plain.
    for (k, _) in u.query_pairs() {
        if k != "sslmode" {
            bail!(
                "the database URL's query parameter {k:?} is not supported by backup and restore                  (only sslmode): put the database, host, port and user in the URL itself"
            );
        }
    }
    let opts: sqlx::postgres::PgConnectOptions = url.parse().context("database URL")?;
    Ok(tool_env(&opts, u.password().map(percent_decode), |k| {
        std::env::var(k).ok()
    }))
}

/// `env` with `option` added to its `PGOPTIONS` (kept: a resolved `-c role=...` makes the
/// restore act as the role the checks did).
fn with_pg_option(mut env: Vec<(String, String)>, option: &str) -> Vec<(String, String)> {
    match env.iter_mut().find(|(k, _)| k == "PGOPTIONS") {
        Some((_, v)) => {
            v.push(' ');
            v.push_str(option);
        }
        None => env.push(("PGOPTIONS".to_string(), option.to_string())),
    }
    env
}

/// The tools' environment for connection options as SQLx resolved them. `inherited` reads
/// this process's environment: only the credential and certificate files SQLx itself
/// honours pass through (they change how the connection authenticates, never where it goes).
fn tool_env(
    opts: &sqlx::postgres::PgConnectOptions,
    password: Option<String>,
    inherited: impl Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    use sqlx::postgres::PgSslMode;
    let host = opts.get_socket().map_or_else(
        || opts.get_host().to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let ssl = match opts.get_ssl_mode() {
        PgSslMode::Disable => "disable",
        PgSslMode::Allow => "allow",
        PgSslMode::Prefer => "prefer",
        PgSslMode::Require => "require",
        PgSslMode::VerifyCa => "verify-ca",
        PgSslMode::VerifyFull => "verify-full",
    };
    let mut env = vec![
        ("PGHOST".to_string(), host),
        ("PGPORT".to_string(), opts.get_port().to_string()),
        ("PGUSER".to_string(), opts.get_username().to_string()),
        // With no database named, the server's connection takes the user's name.
        (
            "PGDATABASE".to_string(),
            opts.get_database()
                .unwrap_or(opts.get_username())
                .to_string(),
        ),
        ("PGSSLMODE".to_string(), ssl.to_string()),
    ];
    if let Some(o) = opts.get_options() {
        env.push(("PGOPTIONS".to_string(), o.to_string()));
    }
    match password {
        Some(p) => env.push(("PGPASSWORD".to_string(), p)),
        None => {
            if let Some(p) = inherited("PGPASSWORD") {
                env.push(("PGPASSWORD".to_string(), p));
            }
        }
    }
    for k in ["PGPASSFILE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY"] {
        if let Some(v) = inherited(k) {
            env.push((k.to_string(), v));
        }
    }
    env
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A PostgreSQL client tool: from `DVISCOPE_PG_BIN_DIR` when set (for example
/// `/usr/lib/postgresql/16/bin`, the client of the server's major version), else on `PATH`.
fn pg_tool(name: &str) -> std::process::Command {
    pg_tool_in(pg_bin_dir().as_deref(), name)
}

/// `DVISCOPE_PG_BIN_DIR`, when set.
fn pg_bin_dir() -> Option<PathBuf> {
    std::env::var_os("DVISCOPE_PG_BIN_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
}

fn pg_tool_in(dir: Option<&Path>, name: &str) -> std::process::Command {
    let mut c = match dir {
        Some(dir) => std::process::Command::new(dir.join(name)),
        None => std::process::Command::new(name),
    };
    scrub_pg_env(&mut c, std::env::vars_os().map(|(k, _)| k));
    c
}

/// Removes every inherited `PG*` variable from a tool's environment: the tool then sees
/// only the settings derived from the database URL (`pg_env`), as the server's own
/// connection does. An inherited `PGHOSTADDR`, `PGSERVICE`, ... would otherwise send it to
/// another database.
fn scrub_pg_env(
    c: &mut std::process::Command,
    inherited: impl Iterator<Item = std::ffi::OsString>,
) {
    for k in inherited {
        if k.to_string_lossy().starts_with("PG") {
            c.env_remove(k);
        }
    }
}

/// The major version a client tool reports (`pg_restore (PostgreSQL) 18.1` → 18).
fn tool_major(dir: Option<&Path>, name: &str) -> Result<u32> {
    let out = pg_tool_in(dir, name)
        .arg("--version")
        .output()
        .with_context(|| format!("running {name} (is the PostgreSQL client installed?)"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_major(&text).with_context(|| format!("{name} --version did not name a version"))
}

fn parse_major(version_text: &str) -> Option<u32> {
    version_text
        .split_whitespace()
        .find_map(|w| w.split('.').next().and_then(|m| m.parse::<u32>().ok()))
}

/// A backup must be restorable with the tools `restore` accepts for its server: before 17,
/// only that major's `pg_restore` restores into it, and it cannot read an archive written by
/// a newer `pg_dump` (a newer archive format). So such a server is backed up with its own
/// major's `pg_dump`; from 17 on, any `pg_dump` at least the server's.
fn check_backup_pairing(dump_major: u32, server_major: u32) -> Result<()> {
    if dump_major < server_major || (server_major < 17 && dump_major != server_major) {
        bail!(
            "pg_dump {dump_major} cannot back up PostgreSQL {server_major} restorably: use the \
             PostgreSQL {server_major} client tools (set DVISCOPE_PG_BIN_DIR to their \
             directory){}",
            if server_major < 17 {
                " (an archive of a newer pg_dump cannot be read by the pg_restore that restores \
                 into this server)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

/// An archive is read by a `pg_restore` at least as new as the `pg_dump` that wrote it.
fn check_archive_reader(dump_major: u32, restore_major: u32) -> Result<()> {
    if dump_major > restore_major {
        bail!(
            "the archive was written by pg_dump {dump_major}; pg_restore {restore_major} cannot \
             read it: use client tools of version {dump_major} or later"
        );
    }
    Ok(())
}

/// `pg_restore` newer than 16 sets `transaction_timeout`, which servers before 17 reject
/// mid-restore: such a pairing is refused before anything is touched.
fn check_restore_pairing(client_major: u32, server_major: u32) -> Result<()> {
    if server_major < 17 && client_major > server_major {
        bail!(
            "pg_restore {client_major} cannot restore into PostgreSQL {server_major} (it sets \
             transaction_timeout, unknown before 17): use the PostgreSQL {server_major} client \
             tools (set DVISCOPE_PG_BIN_DIR to their directory)"
        );
    }
    Ok(())
}

fn sha256_file(p: &Path) -> Result<String> {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    let mut f = std::fs::File::open(p)?;
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

/// Writes a new private file (0600 on Unix). Elsewhere it refuses: an archive holds the
/// whole database (password hashes included), and owner-only ACLs are not implemented on
/// Windows; run backups on the Linux host or in the `ops` container.
fn write_private(p: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    if !cfg!(unix) {
        bail!(
            "backups are written owner-only, which is not implemented on this platform: run \
             `dviscope-server backup` on the Linux host or in the ops container"
        );
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o
        .open(p)
        .with_context(|| format!("creating {}", p.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Refuses a backup destination where file modes do not protect the archive: a Windows
/// drive seen from WSL (`/mnt/*`, or any DrvFS / 9p mount), also through symlinks (the
/// parent directory is resolved first). The archive holds the whole database.
fn check_backup_location(out: &Path) -> Result<()> {
    check_protected_location(out, "a backup (it holds the whole database)")
}

/// Refuses a destination for `what` where owner-only file modes cannot protect it: a
/// Windows drive seen from WSL (`/mnt/*`, DrvFS / 9p), also through symlinks (the parent
/// directory is resolved first).
///
/// # Errors
/// Such a destination, or a missing parent directory.
pub fn check_protected_location(out: &Path, what: &str) -> Result<()> {
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let real = std::fs::canonicalize(&parent)
        .with_context(|| format!("the backup directory {} does not exist", parent.display()))?;
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok();
    if is_windows_location(&real, mounts.as_deref()) {
        bail!(
            "{} is on a Windows drive seen from WSL, where file modes cannot protect {what}: \
             write it to the Linux file system",
            real.display()
        );
    }
    Ok(())
}

/// Whether a resolved directory is on a Windows drive seen from WSL: under `/mnt`, or on a
/// DrvFS / 9p mount wherever it is mounted.
fn is_windows_location(real: &Path, mounts: Option<&str>) -> bool {
    real.starts_with("/mnt")
        || mounts
            .and_then(|m| mount_fstype(m, real))
            .is_some_and(|fs| matches!(fs.as_str(), "9p" | "drvfs" | "v9fs"))
}

/// The file system type of the mount that holds `path` (the longest mount point that is a
/// prefix of it), from a `/proc/self/mounts` text.
fn mount_fstype(mounts: &str, path: &Path) -> Option<String> {
    mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_, point, fstype) = (f.next()?, f.next()?, f.next()?);
            Some((point.replace("\\040", " "), fstype.to_string()))
        })
        .filter(|(point, _)| path.starts_with(point))
        .max_by_key(|(point, _)| point.len())
        .map(|(_, fs)| fs)
}

/// The manifest path of an archive (`<archive>.manifest.json`).
#[must_use]
pub fn manifest_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_owned();
    s.push(".manifest.json");
    PathBuf::from(s)
}

/// Row counts of every conserved table (all tables of the schema but the ones a restore
/// rewrites).
async fn counts(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<BTreeMap<String, i64>> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema() ORDER BY 1",
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut out = BTreeMap::new();
    for t in tables {
        if NOT_CONSERVED.contains(&t.as_str()) {
            continue;
        }
        if !t
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            bail!("unexpected table name {t:?}");
        }
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {t}")))
            .fetch_one(&mut **tx)
            .await?;
        out.insert(t, n);
    }
    Ok(out)
}

/// Readiness of the most recent finished regressions, evaluated at `at`, inside `tx`'s
/// snapshot.
async fn readiness(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    at: OffsetDateTime,
) -> Result<Vec<ReadinessFixture>> {
    let rows = sqlx::query(
        "SELECT r.project_id, pr.name, pr.policy, r.ref, p.name FROM regressions r
           JOIN projects pr ON pr.id = r.project_id
           JOIN producers p ON p.project_id = r.project_id AND p.id = r.producer_id
          WHERE r.state = 'finished' ORDER BY r.finished_at DESC, r.id DESC LIMIT $1",
    )
    .bind(READINESS_SAMPLE)
    .fetch_all(&mut **tx)
    .await?;
    let mut out = vec![];
    for r in rows {
        let (pid, project, policy, regression, producer): (i64, String, String, String, String) =
            (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4));
        let policy = if policy == "retry-pass-accepted" {
            dviscope_core::settlement::Policy::RetryPassAccepted
        } else {
            dviscope_core::settlement::Policy::Strict
        };
        // The regression of this producer (several producers may use one reference); no
        // candidate binding (a fixture records the regression's own verdict).
        let (v, _) = crate::app::App::readiness_in(
            tx,
            pid,
            policy,
            &regression,
            None,
            Some(&producer),
            at,
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("readiness of {regression}: {}", e.message))?;
        out.push(ReadinessFixture {
            project,
            regression,
            producer,
            verdict: v["verdict"].as_str().unwrap_or_default().to_string(),
            digest: v["digest"].as_str().unwrap_or_default().to_string(),
        });
    }
    Ok(out)
}

/// A read-only repeatable-read transaction: one snapshot for everything recorded.
async fn snapshot(db: &PgPool) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Writes a backup: the archive at `out` and its manifest beside it (both new, private).
///
/// # Errors
/// An existing destination, `pg_dump` failure, database errors.
pub async fn backup(db: &PgPool, url: &str, out: &Path, now: OffsetDateTime) -> Result<Manifest> {
    // The URL is checked before anything is read or written.
    let tool_env = pg_env(url)?;
    let man_path = manifest_path(out);
    if out.exists() || man_path.exists() {
        bail!(
            "{} or its manifest exists: choose a new name",
            out.display()
        );
    }
    check_backup_location(out)?;
    // One snapshot for everything: the conservation values are taken in a repeatable-read
    // transaction whose snapshot pg_dump then uses (`--snapshot`), so concurrent writes are
    // in both or in neither.
    let mut tx = snapshot(db).await?;
    let current: i32 =
        sqlx::query_scalar("SELECT coalesce(max(version), 0) FROM schema_migrations")
            .fetch_one(&mut *tx)
            .await?;
    if current < FIRST_SAFE_RESTORE_SCHEMA {
        bail!(
            "the database is at schema {current}: `restore` takes archives of schema \
             {FIRST_SAFE_RESTORE_SCHEMA} or later, so this backup could not be restored with \
             it; before upgrading such a database, back it up with `pg_dump --format=custom` \
             (a rollback restores that with `pg_restore` for the previous version), then migrate"
        );
    }
    let dump_major = tool_major(pg_bin_dir().as_deref(), "pg_dump")?;
    let server_num: String = sqlx::query_scalar("SHOW server_version_num")
        .fetch_one(&mut *tx)
        .await?;
    check_backup_pairing(dump_major, server_num.parse::<u32>().unwrap_or(0) / 10_000)?;
    let snap: String = sqlx::query_scalar("SELECT pg_export_snapshot()")
        .fetch_one(&mut *tx)
        .await?;
    let counts = counts(&mut tx).await?;
    let readiness = readiness(&mut tx, now).await?;
    let schema_version: i32 =
        sqlx::query_scalar("SELECT coalesce(max(version), 0) FROM schema_migrations")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(0);
    // An empty private file the dump writes into (pg_dump keeps its mode).
    write_private(out, b"")?;
    let status = pg_tool("pg_dump")
        .args(["--format=custom", "--no-owner", "--no-privileges"])
        .arg(format!("--snapshot={snap}"))
        .arg("--file")
        .arg(out)
        .envs(tool_env)
        .status()
        .context("running pg_dump (is the PostgreSQL client installed?)")?;
    // The snapshot is held until the dump has read it.
    tx.commit().await?;
    if !status.success() {
        let _ = std::fs::remove_file(out);
        bail!("pg_dump failed ({status})");
    }
    let m = Manifest {
        format: MANIFEST_FORMAT.into(),
        created_at: now.format(&Rfc3339)?,
        schema_version,
        dump_sha256: sha256_file(out)?,
        counts,
        readiness,
        pg_dump_major: dump_major,
    };
    write_private(&man_path, &serde_json::to_vec_pretty(&m)?)?;
    Ok(m)
}

/// Reads and checks a manifest against its archive.
///
/// # Errors
/// A missing or malformed manifest, or an archive that differs from it.
pub fn read_manifest(archive: &Path) -> Result<Manifest> {
    let m: Manifest = serde_json::from_slice(
        &std::fs::read(manifest_path(archive)).context("reading the backup manifest")?,
    )
    .context("the backup manifest is malformed")?;
    if m.format != MANIFEST_FORMAT {
        bail!("not a {MANIFEST_FORMAT} manifest");
    }
    if sha256_file(archive)? != m.dump_sha256 {
        bail!("the archive does not match its manifest (corrupt or replaced)");
    }
    Ok(m)
}

/// Restores an archive into the configured database, then puts it into the safe state:
/// maintenance on, sessions deleted, every token disabled until re-enabled or rotated.
///
/// # Errors
/// A manifest mismatch, `pg_restore` failure, database errors.
pub async fn restore(url: &str, archive: &Path) -> Result<Value> {
    restore_in(url, archive, pg_bin_dir().as_deref()).await
}

/// [`restore`] with the PostgreSQL client tools of `pg_bin` (`None`: on `PATH`).
///
/// # Errors
/// As [`restore`].
pub async fn restore_in(url: &str, archive: &Path, pg_bin: Option<&Path>) -> Result<Value> {
    let m = read_manifest(archive)?;
    if m.schema_version < FIRST_SAFE_RESTORE_SCHEMA {
        bail!(
            "the archive is of schema {} (before {FIRST_SAFE_RESTORE_SCHEMA}, the first with a \
             safe restore): restore it with the version that wrote it",
            m.schema_version
        );
    }
    let created = OffsetDateTime::parse(&m.created_at, &Rfc3339)
        .context("the manifest's created_at is not RFC 3339")?;
    let env = pg_env(url)?;
    {
        let db = crate::db::connect(url, 1, 60_000).await?;
        let num: String = sqlx::query_scalar("SHOW server_version_num")
            .fetch_one(&db)
            .await?;
        // An older schema's archive cannot replace a newer database in place: the newer
        // tables would keep references the restore cannot drop. Rolling an upgrade back is a
        // restore into a new, empty database.
        // Two statements: a statement naming a missing table fails when it is planned,
        // whatever its CASE says (an empty database has no `schema_migrations`).
        let has_schema: bool =
            sqlx::query_scalar("SELECT to_regclass('schema_migrations') IS NOT NULL")
                .fetch_one(&db)
                .await?;
        let target: i32 = if has_schema {
            sqlx::query_scalar("SELECT coalesce(max(version), 0) FROM schema_migrations")
                .fetch_one(&db)
                .await?
        } else {
            0
        };
        db.close().await;
        if target > m.schema_version {
            bail!(
                "the archive is of schema {} but this database is at schema {target}: restore it \
                 into a new, empty database (create one and point DVISCOPE_SERVER_DATABASE_URL \
                 at it); nothing was changed",
                m.schema_version
            );
        }
        let server_major = num.parse::<u32>().unwrap_or(0) / 10_000;
        let restore_major = tool_major(pg_bin, "pg_restore")?;
        check_archive_reader(m.pg_dump_major, restore_major)?;
        check_restore_pairing(restore_major, server_major)?;
    }
    // One transaction: the archive's script, then the safe state. psql commits both or
    // neither, so no client ever sees the restored data with its sessions and tokens live,
    // and a failure at any point leaves the database as it was.
    let hardening = hardening_sql(&m.dump_sha256, created)?;
    let mut dump = pg_tool_in(pg_bin, "pg_restore")
        .args([
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-privileges",
            "--file",
            "-",
        ])
        .arg(archive)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("running pg_restore (is the PostgreSQL client installed?)")?;
    // psql in its own explicit transaction: BEGIN first, COMMIT only once pg_restore has
    // exited successfully and the safe state is written. A truncated script (pg_restore
    // failing between statements) or an interrupted restore ends psql's input inside the
    // open transaction, and the server rolls it back: nothing is committed, ever, but the
    // whole archive with its safe state.
    let mut load = pg_tool_in(pg_bin, "psql")
        .args([
            "--no-psqlrc",
            "--quiet",
            "--set",
            "ON_ERROR_STOP=1",
            "--file",
            "-",
        ])
        .envs(with_pg_option(env, "-c client_min_messages=warning"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .context("running psql (is the PostgreSQL client installed?)")?;
    let (Some(script), Some(sink)) = (dump.stdout.take(), load.stdin.take()) else {
        bail!("pg_restore and psql pipes");
    };
    let feed = std::thread::spawn(move || feed_script(script, sink));
    let dumped = dump.wait()?;
    let fed = feed
        .join()
        .map_err(|_| anyhow::anyhow!("the restore feed panicked"))?;
    let committed = match fed {
        Ok(mut sink) => {
            use std::io::Write as _;
            if dumped.success() {
                sink.write_all(hardening.as_bytes())
                    .and_then(|()| sink.write_all(b"COMMIT;\n"))
                    .and_then(|()| sink.flush())
                    .is_ok()
            } else {
                false
            }
            // `sink` drops here either way: psql reaches the end of its input, committed
            // or (without COMMIT) rolled back.
        }
        Err(_) => false,
    };
    let loaded = load.wait()?;
    if !(committed && loaded.success()) {
        bail!(
            "restore failed (pg_restore {dumped}, psql {loaded}): nothing was committed, the \
             database is as it was"
        );
    }
    let db = crate::db::connect(url, 1, 60_000).await?;
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM restore_disabled_tokens")
        .fetch_one(&db)
        .await?;
    db.close().await;
    Ok(json!({
        "restored": m.created_at, "maintenance": true, "sessions_deleted": true,
        "tokens_disabled": tokens,
        "next": "dviscope-server restore-verify, then re-enable or rotate tokens, then maintenance off",
    }))
}

/// Streams pg_restore's script into psql after `BEGIN`, line by line; returns psql's input
/// (for the safe state and `COMMIT`) when the script ended cleanly. A script that controls
/// transactions itself (it would commit before the safe state) is refused.
fn feed_script(
    script: std::process::ChildStdout,
    mut sink: std::process::ChildStdin,
) -> Result<std::process::ChildStdin> {
    use std::io::{BufRead as _, Write as _};
    sink.write_all(b"BEGIN;\n")?;
    let mut r = std::io::BufReader::new(script);
    let mut line = Vec::new();
    let mut guard = ScriptGuard::default();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        guard.line(String::from_utf8_lossy(&line).trim())?;
        sink.write_all(&line)?;
    }
    Ok(sink)
}

/// Statements that control transactions: a script holding one at top level would commit
/// before the safe state.
const TRANSACTION_CONTROL: &[&str] = &[
    "BEGIN;",
    "COMMIT;",
    "END;",
    "ROLLBACK;",
    "START TRANSACTION;",
];

/// Tracks a restore script line by line: `COPY` data, and dollar-quoted bodies by their
/// exact tag (`$$`, `$fn$`, nested `$inner$` inside an outer body are content), ignoring
/// `$` in single-quoted strings and after `--`. Refuses a top-level transaction control.
#[derive(Debug, Default)]
struct ScriptGuard {
    in_copy: bool,
    /// The open dollar-quote tag, if any.
    tag: Option<String>,
    /// Inside a single-quoted literal (which may span lines; `''` is a quote in it).
    in_string: bool,
    /// Inside a SQL-standard function body (`BEGIN ATOMIC` ... `END;`).
    atomic: bool,
}

impl ScriptGuard {
    fn line(&mut self, t: &str) -> Result<()> {
        if self.in_copy {
            self.in_copy = t != "\\.";
            return Ok(());
        }
        let outside = self.tag.is_none() && !self.in_string;
        if outside && t.starts_with("COPY ") && t.ends_with("FROM stdin;") {
            self.in_copy = true;
            return Ok(());
        }
        self.scan(t);
        let upper = t.to_ascii_uppercase();
        if outside && self.tag.is_none() && !self.in_string {
            // A SQL-standard body's statements and its closing `END;` are content.
            if self.atomic {
                self.atomic = upper != "END;";
                return Ok(());
            }
            if upper.ends_with("BEGIN ATOMIC") {
                self.atomic = true;
                return Ok(());
            }
        }
        if outside
            && self.tag.is_none()
            && !self.in_string
            && TRANSACTION_CONTROL.contains(&upper.as_str())
        {
            bail!("the archive's script controls transactions itself: refused");
        }
        Ok(())
    }

    fn scan(&mut self, t: &str) {
        let b = t.as_bytes();
        let mut i = 0;
        let mut in_string = self.in_string;
        while i < b.len() {
            if let Some(tag) = &self.tag {
                // Inside a body only its own tag closes it.
                match t[i..].find(tag.as_str()) {
                    Some(pos) => {
                        i += pos + tag.len();
                        self.tag = None;
                        continue;
                    }
                    None => {
                        in_string = false;
                        break;
                    }
                }
            }
            let c = b[i];
            if in_string {
                in_string = c != b'\'';
                i += 1;
                continue;
            }
            if c == b'\'' {
                in_string = true;
            } else if c == b'-' && b.get(i + 1) == Some(&b'-') {
                break;
            } else if c == b'$'
                && let Some(len) = dollar_tag_len(b, i)
            {
                self.tag = Some(t[i..i + len].to_string());
                i += len;
                continue;
            }
            i += 1;
        }
        // A literal still open at the end of the line continues on the next.
        self.in_string = in_string;
    }
}

/// The length of a dollar-quote tag starting at `i` (`$$`, `$tag$`; not `$1`).
fn dollar_tag_len(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if b.get(j).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
        j += 1;
    }
    (b.get(j) == Some(&b'$')).then_some(j + 1 - i)
}

/// The first schema with the safe-restore tables (`maintenance`, `restore_disabled_tokens`).
pub const FIRST_SAFE_RESTORE_SCHEMA: i32 = 19;

fn sql_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The safe state, appended to the restore's transaction (schema-qualified: the archive's
/// script empties `search_path`): maintenance on, every session deleted, every live token
/// disabled (its expiry set to now, the original kept for `admin reenable-token`), audited.
fn hardening_sql(dump_sha256: &str, created: OffsetDateTime) -> Result<String> {
    if dump_sha256.len() != 64 || !dump_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("the manifest's archive digest is malformed");
    }
    let detail = json!({"created_at": created.format(&Rfc3339)?}).to_string();
    Ok(format!(
        "
INSERT INTO public.maintenance (id, active, reason, changed_at) VALUES (true, true, 'restored', now())
    ON CONFLICT (id) DO UPDATE SET active = true, reason = 'restored', changed_at = now();
DELETE FROM public.sessions;
INSERT INTO public.restore_disabled_tokens (token_id, original_expires_at)
    SELECT id, expires_at FROM public.api_tokens WHERE revoked_at IS NULL AND expires_at > now()
    ON CONFLICT (token_id) DO NOTHING;
UPDATE public.api_tokens t SET expires_at = now()
    FROM public.restore_disabled_tokens d WHERE d.token_id = t.id AND t.expires_at > now();
INSERT INTO public.audit (actor, action, object, detail)
    VALUES ('admin-cli', 'restore', {}, {}::jsonb);
",
        sql_literal(dump_sha256),
        sql_literal(&detail)
    ))
}

/// Recomputes the conservation values and compares them with the manifest.
///
/// # Errors
/// A manifest mismatch or database errors (differences are a report, not an error).
pub async fn verify(db: &PgPool, archive: &Path) -> Result<Value> {
    let m = read_manifest(archive)?;
    let at = OffsetDateTime::parse(&m.created_at, &Rfc3339)?;
    let mut tx = snapshot(db).await?;
    let now_counts = counts(&mut tx).await?;
    let mut differences = vec![];
    for (t, n) in &m.counts {
        match now_counts.get(t) {
            Some(x) if x == n => {}
            other => differences.push(json!({"table": t, "backup": n, "restored": other})),
        }
    }
    for t in now_counts.keys().filter(|t| !m.counts.contains_key(*t)) {
        // A table added by a migration since: reported, not a difference of the data.
        differences.push(json!({"table": t, "backup": null, "restored": now_counts[t]}));
    }
    let now_ready = readiness(&mut tx, at).await?;
    tx.commit().await?;
    for f in &m.readiness {
        match now_ready.iter().find(|g| {
            g.project == f.project && g.regression == f.regression && g.producer == f.producer
        }) {
            Some(g) if g == f => {}
            other => differences.push(json!({"readiness": f.regression, "backup": f.verdict,
                                            "restored": other.map(|g| g.verdict.clone())})),
        }
    }
    Ok(json!({
        "ok": differences.is_empty(),
        "tables": m.counts.len(),
        "readiness_checked": m.readiness.len(),
        "differences": differences,
    }))
}

/// Turns maintenance on or off.
///
/// # Errors
/// Database errors.
pub async fn set_maintenance(db: &PgPool, on: bool, reason: &str) -> Result<Value> {
    // Exclusive: waits for every write transaction that passed the gate, and every later
    // one sees the new flag (`app::write_gate`).
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(crate::app::MAINTENANCE_GATE)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE maintenance SET active = $1, reason = $2, changed_at = now()")
        .bind(on)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO audit (actor, action, object, detail) VALUES ('admin-cli', $1, 'maintenance', $2)",
    )
    .bind(if on { "maintenance.on" } else { "maintenance.off" })
    .bind(json!({"reason": reason}))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(json!({"maintenance": on}))
}

/// Whether maintenance is on (writes refused).
///
/// # Errors
/// Database errors.
pub async fn maintenance_on(db: &PgPool) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT active FROM maintenance")
            .fetch_optional(db)
            .await?
            .unwrap_or(false),
    )
}

/// Re-enables a token disabled by a restore.
///
/// # Errors
/// An unknown token or database errors.
pub async fn reenable_token(db: &PgPool, id: i64) -> Result<Value> {
    let mut tx = db.begin().await?;
    let n = sqlx::query(
        "UPDATE api_tokens t SET expires_at = d.original_expires_at
           FROM restore_disabled_tokens d
          WHERE d.token_id = t.id AND t.id = $1 AND t.revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 0 {
        bail!("token {id} is not disabled by a restore (or it was revoked)");
    }
    sqlx::query("DELETE FROM restore_disabled_tokens WHERE token_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Audited in the same transaction: no credential change without its record.
    sqlx::query(
        "INSERT INTO audit (actor, action, object, detail) VALUES ('admin-cli', 'token.reenable', $1, '{}')",
    )
    .bind(format!("token:{id}"))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(json!({"reenabled": id}))
}

#[cfg(test)]
mod tests {
    use super::{pg_env, scrub_pg_env, tool_env, with_pg_option};

    /// Restore's own option is added to the resolved options,
    /// never in their place.
    #[test]
    fn restore_keeps_the_resolved_session_options() {
        let opts = sqlx::postgres::PgConnectOptions::new_without_pgpass()
            .host("h")
            .port(5432)
            .username("postgres")
            .database("db")
            .options([("role", "dviscope")]);
        let env = with_pg_option(
            tool_env(&opts, None, |_| None),
            "-c client_min_messages=warning",
        );
        let o: Vec<&str> = env
            .iter()
            .filter(|(k, _)| k == "PGOPTIONS")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(o.len(), 1, "{env:?}");
        assert!(o[0].contains("role=dviscope"), "{o:?}");
        assert!(o[0].ends_with("-c client_min_messages=warning"), "{o:?}");
        let bare = with_pg_option(vec![], "-c x=y");
        assert_eq!(bare, [("PGOPTIONS".to_string(), "-c x=y".to_string())]);
    }

    /// The tools address what the server's connection resolved,
    /// environment defaults included. `postgres://u@h/db` with `PGPORT=5433` inherited:
    /// SQLx connects to port 5433, so the dump and the restore do too (never 5432).
    #[test]
    fn the_tools_address_the_database_the_server_resolves() {
        let get = |env: &[(String, String)], k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let as_resolved = sqlx::postgres::PgConnectOptions::new_without_pgpass()
            .host("h")
            .port(5433)
            .username("u")
            .database("db");
        let env = tool_env(&as_resolved, None, |k| {
            (k == "PGPASSWORD").then(|| "inherited".to_string())
        });
        assert_eq!(get(&env, "PGPORT"), "5433", "{env:?}");
        assert_eq!(get(&env, "PGHOST"), "h");
        assert_eq!(get(&env, "PGUSER"), "u");
        assert_eq!(get(&env, "PGDATABASE"), "db");
        assert_eq!(get(&env, "PGPASSWORD"), "inherited");
        // A socket directory, no database named (the server takes the user's name), a URL
        // password over an inherited one.
        let socket = sqlx::postgres::PgConnectOptions::new_without_pgpass()
            .socket("/var/run/postgresql")
            .port(5432)
            .username("ops");
        let env = tool_env(&socket, Some("url".to_string()), |_| {
            Some("inherited".to_string())
        });
        assert_eq!(get(&env, "PGHOST"), "/var/run/postgresql");
        // (PGDATABASE in this test's environment would be what SQLx resolved.)
        assert_eq!(
            get(&env, "PGDATABASE"),
            socket.get_database().unwrap_or("ops")
        );
        assert_eq!(get(&env, "PGPASSWORD"), "url");
    }

    /// Inherited `PG*` variables never reach the tools.
    #[test]
    fn inherited_pg_variables_are_removed() {
        let mut c = std::process::Command::new("psql");
        scrub_pg_env(
            &mut c,
            ["PGHOSTADDR", "PGSERVICE", "PATH", "PGPASSFILE"]
                .into_iter()
                .map(Into::into),
        );
        c.envs(pg_env("postgres://u:p@h/db").unwrap_or_else(|e| panic!("{e}")));
        let envs: Vec<(String, Option<String>)> = c
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for gone in ["PGHOSTADDR", "PGSERVICE", "PGPASSFILE"] {
            assert!(envs.contains(&(gone.to_string(), None)), "{gone}: {envs:?}");
        }
        assert!(!envs.iter().any(|(k, _)| k == "PATH"));
        assert!(envs.contains(&("PGHOST".to_string(), Some("h".to_string()))));
    }

    /// A query parameter the PostgreSQL tools would not see (`dbname`,
    /// `host`, ...) is refused, so checks and restore always address one database.
    #[test]
    fn only_sslmode_is_accepted_in_the_url_query() {
        let ok =
            pg_env("postgres://u:p@h:5433/db?sslmode=require").unwrap_or_else(|e| panic!("{e}"));
        assert!(ok.contains(&("PGDATABASE".to_string(), "db".to_string())));
        assert!(ok.contains(&("PGSSLMODE".to_string(), "require".to_string())));
        assert!(pg_env("postgres://u:p@h/db").is_ok());
        for bad in [
            "dbname=other",
            "host=elsewhere",
            "port=6000",
            "user=x",
            "options=-c%20x=y",
        ] {
            let e = pg_env(&format!("postgres://u:p@h/db?{bad}"))
                .err()
                .map(|e| e.to_string());
            assert!(e.is_some_and(|e| e.contains("not supported")), "{bad}");
        }
    }

    use super::*;

    #[test]
    fn backups_are_owner_only_or_refused() {
        let d = std::env::temp_dir().join(format!("dviscope-wp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).ok();
        let p = d.join("archive");
        let r = write_private(&p, b"x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert!(r.is_ok(), "{r:?}");
            let mode = std::fs::metadata(&p).map(|m| m.permissions().mode() & 0o777);
            assert_eq!(mode.ok(), Some(0o600));
        }
        #[cfg(not(unix))]
        {
            assert!(r.is_err(), "no owner-only ACLs here: refused");
            assert!(!p.exists(), "nothing written");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Windows drives seen from WSL are refused: directly, through a symlinked parent, or by
    /// the mount's file system type wherever it is mounted.
    #[test]
    fn backups_refuse_windows_drives() {
        assert!(
            check_backup_location(Path::new("/mnt/x.dump")).is_err() || !Path::new("/mnt").exists()
        );
        #[cfg(unix)]
        if Path::new("/mnt").exists() {
            let d = std::env::temp_dir().join(format!("dviscope-loc-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).ok();
            let link = d.join("drive");
            std::os::unix::fs::symlink("/mnt", &link).ok();
            assert!(check_backup_location(&link.join("x.dump")).is_err());
            assert!(check_backup_location(&d.join("x.dump")).is_ok());
            let _ = std::fs::remove_dir_all(&d);
        }
        let mounts = "C:\\134 /win 9p rw 0 0\n/dev/sdb / ext4 rw 0 0\n/dev/sdc /data xfs rw 0 0\n";
        assert_eq!(
            mount_fstype(mounts, Path::new("/win/backups")).as_deref(),
            Some("9p")
        );
        assert_eq!(
            mount_fstype(mounts, Path::new("/data/b")).as_deref(),
            Some("xfs")
        );
        assert_eq!(
            mount_fstype(mounts, Path::new("/home/u")).as_deref(),
            Some("ext4")
        );
        assert!(is_windows_location(Path::new("/win/backups"), Some(mounts)));
        assert!(is_windows_location(Path::new("/mnt/c/b"), None));
        assert!(!is_windows_location(Path::new("/data/b"), Some(mounts)));
    }

    #[test]
    fn script_guard_follows_bodies_by_tag() {
        let run = |lines: &[&str]| {
            let mut g = ScriptGuard::default();
            for l in lines {
                g.line(l)?;
            }
            Ok::<_, anyhow::Error>(g.tag)
        };
        // A body holding a differently tagged literal with transaction-looking lines.
        let nested = [
            "CREATE FUNCTION public.f() RETURNS text LANGUAGE plpgsql AS $outer$",
            "BEGIN",
            "  RETURN $inner$",
            "END;",
            "COMMIT;",
            "$inner$;",
            "END;",
            "$outer$;",
        ];
        assert_eq!(run(&nested).ok(), Some(None), "accepted, and closed");
        // Parameters, strings and comments are not delimiters.
        assert!(run(&["SELECT $1, $2;", "COMMIT;"]).is_err());
        assert!(run(&["SELECT '$$';", "COMMIT;"]).is_err());
        assert!(run(&["-- about $$", "COMMIT;"]).is_err());
        // A body's own END; is content; a top-level COMMIT is refused.
        assert!(run(&["AS $_$", "END;", "$_$;"]).is_ok());
        assert!(run(&["SET x = 1;", "commit;"]).is_err());
        // A multi-line literal (a comment, a default) holding transaction-looking lines and
        // doubled quotes is content; after it closes, a real COMMIT is refused again.
        let multiline = [
            "COMMENT ON TABLE public.projects IS 'instructions:",
            "END;",
            "it''s fine",
            "COMMIT;",
            "';",
        ];
        assert_eq!(run(&multiline).ok(), Some(None));
        let mut g = ScriptGuard::default();
        for l in multiline {
            assert!(g.line(l).is_ok());
        }
        assert!(g.line("COMMIT;").is_err());
        // A SQL-standard function body (dumped unquoted) ends with its own END;.
        let atomic = [
            "CREATE FUNCTION public.one() RETURNS integer",
            "    LANGUAGE sql",
            "    BEGIN ATOMIC",
            " SELECT 1;",
            "END;",
        ];
        let mut g = ScriptGuard::default();
        for l in atomic {
            assert!(g.line(l).is_ok(), "{l}");
        }
        assert!(
            g.line("COMMIT;").is_err(),
            "a top-level COMMIT after it is refused"
        );
        // COPY data is never interpreted.
        assert!(
            run(&[
                "COPY public.t (a) FROM stdin;",
                "COMMIT;",
                "\\.",
                "SELECT 1;"
            ])
            .is_ok()
        );
    }

    #[test]
    fn backup_pairings_stay_restorable() {
        // Before 17: only the server's own major (pg_dump 17 writes format 1.16, which
        // pg_restore 16 cannot read).
        assert!(check_backup_pairing(17, 16).is_err());
        assert!(check_backup_pairing(18, 16).is_err());
        assert!(check_backup_pairing(15, 16).is_err());
        assert!(check_backup_pairing(16, 16).is_ok());
        // From 17: at least the server's.
        assert!(check_backup_pairing(18, 17).is_ok());
        assert!(check_backup_pairing(17, 17).is_ok());
        assert!(check_backup_pairing(16, 17).is_err());
        // The reader is at least the writer.
        assert!(check_archive_reader(17, 16).is_err());
        assert!(check_archive_reader(16, 16).is_ok());
        assert!(check_archive_reader(16, 18).is_ok());
        assert!(
            check_archive_reader(0, 16).is_ok(),
            "unknown: not refused here"
        );
    }

    #[test]
    fn restore_pairings() {
        assert_eq!(
            parse_major("pg_restore (PostgreSQL) 18.1 (Ubuntu 18.1-1)"),
            Some(18)
        );
        assert_eq!(parse_major("pg_restore (PostgreSQL) 16.15"), Some(16));
        assert_eq!(parse_major("nothing"), None);
        assert!(check_restore_pairing(18, 16).is_err());
        assert!(check_restore_pairing(17, 16).is_err());
        assert!(check_restore_pairing(16, 16).is_ok());
        assert!(check_restore_pairing(18, 17).is_ok());
        assert!(check_restore_pairing(17, 17).is_ok());
    }
}
