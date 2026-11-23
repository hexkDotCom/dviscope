//! `cargo xtask <task>`: development checks that CI and the maintainer run.
//!
//! - `schemas [--check]`: generate JSON Schemas into `schemas/` (or fail on drift).
//! - `deps-check`: workspace dependency edges and forbidden APIs in pure crates.
//! - `publication-check`: no simulator log text, keys or logs in tracked files.
//! - `sim-test --case ID -- CMD...`: run a simulator-backed test with private output.
//! - `sentinel`: proves `sim-test` never prints a test's raw output and propagates failure.
//! - `workflow-check`: local rules for `.github/workflows` (no `pull_request_target`,
//!   actions pinned by commit SHA, top-level permissions).
//! - `repo-check`: GitHub repository protections (needs `gh`).
//! - `release-dry-run`: release build and checksums.

#![allow(clippy::print_stdout)]

mod third_party;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use sha2::{Digest as _, Sha256};

#[derive(Debug, Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Generate (or check) the JSON Schemas in `schemas/`.
    Schemas {
        /// Fail if the checked-in schemas differ from the generated ones.
        #[arg(long)]
        check: bool,
    },
    /// Generate (or check) the reference docs: `docs/errors.md` from the error registry and
    /// `docs/cli.md` from both binaries' help.
    Docs {
        /// Fail if the checked-in docs differ from the generated ones.
        #[arg(long)]
        check: bool,
    },
    /// Check workspace dependency edges and forbidden APIs.
    DepsCheck,
    /// Check tracked files against the publication rules.
    PublicationCheck,
    /// Run a simulator-backed test with private output.
    SimTest {
        /// Case ID printed in the public summary (must be declared in the IDs file).
        #[arg(long)]
        case: String,
        /// File declaring the public case and check IDs (one per line, `#` comments).
        #[arg(long, default_value = "corpus/public-ids.txt")]
        ids: PathBuf,
        /// The command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Sentinel: a deliberately failing sim-test whose private text must not leak.
    Sentinel,
    /// The sentinel's child: prints private text and exits with failure (internal).
    #[command(hide = true)]
    SentinelChild,
    /// Local checks of the GitHub workflow files.
    WorkflowCheck,
    /// Check GitHub repository protections (requires the public repository).
    RepoCheck {
        /// `owner/name`.
        #[arg(long, default_value = "hexkDotCom/dviscope")]
        repo: String,
    },
    /// Release build of both binaries for one target, the web UI, and the offline bundle
    /// (binaries, UI, deployment files, docs, licenses, SHA256SUMS) with its archive and
    /// checksum, in `target/dist/`. The release workflow runs the same task.
    ReleaseDryRun {
        /// Target triple (default: the host's release target, static: musl on Linux,
        /// MSVC with a static C runtime on Windows).
        #[arg(long)]
        target: Option<String>,
        /// Do not build the web UI (the bundle then has none).
        #[arg(long)]
        skip_ui: bool,
    },
    /// The third-party licenses a release ships for a target (Rust crates linked into the
    /// binaries, npm packages of the web UI), as `THIRD_PARTY_LICENSES.md`.
    ThirdParty {
        /// Target triple.
        #[arg(long)]
        target: String,
        /// Leave out the web UI's packages.
        #[arg(long)]
        skip_ui: bool,
        /// Where to write the document.
        #[arg(long)]
        out: PathBuf,
    },
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.task {
        Task::Schemas { check } => schemas(check),
        Task::Docs { check } => docs(check),
        Task::DepsCheck => deps_check(),
        Task::PublicationCheck => publication_check(),
        Task::SimTest { case, ids, cmd } => {
            match load_ids(&ids).and_then(|ids| sim_test(&case, &ids, &cmd)) {
                Ok(true) => Ok(()),
                Ok(false) => Err(anyhow::anyhow!("case {case} failed")),
                Err(e) => Err(e),
            }
        }
        Task::Sentinel => sentinel(),
        Task::SentinelChild => {
            print!("{}", sentinel_child_output());
            eprintln!("{SENTINEL_MARKER} on stderr");
            return ExitCode::FAILURE;
        }
        Task::WorkflowCheck => workflow_check(),
        Task::RepoCheck { repo } => workflow_check().and_then(|()| repo_check(&repo)),
        Task::ReleaseDryRun { target, skip_ui } => release_dry_run(target, skip_ui),
        Task::ThirdParty {
            target,
            skip_ui,
            out,
        } => third_party::collect(&root(), &target, !skip_ui)
            .and_then(|d| std::fs::write(&out, d).map_err(Into::into)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e:#}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------------------
// schemas

fn generated_schemas() -> Result<BTreeMap<&'static str, String>> {
    use dviscope_model::wire::{checklist, evidence, hierarchy, ingest, manifest, regression};
    let mut out = BTreeMap::new();
    let mut put = |name: &'static str, schema: schemars::Schema| -> Result<()> {
        out.insert(
            name,
            format!("{}\n", serde_json::to_string_pretty(&schema)?),
        );
        Ok(())
    };
    put(
        "regression-create.json",
        schemars::schema_for!(regression::RegressionCreate),
    )?;
    put(
        "source-manifest.json",
        schemars::schema_for!(regression::SourceManifest),
    )?;
    put(
        "manifest-chunk.json",
        schemars::schema_for!(manifest::ManifestChunk),
    )?;
    put(
        "manifest-seal.json",
        schemars::schema_for!(manifest::ManifestSeal),
    )?;
    put(
        "manifest-amend.json",
        schemars::schema_for!(manifest::ManifestAmend),
    )?;
    put("slot-mark.json", schemars::schema_for!(manifest::SlotMark))?;
    put(
        "hierarchy.json",
        schemars::schema_for!(hierarchy::Hierarchy),
    )?;
    put(
        "ingest-record.json",
        schemars::schema_for!(ingest::IngestRecord),
    )?;
    put("evidence.json", schemars::schema_for!(evidence::Evidence))?;
    put(
        "checklist.json",
        schemars::schema_for!(checklist::Checklist),
    )?;
    put(
        "api-error.json",
        schemars::schema_for!(dviscope_model::errors::ApiError),
    )?;
    Ok(out)
}

fn schemas(check: bool) -> Result<()> {
    let dir = root().join("schemas");
    std::fs::create_dir_all(&dir)?;
    let mut drift = vec![];
    for (name, text) in generated_schemas()? {
        let path = dir.join(name);
        let existing = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        if existing != text {
            if check {
                drift.push(name);
            } else {
                std::fs::write(&path, text)?;
                println!("wrote schemas/{name}");
            }
        }
    }
    if !drift.is_empty() {
        bail!(
            "schemas out of date (run `cargo xtask schemas`): {}",
            drift.join(", ")
        );
    }
    if check {
        println!("schemas: up to date");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// docs

fn errors_md() -> String {
    use dviscope_model::errors::{ErrorCode, Retry};
    let mut s = String::from(
        "# Errors\n\n<!-- Generated by `cargo xtask docs` from the error registry; do not edit. -->\n\n\
         Every error answer is `{code, message, field?, committed, correlation_id}`. `retry`\n\
         says what a client does: `no` (permanent: do not resend the same request), `stop`\n\
         (a credential problem: stop sending and alert), `later` (retry with back-off,\n\
         honouring `Retry-After`). The CLI exits with the code's exit status when the error\n\
         ends a command. HTTP 0 marks a client-only code.\n\n\
         | Code | HTTP | Retry | CLI exit | What to do |\n|---|---|---|---|---|\n",
    );
    for c in ErrorCode::ALL {
        let retry = match c.retry() {
            Retry::No => "no",
            Retry::Stop => "stop",
            Retry::Later => "later",
        };
        s.push_str(&format!(
            "| `{}` | {} | {retry} | {} | {} |\n",
            c.as_str(),
            c.http_status(),
            c.cli_exit(),
            c.recovery().replace('|', "\\|")
        ));
    }
    s
}

/// The help of `bin` and of every subcommand, depth first, as Markdown.
fn help_tree(exe: &Path, name: &str, path: &mut Vec<String>, out: &mut String) -> Result<()> {
    let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
    args.push("--help");
    let o = Command::new(exe)
        .args(&args)
        .env("COLUMNS", "100")
        .output()
        .with_context(|| format!("running {}", exe.display()))?;
    if !o.status.success() {
        bail!("{name} {} --help failed", path.join(" "));
    }
    // The program name as invoked differs by platform (`.exe`): normalize it.
    let text = String::from_utf8_lossy(&o.stdout)
        .replace(&format!("{name}.exe"), name)
        .replace("\r\n", "\n");
    let title = std::iter::once(name.to_string())
        .chain(path.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    let level = "#".repeat((path.len() + 2).min(4));
    out.push_str(&format!(
        "{level} `{title}`\n\n```text\n{}\n```\n\n",
        text.trim_end()
    ));
    let mut subs = vec![];
    let mut in_commands = false;
    for line in text.lines() {
        if line.starts_with("Commands:") {
            in_commands = true;
            continue;
        }
        if in_commands {
            if !line.starts_with("  ") {
                break;
            }
            if let Some(word) = line.split_whitespace().next()
                && word != "help"
                && line.starts_with("  ")
                && !line.starts_with("   ")
            {
                subs.push(word.to_string());
            }
        }
    }
    for s in subs {
        path.push(s);
        help_tree(exe, name, path, out)?;
        path.pop();
    }
    Ok(())
}

fn cli_md() -> Result<String> {
    let st = Command::new("cargo")
        .args(["build", "-q", "-p", "dviscope-cli", "-p", "dviscope-server"])
        .current_dir(root())
        .status()?;
    if !st.success() {
        bail!("building the binaries failed");
    }
    let target_dir =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root().join("target"), PathBuf::from);
    let exe = if cfg!(windows) { ".exe" } else { "" };
    let mut out = String::from(
        "# Command reference\n\n<!-- Generated by `cargo xtask docs` from the binaries' help; do not edit. -->\n\n\
         `dviscope` runs on collector hosts and CI; `dviscope-server` runs the server and its\n\
         administration. Exit codes: [errors.md](errors.md); operations: [operate.md](operate.md).\n\n",
    );
    for name in ["dviscope", "dviscope-server"] {
        let bin = target_dir.join("debug").join(format!("{name}{exe}"));
        help_tree(&bin, name, &mut vec![], &mut out)?;
    }
    Ok(format!("{}\n", out.trim_end()))
}

fn docs(check: bool) -> Result<()> {
    let generated = [("errors.md", errors_md()), ("cli.md", cli_md()?)];
    let mut drift = vec![];
    for (name, text) in generated {
        let path = root().join("docs").join(name);
        let existing = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        if existing != text {
            if check {
                drift.push(name);
            } else {
                std::fs::write(&path, text)?;
                println!("wrote docs/{name}");
            }
        }
    }
    if !drift.is_empty() {
        bail!(
            "docs out of date (run `cargo xtask docs`): {}",
            drift.join(", ")
        );
    }
    if check {
        println!("docs: up to date");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// deps-check

/// Allowed normal (non-dev) workspace edges.
const ALLOWED: &[(&str, &[&str])] = &[
    ("dvi-simlog", &[]),
    ("dviscope-model", &[]),
    ("dviscope-core", &["dviscope-model", "dvi-simlog"]),
    ("dviscope-server", &["dviscope-core", "dviscope-model"]),
    ("dviscope-cli", &["dviscope-core", "dviscope-model"]),
    ("xtask", &["dviscope-model"]),
];

/// Allowed dev-only edges (end-to-end tests).
const ALLOWED_DEV: &[(&str, &[&str])] = &[("dviscope-cli", &["dviscope-server"])];

/// Crates that must stay pure (no file system, network, environment, clock, randomness).
/// Clippy's `disallowed-methods`/`disallowed-types` in each pure crate's `clippy.toml` is the
/// primary check; this scan is a second line that also catches grouped imports.
const PURE: &[&str] = &["dvi-simlog", "dviscope-model", "dviscope-core"];

/// Forbidden path segments in pure crates' non-test code.
const FORBIDDEN_IN_PURE: &[&str] = &[
    "std::fs",
    "std::env",
    "std::net",
    "std::process",
    "SystemTime::now",
    "Instant::now",
    "OffsetDateTime::now",
    "Ulid::new",
    "rand::",
    "tokio::",
    "std::io::stdin",
    "io::stdin",
    "use std as",
    "extern crate std as",
    "use ::std as",
    "self as",
];

/// External (non-workspace) dependencies each pure crate may use.
const PURE_EXTERNAL: &[(&str, &[&str])] = &[
    ("dvi-simlog", &["regex"]),
    (
        "dviscope-model",
        &[
            "serde",
            "serde_json",
            "schemars",
            "sha2",
            "hex",
            "thiserror",
            "ulid",
            "time",
        ],
    ),
    (
        "dviscope-core",
        &[
            "serde",
            "serde_json",
            "thiserror",
            "regex",
            "regex-syntax",
            "regex-automata",
            "serde-saphyr",
        ],
    ),
];

/// Removes `#[cfg(test)] mod name { ... }` blocks (brace-matched), keeping everything else.
fn strip_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(pos) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + "#[cfg(test)]".len()..];
        let trimmed = after.trim_start();
        if let (true, Some(open)) = (trimmed.starts_with("mod "), trimmed.find('{')) {
            {
                let mut depth = 0usize;
                let mut end = None;
                for (i, c) in trimmed[open..].char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(open + i + 1);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(end) = end {
                    rest = &trimmed[end..];
                    continue;
                }
            }
        }
        // Not a test module (e.g. a cfg(test) item): keep scanning after the attribute.
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Violations of the purity rule in one source text.
fn purity_violations(src: &str) -> Vec<String> {
    let code = strip_test_modules(src);
    let mut found = vec![];
    for pat in FORBIDDEN_IN_PURE {
        if code.contains(pat) {
            found.push((*pat).to_string());
        }
    }
    // Grouped imports: `use std::{fs, env}` / `use std::{io, net::TcpStream}`.
    for group in code.match_indices("std::{").map(|(i, _)| &code[i..]) {
        let inner = group.split('}').next().unwrap_or("");
        for item in ["fs", "env", "net", "process"] {
            if inner
                .split([',', '{', ' ', '\n', ':'])
                .any(|t| t.trim() == item)
            {
                found.push(format!("std::{{{item}}}"));
            }
        }
    }
    found
}

fn deps_check() -> Result<()> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root())
        .output()
        .context("running cargo metadata")?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let workspace: Vec<String> = meta["packages"]
        .as_array()
        .map(|p| {
            p.iter()
                .filter_map(|x| x["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let mut errors = vec![];
    for pkg in meta["packages"].as_array().into_iter().flatten() {
        let name = pkg["name"].as_str().unwrap_or_default();
        let Some(allowed) = ALLOWED.iter().find(|(n, _)| *n == name).map(|(_, a)| *a) else {
            errors.push(format!("{name}: not listed in xtask ALLOWED"));
            continue;
        };
        let allowed_dev = ALLOWED_DEV
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(&[][..], |(_, a)| *a);
        let pure_external = PURE_EXTERNAL
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, a)| *a);
        for dep in pkg["dependencies"].as_array().into_iter().flatten() {
            let dep_name = dep["name"].as_str().unwrap_or_default();
            if !workspace.iter().any(|w| w == dep_name) {
                let is_dev = dep["kind"].as_str() == Some("dev");
                if let (Some(allowed_ext), false) = (pure_external, is_dev)
                    && !allowed_ext.contains(&dep_name)
                {
                    errors.push(format!("pure crate {name} may not depend on {dep_name}"));
                }
                continue;
            }
            let is_dev = dep["kind"].as_str() == Some("dev");
            let ok = allowed.contains(&dep_name) || (is_dev && allowed_dev.contains(&dep_name));
            if !ok {
                errors.push(format!(
                    "{name} may not depend on {dep_name}{}",
                    if is_dev { " (dev)" } else { "" }
                ));
            }
        }
    }
    for krate in PURE {
        let src = root().join("crates").join(krate).join("src");
        for file in walk(&src)? {
            let text = std::fs::read_to_string(&file)?;
            for v in purity_violations(&text) {
                errors.push(format!("{}: pure crate uses {v}", file.display()));
            }
        }
        if !root()
            .join("crates")
            .join(krate)
            .join("clippy.toml")
            .exists()
        {
            errors.push(format!(
                "{krate}: missing clippy.toml with disallowed methods"
            ));
        }
    }
    if errors.is_empty() {
        println!("deps-check: ok");
        Ok(())
    } else {
        bail!("{}", errors.join("\n"))
    }
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = vec![];
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            out.extend(walk(&path)?);
        } else {
            out.push(path);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// publication-check

/// Signatures of commercial simulator output and private material that must never be
/// committed. Built from parts so this file does not itself contain them (no file is
/// exempt from the check).
fn banned() -> Vec<(String, &'static str)> {
    let j = |parts: &[&str]| parts.concat();
    vec![
        (j(&["Chronologic", " VCS ", "simulator"]), "VCS log banner"),
        (
            j(&["V C S   S i m u l", " a t i o n   R e p o r t"]),
            "VCS log trailer",
        ),
        (
            j(&["Contains Synopsys ", "proprietary information"]),
            "Synopsys banner",
        ),
        (j(&["Questa ", "Sim-64"]), "Questa banner"),
        (j(&["Unpublished work. ", "Copyright"]), "vendor banner"),
        (
            j(&["This material contains ", "trade secrets"]),
            "vendor banner",
        ),
        (j(&["-----BEGIN ", "PRIVATE KEY-----"]), "private key"),
        (j(&["-----BEGIN EC ", "PRIVATE KEY-----"]), "private key"),
        (j(&["-----BEGIN RSA ", "PRIVATE KEY-----"]), "private key"),
    ]
}

/// File types never committed.
const NEVER_COMMITTED: &[&str] = &[
    ".log", ".vcd", ".fst", ".wlf", ".key", ".pem", ".vpd", ".fsdb", ".shm",
];

fn token_like(text: &str) -> bool {
    let prefix = ["dvis", "_"].concat();
    text.match_indices(&prefix).any(|(i, _)| {
        text[i + prefix.len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .count()
            >= 43
    })
}

fn publication_violations(rel: &str, bytes: &[u8]) -> Vec<String> {
    let mut errors = vec![];
    let lower = rel.to_ascii_lowercase();
    if NEVER_COMMITTED.iter().any(|ext| lower.ends_with(ext)) {
        errors.push(format!("{rel}: file type never committed"));
    }
    let text = String::from_utf8_lossy(bytes);
    for (pat, what) in banned() {
        if text.contains(&pat) {
            errors.push(format!("{rel}: {what}"));
        }
    }
    if token_like(&text) {
        errors.push(format!("{rel}: possible DVIScope token"));
    }
    errors
}

/// The native path for a name as git printed it (raw bytes on Unix; UTF-8 elsewhere).
fn native_path(raw: &[u8]) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(raw).ok().map(PathBuf::from)
    }
}

/// Scans the content staged in the index (what the next commit contains), independently of
/// the working tree.
fn index_violations() -> Result<Vec<String>> {
    let out = Command::new("git")
        .args(["ls-files", "-s", "-z"])
        .current_dir(root())
        .output()
        .context("git ls-files -s")?;
    if !out.status.success() {
        bail!("git ls-files -s failed");
    }
    let mut entries = vec![];
    for rec in out.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        // "<mode> <sha> <stage>\t<path>"
        let tab = rec
            .iter()
            .position(|b| *b == b'\t')
            .context("unexpected ls-files output")?;
        let meta = String::from_utf8_lossy(&rec[..tab]).to_string();
        let path = String::from_utf8_lossy(&rec[tab + 1..]).to_string();
        let sha = meta
            .split_whitespace()
            .nth(1)
            .context("unexpected ls-files output")?
            .to_string();
        entries.push((sha, path));
    }
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(root())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("git cat-file --batch")?;
    let mut stdin = child.stdin.take().context("cat-file stdin")?;
    let list: String = entries.iter().map(|(sha, _)| format!("{sha}\n")).collect();
    let writer = std::thread::spawn(move || std::io::Write::write_all(&mut stdin, list.as_bytes()));
    let output = child.wait_with_output().context("git cat-file --batch")?;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("cat-file writer panicked"))??;
    let mut errors = vec![];
    let mut buf = output.stdout.as_slice();
    for (_, path) in &entries {
        let nl = buf
            .iter()
            .position(|b| *b == b'\n')
            .context("truncated cat-file output")?;
        let header = String::from_utf8_lossy(&buf[..nl]).to_string();
        let size: usize = header
            .split_whitespace()
            .nth(2)
            .and_then(|n| n.parse().ok())
            .context("bad cat-file header")?;
        let body = buf
            .get(nl + 1..nl + 1 + size)
            .context("truncated cat-file body")?;
        errors.extend(publication_violations(&format!("{path} (staged)"), body));
        buf = buf.get(nl + 1 + size + 1..).unwrap_or(&[]);
    }
    Ok(errors)
}

fn publication_check() -> Result<()> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root())
        .output()
        .context("git ls-files")?;
    if !out.status.success() {
        bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Staged content is what the next commit contains: scan it first, then the working tree.
    let mut errors = index_violations()?;
    let mut files = 0usize;
    for raw in out.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let rel = String::from_utf8_lossy(raw).to_string();
        let path = match native_path(raw) {
            Some(p) => root().join(p),
            None => {
                errors.push(format!("{rel}: file name is not valid UTF-8 (rename it)"));
                continue;
            }
        };
        match std::fs::read(&path) {
            Ok(bytes) => errors.extend(publication_violations(&rel, &bytes)),
            // Absent from the working tree: its staged content was scanned above.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("{rel}: unreadable ({e})")),
        }
        files += 1;
    }
    if files == 0 {
        bail!("publication-check found no tracked files (is this a git checkout?)");
    }
    if errors.is_empty() {
        println!("publication-check: ok ({files} files, staged and working tree)");
        Ok(())
    } else {
        bail!("publication rules violated:\n{}", errors.join("\n"))
    }
}

// ---------------------------------------------------------------------------------------
// sim-test

/// A unique private directory for raw output (0700 on Unix; under the per-user temp
/// directory on Windows), always outside the repository.
fn private_dir() -> Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir =
        std::env::temp_dir().join(format!("dviscope-sim-test-{}-{nanos}", std::process::id()));
    if dir.starts_with(root()) {
        bail!("the temporary directory is inside the repository; set TMPDIR/TEMP elsewhere");
    }
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Allowed values of the `state` field.
const STATES: &[&str] = &[
    "pass",
    "fail",
    "error",
    "timeout",
    "killed",
    "blocked",
    "complete",
    "incomplete",
    "missing",
    "met",
    "not_met",
    "unassessable",
    "not_applicable",
    "passed",
    "failed",
    "running",
];

/// Loads declared public IDs (one per line; blank lines and `#` comments ignored).
fn load_ids(path: &Path) -> Result<Vec<String>> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root().join(path)
    };
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// A structural line: `DVISCOPE-STRUCT: {json object}` with typed fields only:
/// `case`/`check`/`id` IDs declared in the public IDs file, `state` from a fixed list, `ok`
/// boolean, `count` non-negative integer, `expected`/`actual` integers or booleans.
/// Anything else is rejected. Returns the sanitized form.
fn structural(line: &str, ids: &[String]) -> Option<String> {
    let rest = line.strip_prefix("DVISCOPE-STRUCT:")?.trim();
    let v: serde_json::Value = serde_json::from_str(rest).ok()?;
    let obj = v.as_object()?;
    if obj.is_empty() || obj.len() > 8 {
        return None;
    }
    for (k, v) in obj {
        let ok = match k.as_str() {
            "case" | "check" | "id" => v.as_str().is_some_and(|s| ids.iter().any(|d| d == s)),
            "state" => v.as_str().is_some_and(|s| STATES.contains(&s)),
            "ok" => v.is_boolean(),
            "count" => v.is_u64(),
            "expected" | "actual" => v.is_u64() || v.is_i64() || v.is_boolean(),
            _ => false,
        };
        if !ok {
            return None;
        }
    }
    serde_json::to_string(obj).ok()
}

/// Runs `cmd` with stdout/stderr captured to a private file outside the repository and
/// prints only the (declared) case ID, the result and validated structural lines. Writes
/// nothing else. Returns whether it passed.
fn sim_test(case: &str, ids: &[String], cmd: &[String]) -> Result<bool> {
    if !ids.iter().any(|d| d == case) {
        bail!("the case ID is not declared in the public IDs file");
    }
    let (prog, args) = cmd.split_first().context("empty command")?;
    let out = Command::new(prog)
        .args(args)
        .output()
        .with_context(|| format!("running {prog}"))?;
    let dir = private_dir()?;
    let private = dir.join("output.txt");
    let mut raw = out.stdout.clone();
    raw.extend_from_slice(&out.stderr);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    std::io::Write::write_all(&mut opts.open(&private)?, &raw)?;
    let ok = out.status.success();
    println!("case {case}: {}", if ok { "passed" } else { "FAILED" });
    let mut rejected = 0usize;
    for line in String::from_utf8_lossy(&raw).lines() {
        if line.starts_with("DVISCOPE-STRUCT:") {
            match structural(line, ids) {
                Some(s) => println!("  {s}"),
                None => rejected += 1,
            }
        }
    }
    if rejected > 0 {
        println!("  {rejected} structural line(s) rejected (not structural)");
    }
    if !ok {
        println!("  raw output kept privately in {}", private.display());
    }
    Ok(ok)
}

const SENTINEL_MARKER: &str = "SENTINEL-PRIVATE-TEXT-7f3a";
const SENTINEL_MARKER_LOWER: &str = "sentinel-private-text-7f3a";

/// A token-shaped private string (never a real token).
fn sentinel_token() -> String {
    format!("{}{}", ["dvis", "_"].concat(), "q".repeat(43))
}

/// What the sentinel's child prints on stdout: private text plainly, after the structural
/// prefix, inside structural-looking objects (unknown key, string `actual`, undeclared
/// lowercase ID, token-shaped ID, unknown state), and one valid structural line.
fn sentinel_child_output() -> String {
    format!(
        "{m}\nDVISCOPE-STRUCT: {m}\nDVISCOPE-STRUCT: {{\"check\":\"x\",\"detail\":\"{m} text\"}}\n\
         DVISCOPE-STRUCT: {{\"check\":\"x\",\"actual\":\"{m}\"}}\n\
         DVISCOPE-STRUCT: {{\"check\":\"{m}\"}}\n\
         DVISCOPE-STRUCT: {{\"check\":\"{l}\"}}\n\
         DVISCOPE-STRUCT: {{\"id\":\"{t}\"}}\n\
         DVISCOPE-STRUCT: {{\"state\":\"{m}\"}}\n\
         DVISCOPE-STRUCT: {{\"check\":\"sentinel\",\"ok\":false}}\n",
        m = SENTINEL_MARKER,
        l = SENTINEL_MARKER_LOWER,
        t = sentinel_token()
    )
}

fn git_status() -> Result<Vec<u8>> {
    let out = Command::new("git")
        .args(["status", "--porcelain", "-z", "--ignored"])
        .current_dir(root())
        .output()?;
    if !out.status.success() {
        bail!("git status failed");
    }
    Ok(out.stdout)
}

/// The sentinel: runs `sim-test` around a child (this binary's hidden `sentinel-child`) that
/// prints private text on stdout and stderr and fails. `sim-test` must exit non-zero, print
/// none of the private text (only the valid structural line), refuse undeclared case IDs,
/// and leave the repository untouched (no report artifacts inside it).
fn sentinel() -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe_s = exe.to_string_lossy().to_string();
    let ids_dir = private_dir()?;
    let ids_file = ids_dir.join("ids.txt");
    std::fs::write(&ids_file, "sentinel\nx\n")?;
    let before = git_status()?;
    let out = Command::new(&exe)
        .args(["sim-test", "--case", "sentinel", "--ids"])
        .arg(&ids_file)
        .args(["--", &exe_s, "sentinel-child"])
        .output()
        .context("running sim-test")?;
    let undeclared = Command::new(&exe)
        .args(["sim-test", "--case", SENTINEL_MARKER_LOWER, "--ids"])
        .arg(&ids_file)
        .args(["--", &exe_s, "sentinel-child"])
        .output()
        .context("running sim-test")?;
    if git_status()? != before {
        bail!("sentinel: sim-test changed the repository (reports must stay outside it)");
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let undeclared_text = format!(
        "{}{}",
        String::from_utf8_lossy(&undeclared.stdout),
        String::from_utf8_lossy(&undeclared.stderr)
    );
    if out.status.success() {
        bail!("sentinel: sim-test exited successfully for a failing command");
    }
    if undeclared.status.success() || undeclared_text.contains(SENTINEL_MARKER_LOWER) {
        bail!("sentinel: an undeclared case ID was accepted or echoed");
    }
    for leak in [SENTINEL_MARKER, SENTINEL_MARKER_LOWER, &sentinel_token()] {
        if text.contains(leak) {
            bail!("sentinel leaked: sim-test printed private output");
        }
    }
    if !text.contains("case sentinel: FAILED") || !text.contains("\"check\":\"sentinel\"") {
        bail!("sentinel did not report the failure and the valid structural line: {text}");
    }
    let _ = std::fs::remove_dir_all(&ids_dir);
    println!("sentinel: ok (failure propagated, private text not printed, repository untouched)");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// workflow-check and repo-check

/// Collects every `uses` string value anywhere in a workflow document.
fn collect_uses(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                if let ("uses", Some(s)) = (k.as_str(), val.as_str()) {
                    out.push(s.to_string());
                }
                collect_uses(val, out);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|i| collect_uses(i, out)),
        _ => {}
    }
}

/// The trigger names of a workflow's `on` (a string, a list or a map).
fn triggers(doc: &serde_json::Value) -> Vec<String> {
    match &doc["on"] {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        serde_json::Value::Object(m) => m.keys().cloned().collect(),
        _ => vec![],
    }
}

fn workflow_violations(name: &str, text: &str) -> Vec<String> {
    let doc: serde_json::Value = match serde_saphyr::from_str(text) {
        Ok(d) => d,
        Err(e) => return vec![format!("{name}: not valid YAML: {e}")],
    };
    let mut errors = vec![];
    if triggers(&doc)
        .iter()
        .any(|t| t == "pull_request_target" || t == "workflow_run")
    {
        errors.push(format!(
            "{name}: uses a privileged trigger (pull_request_target or workflow_run)"
        ));
    }
    if doc.get("permissions").is_none() {
        errors.push(format!("{name}: no top-level permissions block"));
    }
    let mut uses = vec![];
    collect_uses(&doc, &mut uses);
    for spec in uses {
        if spec.starts_with("./") {
            continue;
        }
        let pinned = spec
            .split_once('@')
            .is_some_and(|(_, v)| v.len() == 40 && v.bytes().all(|b| b.is_ascii_hexdigit()));
        if !pinned {
            errors.push(format!(
                "{name}: action or reusable workflow not pinned by commit SHA: {spec}"
            ));
        }
    }
    errors
}

/// Paths that CODEOWNERS must cover.
const OWNED_PATHS: &[&str] = &["/.github/", "/deploy/", "/xtask/"];

fn codeowners_violations(text: &str) -> Vec<String> {
    let rules: Vec<(&str, usize)> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let pattern = parts.next()?;
            Some((pattern, parts.count()))
        })
        .collect();
    // GitHub applies the last matching rule, and an ownerless rule removes ownership.
    // Rejecting every ownerless rule guarantees that whichever rule matches a protected path
    // has an owner.
    let mut errors: Vec<String> = rules
        .iter()
        .filter(|(_, owners)| *owners == 0)
        .map(|(pat, _)| format!("CODEOWNERS: rule {pat} has no owner"))
        .collect();
    errors.extend(
        OWNED_PATHS
            .iter()
            .filter(|p| !rules.iter().any(|(pat, owners)| pat == *p && *owners > 0))
            .map(|p| format!("CODEOWNERS: no owner for {p}")),
    );
    errors
}

fn workflow_check() -> Result<()> {
    let mut errors = vec![];
    for file in walk(&root().join(".github").join("workflows"))? {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        errors.extend(workflow_violations(&name, &std::fs::read_to_string(&file)?));
    }
    match std::fs::read_to_string(root().join(".github").join("CODEOWNERS")) {
        Ok(text) => errors.extend(codeowners_violations(&text)),
        Err(e) => errors.push(format!("CODEOWNERS: {e}")),
    }
    if errors.is_empty() {
        println!("workflow-check: ok");
        Ok(())
    } else {
        bail!("{}", errors.join("\n"))
    }
}

fn gh_json(path: &str) -> Result<serde_json::Value> {
    let out = Command::new("gh")
        .args(["api", path])
        .output()
        .context("running gh (is it installed and logged in?)")?;
    if !out.status.success() {
        bail!(
            "gh api {path}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// Status checks that must be required on `main` (job names of ci.yml).
const REQUIRED_CHECKS: &[&str] = &[
    "checks (ubuntu-24.04)",
    "checks (windows-2025)",
    "supply-chain",
];

fn repo_check(repo: &str) -> Result<()> {
    let mut errors = vec![];
    let r = gh_json(&format!("repos/{repo}"))?;
    if r["security_and_analysis"]["secret_scanning"]["status"] != "enabled" {
        errors.push("secret scanning is not enabled".to_string());
    }
    if r["security_and_analysis"]["secret_scanning_push_protection"]["status"] != "enabled" {
        errors.push("push protection is not enabled".to_string());
    }
    match gh_json(&format!("repos/{repo}/branches/main/protection")) {
        Ok(p) => {
            let contexts: Vec<String> = p["required_status_checks"]["checks"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|c| c["context"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            for need in REQUIRED_CHECKS {
                if !contexts.iter().any(|c| c == need) {
                    errors.push(format!("main: required status check missing: {need}"));
                }
            }
            if p["enforce_admins"]["enabled"] != true {
                errors.push("main: protection not enforced for administrators".to_string());
            }
            if p["allow_force_pushes"]["enabled"] == true {
                errors.push("main: force pushes allowed".to_string());
            }
            if p["allow_deletions"]["enabled"] == true {
                errors.push("main: deletions allowed".to_string());
            }
            let bypass = &p["required_pull_request_reviews"]["bypass_pull_request_allowances"];
            for kind in ["users", "teams", "apps"] {
                if bypass[kind].as_array().is_some_and(|a| !a.is_empty()) {
                    errors.push(format!(
                        "main: pull-request requirement can be bypassed by {kind}"
                    ));
                }
            }
            if p["required_pull_request_reviews"].is_null() {
                errors.push("main: pull requests not required".to_string());
            } else if p["required_pull_request_reviews"]["require_code_owner_reviews"] != true {
                // Sole-maintainer phase: approvals may be 0, but code-owner review must be on
                // so it takes effect as soon as a second maintainer exists.
                errors.push("main: code-owner reviews not required".to_string());
            }
        }
        Err(e) => errors.push(format!("main is not protected: {e}")),
    }
    let perms = gh_json(&format!("repos/{repo}/actions/permissions/workflow"))?;
    if perms["default_workflow_permissions"] != "read" {
        errors.push("default GITHUB_TOKEN permissions are not read-only".to_string());
    }
    if gh_json(&format!("repos/{repo}/private-vulnerability-reporting"))?["enabled"] != true {
        errors.push("private vulnerability reporting is disabled".to_string());
    }
    if gh_json(&format!("repos/{repo}/codeowners/errors"))?["errors"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        errors.push("CODEOWNERS has errors (unknown owners?)".to_string());
    }
    if errors.is_empty() {
        println!("repo-check: ok");
        Ok(())
    } else {
        bail!("{}", errors.join("\n"))
    }
}

// ---------------------------------------------------------------------------------------
// release-dry-run

/// The files of the offline bundle besides the binaries and the UI: (source, bundle path).
const BUNDLE_FILES: &[(&str, &str)] = &[
    ("README.md", "README.md"),
    ("LICENSE", "LICENSE"),
    ("NOTICE", "NOTICE"),
    ("CHANGELOG.md", "CHANGELOG.md"),
    ("SECURITY.md", "SECURITY.md"),
    ("deploy/compose.yaml", "deploy/compose.yaml"),
    // The bundle builds its images from its own binaries and UI.
    ("deploy/Dockerfile.bundle", "deploy/Dockerfile"),
    ("deploy/server.toml", "deploy/server.toml"),
    ("deploy/provision-tls.sh", "deploy/provision-tls.sh"),
    ("deploy/provision-db.sh", "deploy/provision-db.sh"),
];

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let (src, dst) = (e.path(), to.join(e.file_name()));
        if e.file_type()?.is_dir() {
            copy_tree(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst).with_context(|| format!("copying {}", src.display()))?;
        }
    }
    Ok(())
}

/// The commit time of `HEAD` (`SOURCE_DATE_EPOCH` when set): every archive entry carries
/// it, so the same commit gives the same archive.
fn source_epoch() -> u64 {
    if let Some(v) = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return v;
    }
    Command::new("git")
        .args(["log", "-1", "--format=%ct"])
        .current_dir(root())
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

/// A gzip-compressed tar of `dir` under the top-level name `top`, byte-for-byte
/// reproducible: entries sorted, every time `mtime`, owner 0:0 without names, modes 0755
/// (`bin/`, `*.sh`) or 0644, and a gzip header without name or time.
fn reproducible_tar_gz(dir: &Path, top: &str, mtime: u64) -> Result<Vec<u8>> {
    let gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::best());
    let mut t = tar::Builder::new(gz);
    t.mode(tar::HeaderMode::Deterministic);
    for rel in files_under(dir)? {
        let bytes = std::fs::read(dir.join(&rel))?;
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        // Executables: the binaries and the deploy scripts.
        let exec = rel.starts_with("bin/") || rel.ends_with(".sh");
        h.set_mode(if exec { 0o755 } else { 0o644 });
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(mtime);
        h.set_entry_type(tar::EntryType::Regular);
        t.append_data(&mut h, format!("{top}/{rel}"), &bytes[..])?;
    }
    Ok(t.into_inner()?.finish()?)
}

/// Every file under `dir`, relative, with `/` separators, sorted.
fn files_under(dir: &Path) -> Result<Vec<String>> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d)? {
            let p = e?.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir)?.to_string_lossy().replace('\\', "/");
                out.push(rel);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn sha256_file(p: &Path) -> Result<String> {
    let bytes = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn run_in(dir: &Path, program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<()> {
    let mut c = Command::new(program);
    c.args(args).current_dir(dir);
    for (k, v) in env {
        c.env(k, v);
    }
    let st = c.status().with_context(|| format!("running {program}"))?;
    if !st.success() {
        bail!("{program} {} failed", args.join(" "));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // one release recipe, in order
fn release_dry_run(target: Option<String>, skip_ui: bool) -> Result<()> {
    let target = target.unwrap_or_else(|| {
        if cfg!(windows) {
            "x86_64-pc-windows-msvc".into()
        } else {
            "x86_64-unknown-linux-musl".into()
        }
    });
    let windows = target.contains("windows");
    let exe = if windows { ".exe" } else { "" };
    let version = env!("CARGO_PKG_VERSION");
    // Static binaries: musl on Linux, the static C runtime on Windows.
    let rustflags = if windows {
        "-C target-feature=+crt-static"
    } else {
        ""
    };
    run_in(
        &root(),
        "cargo",
        &[
            "build",
            "--release",
            "--locked",
            "--target",
            &target,
            "-p",
            "dviscope-cli",
            "-p",
            "dviscope-server",
        ],
        &[("RUSTFLAGS", rustflags)],
    )?;

    let name = format!("dviscope-{version}-{target}");
    // Cargo's target directory (it may be moved by CARGO_TARGET_DIR).
    let target_dir =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root().join("target"), PathBuf::from);
    let dist = target_dir.join("dist");
    let bundle = dist.join(&name);
    if bundle.exists() {
        std::fs::remove_dir_all(&bundle)?;
    }
    std::fs::create_dir_all(bundle.join("bin"))?;
    for bin in ["dviscope", "dviscope-server"] {
        let from = target_dir
            .join(&target)
            .join("release")
            .join(format!("{bin}{exe}"));
        std::fs::copy(&from, bundle.join("bin").join(format!("{bin}{exe}")))
            .with_context(|| format!("copying {}", from.display()))?;
    }
    if !skip_ui {
        let web = root().join("web");
        let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
        run_in(&web, npm, &["ci", "--no-audit", "--no-fund"], &[])?;
        run_in(&web, npm, &["run", "build"], &[])?;
        copy_tree(&web.join("dist"), &bundle.join("ui"))?;
    }
    for (from, to) in BUNDLE_FILES {
        let dst = bundle.join(to);
        if let Some(p) = dst.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::copy(root().join(from), &dst).with_context(|| format!("copying {from}"))?;
    }
    copy_tree(&root().join("docs"), &bundle.join("docs"))?;
    // Every shipped dependency's license and notices.
    std::fs::write(
        bundle.join("THIRD_PARTY_LICENSES.md"),
        third_party::collect(&root(), &target, !skip_ui)?,
    )?;
    let notices = bundle.join(third_party::RUST_LIBRARY_NOTICES);
    if let Some(dir) = notices.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::copy(third_party::rust_library_notices(&root())?, &notices)?;
    // The wire contracts the docs and examples refer to.
    copy_tree(&root().join("schemas"), &bundle.join("schemas"))?;

    // The bundle's own checksums, then its archive and the archive's checksum.
    let mut sums = vec![];
    for rel in files_under(&bundle)? {
        sums.push(format!("{}  {rel}", sha256_file(&bundle.join(&rel))?));
    }
    std::fs::write(bundle.join("SHA256SUMS"), format!("{}\n", sums.join("\n")))?;
    let archive = format!("{name}.tar.gz");
    let _ = std::fs::remove_file(dist.join(&archive));
    std::fs::write(
        dist.join(&archive),
        reproducible_tar_gz(&bundle, &name, source_epoch())?,
    )?;
    let line = format!("{}  {archive}", sha256_file(&dist.join(&archive))?);
    std::fs::write(dist.join(format!("{archive}.sha256")), format!("{line}\n"))?;

    // Smoke: the bundled binaries start and name this version.
    for bin in ["dviscope", "dviscope-server"] {
        let out = Command::new(bundle.join("bin").join(format!("{bin}{exe}")))
            .arg("--version")
            .output()
            .with_context(|| format!("running the bundled {bin}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() || !text.contains(version) {
            bail!("the bundled {bin} does not report version {version}: {text}");
        }
    }
    println!("release-dry-run: {}", bundle.display());
    println!("{line}");
    println!(
        "{} files; UI {}",
        sums.len(),
        if skip_ui { "skipped" } else { "included" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same files give the same archive, whatever their times or the order the file
    /// system lists them in.
    #[test]
    fn archives_are_reproducible() {
        let base = std::env::temp_dir().join(format!("dviscope-tar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let make = |name: &str, order: &[&str]| {
            let d = base.join(name);
            std::fs::create_dir_all(d.join("bin")).ok();
            for f in order {
                std::fs::write(d.join(f), f.as_bytes()).ok();
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            d
        };
        let a = make("a", &["bin/x", "README.md", "docs.md", "bin/p.sh"]);
        let b = make("b", &["bin/p.sh", "docs.md", "README.md", "bin/x"]);
        let ta = reproducible_tar_gz(&a, "top", 1_700_000_000).unwrap_or_default();
        let tb = reproducible_tar_gz(&b, "top", 1_700_000_000).unwrap_or_default();
        assert!(!ta.is_empty());
        assert_eq!(ta, tb);
        // Contents and modes as stated.
        let mut entries = vec![];
        let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(&ta[..]));
        for e in ar.entries().into_iter().flatten().flatten() {
            let h = e.header();
            entries.push((
                e.path()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                h.mode().unwrap_or(0),
                h.mtime().unwrap_or(0),
                h.uid().unwrap_or(1),
            ));
        }
        assert_eq!(
            entries,
            [
                ("top/README.md".to_string(), 0o644, 1_700_000_000, 0),
                ("top/bin/p.sh".to_string(), 0o755, 1_700_000_000, 0),
                ("top/bin/x".to_string(), 0o755, 1_700_000_000, 0),
                ("top/docs.md".to_string(), 0o644, 1_700_000_000, 0),
            ]
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The deploy scripts are executable in the repository, and one PostgreSQL image is
    /// named everywhere (compose, both Dockerfiles, the offline install recipe).
    #[test]
    fn deploy_scripts_and_images_are_consistent() {
        let out = Command::new("git")
            .args(["ls-files", "-s", "deploy"])
            .current_dir(root())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let scripts: Vec<&str> = out.lines().filter(|l| l.ends_with(".sh")).collect();
        assert!(scripts.len() >= 2, "{out}");
        for l in scripts {
            assert!(l.starts_with("100755"), "not executable: {l}");
        }
        let mut refs = std::collections::BTreeSet::new();
        for f in [
            "deploy/compose.yaml",
            "deploy/Dockerfile",
            "deploy/Dockerfile.bundle",
            "docs/install.md",
        ] {
            let text = std::fs::read_to_string(root().join(f)).unwrap_or_default();
            for (i, _) in text.match_indices("postgres:1") {
                let r: String = text[i..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '-'))
                    .collect();
                refs.insert(r);
            }
        }
        assert_eq!(refs.len(), 1, "one PostgreSQL image reference: {refs:?}");
    }

    /// Everything a deploy script provisions (`$here/<dir>`: secrets, keys, backups) is
    /// excluded from every image build context.
    #[test]
    fn provisioned_paths_never_enter_a_build_context() {
        let ignore = std::fs::read_to_string(root().join(".dockerignore")).unwrap_or_default();
        let ignored: Vec<&str> = ignore.lines().map(str::trim).collect();
        let mut seen = 0;
        for e in std::fs::read_dir(root().join("deploy"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(".sh") {
                continue;
            }
            let text = std::fs::read_to_string(e.path()).unwrap_or_default();
            for (i, _) in text.match_indices("$here/") {
                let dir: String = text[i + 6..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .collect();
                if dir.is_empty() || dir.starts_with('.') {
                    continue;
                }
                seen += 1;
                let path = format!("deploy/{dir}");
                assert!(
                    ignored.contains(&path.as_str()),
                    "{path} is not in .dockerignore"
                );
            }
        }
        assert!(seen >= 3, "the scan found the provisioned directories");
    }

    #[test]
    fn purity_scan_catches_bypasses() {
        assert!(!purity_violations("use std::{fs, io};").is_empty());
        assert!(!purity_violations("use std::{\n    io,\n    env,\n};").is_empty());
        // Production code after a test module is still scanned.
        let src = "#[cfg(test)]\nmod tests { fn t() { let _ = 1; } }\nfn prod() { std::fs::read(\"x\"); }";
        assert!(!purity_violations(src).is_empty());
        // Inside a test module it is allowed.
        let ok = "fn prod() {}\n#[cfg(test)]\nmod tests { fn t() { std::env::var(\"X\"); } }";
        assert!(purity_violations(ok).is_empty());
        assert!(
            !purity_violations("use std as platform;\nfn f() { platform::env::var_os(\"X\"); }")
                .is_empty()
        );
        assert!(!purity_violations("fn f() { let _ = std::io::stdin(); }").is_empty());
        assert!(
            !purity_violations(
                "use std::{self as platform};\nfn f() { platform::env::vars_os(); }"
            )
            .is_empty()
        );
    }

    #[test]
    fn workflow_rules_yaml() {
        let quoted = "on: \"pull_request_target\"\npermissions: {}\n";
        assert!(!workflow_violations("w", quoted).is_empty());
        let list = "on: [push, pull_request_target]\npermissions: {}\n";
        assert!(!workflow_violations("w", list).is_empty());
        let flow = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - {uses: actions/checkout@v4}\n";
        assert!(!workflow_violations("w", flow).is_empty());
        let reusable = "on: push\npermissions: {}\njobs:\n  a:\n    uses: org/repo/.github/workflows/x.yml@main\n";
        assert!(!workflow_violations("w", reusable).is_empty());
    }

    #[test]
    fn codeowners_coverage() {
        assert!(codeowners_violations("/.github/ @o\n/deploy/ @o\n/xtask/ @o\n").is_empty());
        assert!(!codeowners_violations("/.github/ @o\n/deploy/\n").is_empty());
        let override_rule = "/.github/ @o\n/deploy/ @o\n/xtask/ @o\n/.github/workflows/\n";
        assert!(!codeowners_violations(override_rule).is_empty());
    }

    #[test]
    fn workflow_rules() {
        let pinned = "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n";
        assert!(workflow_violations("w", pinned).is_empty());
        let comment_only = "# never use pull_request_target here\npermissions: {}\n";
        assert!(workflow_violations("w", comment_only).is_empty());
        let trigger = "on:\n  pull_request_target:\npermissions: {}\n";
        assert!(!workflow_violations("w", trigger).is_empty());
        let unpinned = "permissions: {}\nsteps:\n  - uses: actions/checkout@v4\n";
        assert!(!workflow_violations("w", unpinned).is_empty());
    }

    #[test]
    fn structural_lines_are_allowlisted() {
        let ids: Vec<String> = ["m01", "x", "sentinel"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let structural = |l: &str| structural(l, &ids);
        assert!(structural(r#"DVISCOPE-STRUCT: {"check":"undeclared-lowercase"}"#).is_none());
        assert!(structural(r#"DVISCOPE-STRUCT: {"check":"m01","ok":true,"count":3}"#).is_some());
        assert!(structural("DVISCOPE-STRUCT: free text").is_none());
        assert!(structural(r#"DVISCOPE-STRUCT: {"check":"x","detail":"msg"}"#).is_none());
        assert!(structural(r#"DVISCOPE-STRUCT: {"check":"has space"}"#).is_none());
        assert!(structural(r#"DVISCOPE-STRUCT: {"actual":"private text"}"#).is_none());
        assert!(structural(r#"DVISCOPE-STRUCT: {"check":"Upper"}"#).is_none());
        assert!(structural(r#"DVISCOPE-STRUCT: {"state":"whatever"}"#).is_none());
        assert!(
            structural(r#"DVISCOPE-STRUCT: {"state":"met","expected":3,"actual":3}"#).is_some()
        );
    }

    #[test]
    fn publication_rules() {
        let banner = ["Chronologic", " VCS ", "simulator"].concat();
        assert!(!publication_violations("a.txt", banner.as_bytes()).is_empty());
        assert!(!publication_violations("x.log", b"").is_empty());
        let token = format!("{}{}", ["dvis", "_"].concat(), "A".repeat(43));
        assert!(!publication_violations("a.rs", token.as_bytes()).is_empty());
        assert!(
            publication_violations("a.rs", b"tokens look like dvis_... and never print").is_empty()
        );
        // Invalid UTF-8 is still scanned.
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend_from_slice(banner.as_bytes());
        assert!(!publication_violations("b.bin", &bytes).is_empty());
    }
}
