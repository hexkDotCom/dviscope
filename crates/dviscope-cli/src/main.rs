//! `dviscope` binary.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use dviscope_cli::config::{CliConfig, Overrides};
use dviscope_cli::{doctor, rules, tls};

#[derive(Debug, Parser)]
#[command(name = "dviscope", version, about = "DVIScope command-line client")]
struct Cli {
    /// Server URL (https:// only).
    #[arg(long = "server-url", global = true)]
    server_url: Option<String>,
    /// Extra CA certificate to trust (PEM).
    #[arg(long, global = true)]
    ca_file: Option<PathBuf>,
    /// Private state directory.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a command supervised and journal the attempt (spool for delivery).
    Run {
        /// Journal directory.
        #[arg(long)]
        journal: PathBuf,
        /// Launch specification (JSON: producer, regression, slot, attempt, execution).
        #[arg(long)]
        launch: PathBuf,
        /// Timeout, seconds.
        #[arg(long)]
        timeout: Option<f64>,
        /// Grace period after the polite stop, seconds.
        #[arg(long, default_value_t = 10.0)]
        grace: f64,
        /// Capture the command's stdout and stderr in this file.
        #[arg(long)]
        console: Option<PathBuf>,
        /// The log to extract after the run.
        #[arg(long)]
        log: Option<PathBuf>,
        #[command(flatten)]
        packs: PackArgs,
        /// The command and its arguments.
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// The delivery journal.
    Journal {
        #[command(subcommand)]
        action: JournalAction,
    },
    /// Delivery of journalled records.
    Spool {
        #[command(subcommand)]
        action: SpoolAction,
    },
    /// Feature checklists.
    Checklist {
        #[command(subcommand)]
        action: ChecklistAction,
    },
    /// The project hierarchy of the health dashboard (SoC, subsystems, blocks).
    Hierarchy {
        #[command(subcommand)]
        action: HierarchyAction,
    },
    /// Source identity of a candidate.
    Source {
        #[command(subcommand)]
        action: SourceAction,
    },
    /// Journal a source manifest (repositories and revisions of a regression).
    SourceManifest {
        /// Journal directory.
        #[arg(long)]
        journal: PathBuf,
        /// The `SourceManifest` record (JSON file).
        #[arg(long)]
        body: PathBuf,
    },
    /// Journal regression operations.
    Regression {
        #[command(subcommand)]
        action: RegressionAction,
    },
    /// Journal manifest operations of a regression.
    Manifest {
        #[command(subcommand)]
        action: ManifestAction,
    },
    /// Test helper: start a process tree and sleep (supervision tests).
    #[command(hide = true, name = "__tree")]
    Tree {
        /// Children to start (each sleeps).
        #[arg(long, default_value_t = 2)]
        children: u32,
        /// Seconds to sleep.
        #[arg(long, default_value_t = 60.0)]
        sleep: f64,
        /// File receiving the PIDs (one per line).
        #[arg(long)]
        pids: Option<PathBuf>,
        /// Exit code after sleeping.
        #[arg(long, default_value_t = 0)]
        exit: i32,
        /// Abort (a fault: SIGABRT / fast-fail) instead of exiting.
        #[arg(long)]
        abort: bool,
        /// Copy FROM to TO first (a fake simulator writing its log).
        #[arg(long, num_args = 2, value_names = ["FROM", "TO"])]
        copy: Vec<PathBuf>,
        /// Write TEXT (`\n` for line breaks) to FILE, truncating it in place (a model
        /// writing its program log).
        #[arg(long, num_args = 2, value_names = ["FILE", "TEXT"])]
        write: Vec<String>,
        /// Print TEXT (`\n` for line breaks) on stdout (the console).
        #[arg(long)]
        say: Option<String>,
        /// Rename FROM over TO (replacing a file another process created).
        #[arg(long, num_args = 2, value_names = ["FROM", "TO"])]
        rename: Vec<PathBuf>,
        /// Delete FILE.
        #[arg(long)]
        remove: Option<PathBuf>,
    },
    /// Local TLS certificates for a single-machine install.
    Tls {
        #[command(subcommand)]
        action: TlsAction,
    },
    /// Check configuration and, with --server, the server.
    Doctor {
        /// Also reach the server.
        #[arg(long)]
        server: bool,
        /// Print each producer's integration assurance profile for this project (what its
        /// data supports: counting, build provenance, merge gating; project admins).
        #[arg(long, value_name = "PROJECT")]
        assurance: Option<String>,
        /// Pilot checks: state location and privacy, token file, runner prerequisites,
        /// simulators on PATH and (with --server) CA trust and the clock offset.
        #[arg(long)]
        pilot: bool,
        /// Reconcile these journals with the server (repeatable; as `journal reconcile`).
        #[arg(long = "reconcile", value_name = "JOURNAL_DIR")]
        reconcile: Vec<PathBuf>,
    },
    /// Evaluate merge readiness on the server; write the summary, then exit 0 (pass), 10
    /// (fail), 11 (insufficient evidence), 2 usage, 3 rejected, 4 unreachable, 5 internal.
    Verdict {
        /// Project.
        #[arg(long)]
        project: String,
        /// Regression reference (merge mode).
        #[arg(long)]
        regression: Option<String>,
        /// `merge` (a regression for a candidate) or `feature` (a checklist for a branch).
        #[arg(long, default_value = "merge")]
        mode: String,
        /// Checklist ID (feature mode).
        #[arg(long)]
        checklist: Option<String>,
        /// Checklist version (feature mode; default: the latest).
        #[arg(long)]
        checklist_version: Option<String>,
        /// Repository-qualified branch, `repo/name` (feature mode).
        #[arg(long)]
        branch: Option<String>,
        /// The candidate's source digest (`dviscope source digest`).
        #[arg(long)]
        expect_source: Option<String>,
        /// `log-free` (default, safe to publish), `markdown` (the log-free summary for a CI
        /// comment, every value escaped) or `json`.
        #[arg(long, default_value = "log-free")]
        summary: String,
        /// File receiving the summary (written before exiting, also on errors).
        #[arg(long)]
        summary_file: Option<PathBuf>,
        /// Treat accepted_with_exceptions as failing (suite policy says otherwise).
        #[arg(long)]
        exceptions_fail: bool,
        /// Wait while the verdict can still change by waiting (the collection is open,
        /// attempts are running, the server is unreachable), up to --deadline.
        #[arg(long)]
        wait_processed: bool,
        /// How long --wait-processed waits (90s, 15m, 2h).
        #[arg(long, default_value = "15m")]
        deadline: String,
        /// Re-evaluation interval while waiting.
        #[arg(long, default_value = "10s", hide = true)]
        poll: String,
        /// Store a publication receipt of the evaluation for this commit-status target
        /// (needs --target-repository, --target-commit, --target-context; triage rights).
        #[arg(long)]
        publish_receipt: bool,
        /// Status target: `owner/name`.
        #[arg(long)]
        target_repository: Option<String>,
        /// Status target: full commit SHA.
        #[arg(long)]
        target_commit: Option<String>,
        /// Status target: context.
        #[arg(long, default_value = "dviscope/merge")]
        target_context: String,
    },
    /// Journal a run that already ended (executed by other means): extract its log and
    /// spool the attempt (output `state: spooled`; deliver with `spool flush`).
    Collect {
        /// Journal directory.
        #[arg(long)]
        journal: PathBuf,
        /// The launch specification (as for `run`).
        #[arg(long)]
        launch: PathBuf,
        /// The run's log (none: evidence of a missing log).
        #[arg(long)]
        log: Option<PathBuf>,
        /// The run's exit code (none: the termination is unknown, never a pass).
        #[arg(long)]
        exit_code: Option<i32>,
        /// Start (RFC 3339).
        #[arg(long)]
        started_at: String,
        /// End (RFC 3339).
        #[arg(long)]
        finished_at: Option<String>,
        #[command(flatten)]
        packs: PackArgs,
    },
    /// Extract evidence from a log (local; prints the evidence JSON).
    Extract {
        /// Log file.
        log: PathBuf,
        #[command(flatten)]
        packs: PackArgs,
        /// Write the evidence here instead of standard output.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Pattern packs: validation, debugging and activation.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// The project's activation sample.
    Sample {
        #[command(subcommand)]
        action: SampleAction,
    },
    /// Decisions ledger: export and import (owners, notes, bug URLs, exceptions).
    Ledger {
        #[command(subcommand)]
        action: LedgerAction,
    },
    /// Import results collected elsewhere.
    Import {
        #[command(subcommand)]
        action: ImportAction,
    },
    /// Private sample corpus.
    Corpus {
        #[command(subcommand)]
        action: CorpusAction,
    },
}

#[derive(Debug, Subcommand)]
enum CorpusAction {
    /// Add a local log to a private sample directory as a case: the log and a starting
    /// expectation from today's extraction (review it before `sample upload`).
    Capture {
        /// The log.
        #[arg(long)]
        log: PathBuf,
        /// Case name.
        #[arg(long)]
        case: String,
        /// Private sample directory.
        #[arg(long)]
        dir: PathBuf,
        /// The run's exit code (default 0 in the check).
        #[arg(long)]
        exit_code: Option<i32>,
        /// The slot's expected-outcome contract (JSON, as in its manifest declaration), so
        /// the check compares the expectation assessment too.
        #[arg(long)]
        expected: Option<PathBuf>,
        /// Replace an existing case.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        packs: PackArgs,
    },
}

#[derive(Debug, Subcommand)]
enum ImportAction {
    /// A folder of logs and a CSV of the regression's expected jobs (columns: slot, test,
    /// seed, log, exit_code[, started_at, finished_at, required]); a preview unless
    /// --submit.
    Folder {
        /// The folder the CSV's log paths are relative to (a local path).
        #[arg(long)]
        root: PathBuf,
        /// The CSV of expected jobs (one row per job; an empty log = did not report).
        #[arg(long)]
        manifest: PathBuf,
        /// Regression reference.
        #[arg(long)]
        regression: String,
        /// Producer (the collector token's).
        #[arg(long)]
        producer: String,
        /// Repository of the branch and the sources.
        #[arg(long)]
        repository: String,
        /// Branch name.
        #[arg(long)]
        branch: String,
        /// Source revision.
        #[arg(long)]
        revision: String,
        /// Suite.
        #[arg(long, default_value = "nightly")]
        suite: String,
        /// Regression start (RFC 3339); default: the earliest started_at.
        #[arg(long)]
        started_at: Option<String>,
        /// Private journal directory (required with --submit; reusing it resumes).
        #[arg(long)]
        journal: Option<PathBuf>,
        /// Journal and deliver (otherwise only the preview).
        #[arg(long)]
        submit: bool,
        #[command(flatten)]
        packs: PackArgs,
    },
}

#[derive(Debug, Subcommand)]
enum LedgerAction {
    /// Export the project's decisions (`dviscope.ledger/1.0`, project admins).
    Export {
        /// Project.
        #[arg(long)]
        project: String,
        /// Write the ledger here (private: notes may name people).
        #[arg(long)]
        out: PathBuf,
    },
    /// Import a ledger: maps by fingerprint (or `--mapping`), applies what you may do,
    /// keeps existing decisions, lists the rest.
    Import {
        /// Project.
        #[arg(long)]
        project: String,
        /// The ledger file.
        file: PathBuf,
        /// JSON object mapping exported fingerprints to this project's.
        #[arg(long)]
        mapping: Option<PathBuf>,
        /// Show what would apply; write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SampleAction {
    /// Upload the activation sample (<case>.log + <case>.expect.json), resumable; it
    /// becomes the sample activations are checked against.
    Upload {
        /// Project.
        #[arg(long)]
        project: String,
        /// Private sample directory.
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
struct PackArgs {
    /// Evidence subject: simulation or build.
    #[arg(long, default_value = "simulation")]
    subject: String,
    /// Simulator the run declares (questa, vcs, verilator); default: detected.
    #[arg(long)]
    simulator: Option<String>,
    /// Extra pack: a YAML file or builtin:NAME (repeatable).
    #[arg(long = "pack")]
    packs: Vec<String>,
    /// Do not load the shipped packs.
    #[arg(long)]
    no_default_packs: bool,
    /// Path prefix that makes source anchors repository-relative (repeatable).
    #[arg(long = "source-root")]
    source_roots: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum JournalAction {
    /// Create a journal.
    Init {
        /// Journal directory.
        #[arg(long)]
        dir: PathBuf,
        /// Journal ID.
        #[arg(long)]
        id: String,
        /// Coordinator journal of the regression to join (registered before this journal
        /// exists, so the finish barrier covers it).
        #[arg(long)]
        coordinator: Option<PathBuf>,
    },
    /// Recover interrupted attempts (termination `unknown`; never relaunches).
    Recover {
        /// Journal directory.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Close launches and print the watermark.
    Close {
        /// Journal directory.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Finish the regression once every participating journal has closed its launches
    /// and their starts are committed (the finish barrier).
    Finish {
        /// Coordinator journal directory.
        #[arg(long)]
        dir: PathBuf,
        /// Regression reference.
        #[arg(long)]
        regression: String,
        /// Participating journal directories (repeatable; optional: every registered
        /// participant is always included, and each one given must be registered).
        #[arg(long = "participant")]
        participants: Vec<PathBuf>,
    },
    /// Entries and their delivery state.
    Status {
        /// Journal directory.
        #[arg(long)]
        dir: PathBuf,
    },
    /// Compare the journal (and its registered participants) with the server: records
    /// committed but missing or different there, records never delivered, and started or
    /// reported slots the server does not count. Changes nothing; exit 0 when they agree,
    /// 10 when they do not.
    Reconcile {
        /// Journal directory (a coordinator covers its participants).
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RegressionAction {
    /// Journal the creation of a regression (depends on its source manifest when this
    /// journal holds it).
    Create {
        /// Journal directory.
        #[arg(long)]
        journal: PathBuf,
        /// The `RegressionCreate` record (JSON file).
        #[arg(long)]
        body: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ManifestAction {
    /// Journal manifest chunk N (a `ManifestChunk` JSON file).
    Declare {
        /// Journal directory.
        #[arg(long)]
        journal: PathBuf,
        /// Regression reference.
        #[arg(long)]
        regression: String,
        /// Chunk number (from 1).
        #[arg(long)]
        chunk: u32,
        /// The chunk (JSON file).
        #[arg(long)]
        body: PathBuf,
    },
    /// Journal the seal, computed from this journal's chunks of the regression.
    Seal {
        /// Journal directory.
        #[arg(long)]
        journal: PathBuf,
        /// Regression reference.
        #[arg(long)]
        regression: String,
    },
    /// Journal an amendment (a `ManifestAmend` JSON file).
    Amend {
        /// Journal directory.
        #[arg(long)]
        journal: PathBuf,
        /// Regression reference.
        #[arg(long)]
        regression: String,
        /// The amendment (JSON file).
        #[arg(long)]
        body: PathBuf,
    },
    /// Journal slot marks (a `SlotMark` JSON file).
    Mark {
        /// Journal directory.
        #[arg(long)]
        journal: PathBuf,
        /// Regression reference.
        #[arg(long)]
        regression: String,
        /// The marks (JSON file).
        #[arg(long)]
        body: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum SpoolAction {
    /// Deliver pending entries.
    Flush {
        /// Journal directory.
        #[arg(long)]
        dir: PathBuf,
        /// Receipt endpoint: `server` (the configured server URL, CA file and token file),
        /// or `dir:PATH` (the directory-backed test endpoint).
        #[arg(long, default_value = "server")]
        endpoint: String,
        /// `committed`: retry until every record is committed (or rejected), up to
        /// --deadline; exit 4 if some are still pending then.
        #[arg(long)]
        wait: Option<String>,
        /// How long --wait retries (90s, 10m, 1h).
        #[arg(long, default_value = "10m")]
        deadline: String,
    },
}

#[derive(Debug, Subcommand)]
enum RulesAction {
    /// Compile the packs, run their self-tests and, with --sample, the sample's
    /// structural expectations (<case>.log + <case>.expect.json).
    Check {
        #[command(flatten)]
        packs: PackArgs,
        /// Private sample directory.
        #[arg(long)]
        sample: Option<PathBuf>,
        /// Write each case's evidence into this (private) directory.
        #[arg(long)]
        evidence_out: Option<PathBuf>,
    },
    /// Check a new pipeline against the project's active one over the activation sample
    /// and activate it when the check passes (project admins).
    Import {
        /// Project.
        #[arg(long)]
        project: String,
        /// Extra pack, in order: `builtin:NAME` or a YAML file (repeatable).
        #[arg(long = "pack")]
        packs: Vec<String>,
        /// Do not load the shipped packs.
        #[arg(long)]
        no_default_packs: bool,
        /// The local copy of the server's activation sample.
        #[arg(long)]
        sample: PathBuf,
    },
    /// Show how a log line is assembled and classified.
    Explain {
        #[command(flatten)]
        packs: PackArgs,
        /// Log file (for a Verilator model with its own main: its program log).
        #[arg(long)]
        log: PathBuf,
        /// A Verilator model with its own main: its console capture, joined after the
        /// program log as the collector joins them (the line is then a joined line).
        #[arg(long)]
        console: Option<PathBuf>,
        /// 1-based line number.
        #[arg(long)]
        line: u64,
    },
}

fn options(a: &PackArgs) -> anyhow::Result<dviscope_core::extract::ExtractOptions> {
    let mut o = dviscope_core::extract::ExtractOptions::simulation("");
    o.subject = rules::subject(&a.subject)?;
    o.simulator.clone_from(&a.simulator);
    o.source_roots.clone_from(&a.source_roots);
    Ok(o)
}

fn local(command: &Command) -> Option<anyhow::Result<bool>> {
    let run = || -> anyhow::Result<bool> {
        match command {
            Command::Extract { log, packs, out } => {
                let p = rules::pipeline(&packs.packs, packs.no_default_packs)?;
                let (ev, _) = rules::extract_file(&p, options(packs)?, log)?;
                let text = serde_json::to_string_pretty(&ev)?;
                match out {
                    Some(o) => std::fs::write(o, text)?,
                    None => {
                        let _ = writeln!(std::io::stdout(), "{text}");
                    }
                }
                Ok(true)
            }
            Command::Rules {
                action:
                    RulesAction::Check {
                        packs,
                        sample,
                        evidence_out,
                    },
            } => {
                let p = rules::pipeline(&packs.packs, packs.no_default_packs)?;
                let (report, ok) = rules::check(
                    &p,
                    sample.as_deref(),
                    evidence_out.as_deref(),
                    &packs.source_roots,
                )?;
                print_json(&report);
                Ok(ok)
            }
            Command::Collect {
                journal,
                launch,
                log,
                exit_code,
                started_at,
                finished_at,
                packs,
            } => {
                let p = rules::pipeline(&packs.packs, packs.no_default_packs)?;
                let j = dviscope_cli::journal::Journal::open(journal)?;
                let spec: dviscope_cli::run::LaunchSpec =
                    serde_json::from_slice(&std::fs::read(launch)?)?;
                let ev = match log {
                    Some(l) => rules::extract_file(&p, options(packs)?, l)?.0,
                    None => dviscope_core::extract::extract_bytes(&p, options(packs)?, b"").0,
                };
                let termination = match exit_code {
                    Some(c) => serde_json::json!({"kind": "exited", "exit_code": c}),
                    None => serde_json::json!({"kind": "unknown"}),
                };
                let runner: dviscope_model::wire::ingest::Runner =
                    serde_json::from_value(serde_json::json!({
                        "termination": termination,
                        "started_at": started_at,
                        "finished_at": finished_at,
                    }))
                    .map_err(|e| anyhow::anyhow!("--started-at/--finished-at: {e}"))?;
                let out = dviscope_cli::run::import_attempt(&j, &spec, runner, ev)?;
                print_json(&out);
                Ok(true)
            }
            Command::Corpus {
                action:
                    CorpusAction::Capture {
                        log,
                        case,
                        dir,
                        exit_code,
                        expected,
                        force,
                        packs,
                    },
            } => {
                let p = rules::pipeline(&packs.packs, packs.no_default_packs)?;
                let contract = match expected {
                    Some(f) => Some(
                        serde_json::from_slice(&std::fs::read(f)?)
                            .map_err(|e| anyhow::anyhow!("--expected: {e}"))?,
                    ),
                    None => None,
                };
                let out = dviscope_cli::activation::capture(
                    &p,
                    options(packs)?,
                    log,
                    dir,
                    case,
                    *exit_code,
                    contract,
                    *force,
                )
                .map_err(|e| anyhow::anyhow!(e))?;
                print_json(&out);
                Ok(true)
            }
            Command::Rules {
                action:
                    RulesAction::Explain {
                        packs,
                        log,
                        console,
                        line,
                    },
            } => {
                let p = rules::pipeline(&packs.packs, packs.no_default_packs)?;
                match console {
                    Some(c) => {
                        print_json(&rules::explain_joined(&p, options(packs)?, log, c, *line)?)
                    }
                    None => print_json(&rules::explain(&p, options(packs)?, log, *line)?),
                }
                Ok(true)
            }
            Command::Run {
                journal,
                launch,
                timeout,
                grace,
                console,
                log,
                packs,
                cmd,
            } => {
                let p = rules::pipeline(&packs.packs, packs.no_default_packs)?;
                let j = dviscope_cli::journal::Journal::open(journal)?;
                let spec: dviscope_cli::run::LaunchSpec =
                    serde_json::from_slice(&std::fs::read(launch)?)?;
                let out = dviscope_cli::run::run(
                    &j,
                    &spec,
                    &p,
                    dviscope_cli::run::RunOptions {
                        argv: cmd,
                        timeout: timeout.map(std::time::Duration::from_secs_f64),
                        grace: std::time::Duration::from_secs_f64(*grace),
                        console: console.as_deref(),
                        log: log.as_deref(),
                        extract: options(packs)?,
                    },
                )?;
                print_json(&out);
                Ok(true)
            }
            Command::Journal { action } => {
                use dviscope_cli::journal::Journal;
                match action {
                    JournalAction::Init {
                        dir,
                        id,
                        coordinator,
                    } => {
                        match coordinator {
                            Some(c) => {
                                // create (dormant) → register → activate; re-running the
                                // same command resumes an interrupted initialization.
                                let c = Journal::open(c)?;
                                let resumed = dir.join("journal.json").exists();
                                let j = if resumed {
                                    let j = Journal::open(dir)?;
                                    if j.id() != id
                                        || j.coordinator_id()?.as_deref() != Some(c.id())
                                    {
                                        anyhow::bail!(
                                            "{} holds another journal (not participant {id} of {})",
                                            dir.display(),
                                            c.id()
                                        );
                                    }
                                    j
                                } else {
                                    Journal::create_with(dir, id, Some(c.id()))?
                                };
                                if let Err(e) = c.locked(|c| c.register(dir, id)) {
                                    // Refused (e.g. the regression is finished): a dormant
                                    // journal this command just created, still empty, goes.
                                    if !resumed
                                        && j.entries().map(|v| v.is_empty()).unwrap_or(false)
                                    {
                                        let _ = std::fs::remove_dir_all(dir);
                                    }
                                    return Err(e);
                                }
                                j.activate()?;
                            }
                            None => {
                                Journal::create(dir, id)?;
                            }
                        }
                        print_json(&serde_json::json!({"journal": id}));
                    }
                    JournalAction::Recover { dir } => {
                        let j = Journal::open(dir)?;
                        let p = rules::pipeline(&[], false)?;
                        let o = dviscope_core::extract::ExtractOptions::simulation("");
                        print_json(&dviscope_cli::run::recover(&j, &p, &o)?);
                    }
                    JournalAction::Close { dir } => {
                        let j = Journal::open(dir)?;
                        let w = j.locked(Journal::close)?;
                        print_json(&serde_json::json!({"watermark": w}));
                    }
                    JournalAction::Finish {
                        dir,
                        regression,
                        participants,
                    } => {
                        let j = Journal::open(dir)?;
                        let parts = participants
                            .iter()
                            .map(|p| Journal::open(p))
                            .collect::<anyhow::Result<Vec<_>>>()?;
                        let record = serde_json::json!({"deliver": {"kind": "finish", "regression_ref": regression}});
                        let seq = j.locked(|j| j.finish(&parts, record))?;
                        print_json(&serde_json::json!({"finish": seq}));
                    }
                    JournalAction::Reconcile { .. } => {
                        unreachable!("reconciliation is handled by the async path")
                    }
                    JournalAction::Status { dir } => {
                        let j = Journal::open(dir)?;
                        let outcomes = j.outcomes()?;
                        let entries = j.entries()?;
                        // Launches whose runner facts were recovered as termination
                        // `unknown` (interrupted: no result; a resumed run re-runs them).
                        let interrupted: std::collections::BTreeSet<u64> = entries
                            .iter()
                            .flatten()
                            .filter(|e| e.kind == dviscope_cli::journal::kind::RUNNER_RESULT)
                            .filter_map(|e| e.record.as_ref())
                            .filter(|r| r["runner"]["termination"]["kind"] == "unknown")
                            .filter_map(|r| r["launch"].as_u64())
                            .collect();
                        let rows: Vec<serde_json::Value> = entries
                            .into_iter()
                            .map(|e| match e {
                                Ok(e) => {
                                    let mut row = serde_json::json!({
                                        "seq": e.seq, "kind": e.kind, "identity": e.identity,
                                        "state": outcomes.get(&e.seq).map_or_else(
                                            || if dviscope_cli::journal::delivered(&e.kind) { "pending".to_string() } else { "local".to_string() },
                                            |o| serde_json::to_value(o).ok().and_then(|v| v["outcome"].as_str().map(str::to_string)).unwrap_or_default()),
                                    });
                                    if interrupted.contains(&e.seq) {
                                        row["interrupted"] = serde_json::json!(true);
                                    }
                                    row
                                }
                                Err(seq) => serde_json::json!({"seq": seq, "state": "corrupt"}),
                            })
                            .collect();
                        print_json(&serde_json::json!({"entries": rows}));
                    }
                }
                Ok(true)
            }
            Command::Source {
                action:
                    SourceAction::Digest {
                        repos,
                        revs,
                        allow_dirty,
                    },
            } => {
                print_json(&dviscope_cli::source::digest(repos, revs, *allow_dirty)?);
                Ok(true)
            }
            Command::SourceManifest { journal, body } => {
                let j = dviscope_cli::journal::Journal::open(journal)?;
                print_json(&dviscope_cli::collect::source_manifest(&j, body)?);
                Ok(true)
            }
            Command::Regression {
                action: RegressionAction::Create { journal, body },
            } => {
                let j = dviscope_cli::journal::Journal::open(journal)?;
                print_json(&dviscope_cli::collect::regression_create(&j, body)?);
                Ok(true)
            }
            Command::Manifest { action } => {
                use dviscope_cli::collect;
                let out = match action {
                    ManifestAction::Declare {
                        journal,
                        regression,
                        chunk,
                        body,
                    } => collect::declare(
                        &dviscope_cli::journal::Journal::open(journal)?,
                        regression,
                        *chunk,
                        body,
                    )?,
                    ManifestAction::Seal {
                        journal,
                        regression,
                    } => {
                        collect::seal(&dviscope_cli::journal::Journal::open(journal)?, regression)?
                    }
                    ManifestAction::Amend {
                        journal,
                        regression,
                        body,
                    } => collect::amend(
                        &dviscope_cli::journal::Journal::open(journal)?,
                        regression,
                        body,
                    )?,
                    ManifestAction::Mark {
                        journal,
                        regression,
                        body,
                    } => collect::mark(
                        &dviscope_cli::journal::Journal::open(journal)?,
                        regression,
                        body,
                    )?,
                };
                print_json(&out);
                Ok(true)
            }
            Command::Spool {
                action: SpoolAction::Flush { dir, endpoint, .. },
            } => {
                let j = dviscope_cli::journal::Journal::open(dir)?;
                let Some(path) = endpoint.strip_prefix("dir:") else {
                    unreachable!("the server endpoint is handled by the async path");
                };
                let mut t = dviscope_cli::spool::DirEndpoint::new(std::path::Path::new(path))?;
                let sum = dviscope_cli::spool::flush(&j, &mut t)?;
                let done = sum.pending == 0;
                print_json(&serde_json::to_value(&sum)?);
                Ok(done)
            }
            Command::Tree {
                children,
                sleep,
                pids,
                exit,
                abort,
                copy,
                write,
                say,
                rename,
                remove,
            } => {
                if let [from, to] = copy.as_slice() {
                    std::fs::copy(from, to)?;
                }
                if let [from, to] = rename.as_slice() {
                    std::fs::rename(from, to)?;
                }
                if let Some(f) = remove {
                    std::fs::remove_file(f)?;
                }
                if let [file, text] = write.as_slice() {
                    use std::io::Write as _;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(file)?;
                    f.write_all(text.replace("\\n", "\n").as_bytes())?;
                }
                if let Some(t) = say {
                    use std::io::Write as _;
                    let mut out = std::io::stdout().lock();
                    out.write_all(t.replace("\\n", "\n").as_bytes())?;
                    out.flush()?;
                }
                let me = std::env::current_exe()?;
                let mut list = vec![std::process::id().to_string()];
                for _ in 0..*children {
                    let c = std::process::Command::new(&me)
                        .args(["__tree", "--children", "0", "--sleep", &sleep.to_string()])
                        .spawn()?;
                    list.push(c.id().to_string());
                }
                if let Some(p) = pids {
                    std::fs::write(p, list.join("\n"))?;
                }
                std::thread::sleep(std::time::Duration::from_secs_f64(*sleep));
                if *abort {
                    std::process::abort();
                }
                std::process::exit(*exit);
            }
            _ => unreachable!("only local commands"),
        }
    };
    match command {
        Command::Extract { .. }
        | Command::Collect { .. }
        | Command::Corpus { .. }
        | Command::Rules {
            action: RulesAction::Check { .. } | RulesAction::Explain { .. },
        }
        | Command::Run { .. }
        | Command::Journal {
            action:
                JournalAction::Init { .. }
                | JournalAction::Recover { .. }
                | JournalAction::Close { .. }
                | JournalAction::Finish { .. }
                | JournalAction::Status { .. },
        }
        | Command::Source { .. }
        | Command::SourceManifest { .. }
        | Command::Regression { .. }
        | Command::Manifest { .. }
        | Command::Tree { .. } => Some(run()),
        Command::Spool {
            action: SpoolAction::Flush { endpoint, .. },
        } if endpoint.starts_with("dir:") => Some(run()),
        _ => None,
    }
}

#[derive(Debug, Subcommand)]
enum ChecklistAction {
    /// Import a `dviscope.checklist/1.0` YAML file as a new immutable version.
    Import {
        /// Project.
        #[arg(long)]
        project: String,
        /// The checklist file.
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum HierarchyAction {
    /// Import a `dviscope.hierarchy/1` YAML file (a new revision when it changed; project
    /// admins).
    Import {
        /// Project.
        #[arg(long)]
        project: String,
        /// Validate locally and print the tree; import nothing.
        #[arg(long)]
        dry_run: bool,
        /// The hierarchy file.
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum SourceAction {
    /// The candidate's source digest (what `verdict --expect-source` binds to).
    Digest {
        /// A repository's local checkout: its `HEAD` revision (NAME=PATH).
        #[arg(long = "repo")]
        repos: Vec<String>,
        /// A repository's revision given explicitly (NAME=REVISION).
        #[arg(long = "rev")]
        revs: Vec<String>,
        /// Digest `HEAD` even when the checkout has uncommitted changes.
        #[arg(long)]
        allow_dirty: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TlsAction {
    /// Create a local CA and a server certificate (never replaces an existing CA).
    Init {
        /// Directory for the CA (keep private; default: <state>/ca).
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        /// Directory for the server certificate and key.
        #[arg(long)]
        server_dir: PathBuf,
    },
    /// Reissue the server certificate with the existing CA.
    Renew {
        /// Directory of the CA (default: <state>/ca).
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        /// Directory for the server certificate and key.
        #[arg(long)]
        server_dir: PathBuf,
    },
}

/// `spool flush --endpoint server`: the configured server, CA file and token file; the
/// flush itself runs on a blocking thread (the transport blocks on this runtime).
async fn flush_to_server(
    cfg: &CliConfig,
    dir: PathBuf,
) -> anyhow::Result<(serde_json::Value, bool)> {
    flush_until(cfg, dir, None).await
}

/// [`flush_to_server`] bounded by an absolute deadline (every request included).
async fn flush_until(
    cfg: &CliConfig,
    dir: PathBuf,
    deadline: Option<std::time::Instant>,
) -> anyhow::Result<(serde_json::Value, bool)> {
    let token_file = cfg.token_file.clone().ok_or_else(|| {
        anyhow::anyhow!("no token_file configured (DVISCOPE_TOKEN_FILE or the config file)")
    })?;
    let token = std::fs::read_to_string(&token_file)
        .map_err(|e| anyhow::anyhow!("reading the token file: {e}"))?
        .trim()
        .to_string();
    let client = dviscope_cli::client::build(&cfg.server_url, cfg.ca_file.as_deref())?;
    let base = cfg.server_url.clone();
    let rt = tokio::runtime::Handle::current();
    let work = tokio::task::spawn_blocking(move || {
        let j = dviscope_cli::journal::Journal::open(&dir)?;
        let mut t = dviscope_cli::transport::HttpTransport::new(client, &base, token, rt)
            .map_err(|e| anyhow::anyhow!(e))?
            .with_deadline(deadline);
        let sum = dviscope_cli::spool::flush(&j, &mut t)?;
        let done = sum.pending == 0;
        Ok((serde_json::to_value(&sum)?, done))
    });
    // The deadline bounds the whole flush, waiting for the journal's writer lock
    // included: past it the command ends (its blocking worker ends with the process; the
    // journal's writes are crash-safe, so an interrupted flush is resumed by the next).
    match deadline {
        None => work.await?,
        Some(t) => {
            let left = t
                .checked_duration_since(std::time::Instant::now())
                .unwrap_or_default();
            match tokio::time::timeout(left, work).await {
                Ok(r) => r?,
                Err(_) => Err(DeadlinePassed.into()),
            }
        }
    }
}

/// The deadline passed during a flush (the process exits without waiting for the worker).
#[derive(Debug)]
struct DeadlinePassed;

impl std::fmt::Display for DeadlinePassed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the deadline passed during the flush (records stay pending)")
    }
}

impl std::error::Error for DeadlinePassed {}

/// `doctor --reconcile DIR...`: each journal's reconciliation in the report; whether all
/// agree with the server.
async fn reconcile_into(
    cfg: &dviscope_cli::config::CliConfig,
    dirs: &[PathBuf],
    report: &mut serde_json::Value,
) -> bool {
    if dirs.is_empty() {
        return true;
    }
    let mut ok = true;
    let mut out = vec![];
    for d in dirs {
        match dviscope_cli::reconcile::run(cfg, d).await {
            Ok(r) => {
                ok &= r["ok"] == true;
                out.push(serde_json::json!({"journal_dir": d.display().to_string(), "result": r}));
            }
            Err((_, msg)) => {
                ok = false;
                out.push(serde_json::json!({"journal_dir": d.display().to_string(), "error": msg}));
            }
        }
    }
    report["reconcile"] = serde_json::json!(out);
    if !ok {
        report["ok"] = serde_json::json!(false);
    }
    ok
}

fn print_json(v: &serde_json::Value) {
    let text = serde_json::to_string_pretty(v).unwrap_or_default();
    let _ = writeln!(std::io::stdout(), "{text}");
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    dviscope_cli::crash::arm(std::env::var("DVISCOPE_TEST_CRASH_POINT").ok());
    if let Some(res) = local(&cli.command) {
        return match res {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "error: {e:#}");
                ExitCode::from(2)
            }
        };
    }
    let env: BTreeMap<String, String> = std::env::vars().collect();
    let flags = Overrides {
        server_url: cli.server_url.clone(),
        ca_file: cli.ca_file.clone(),
        state_dir: cli.state_dir.clone(),
    };
    let cfg = match CliConfig::resolve(&env, &flags) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "error: {e}");
            return ExitCode::from(2);
        }
    };
    match cli.command {
        Command::Tls { action } => {
            let (ca_dir, server_dir, renew) = match action {
                TlsAction::Init { ca_dir, server_dir } => (ca_dir, server_dir, false),
                TlsAction::Renew { ca_dir, server_dir } => (ca_dir, server_dir, true),
            };
            let paths = tls::TlsPaths::new(
                &ca_dir.unwrap_or_else(|| cfg.state_dir.join("ca")),
                &server_dir,
            );
            let now = time::OffsetDateTime::now_utc();
            let policy = tls::PrivatePolicy {
                allow_any_location: false,
            };
            let res = if renew {
                tls::renew(&paths, now, &policy)
            } else {
                tls::init(&paths, now, &policy)
            };
            match res {
                Ok(()) => {
                    print_json(&serde_json::json!({
                        "ca_cert": paths.ca_cert.display().to_string(),
                        "server_cert": paths.server_cert.display().to_string(),
                        "server_key": paths.server_key.display().to_string(),
                        "valid_days": tls::LEAF_DAYS,
                    }));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "error: {e}");
                    ExitCode::from(5)
                }
            }
        }
        Command::Spool {
            action:
                SpoolAction::Flush {
                    dir,
                    endpoint,
                    wait,
                    deadline,
                },
        } => {
            let until = match (
                wait.as_deref(),
                dviscope_cli::verdict::parse_duration(&deadline),
            ) {
                (None, _) => None,
                (Some("committed"), Ok(d)) => Some(std::time::Instant::now() + d),
                (Some("committed"), Err(e)) => {
                    let _ = writeln!(std::io::stderr(), "error: {e}");
                    return ExitCode::from(2);
                }
                (Some(_), _) => {
                    let _ = writeln!(std::io::stderr(), "error: --wait takes committed");
                    return ExitCode::from(2);
                }
            };
            if endpoint != "server" {
                let _ = writeln!(
                    std::io::stderr(),
                    "error: endpoint must be server or dir:PATH"
                );
                return ExitCode::from(2);
            }
            let mut flushed = flush_until(&cfg, dir.clone(), until).await;
            // --wait committed: retry while records stay pending (an outage, a dependency
            // not delivered yet), until the deadline; every request is bounded by it.
            while let (Ok((_, false)), Some(t)) = (&flushed, until) {
                let Some(left) = t
                    .checked_duration_since(std::time::Instant::now())
                    .filter(|l| !l.is_zero())
                else {
                    break;
                };
                tokio::time::sleep(left.min(std::time::Duration::from_secs(5))).await;
                if std::time::Instant::now() >= t {
                    break;
                }
                flushed = flush_until(&cfg, dir.clone(), until).await;
            }
            match flushed {
                Ok((sum, done)) => {
                    print_json(&sum);
                    if done {
                        ExitCode::SUCCESS
                    } else if until.is_some() {
                        ExitCode::from(4)
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(e) if e.is::<DeadlinePassed>() => {
                    let _ = writeln!(std::io::stderr(), "error: {e}");
                    // A worker may still wait for the journal lock: never wait for it.
                    std::process::exit(4);
                }
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "error: {e:#}");
                    ExitCode::from(2)
                }
            }
        }
        Command::Verdict {
            project,
            regression,
            mode,
            checklist,
            checklist_version,
            branch,
            expect_source,
            summary,
            summary_file,
            exceptions_fail,
            wait_processed,
            deadline,
            poll,
            publish_receipt,
            target_repository,
            target_commit,
            target_context,
        } => {
            if mode == "feature" {
                let (Some(checklist), Some(branch)) = (checklist, branch) else {
                    let _ = writeln!(
                        std::io::stderr(),
                        "error: --mode feature needs --checklist and --branch"
                    );
                    return ExitCode::from(2);
                };
                let code = dviscope_cli::verdict::run_feature(
                    &cfg,
                    &dviscope_cli::verdict::FeatureRequest {
                        project: &project,
                        checklist: &checklist,
                        version: checklist_version.as_deref(),
                        branch: &branch,
                        summary_file: summary_file.as_deref(),
                    },
                )
                .await;
                return ExitCode::from(code);
            }
            let Some(regression) = regression else {
                let _ = writeln!(std::io::stderr(), "error: --mode merge needs --regression");
                return ExitCode::from(2);
            };
            if mode != "merge" || !["log-free", "json", "markdown"].contains(&summary.as_str()) {
                let _ = writeln!(
                    std::io::stderr(),
                    "error: --mode merge|feature, --summary log-free|json|markdown"
                );
                return ExitCode::from(2);
            }
            let (deadline, poll) = match (
                dviscope_cli::verdict::parse_duration(&deadline),
                dviscope_cli::verdict::parse_duration(&poll),
            ) {
                (Ok(d), Ok(p)) => (d, p.max(std::time::Duration::from_secs(1))),
                (Err(e), _) | (_, Err(e)) => {
                    let _ = writeln!(std::io::stderr(), "error: {e}");
                    return ExitCode::from(2);
                }
            };
            let publish = match (publish_receipt, &target_repository, &target_commit) {
                (false, _, _) => None,
                (true, Some(r), Some(c)) => Some(dviscope_cli::verdict::Target {
                    repository: r,
                    commit: c,
                    context: &target_context,
                }),
                (true, _, _) => {
                    let _ = writeln!(
                        std::io::stderr(),
                        "error: --publish-receipt needs --target-repository and --target-commit"
                    );
                    return ExitCode::from(2);
                }
            };
            let code = dviscope_cli::verdict::run(
                &cfg,
                &dviscope_cli::verdict::Request {
                    project: &project,
                    regression: &regression,
                    expect_source: expect_source.as_deref(),
                    exceptions_pass: !exceptions_fail,
                    summary: &summary,
                    summary_file: summary_file.as_deref(),
                    wait_until: wait_processed.then(|| std::time::Instant::now() + deadline),
                    poll,
                    publish,
                },
            )
            .await;
            ExitCode::from(code)
        }
        Command::Import {
            action:
                ImportAction::Folder {
                    root,
                    manifest,
                    regression,
                    producer,
                    repository,
                    branch,
                    revision,
                    suite,
                    started_at,
                    journal,
                    submit,
                    packs,
                },
        } => {
            if submit && journal.is_none() {
                let _ = writeln!(std::io::stderr(), "error: --submit needs --journal DIR");
                return ExitCode::from(2);
            }
            let plan = dviscope_cli::import::ImportPlan {
                producer,
                regression,
                suite,
                repository,
                branch,
                revision,
                started_at,
            };
            let prepared = (|| -> anyhow::Result<serde_json::Value> {
                let p = rules::pipeline(&packs.packs, packs.no_default_packs)?;
                let opts = options(&packs)?;
                dviscope_cli::import::import_folder(
                    &root,
                    &manifest,
                    &plan,
                    &p,
                    &opts,
                    journal.as_deref().filter(|_| submit),
                )
            })();
            let mut out = match prepared {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "error: {e:#}");
                    return ExitCode::from(3);
                }
            };
            if !submit {
                print_json(&out);
                return ExitCode::SUCCESS;
            }
            let dir = journal.unwrap_or_default();
            // Deliver the runs, then close and finish, then deliver the finish.
            let delivered = async {
                let (first, done) = flush_to_server(&cfg, dir.clone()).await?;
                if !done {
                    return Ok::<_, anyhow::Error>((first, false));
                }
                dviscope_cli::import::finish_import(&dir, &plan.regression)?;
                let (last, done) = flush_to_server(&cfg, dir.clone()).await?;
                Ok((serde_json::json!({"runs": first, "finish": last}), done))
            };
            match delivered.await {
                Ok((sum, done)) => {
                    out["delivery"] = sum;
                    print_json(&out);
                    if done {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(4)
                    }
                }
                Err(e) => {
                    let _ = writeln!(std::io::stderr(), "error: {e:#}");
                    ExitCode::from(4)
                }
            }
        }
        Command::Ledger {
            action: LedgerAction::Export { project, out },
        } => match dviscope_cli::activation::export_ledger(&cfg, &project, &out).await {
            Ok(v) => {
                print_json(&v);
                ExitCode::SUCCESS
            }
            Err((code, reason)) => {
                let _ = writeln!(std::io::stderr(), "error: {reason}");
                ExitCode::from(code)
            }
        },
        Command::Ledger {
            action:
                LedgerAction::Import {
                    project,
                    file,
                    mapping,
                    dry_run,
                },
        } => match dviscope_cli::activation::import_ledger(
            &cfg,
            &project,
            &file,
            mapping.as_deref(),
            dry_run,
        )
        .await
        {
            Ok(v) => {
                print_json(&v);
                ExitCode::SUCCESS
            }
            Err((code, reason)) => {
                let _ = writeln!(std::io::stderr(), "error: {reason}");
                ExitCode::from(code)
            }
        },
        Command::Sample {
            action: SampleAction::Upload { project, dir },
        } => match dviscope_cli::activation::upload_sample(&cfg, &project, &dir).await {
            Ok(v) => {
                print_json(&v);
                ExitCode::SUCCESS
            }
            Err((code, reason)) => {
                let _ = writeln!(std::io::stderr(), "error: {reason}");
                ExitCode::from(code)
            }
        },
        Command::Rules {
            action:
                RulesAction::Import {
                    project,
                    packs,
                    no_default_packs,
                    sample,
                },
        } => match dviscope_cli::activation::import_rules(
            &cfg,
            &project,
            &packs,
            no_default_packs,
            &sample,
        )
        .await
        {
            Ok(v) => {
                print_json(&v);
                if v["activated"] == true {
                    ExitCode::SUCCESS
                } else {
                    let _ = writeln!(
                        std::io::stderr(),
                        "error: the check fails; nothing was activated"
                    );
                    ExitCode::from(3)
                }
            }
            Err((code, reason)) => {
                let _ = writeln!(std::io::stderr(), "error: {reason}");
                ExitCode::from(code)
            }
        },
        Command::Hierarchy {
            action:
                HierarchyAction::Import {
                    project,
                    dry_run,
                    file,
                },
        } => match dviscope_cli::verdict::import_hierarchy(&cfg, &project, &file, dry_run).await {
            Ok(v) => {
                print_json(&v);
                ExitCode::SUCCESS
            }
            Err((code, reason)) => {
                let _ = writeln!(std::io::stderr(), "error: {reason}");
                ExitCode::from(code)
            }
        },
        Command::Checklist {
            action: ChecklistAction::Import { project, file },
        } => match dviscope_cli::verdict::import_checklist(&cfg, &project, &file).await {
            Ok(v) => {
                print_json(&v);
                ExitCode::SUCCESS
            }
            Err((code, reason)) => {
                let _ = writeln!(std::io::stderr(), "error: {reason}");
                ExitCode::from(code)
            }
        },
        Command::Journal {
            action: JournalAction::Reconcile { dir },
        } => match dviscope_cli::reconcile::run(&cfg, &dir).await {
            Ok(r) => {
                print_json(&r);
                if r["ok"] == true {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(10)
                }
            }
            Err((code, msg)) => {
                let _ = writeln!(std::io::stderr(), "error: {msg}");
                ExitCode::from(code)
            }
        },
        Command::Doctor {
            server,
            assurance: Some(project),
            pilot,
            reconcile,
        } => {
            let (mut report, mut ok) = doctor::run_with(&cfg, server, pilot).await;
            ok &= reconcile_into(&cfg, &reconcile, &mut report).await;
            match dviscope_cli::verdict::call(
                &cfg,
                reqwest::Method::GET,
                &project,
                &["admin"],
                &[],
                None,
            )
            .await
            {
                Ok(o) => {
                    report["assurance"] = serde_json::json!(o["producers"]
                        .as_array()
                        .map(|a| a
                            .iter()
                            .map(|p| serde_json::json!({"producer": p["name"], "profile": p["assurance"]}))
                            .collect::<Vec<_>>())
                        .unwrap_or_default());
                }
                Err((_, reason)) => {
                    report["assurance"] = serde_json::json!({"error": reason});
                    ok = false;
                }
            }
            print_json(&report);
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(4)
            }
        }
        Command::Doctor {
            server,
            pilot,
            reconcile,
            ..
        } => {
            let (mut report, mut ok) = doctor::run_with(&cfg, server, pilot).await;
            ok &= reconcile_into(&cfg, &reconcile, &mut report).await;
            print_json(&report);
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(4)
            }
        }
        _ => ExitCode::from(2),
    }
}
