//! `dviscope run`: supervised execution journalled before, during and after the child. A failing simulation never makes `run` fail; recovery
//! turns an interrupted attempt into termination `unknown`, never a pass.

use std::io::Seek as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use dviscope_core::extract::ExtractOptions;
use dviscope_core::packs::Pipeline;
use dviscope_model::ids::ExternalKey;
use dviscope_model::schema::INGEST;
use dviscope_model::values::{Measure, SafeU64, UtcTime};
use dviscope_model::wire::evidence::Evidence;
use dviscope_model::wire::ingest::{
    AttemptResult, AttemptStarted, CpuScope, IngestRecord, PeakScope, Purpose, Runner,
    SimulationAttempt, Termination, TerminationKind,
};
use dviscope_model::wire::manifest::ExecInputs;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::crash;
use crate::journal::{Journal, kind};
use crate::platform::{self, Ended};

/// What the adapter knows about the attempt before it starts (`--launch FILE`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    /// Producer.
    pub producer_id: ExternalKey,
    /// Regression.
    pub regression_ref: ExternalKey,
    /// Slot.
    pub slot_ref: ExternalKey,
    /// Attempt reference (unique per attempt).
    pub attempt_ref: ExternalKey,
    /// Build attempts used, one per build requirement.
    #[serde(default)]
    pub build_refs: Vec<ExternalKey>,
    /// Source manifest.
    pub source_manifest_ref: ExternalKey,
    /// Exact execution inputs.
    pub execution: ExecInputs,
    /// Journal entries the attempt's records depend on (e.g. its manifest chunk).
    #[serde(default)]
    pub depends_on: Vec<u64>,
}

/// Options of a supervised run.
#[derive(Debug)]
pub struct RunOptions<'a> {
    /// Program and arguments.
    pub argv: &'a [String],
    /// Timeout.
    pub timeout: Option<Duration>,
    /// Grace period.
    pub grace: Duration,
    /// Console capture file.
    pub console: Option<&'a Path>,
    /// The log to extract after the run.
    pub log: Option<&'a Path>,
    /// Extraction options (simulator, source roots).
    pub extract: ExtractOptions,
}

fn utc_now() -> UtcTime {
    UtcTime::new(time::OffsetDateTime::now_utc())
}

fn measure(v: f64) -> Option<Measure> {
    Measure::try_from(format!("{v:.3}")).ok()
}

fn runner_from(facts: &platform::Facts, started: UtcTime, timeout: Option<Duration>) -> Runner {
    let kind = match facts.ended {
        Ended::Exited => TerminationKind::Exited,
        Ended::Timeout => TerminationKind::Timeout,
        Ended::External => TerminationKind::TerminatedExternally,
        Ended::Crash => TerminationKind::Crash,
    };
    Runner {
        termination: Termination {
            kind,
            exit_code: facts.exit_code,
            posix_signal: facts.posix_signal,
            windows_status: facts.windows_status.clone(),
        },
        started_at: started,
        finished_at: Some(utc_now()),
        wall_s: measure(facts.wall_s),
        timeout_s: timeout.and_then(|t| measure(t.as_secs_f64())),
        cpu_s: facts.cpu.and_then(|(c, _)| measure(c)),
        cpu_scope: facts.cpu.map(|(_, s)| match s {
            "job" => CpuScope::Job,
            _ => CpuScope::ProcessAndWaitedChildren,
        }),
        peak_rss_kb: facts.peak_kb.map(SafeU64::saturating),
        peak_scope: facts.peak_kb.map(|_| PeakScope::LargestProcess),
        host: None,
    }
}

/// Whether execution inputs declare a Verilator model with its own C++ main
/// (`extra.tool.main = "model"`; plan F2). Any other value is refused.
///
/// # Errors
/// A value other than `model`.
pub fn declares_model_main(exec: &ExecInputs) -> Result<bool> {
    dviscope_core::model_main::declares(exec).map_err(|m| anyhow::anyhow!(m))
}

/// Bytes read per chunk from an attempt's files.
const CHUNK: usize = 64 * 1024;

/// Evidence of a model with its own main: the program log, then the console, read through
/// the handles the collector created (rewound), never reopened by path.
///
/// # Errors
/// Reading either file.
pub fn evidence_joined(
    p: &Pipeline,
    mut opts: ExtractOptions,
    log_name: &str,
    program: &mut impl std::io::Read,
    console: &mut impl std::io::Read,
) -> Result<Evidence> {
    opts.model_main = true;
    opts.log_name = log_name.to_string();
    let mut x = dviscope_core::extract::Extractor::new(p, opts);
    let mut buf = vec![0u8; CHUNK];
    for (n, f) in [program as &mut dyn std::io::Read, console]
        .into_iter()
        .enumerate()
    {
        if n == 1 {
            x.begin_console();
        }
        loop {
            let k = f.read(&mut buf).context("reading the attempt's files")?;
            if k == 0 {
                break;
            }
            x.push(&buf[..k]);
        }
    }
    Ok(x.finish())
}

/// Unix: the path still names the file the collector created (not replaced since).
#[cfg(unix)]
fn same_file(f: &std::fs::File, path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let (a, b) = (f.metadata()?, std::fs::metadata(path)?);
    Ok(a.dev() == b.dev() && a.ino() == b.ino())
}

/// Windows: the collector's handle refuses deletion and renaming while it is held, so
/// the path cannot name another file.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // same signature as the Unix check
fn same_file(_f: &std::fs::File, _path: &Path) -> Result<bool> {
    Ok(true)
}

/// Evidence of one log read from `reader` (the collector's own handle).
fn evidence_from(
    p: &Pipeline,
    mut opts: ExtractOptions,
    log_name: &str,
    reader: &mut impl std::io::Read,
) -> Result<Evidence> {
    if opts.log_name.is_empty() {
        opts.log_name = log_name.to_string();
    }
    let mut x = dviscope_core::extract::Extractor::new(p, opts);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let k = reader.read(&mut buf).context("reading the attempt's log")?;
        if k == 0 {
            break;
        }
        x.push(&buf[..k]);
    }
    Ok(x.finish())
}

fn evidence(p: &Pipeline, mut opts: ExtractOptions, log: Option<&Path>) -> Result<Evidence> {
    match log {
        Some(l) if l.exists() => Ok(crate::rules::extract_file(p, opts, l)?.0),
        // No log: empty evidence (completion `missing`, outcome row 4).
        _ => {
            opts.log_name = log
                .and_then(|l| l.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(dviscope_core::extract::extract_bytes(p, opts, b"").0)
        }
    }
}

/// The report ID of an attempt's first report: `<attempt_ref>:r1`, or, when that would
/// exceed the key length, a bounded deterministic form (a prefix of the reference and a
/// hash of all of it). Always a valid key.
///
/// # Errors
/// Never for a valid attempt reference.
pub fn report_id(attempt_ref: &ExternalKey) -> Result<ExternalKey> {
    const PREFIX: usize = 160;
    const HASH_HEX: usize = 32;
    let a = attempt_ref.as_str();
    // A reference that already has the shortened form's shape is shortened too, so a
    // short image never equals a shortened one (the mapping is injective up to a 128-bit
    // hash collision).
    let shaped_like_long = a.len() == PREFIX + 1 + HASH_HEX
        && a.as_bytes()[PREFIX] == b'+'
        && a[PREFIX + 1..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    let id = if a.len() + 3 <= ExternalKey::MAX_LEN && !shaped_like_long {
        format!("{a}:r1")
    } else {
        let h = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(a.as_bytes()));
        format!("{}+{}:r1", &a[..PREFIX], &h[..HASH_HEX])
    };
    ExternalKey::try_from(id).map_err(|e| anyhow::anyhow!("{e}"))
}

/// The journal identity of an attempt's report (the server's receipt identity).
///
/// # Errors
/// See [`report_id`].
pub fn report_identity(attempt_ref: &ExternalKey) -> Result<String> {
    Ok(format!(
        "simulation_attempt:{}",
        report_id(attempt_ref)?.as_str()
    ))
}

fn envelope(spec: &LaunchSpec, attempt_seq: u32, runner: Runner, ev: Evidence) -> Result<Value> {
    let report_id = report_id(&spec.attempt_ref)?;
    let rec = IngestRecord::SimulationAttempt(Box::new(SimulationAttempt {
        schema: INGEST.to_string(),
        producer_id: spec.producer_id.clone(),
        report_id,
        report_revision: 1,
        regression_ref: spec.regression_ref.clone(),
        slot_ref: spec.slot_ref.clone(),
        attempt_ref: spec.attempt_ref.clone(),
        attempt_seq,
        build_refs: spec.build_refs.clone(),
        source_manifest_ref: spec.source_manifest_ref.clone(),
        execution: spec.execution.clone(),
        result: AttemptResult {
            outcome_reported: None,
            runner,
        },
        evidence: ev,
        artifacts: vec![],
        purpose: Purpose::Production,
        experiment_ref: None,
        rerun_of: None,
        ext: dviscope_model::wire::Ext::default(),
    }));
    Ok(serde_json::to_value(rec)?)
}

/// The dependencies of a launch: those the spec names, plus the regression, the manifest
/// chunks and the amendments of its regression held by this journal (the server refuses an
/// attempt of an undeclared slot, so the start is never sent before what declares it).
fn launch_deps(j: &Journal, spec: &LaunchSpec) -> Result<Vec<u64>> {
    let r = spec.regression_ref.as_str();
    let chunk_prefix = format!("manifest_chunk:{r}/");
    let amend_prefix = format!("manifest_amend:{r}/");
    let regression = format!("regression:{r}");
    let mut deps = spec.depends_on.clone();
    for e in j.intact()? {
        let Some(id) = e.identity.as_deref() else {
            continue;
        };
        if (e.kind == kind::MANIFEST_CHUNK && id.starts_with(&chunk_prefix))
            || (e.kind == kind::MANIFEST_AMEND && id.starts_with(&amend_prefix))
            || (e.kind == kind::REGRESSION_CREATE && id == regression)
        {
            deps.push(e.seq);
        }
    }
    deps.sort_unstable();
    deps.dedup();
    Ok(deps)
}

/// Runs one attempt supervised and journals it. Returns a JSON summary.
///
/// # Errors
/// Journal I/O, a closed journal, or a command that could not be started (journalled as
/// an `unknown` termination first).
pub fn run(j: &Journal, spec: &LaunchSpec, p: &Pipeline, o: RunOptions<'_>) -> Result<Value> {
    // Everything derived later is validated before anything is launched.
    let identity = report_identity(&spec.attempt_ref)?;
    let mut extract = o.extract.clone();
    extract.model_main = declares_model_main(&spec.execution)?;
    if extract.model_main {
        if o.log.is_none() || o.console.is_none() {
            bail!(
                "a model with its own main (extra.tool.main = \"model\") needs --log (its program log) and --console"
            );
        }
        if extract
            .simulator
            .as_deref()
            .is_some_and(|s| s != "verilator")
        {
            bail!("a model with its own main is a Verilator model: --simulator verilator or none");
        }
    }
    let supervisor_start = platform::process_identity(std::process::id())
        .context("the supervisor's start identity is unavailable (recovery needs it)")?;
    let started = utc_now();
    let launch = j.locked(|j| {
        if j.closed()? {
            bail!("launches are closed in this journal (closure or finish written)");
        }
        j.check_may_launch()?;
        // The attempt owns its log and console paths exclusively: each is created here
        // (refused if it exists), so no earlier or concurrent execution can write the
        // file that becomes this attempt's evidence, and the handles are kept: the console
        // is handed to the child as this handle, and a model's files are read back through
        // them. One attempt may use one path for both, except a model with its own main
        // (two streams). A tool that never writes its log leaves it empty (no log).
        let mut owned: Vec<(std::path::PathBuf, std::fs::File)> = vec![];
        for (what, path) in [("log", o.log), ("console", o.console)] {
            let Some(path) = path else { continue };
            let abs = std::path::absolute(path)?;
            if owned.iter().any(|(a, _)| *a == abs) {
                if extract.model_main {
                    bail!("a model with its own main needs distinct --log and --console files");
                }
                continue;
            }
            let mut oo = std::fs::OpenOptions::new();
            oo.read(true).write(true).create_new(true);
            #[cfg(windows)]
            {
                // No delete or rename while the collector holds it (FILE_SHARE_READ |
                // FILE_SHARE_WRITE): the path keeps naming this file, for every run. A tool writes its log in place.
                use std::os::windows::fs::OpenOptionsExt as _;
                oo.share_mode(0x1 | 0x2);
            }
            let f = oo.open(path).with_context(|| {
                format!(
                    "the {what} file {} exists or cannot be created: give each attempt fresh paths",
                    path.display()
                )
            })?;
            owned.push((abs, f));
        }
        let attempt_seq = j.next_attempt_seq(spec.slot_ref.as_str())?;
        let started_rec = IngestRecord::AttemptStarted(AttemptStarted {
            schema: INGEST.to_string(),
            producer_id: spec.producer_id.clone(),
            regression_ref: spec.regression_ref.clone(),
            slot_ref: spec.slot_ref.clone(),
            attempt_ref: spec.attempt_ref.clone(),
            attempt_seq,
            build_refs: spec.build_refs.clone(),
            started_at: started,
            purpose: Purpose::Production,
            experiment_ref: None,
            rerun_of: None,
        });
        let seq = j.append(
            kind::LAUNCH,
            Some(format!("attempt_started:{}", spec.attempt_ref.as_str())),
            Some(json!({
                "slot_ref": spec.slot_ref.as_str(),
                "attempt_seq": attempt_seq,
                "started_at": started,
                "supervisor_pid": std::process::id(),
                "supervisor_start": supervisor_start,
                "spec": spec,
                "deliver": started_rec,
            })),
            launch_deps(j, spec)?,
            None,
        )?;
        Ok((seq, attempt_seq, owned))
    })?;
    let (launch, attempt_seq, mut owned) = (launch.0, launch.1, launch.2);
    let handle_of = |path: Option<&Path>| -> Result<Option<usize>> {
        Ok(match path {
            Some(p) => {
                let abs = std::path::absolute(p)?;
                owned.iter().position(|(a, _)| *a == abs)
            }
            None => None,
        })
    };
    let (log_ix, console_ix) = (handle_of(o.log)?, handle_of(o.console)?);
    crash::point("after_launch");
    let spec_run = platform::Spec {
        argv: o.argv,
        cwd: None,
        timeout: o.timeout,
        grace: o.grace,
        console: console_ix.map(|i| &owned[i].1),
    };
    // The child entry is written by a helper thread: waiting for the journal lock (a flush
    // may hold it) never delays timeout enforcement. It is joined before the runner facts
    // are written, so the child entry always precedes them.
    let ran = std::thread::scope(|scope| {
        let mut writer = None;
        let r = platform::run(&spec_run, &mut |pid: u32, start: Option<String>| {
            crash::point("after_spawn");
            writer = Some(scope.spawn(move || {
                j.locked(|j| {
                    j.append(
                        kind::CHILD,
                        None,
                        Some(json!({"launch": launch, "pid": pid, "start": start, "spawned_at": utc_now()})),
                        vec![launch],
                        None,
                    )
                })
            }));
        });
        let child_entry = writer.map(|w| w.join());
        (r, child_entry)
    });
    let (ran, child_entry) = ran;
    if let Some(Ok(Err(e))) = &child_entry {
        eprintln!("warning: the child entry was not journalled: {e:#}");
    }
    let facts = match ran {
        Ok(f) => f,
        Err(e) => {
            // Not started: recorded as interrupted (never a pass), then reported.
            recover(j, p, &extract)?;
            return Err(e).context("starting the command");
        }
    };
    crash::point("after_exit");
    let mut runner = runner_from(&facts, started, o.timeout);
    let mut replaced: Option<std::path::PathBuf> = None;
    let ev = match (extract.model_main, log_ix, console_ix, o.log, o.console) {
        (true, Some(li), Some(ci), Some(lp), Some(cp)) => {
            for (i, path) in [(li, lp), (ci, cp)] {
                // Moved away, deleted or uninspectable counts as replaced.
                if !same_file(&owned[i].1, path).unwrap_or(false) {
                    replaced = Some(path.to_path_buf());
                }
            }
            if replaced.is_some() {
                // Replaced after it was created: not this attempt's evidence. Recorded as
                // interrupted (termination unknown, evidence of a missing log), never a pass.
                runner.termination = Termination {
                    kind: TerminationKind::Unknown,
                    exit_code: None,
                    posix_signal: None,
                    windows_status: None,
                };
                evidence(p, extract.clone(), None)?
            } else {
                joined_from(p, &extract, &mut owned, (li, lp), ci)?
            }
        }
        (false, Some(li), _, Some(lp), _) => {
            // Every run's log is read through the handle the collector created, and only if
            // the path still names that file: a log replaced during the attempt (an earlier
            // run's, say) is never this attempt's evidence.
            if same_file(&owned[li].1, lp).unwrap_or(false) {
                let name = lp
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let f = &mut owned[li].1;
                f.rewind()?;
                evidence_from(p, extract.clone(), &name, f)?
            } else {
                replaced = Some(lp.to_path_buf());
                runner.termination = Termination {
                    kind: TerminationKind::Unknown,
                    exit_code: None,
                    posix_signal: None,
                    windows_status: None,
                };
                evidence(p, extract.clone(), None)?
            }
        }
        _ => evidence(p, extract.clone(), o.log)?,
    };
    let env = envelope(spec, attempt_seq, runner.clone(), ev)?;
    let env_seq = j.locked(|j| {
        j.append(
            kind::RUNNER_RESULT,
            None,
            Some(json!({"launch": launch, "runner": runner, "unreaped": facts.unreaped})),
            vec![launch],
            None,
        )?;
        j.append(
            kind::ENVELOPE,
            Some(identity.clone()),
            Some(json!({"launch": launch})),
            std::iter::once(launch)
                .chain(spec.depends_on.iter().copied())
                .collect(),
            Some(&serde_json::to_vec(&env)?),
        )
    })?;
    if let Some(path) = replaced {
        bail!(
            "{} was replaced during the attempt: recorded as interrupted",
            path.display()
        );
    }
    Ok(json!({
        "state": "spooled",
        "attempt_seq": attempt_seq,
        "launch": launch,
        "envelope": env_seq,
        "termination": runner.termination,
        "wall_s": runner.wall_s,
        "unreaped": facts.unreaped,
    }))
}

/// The joined evidence of a model with its own main, read through the collector's handles.
fn joined_from(
    p: &Pipeline,
    extract: &ExtractOptions,
    owned: &mut [(std::path::PathBuf, std::fs::File)],
    (li, lp): (usize, &Path),
    ci: usize,
) -> Result<Evidence> {
    let name = lp
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (a, b) = owned.split_at_mut(li.max(ci));
    let (lf, cf) = if li < ci {
        (&mut a[li].1, &mut b[0].1)
    } else {
        (&mut b[0].1, &mut a[ci].1)
    };
    lf.rewind()?;
    cf.rewind()?;
    evidence_joined(p, extract.clone(), &name, lf, cf)
}

/// Journals one run that already ended elsewhere (`collect`, the folder importer): its
/// launch, its runner facts and its envelope, under the writer lock. The launch obeys the
/// same guards as a supervised one (closure; a participant journal registered with its
/// coordinator). An attempt whose envelope is journalled is left as it is; one interrupted
/// between its writes (launch without envelope) is completed with its original attempt
/// sequence when the same launch is collected again.
///
/// # Errors
/// Journal I/O, a closed or unregistered journal, another launch under this attempt
/// reference, or an invalid attempt reference.
pub fn import_attempt(
    j: &Journal,
    spec: &LaunchSpec,
    runner: Runner,
    ev: Evidence,
) -> Result<Value> {
    let identity = report_identity(&spec.attempt_ref)?;
    let launch_identity = format!("attempt_started:{}", spec.attempt_ref.as_str());
    j.locked(|j| {
        let entries = j.intact()?;
        let existing = entries
            .iter()
            .find(|e| e.kind == kind::LAUNCH && e.identity.as_deref() == Some(&launch_identity));
        let (launch, attempt_seq, resumed) = match existing {
            Some(l) => {
                if entries
                    .iter()
                    .any(|e| e.kind == kind::ENVELOPE && e.identity.as_deref() == Some(&identity))
                {
                    return Ok(json!({"state": "existing", "launch": l.seq}));
                }
                // Interrupted between its writes: complete it, only if it is this import
                // (a supervised launch recovers through `journal recover`), with the same
                // inputs as when it was journalled.
                let rec = l.record.as_ref().context("launch without record")?;
                if rec["imported"] != true {
                    bail!(
                        "attempt {} is a supervised launch: recover it with `journal recover`",
                        spec.attempt_ref.as_str()
                    );
                }
                if rec["spec"] != serde_json::to_value(spec)?
                    || rec["runner"] != serde_json::to_value(&runner)?
                    || rec["evidence"] != json!(evidence_digest(&ev)?)
                {
                    bail!(
                        "attempt {} was collected with other inputs (specification, run facts or log)",
                        spec.attempt_ref.as_str()
                    );
                }
                let seq = u32::try_from(rec["attempt_seq"].as_u64().unwrap_or(0))?;
                (l.seq, seq, true)
            }
            None => {
                if j.closed()? {
                    bail!("launches are closed in this journal (closure or finish written)");
                }
                j.check_may_launch()?;
                let attempt_seq = j.next_attempt_seq(spec.slot_ref.as_str())?;
                let started_rec = IngestRecord::AttemptStarted(AttemptStarted {
                    schema: INGEST.to_string(),
                    producer_id: spec.producer_id.clone(),
                    regression_ref: spec.regression_ref.clone(),
                    slot_ref: spec.slot_ref.clone(),
                    attempt_ref: spec.attempt_ref.clone(),
                    attempt_seq,
                    build_refs: spec.build_refs.clone(),
                    started_at: runner.started_at,
                    purpose: Purpose::Production,
                    experiment_ref: None,
                    rerun_of: None,
                });
                let launch = j.append(
                    kind::LAUNCH,
                    Some(launch_identity.clone()),
                    Some(json!({
                        "slot_ref": spec.slot_ref.as_str(),
                        "attempt_seq": attempt_seq,
                        "started_at": runner.started_at,
                        "imported": true,
                        "spec": spec,
                        "runner": runner,
                        "evidence": evidence_digest(&ev)?,
                        "deliver": started_rec,
                    })),
                    launch_deps(j, spec)?,
                    None,
                )?;
                crash::point("import_after_launch");
                (launch, attempt_seq, false)
            }
        };
        let has_runner = j.intact()?.iter().any(|e| {
            e.kind == kind::RUNNER_RESULT
                && e.record.as_ref().is_some_and(|r| r["launch"] == launch)
        });
        if !has_runner {
            j.append(
                kind::RUNNER_RESULT,
                None,
                Some(json!({"launch": launch, "runner": runner, "unreaped": null})),
                vec![launch],
                None,
            )?;
            crash::point("import_after_runner");
        }
        let env = envelope(spec, attempt_seq, runner, ev)?;
        let env_seq = j.append(
            kind::ENVELOPE,
            Some(identity.clone()),
            Some(json!({"launch": launch})),
            std::iter::once(launch)
                .chain(spec.depends_on.iter().copied())
                .collect(),
            Some(&serde_json::to_vec(&env)?),
        )?;
        Ok(
            json!({"state": "spooled", "attempt_seq": attempt_seq, "launch": launch,
                  "envelope": env_seq, "resumed": resumed}),
        )
    })
}

/// The digest an import binds its evidence to (a retry must extract the same).
fn evidence_digest(ev: &Evidence) -> Result<String> {
    Ok(dviscope_model::canonical::digest_of(ev)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .as_str()
        .to_string())
}

/// Recovery: every launch without runner facts whose child is gone gets termination
/// `unknown` and an envelope (evidence of a missing log). Never relaunches anything.
///
/// # Errors
/// Journal I/O.
pub fn recover(j: &Journal, p: &Pipeline, opts: &ExtractOptions) -> Result<Value> {
    j.locked(|j| {
        let rec = j.recover()?;
        let entries: Vec<_> = j.entries()?.into_iter().flatten().collect();
        let mut envelopes = vec![];
        let mut errors = vec![];
        for launch in entries.iter().filter(|e| e.kind == kind::LAUNCH) {
            match recover_envelope(j, p, opts, &entries, launch) {
                Ok(Some(seq)) => envelopes.push(seq),
                Ok(None) => {}
                // One launch's problem never stops the recovery of the others.
                Err(e) => errors.push(json!({"launch": launch.seq, "error": format!("{e:#}")})),
            }
        }
        Ok(json!({
            "recovered": rec.recovered,
            "live_orphans": rec.live_orphans,
            "unverifiable": rec.unverifiable,
            "envelopes": envelopes,
            "errors": errors,
        }))
    })
}

fn recover_envelope(
    j: &Journal,
    p: &Pipeline,
    opts: &ExtractOptions,
    entries: &[crate::journal::Entry],
    launch: &crate::journal::Entry,
) -> Result<Option<u64>> {
    {
        {
            let has_envelope = entries.iter().any(|e| {
                e.kind == kind::ENVELOPE
                    && e.record.as_ref().is_some_and(|r| r["launch"] == launch.seq)
            });
            let result = entries.iter().find(|e| {
                e.kind == kind::RUNNER_RESULT
                    && e.record.as_ref().is_some_and(|r| r["launch"] == launch.seq)
            });
            let (Some(result), false) = (result, has_envelope) else {
                return Ok(None);
            };
            let rec = launch.record.as_ref().context("launch without record")?;
            let spec: LaunchSpec = serde_json::from_value(rec["spec"].clone())?;
            let attempt_seq = u32::try_from(rec["attempt_seq"].as_u64().unwrap_or(0)).unwrap_or(0);
            let runner: Runner = match result.record.as_ref().map(|r| r["runner"].clone()) {
                Some(v) if v["termination"]["kind"] == "unknown" => Runner {
                    termination: Termination {
                        kind: TerminationKind::Unknown,
                        exit_code: None,
                        posix_signal: None,
                        windows_status: None,
                    },
                    started_at: serde_json::from_value(rec["started_at"].clone())?,
                    finished_at: None,
                    wall_s: None,
                    timeout_s: None,
                    cpu_s: None,
                    cpu_scope: None,
                    peak_rss_kb: None,
                    peak_scope: None,
                    host: None,
                },
                Some(v) => serde_json::from_value(v)?,
                None => return Ok(None),
            };
            // The log is not re-read after an interruption: evidence of a missing log, under
            // the profile the slot declares (the server checks the two agree).
            let mut opts = opts.clone();
            opts.model_main = declares_model_main(&spec.execution).unwrap_or(false);
            let ev = evidence(p, opts, None)?;
            let env = envelope(&spec, attempt_seq, runner, ev)?;
            let seq = j.append(
                kind::ENVELOPE,
                Some(report_identity(&spec.attempt_ref)?),
                Some(json!({"launch": launch.seq, "recovered": true})),
                std::iter::once(launch.seq)
                    .chain(spec.depends_on.iter().copied())
                    .collect(),
                Some(&serde_json::to_vec(&env)?),
            )?;
            Ok(Some(seq))
        }
    }
}
