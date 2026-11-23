//! `dviscope import folder`: a folder of logs from a
//! finished regression and a CSV of its expected jobs become a regression, without
//! installing anything on compute nodes. It starts with a **preview** (what each row maps
//! to, missing metadata, unreadable logs, failures without diagnostics, duplicate
//! identities); `--submit` journals the regression, its manifest (the CSV is the expected
//! set: a row without a log is an expected job that did not report), every run and the
//! finish, so a second import adds nothing.
//!
//! Confinement: the root is opened with cap-std; every log is opened beneath it (symlink
//! and junction escapes refused), non-blocking on Unix (a FIFO cannot block), checked to be
//! a regular file through the same handle and read from it. CSV paths use a portable
//! grammar. Output never contains log text.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use dviscope_core::extract::{ExtractOptions, Extractor};
use dviscope_core::packs::Pipeline;
use dviscope_model::ids::ExternalKey;
use dviscope_model::schema::{INGEST, MANIFEST};
use dviscope_model::wire::evidence::Evidence;
use dviscope_model::wire::ingest::Runner;
use serde_json::{Value, json};

use crate::collect;
use crate::journal::Journal;
use crate::run::{LaunchSpec, import_attempt};

/// Slots per manifest chunk.
const CHUNK_SLOTS: usize = 500;
/// Mappings shown in the preview.
const PREVIEW_ROWS: usize = 5;
/// Read chunk size.
const READ_CHUNK: usize = 64 * 1024;

/// One CSV row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// 1-based line in the CSV.
    pub line: usize,
    /// Slot key.
    pub slot: String,
    /// Test name.
    pub test: String,
    /// Seed.
    pub seed: String,
    /// Log path under the root (portable grammar); none: the job did not report.
    pub log: Option<String>,
    /// Exit code; none: unknown (the termination is recorded as unknown).
    pub exit_code: Option<i32>,
    /// Start (RFC 3339).
    pub started_at: Option<String>,
    /// End (RFC 3339).
    pub finished_at: Option<String>,
    /// Required by readiness (default true).
    pub required: bool,
    /// A Verilator model with its own C++ main (`main` = `model`): the slot declares it and
    /// the evidence joins the program log (`log`) and the console capture (`console`).
    pub model_main: bool,
    /// The console capture under the root (only with `main` = `model`).
    pub console: Option<String>,
}

const COLUMNS: &[&str] = &[
    "slot",
    "test",
    "seed",
    "log",
    "exit_code",
    "started_at",
    "finished_at",
    "required",
    "main",
    "console",
];
const REQUIRED_COLUMNS: &[&str] = &["slot", "test", "seed", "log", "exit_code"];

/// Splits one CSV line (RFC 4180 quoting: `"a,b"`, `""` for a quote).
fn fields(line: &str) -> Result<Vec<String>> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (false, '"') if cur.is_empty() => quoted = true,
            (false, ',') => out.push(std::mem::take(&mut cur)),
            (_, c) => cur.push(c),
        }
    }
    if quoted {
        bail!("an unterminated quote");
    }
    out.push(cur);
    Ok(out.into_iter().map(|f| f.trim().to_string()).collect())
}

/// Parses the CSV: UTF-8 (optional BOM), LF or CRLF, a header naming the columns.
///
/// # Errors
/// UTF-16, invalid UTF-8, a missing or unknown column, a malformed row (named by line).
pub fn parse_csv(bytes: &[u8]) -> Result<Vec<Row>> {
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) || bytes.contains(&0) {
        bail!("the CSV is UTF-16: save it as UTF-8");
    }
    let text = std::str::from_utf8(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes))
        .context("the CSV is not UTF-8")?;
    let mut lines = text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty());
    let Some((_, header)) = lines.next() else {
        bail!("the CSV is empty");
    };
    let header = fields(header)?;
    for h in &header {
        if !COLUMNS.contains(&h.as_str()) {
            bail!("unknown column {h:?} (columns: {})", COLUMNS.join(", "));
        }
    }
    for r in REQUIRED_COLUMNS {
        if !header.iter().any(|h| h == r) {
            bail!("the CSV needs a {r} column");
        }
    }
    let col = |name: &str| header.iter().position(|h| h == name);
    let mut rows = vec![];
    for (i, line) in lines {
        let n = i + 1;
        let f = fields(line).with_context(|| format!("line {n}"))?;
        if f.len() != header.len() {
            bail!(
                "line {n}: {} fields, the header has {}",
                f.len(),
                header.len()
            );
        }
        let get = |name: &str| col(name).map(|c| f[c].clone()).filter(|v| !v.is_empty());
        let slot = get("slot").with_context(|| format!("line {n}: slot is required"))?;
        let test = get("test").with_context(|| format!("line {n}: test is required"))?;
        let exit_code = match get("exit_code") {
            Some(v) => Some(
                v.parse::<i32>()
                    .with_context(|| format!("line {n}: exit_code is an integer"))?,
            ),
            None => None,
        };
        let required = match get("required").as_deref() {
            None | Some("true" | "yes" | "1") => true,
            Some("false" | "no" | "0") => false,
            Some(v) => bail!("line {n}: required is true or false, not {v:?}"),
        };
        let log = get("log");
        if let Some(p) = &log {
            check_path(p).map_err(|e| anyhow::anyhow!("line {n}: log path {p:?}: {e}"))?;
        }
        let model_main = match get("main").as_deref() {
            None => false,
            Some("model") => true,
            Some(v) => bail!("line {n}: main is model or empty, not {v:?}"),
        };
        let console = get("console");
        if let Some(c) = &console {
            check_path(c).map_err(|e| anyhow::anyhow!("line {n}: console path {c:?}: {e}"))?;
        }
        match (model_main, &log, &console) {
            (false, _, Some(_)) => {
                bail!("line {n}: a console column is only for main = model (its own main)")
            }
            (true, Some(l), Some(c)) if l == c => {
                bail!("line {n}: main = model needs distinct log and console files")
            }
            (true, Some(_), None) => {
                bail!("line {n}: main = model needs the console capture (console column)")
            }
            _ => {}
        }
        rows.push(Row {
            line: n,
            slot,
            test,
            seed: get("seed").unwrap_or_default(),
            log,
            exit_code,
            started_at: get("started_at"),
            finished_at: get("finished_at"),
            required,
            model_main,
            console,
        });
    }
    if rows.is_empty() {
        bail!("the CSV has no rows");
    }
    Ok(rows)
}

/// The portable path grammar: `/`-separated, relative, no empty, `.` or `..` components,
/// no `:` or `\`, no reserved device names, no control characters, no trailing dot or
/// space in a component.
///
/// # Errors
/// What is wrong.
pub fn check_path(p: &str) -> std::result::Result<(), &'static str> {
    if p.starts_with('/') {
        return Err("a path is relative to the root (no leading /)");
    }
    if p.contains(':') || p.contains('\\') {
        return Err("no ':' or '\\' (portable paths use '/')");
    }
    if p.chars().any(char::is_control) {
        return Err("no control characters");
    }
    for c in p.split('/') {
        if c.is_empty() || c == "." || c == ".." {
            return Err("no empty, '.' or '..' components");
        }
        if c.ends_with('.') || c.ends_with(' ') {
            return Err("no component ending in a dot or a space");
        }
        let stem = c.split('.').next().unwrap_or("").to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ((stem.starts_with("COM") || stem.starts_with("LPT"))
                && stem.len() == 4
                && stem.as_bytes()[3].is_ascii_digit());
        if reserved {
            return Err("a reserved device name");
        }
    }
    Ok(())
}

/// Opens a log beneath the root: confined, non-blocking on Unix, a regular file only.
fn open_log(root: &Dir, path: &str) -> std::io::Result<cap_std::fs::File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        #[cfg(target_os = "linux")]
        const O_NONBLOCK: i32 = 0o4000;
        #[cfg(not(target_os = "linux"))]
        const O_NONBLOCK: i32 = 0x0004;
        o.custom_flags(O_NONBLOCK);
    }
    let f = root.open_with(path, &o)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(f)
}

fn extract(
    p: &Pipeline,
    opts: ExtractOptions,
    mut f: cap_std::fs::File,
) -> std::io::Result<Evidence> {
    let mut x = Extractor::new(p, opts);
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        x.push(&buf[..n]);
    }
    Ok(x.finish_with_trace().0)
}

/// What an import needs besides the rows.
#[derive(Debug, Clone)]
pub struct ImportPlan {
    /// Producer (the collector token's).
    pub producer: String,
    /// Regression reference.
    pub regression: String,
    /// Suite.
    pub suite: String,
    /// Repository of the branch and of the source manifest.
    pub repository: String,
    /// Branch name.
    pub branch: String,
    /// Source revision.
    pub revision: String,
    /// Regression start (RFC 3339); default: the earliest row start.
    pub started_at: Option<String>,
}

/// One analysed row.
struct Analysed {
    row: Row,
    evidence: Option<Evidence>,
    problem: Option<String>,
    failing: bool,
    diagnosed: bool,
}

/// A row's execution inputs: test and seed, and `extra.tool.main = "model"` for a model with
/// its own main (the slot's declaration the server checks the evidence against).
fn exec_inputs(row: &Row) -> Value {
    if row.model_main {
        json!({"test": row.test, "seed": row.seed, "extra": {"tool": {"main": "model"}}})
    } else {
        json!({"test": row.test, "seed": row.seed})
    }
}

fn attempt_ref(plan: &ImportPlan, row: &Row) -> String {
    format!("{}.{}.import", plan.regression, row.slot)
}

/// Previews (and, with `journal`, journals) an import. Returns the preview, plus the
/// journalled state when submitting.
///
/// # Errors
/// An unreadable root or CSV, invalid keys, or (when submitting) problems in the preview
/// or journal I/O.
#[allow(clippy::too_many_lines)] // analyse, then journal in order
pub fn import_folder(
    root: &Path,
    csv: &Path,
    plan: &ImportPlan,
    p: &Pipeline,
    base: &ExtractOptions,
    journal: Option<&Path>,
) -> Result<Value> {
    let rows = parse_csv(&std::fs::read(csv).context("reading the CSV")?)?;
    let dir = Dir::open_ambient_dir(root, ambient_authority())
        .with_context(|| format!("opening the root {}", root.display()))?;
    let mut seen = BTreeSet::new();
    let mut duplicates = vec![];
    for r in &rows {
        if !seen.insert(r.slot.clone()) {
            duplicates.push(r.slot.clone());
        }
        ExternalKey::try_from(attempt_ref(plan, r))
            .map_err(|e| anyhow::anyhow!("line {}: slot {:?}: {e}", r.line, r.slot))?;
    }
    let mut analysed = vec![];
    for r in rows {
        let (evidence, problem) = match (&r.log, &r.console) {
            (None, _) => (None, None),
            (Some(path), Some(console)) if r.model_main => {
                let name = path.rsplit('/').next().unwrap_or(path);
                let joined = open_log(&dir, path).and_then(|mut lf| {
                    let mut cf = open_log(&dir, console)?;
                    crate::run::evidence_joined(p, base.clone(), name, &mut lf, &mut cf)
                        .map_err(std::io::Error::other)
                });
                match joined {
                    Ok(ev) => (Some(ev), None),
                    Err(e) => (None, Some(format!("unreadable log or console: {e}"))),
                }
            }
            (Some(path), _) => {
                let mut opts = base.clone();
                opts.log_name = path.rsplit('/').next().unwrap_or(path).to_string();
                match open_log(&dir, path).and_then(|f| extract(p, opts, f)) {
                    Ok(ev) => (Some(ev), None),
                    Err(e) => (None, Some(format!("unreadable log: {e}"))),
                }
            }
        };
        let failing_buckets = evidence
            .as_ref()
            .is_some_and(|e| e.buckets.iter().any(|b| b.fails_run));
        let failing = r.exit_code.is_some_and(|c| c != 0) || failing_buckets;
        analysed.push(Analysed {
            diagnosed: failing_buckets,
            failing,
            evidence,
            problem,
            row: r,
        });
    }
    let unreadable: Vec<Value> = analysed
        .iter()
        .filter_map(|a| {
            a.problem
                .as_ref()
                .map(|p| json!({"line": a.row.line, "slot": a.row.slot, "problem": p}))
        })
        .collect();
    let missing_metadata = analysed
        .iter()
        .filter(|a| {
            a.row.log.is_some() && (a.row.exit_code.is_none() || a.row.started_at.is_none())
        })
        .count();
    let without_diag = analysed
        .iter()
        .filter(|a| a.evidence.is_some() && a.failing && !a.diagnosed)
        .count();
    let example = |pred: &dyn Fn(&Analysed) -> bool| {
        analysed
            .iter()
            .find(|a| pred(a))
            .map(|a| json!({"line": a.row.line, "slot": a.row.slot}))
    };
    let mut preview = json!({
        "format": "dviscope.import-preview/1",
        "regression": plan.regression,
        "completeness": format!("Expected jobs known ({} rows)", analysed.len()),
        "rows": analysed.len(),
        "with_log": analysed.iter().filter(|a| a.row.log.is_some()).count(),
        "expected_without_log": analysed.iter().filter(|a| a.row.log.is_none()).count(),
        "unreadable": unreadable,
        "missing_metadata": missing_metadata,
        "failures_without_diagnostics": without_diag,
        "duplicate_slots": duplicates,
        "sample": analysed.iter().take(PREVIEW_ROWS).map(|a| json!({
            "line": a.row.line,
            "log": a.row.log,
            "slot": a.row.slot,
            "test": a.row.test,
            "seed": a.row.seed,
            "attempt": a.row.log.as_ref().map(|_| attempt_ref(plan, &a.row)),
        })).collect::<Vec<_>>(),
        "examples": {
            "passing": example(&|a| a.evidence.is_some() && !a.failing),
            "failing": example(&|a| a.evidence.is_some() && a.failing),
            "problematic": example(&|a| a.problem.is_some() || (a.row.log.is_some() && a.row.exit_code.is_none())),
        },
    });
    let Some(journal) = journal else {
        return Ok(preview);
    };
    if !duplicates.is_empty() || !unreadable.is_empty() {
        bail!(
            "the preview shows duplicate slots or unreadable logs: fix the CSV or the folder first"
        );
    }
    // Journal: source manifest, regression, chunks, seal, every run, finish.
    let j = if journal.join("journal.json").exists() {
        Journal::open(journal)?
    } else {
        Journal::create(journal, &plan.regression)?
    };
    let started = plan.started_at.clone().or_else(|| {
        analysed
            .iter()
            .filter_map(|a| a.row.started_at.clone())
            .min()
    });
    let Some(started) = started else {
        bail!("no regression start: give --started-at or started_at columns");
    };
    let sm_ref = format!("{}@{}", plan.repository, plan.revision);
    collect::source_manifest_body(
        &j,
        &json!({"schema": INGEST, "producer_id": plan.producer, "source_manifest_ref": sm_ref,
                    "repositories": [{"repository": plan.repository, "revision": plan.revision}]}),
    )?;
    collect::regression_create_body(
        &j,
        &json!({"schema": INGEST, "producer_id": plan.producer,
                    "regression_ref": plan.regression, "suite": plan.suite,
                    "branch": {"repository": plan.repository, "name": plan.branch},
                    "source_manifest_ref": sm_ref, "trigger": {"kind": "other"},
                    "started_at": started}),
    )?;
    let decls: Vec<Value> = analysed
        .iter()
        .map(|a| {
            json!({"slot_ref": a.row.slot, "required": a.row.required,
                   "exec_inputs": exec_inputs(&a.row)})
        })
        .collect();
    for (n, chunk) in decls.chunks(CHUNK_SLOTS).enumerate() {
        collect::declare_body(
            &j,
            &plan.regression,
            u32::try_from(n + 1)?,
            &json!({"schema": MANIFEST, "slots": chunk}),
        )?;
    }
    collect::seal(&j, &plan.regression)?;
    let mut journalled = 0u32;
    for a in analysed {
        let Some(ev) = a.evidence else { continue };
        let r = &a.row;
        let spec: LaunchSpec = serde_json::from_value(json!({
            "producer_id": plan.producer, "regression_ref": plan.regression,
            "slot_ref": r.slot, "attempt_ref": attempt_ref(plan, r),
            "source_manifest_ref": sm_ref,
            "execution": exec_inputs(r),
        }))?;
        let termination = match r.exit_code {
            Some(c) => json!({"kind": "exited", "exit_code": c}),
            None => json!({"kind": "unknown"}),
        };
        let runner: Runner = serde_json::from_value(json!({
            "termination": termination,
            "started_at": r.started_at.clone().unwrap_or_else(|| started.clone()),
            "finished_at": r.finished_at,
        }))
        .with_context(|| format!("line {}: started_at/finished_at are RFC 3339", r.line))?;
        if import_attempt(&j, &spec, runner, ev)?["state"] == "spooled" {
            journalled += 1;
        }
    }
    preview["journalled_attempts"] = json!(journalled);
    preview["journal"] = json!(journal.display().to_string());
    Ok(preview)
}

/// After the runs are delivered: closes the journal's launches and journals the finish
/// (both once; a repeated import finds them done).
///
/// # Errors
/// Journal I/O, or launches not delivered yet.
pub fn finish_import(journal: &Path, regression: &str) -> Result<()> {
    let j = Journal::open(journal)?;
    if j.intact()?
        .iter()
        .any(|e| e.kind == crate::journal::kind::FINISH)
    {
        return Ok(());
    }
    if !j.closed()? {
        j.locked(Journal::close)?;
    }
    let record = json!({"deliver": {"kind": "finish", "regression_ref": regression}});
    j.locked(|j| j.finish(&[], record))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_portable_path_grammar() {
        for ok in ["a.log", "runs/t1/sim.log", "x y/a.b.log"] {
            assert!(check_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "/abs.log",
            "a/../b.log",
            "./a.log",
            "a//b.log",
            "c:/x.log",
            "a\\b.log",
            "CON",
            "dir/nul.txt",
            "COM1.log",
            "lpt9",
            "a./b",
            "a /b",
            "a\u{7}b",
            "f.log:stream",
        ] {
            assert!(check_path(bad).is_err(), "{bad}");
        }
        assert!(
            check_path("COM10.log").is_ok(),
            "only COM1-COM9 are reserved"
        );
    }

    #[test]
    fn csv_encodings_and_quoting() {
        let rows = parse_csv(
            b"\xEF\xBB\xBFslot,test,seed,log,exit_code\r\ns1,\"t,1\",7,a.log,0\r\ns2,t2,,,\r\n",
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].test, "t,1");
        assert_eq!(rows[1].log, None);
        assert_eq!(rows[1].exit_code, None);
        assert!(parse_csv(b"\xFF\xFEs\0l\0").is_err(), "UTF-16");
        assert!(
            parse_csv(b"slot,test,seed,log\ns1,t,1,a.log\n").is_err(),
            "exit_code column"
        );
        assert!(
            parse_csv(b"slot,test,seed,log,exit_code,color\n").is_err(),
            "unknown column"
        );
        assert!(parse_csv(b"slot,test,seed,log,exit_code\ns1,t,1,../x.log,0\n").is_err());
    }

    /// `main` = `model` declares a model with its own main; it needs a distinct
    /// `console`; a console without it is refused.
    #[test]
    fn model_main_rows() {
        let h = "slot,test,seed,log,exit_code,main,console\n";
        let rows =
            parse_csv(format!("{h}s1,t,1,p.log,0,model,c.txt\ns2,t,1,q.log,0,,\n").as_bytes())
                .unwrap_or_else(|e| panic!("{e:#}"));
        assert!(rows[0].model_main);
        assert_eq!(rows[0].console.as_deref(), Some("c.txt"));
        assert!(!rows[1].model_main);
        assert_eq!(
            exec_inputs(&rows[0]),
            json!({"test": "t", "seed": "1", "extra": {"tool": {"main": "model"}}})
        );
        assert_eq!(exec_inputs(&rows[1]), json!({"test": "t", "seed": "1"}));
        for (bad, why) in [
            ("s1,t,1,p.log,0,model,\n", "console capture"),
            ("s1,t,1,p.log,0,model,p.log\n", "distinct"),
            ("s1,t,1,p.log,0,,c.txt\n", "only for main"),
            ("s1,t,1,p.log,0,binary,c.txt\n", "model or empty"),
            ("s1,t,1,p.log,0,model,../c.txt\n", "console path"),
        ] {
            let e = parse_csv(format!("{h}{bad}").as_bytes())
                .err()
                .map(|e| format!("{e:#}"))
                .unwrap_or_default();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    /// A model row's evidence joins the program log and the console (preview, no journal).
    #[test]
    fn a_model_row_is_extracted_joined() {
        let d = std::env::temp_dir().join(format!("dviscope-import-mm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).ok();
        std::fs::write(d.join("p.log"), "TOY RESULT PASS\n").ok();
        std::fs::write(
            d.join("c.txt"),
            "TOY MODEL BEGIN\n- rtl/top.sv:3: Verilog $finish\nTOY END\n",
        )
        .ok();
        let csv = d.join("jobs.csv");
        std::fs::write(
            &csv,
            "slot,test,seed,log,exit_code,started_at,main,console\ns1,t,1,p.log,0,2026-11-09T00:00:00Z,model,c.txt\n",
        )
        .ok();
        let mut inputs = dviscope_core::packs::shipped::default_inputs();
        inputs.push(dviscope_core::packs::PackInput {
            name: "toy.yaml".into(),
            text: "format: dviscope.rules/1.0\npack: toy\nversion: 1.0.0\ntier: project\nmarkers:\n  - {id: b, match: '^TOY MODEL BEGIN$'}\n  - {id: e, match: '^TOY END$'}\nverdicts:\n  - {id: r, source: test_result, match: '^TOY RESULT PASS$', value: pass}\ncompletion:\n  model_main: {start: b, trailer: [e]}\n".into(),
        });
        let p = dviscope_core::packs::compile(&inputs).unwrap_or_else(|e| panic!("{e}"));
        let plan = ImportPlan {
            producer: "pilot".into(),
            regression: "r1".into(),
            suite: "s".into(),
            repository: "rtl".into(),
            branch: "main".into(),
            revision: "v1".into(),
            started_at: None,
        };
        let out = import_folder(&d, &csv, &plan, &p, &ExtractOptions::simulation(""), None)
            .unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(out["unreadable"], json!([]), "{out}");
        assert_eq!(out["with_log"], 1, "{out}");
        // Joined and complete: a passing row, not a problematic one.
        assert_eq!(out["failures_without_diagnostics"], 0, "{out}");
        assert_eq!(out["examples"]["passing"]["slot"], "s1", "{out}");
        let (mut lf, mut cf) = (
            std::fs::File::open(d.join("p.log")).unwrap_or_else(|e| panic!("{e}")),
            std::fs::File::open(d.join("c.txt")).unwrap_or_else(|e| panic!("{e}")),
        );
        let ev = crate::run::evidence_joined(
            &p,
            ExtractOptions::simulation(""),
            "p.log",
            &mut lf,
            &mut cf,
        )
        .unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(ev.completion.profile, "verilator-model-main");
        assert_eq!(
            ev.completion.state,
            dviscope_model::wire::evidence::CompletionState::Complete,
            "{:?}",
            ev.completion
        );
    }
}
