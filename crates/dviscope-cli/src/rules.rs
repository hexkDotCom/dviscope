//! Local extraction commands: `extract`, `rules check`, `rules explain`.
//! Output never contains log text except `explain`, which the user runs on their own log.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use dviscope_core::extract::{ExtractOptions, Extractor, Subject, TraceRecord};
use dviscope_core::packs::{self, PackInput, Pipeline, shipped};
pub use dviscope_core::rule_check::{Expectation, compare};
use dviscope_model::wire::evidence::Evidence;
use serde_json::{Value, json};

/// Read chunk size.
const CHUNK: usize = 64 * 1024;

/// Builds the pipeline: the default packs (unless `no_default`) plus `extra`
/// (`builtin:NAME` or a file path).
///
/// # Errors
/// Unreadable or invalid packs.
pub fn pipeline(extra: &[String], no_default: bool) -> Result<Pipeline> {
    let mut inputs = if no_default {
        vec![]
    } else {
        shipped::default_inputs()
    };
    for e in extra {
        if let Some(name) = e.strip_prefix("builtin:") {
            inputs
                .push(shipped::example(name).with_context(|| format!("no built-in pack {name}"))?);
        } else {
            let text = std::fs::read_to_string(e).with_context(|| format!("reading pack {e}"))?;
            let name = Path::new(e)
                .file_name()
                .map_or_else(|| e.clone(), |n| n.to_string_lossy().into_owned());
            inputs.push(PackInput { name, text });
        }
    }
    Ok(packs::compile(&inputs)?)
}

/// Parses `simulation` / `build`.
///
/// # Errors
/// Any other value.
pub fn subject(s: &str) -> Result<Subject> {
    match s {
        "simulation" | "run" => Ok(Subject::Simulation),
        "build" => Ok(Subject::Build),
        other => bail!("subject must be simulation or build, not {other}"),
    }
}

/// Extracts a file, streaming it in chunks.
///
/// # Errors
/// The file cannot be read.
pub fn extract_file(
    p: &Pipeline,
    mut opts: ExtractOptions,
    path: &Path,
) -> Result<(Evidence, Vec<TraceRecord>)> {
    if opts.log_name.is_empty() {
        opts.log_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
    }
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut x = Extractor::new(p, opts);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        x.push(&buf[..n]);
    }
    Ok(x.finish_with_trace())
}

/// `rules check`: compiles, runs the pack self-tests and, with a sample directory, every
/// `<case>.log` that has a `<case>.expect.json`. Optionally writes each case's evidence.
///
/// # Errors
/// Invalid packs or an unreadable sample.
pub fn check(
    p: &Pipeline,
    sample: Option<&Path>,
    evidence_out: Option<&Path>,
    source_roots: &[String],
) -> Result<(Value, bool)> {
    let self_test = shipped::self_test(p);
    let mut ok = self_test.is_empty();
    let mut cases = vec![];
    if let Some(dir) = sample {
        let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.to_string_lossy().ends_with(".expect.json"))
            .collect();
        names.sort();
        for exp_path in names {
            let file = exp_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let case = file.trim_end_matches(".expect.json").to_string();
            let x: Expectation = serde_json::from_slice(&std::fs::read(&exp_path)?)
                .with_context(|| format!("expectation {file}"))?;
            if x.format != "dviscope.expect/1" {
                bail!("{file}: format must be dviscope.expect/1");
            }
            let log = match &x.log {
                Some(rel) => dir.join(rel),
                None => dir.join(format!("{case}.log")),
            };
            let mut opts = ExtractOptions::simulation("");
            opts.simulator.clone_from(&x.simulator);
            opts.source_roots = source_roots.to_vec();
            if let Some(s) = &x.subject {
                opts.subject = subject(s)?;
            }
            let started = std::time::Instant::now();
            let (ev, _) = extract_file(p, opts, &log)?;
            let secs = started.elapsed().as_secs_f64();
            let diffs = compare(&ev, &x);
            ok &= diffs.is_empty();
            if let Some(out) = evidence_out {
                std::fs::create_dir_all(out)?;
                std::fs::write(
                    out.join(format!("{case}.evidence.json")),
                    serde_json::to_vec_pretty(&ev)?,
                )?;
            }
            cases.push(json!({
                "case": case,
                "ok": diffs.is_empty(),
                "differences": diffs,
                "bytes": ev.source.bytes.get(),
                "seconds": (secs * 1000.0).round() / 1000.0,
            }));
        }
    }
    let passed = cases.iter().filter(|c| c["ok"] == true).count();
    Ok((
        json!({
            "pipeline_digest": p.digest.as_str(),
            "packs": p.packs.iter().map(|k| format!("{}@{}", k.id, k.version)).collect::<Vec<_>>(),
            "self_test_failures": self_test,
            "cases": cases.len(),
            "cases_passed": passed,
            "results": cases,
        }),
        ok,
    ))
}

/// `rules explain`: the record covering a line, its rule, captures, cut, shadowed rules
/// and identity contributions.
///
/// # Errors
/// Unreadable log.
pub fn explain(p: &Pipeline, mut opts: ExtractOptions, log: &Path, line: u64) -> Result<Value> {
    opts.trace = true;
    let (ev, trace) = extract_file(p, opts, log)?;
    let record = trace
        .iter()
        .find(|r| r.start_line <= line && line <= r.end_line)
        .cloned();
    let event = ev.events.iter().find(|e| match &e.provenance {
        dviscope_model::wire::evidence::EventProvenance::Log { span, .. } => {
            span.line_start.get() <= line && line <= span.line_end.get()
        }
        dviscope_model::wire::evidence::EventProvenance::Synthetic { .. } => false,
    });
    let text = read_line(log, line)?;
    Ok(json!({
        "line": line,
        "text": text,
        "record": record,
        "claimed": record.is_some(),
        "candidate_rules": p.start_candidates(&text),
        "event": event,
        "completion": ev.completion,
    }))
}

/// `rules explain --console`: a Verilator model with its own main, the program log then
/// the console joined as the collector joins them; the line is a line of the joined log.
/// Adds the segments and every marker's count and positions (the profile's exactly-once and
/// order rules).
///
/// # Errors
/// Unreadable files.
pub fn explain_joined(
    p: &Pipeline,
    mut opts: ExtractOptions,
    log: &Path,
    console: &Path,
    line: u64,
) -> Result<Value> {
    opts.trace = true;
    opts.model_main = true;
    opts.log_name = log
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let program = std::fs::read(log).with_context(|| format!("reading {}", log.display()))?;
    let cons = std::fs::read(console).with_context(|| format!("reading {}", console.display()))?;
    let mut x = dviscope_core::extract::Extractor::new(p, opts);
    x.push(&program);
    x.begin_console();
    x.push(&cons);
    let (ev, trace, markers) = x.finish_explained();
    let record = trace
        .iter()
        .find(|r| r.start_line <= line && line <= r.end_line)
        .cloned();
    let mut lines = vec![];
    let mut s = dviscope_core::extract::decode::Splitter::new();
    s.push(&program, &mut |l| lines.push(l));
    s.boundary(&mut |l| lines.push(l));
    s.push(&cons, &mut |l| lines.push(l));
    s.finish(&mut |l| lines.push(l));
    let text = lines
        .into_iter()
        .find(|l| l.no == line)
        .map(|l| l.text)
        .unwrap_or_default();
    Ok(json!({
        "line": line,
        "text": text,
        "record": record,
        "claimed": record.is_some(),
        "candidate_rules": p.start_candidates(&text),
        "segments": ev.source.segments,
        "markers": markers,
        "completion": ev.completion,
    }))
}

fn read_line(path: &Path, n: u64) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let mut lines = vec![];
    let mut s = dviscope_core::extract::decode::Splitter::new();
    s.push(&bytes, &mut |l| lines.push(l));
    s.finish(&mut |l| lines.push(l));
    Ok(lines
        .into_iter()
        .find(|l| l.no == n)
        .map(|l| l.text)
        .unwrap_or_default())
}
