//! `dviscope sample upload` and `dviscope rules import`: the activation
//! sample is uploaded in chunks of ≤ 4 MiB, resumable by file digest; an import checks the
//! new pipeline locally against the server's active one over the same sample (the same
//! `core::rule_check` the server re-runs) and submits it only when it passes.
//! Output never contains log text: IDs, counts, states and digests only.

use std::path::{Path, PathBuf};

use dviscope_core::packs::shipped;
use dviscope_core::rule_check::{
    self, DEFINITION_FORMAT, Expectation, PackText, PipelineDefinition, SAMPLE_FORMAT, SampleCase,
    SampleManifest,
};
use dviscope_model::canonical::Digest;
use serde_json::{Value, json};

use crate::config::CliConfig;
use crate::verdict::{Answer, Payload, call_with};

/// Upload chunk size (≤ 4 MiB).
pub const CHUNK: usize = 4 * 1024 * 1024;

/// Reads a local sample directory: every `<case>.expect.json` and its log (`log` in the
/// expectation, else `<case>.log`). Returns the manifest (without local paths) and the
/// log paths, in manifest order.
///
/// # Errors
/// An unreadable or invalid case, or a sample over the limits.
pub fn load_sample(dir: &Path) -> Result<(SampleManifest, Vec<PathBuf>), String> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read the sample directory: {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.to_string_lossy().ends_with(".expect.json"))
        .collect();
    names.sort();
    let mut cases = vec![];
    let mut paths = vec![];
    for exp in names {
        let file = exp
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let case = file.trim_end_matches(".expect.json").to_string();
        let bytes = std::fs::read(&exp).map_err(|e| format!("{file}: {e}"))?;
        let mut x: Expectation =
            serde_json::from_slice(&bytes).map_err(|e| format!("{file}: {e}"))?;
        let log = match x.log.take() {
            Some(rel) => dir.join(rel),
            None => dir.join(format!("{case}.log")),
        };
        let content = std::fs::read(&log).map_err(|e| format!("{case}: the log: {e}"))?;
        let digest = Digest::of_bytes(&content);
        cases.push(SampleCase {
            case,
            log_sha256: digest.as_str().trim_start_matches("sha256:").to_string(),
            bytes: content.len() as u64,
            expect: x,
        });
        paths.push(log);
    }
    let m = SampleManifest {
        format: SAMPLE_FORMAT.into(),
        cases,
    };
    m.validate()?;
    Ok((m, paths))
}

/// A pipeline definition from `--pack` arguments (`builtin:NAME` or a file), the same
/// packs (names and texts) a collector's `--pack` arguments compile.
///
/// # Errors
/// An unknown built-in or an unreadable file.
pub fn definition(packs: &[String], no_default: bool) -> Result<PipelineDefinition, String> {
    let mut out = vec![];
    for p in packs {
        if let Some(name) = p.strip_prefix("builtin:") {
            let i = shipped::example(name).ok_or_else(|| format!("no built-in pack {name}"))?;
            out.push(PackText {
                name: i.name,
                text: i.text,
            });
        } else {
            let text = std::fs::read_to_string(p).map_err(|e| format!("pack {p}: {e}"))?;
            let name = Path::new(p)
                .file_name()
                .map_or_else(|| p.clone(), |n| n.to_string_lossy().into_owned());
            out.push(PackText { name, text });
        }
    }
    Ok(PipelineDefinition {
        format: DEFINITION_FORMAT.into(),
        default_packs: !no_default,
        packs: out,
    })
}

/// `dviscope sample upload`: uploads every log not yet complete on the server (resuming
/// where an earlier upload stopped), then registers the sample.
pub async fn upload_sample(cfg: &CliConfig, project: &str, dir: &Path) -> Answer {
    let (m, paths) = load_sample(dir).map_err(|e| (2, e))?;
    let (mut uploaded, mut present) = (0u32, 0u32);
    for (c, path) in m.cases.iter().zip(&paths) {
        let segs = ["rules", "sample", "files", c.log_sha256.as_str()];
        let st = call_with(
            cfg,
            reqwest::Method::GET,
            project,
            &segs,
            &[],
            Payload::None,
        )
        .await?;
        if st["complete"] == true {
            present += 1;
            continue;
        }
        let content = std::fs::read(path).map_err(|e| (2, format!("{}: {e}", c.case)))?;
        let mut off = usize::try_from(st["received"].as_u64().unwrap_or(0)).unwrap_or(0);
        let size = content.len().to_string();
        loop {
            let end = (off + CHUNK).min(content.len());
            let offset = off.to_string();
            let r = call_with(
                cfg,
                reqwest::Method::PUT,
                project,
                &segs,
                &[("size", size.as_str()), ("offset", offset.as_str())],
                Payload::Bytes(&content[off..end]),
            )
            .await?;
            if r["complete"] == true {
                break;
            }
            let next = usize::try_from(r["received"].as_u64().unwrap_or(0)).unwrap_or(0);
            if next <= off {
                return Err((5, format!("{}: the upload does not advance", c.case)));
            }
            off = next;
        }
        uploaded += 1;
    }
    let body = serde_json::to_value(&m).map_err(|e| (5, e.to_string()))?;
    let r = call_with(
        cfg,
        reqwest::Method::POST,
        project,
        &["rules", "sample"],
        &[],
        Payload::Json(&body),
    )
    .await?;
    Ok(json!({
        "sample": r["digest"],
        "cases": m.cases.len(),
        "uploaded": uploaded,
        "already_uploaded": present,
    }))
}

/// `dviscope rules import`: checks the new pipeline against the server's active one over
/// the local copy of the server's sample; submits it only when the check passes. The
/// answer carries `activated` (false: the check failed locally, nothing was sent).
pub async fn import_rules(
    cfg: &CliConfig,
    project: &str,
    packs: &[String],
    no_default: bool,
    sample_dir: &Path,
) -> Answer {
    let active = call_with(
        cfg,
        reqwest::Method::GET,
        project,
        &["rules", "definition"],
        &[],
        Payload::None,
    )
    .await?;
    let old_def: PipelineDefinition = serde_json::from_value(active["definition"].clone())
        .map_err(|_| (5, "malformed active definition".to_string()))?;
    let new_def = definition(packs, no_default).map_err(|e| (2, e))?;
    let (m, paths) = load_sample(sample_dir).map_err(|e| (2, e))?;
    if active["sample"].as_str() != Some(m.digest().as_str()) {
        return Err((
            3,
            "the server's activation sample differs from this directory: upload it first \
             (dviscope sample upload)"
                .into(),
        ));
    }
    let logs: Vec<Vec<u8>> = paths
        .iter()
        .map(std::fs::read)
        .collect::<Result<_, _>>()
        .map_err(|e| (2, format!("a sample log: {e}")))?;
    let old = old_def.compile().map_err(|e| (5, e))?;
    let new = new_def.compile().map_err(|e| (2, e))?;
    let refs: Vec<&[u8]> = logs.iter().map(Vec::as_slice).collect();
    let started = std::time::Instant::now();
    let check = rule_check::check(&old, &new, &m, &refs).map_err(|e| (2, e))?;
    let secs = started.elapsed().as_secs_f64();
    let mb = logs.iter().map(Vec::len).sum::<usize>() as f64 / 1_048_576.0;
    let mb_per_s = if secs > 0.0 {
        (mb / secs * 10.0).round() / 10.0
    } else {
        0.0
    };
    if !check.pass {
        return Ok(json!({"activated": false, "check": check, "new_mb_per_s": mb_per_s}));
    }
    let body = json!({"definition": new_def, "check": check});
    let r: Value = call_with(
        cfg,
        reqwest::Method::POST,
        project,
        &["rules", "activations"],
        &[],
        Payload::Json(&body),
    )
    .await?;
    Ok(json!({"activated": true, "activation": r, "check": check, "new_mb_per_s": mb_per_s}))
}

/// `dviscope ledger export`: writes the ledger privately (owner-only where supported) and
/// prints counts only.
pub async fn export_ledger(cfg: &CliConfig, project: &str, out: &Path) -> Answer {
    let l = call_with(
        cfg,
        reqwest::Method::GET,
        project,
        &["ledger"],
        &[],
        Payload::None,
    )
    .await?;
    let text = serde_json::to_vec_pretty(&l).map_err(|e| (5, e.to_string()))?;
    write_private(out, &text).map_err(|e| (2, format!("cannot write the ledger: {e}")))?;
    Ok(json!({
        "ledger": out.display().to_string(),
        "triage": l["triage"].as_array().map_or(0, Vec::len),
        "exceptions": l["exceptions"].as_array().map_or(0, Vec::len),
    }))
}

/// `dviscope ledger import`.
pub async fn import_ledger(
    cfg: &CliConfig,
    project: &str,
    file: &Path,
    mapping: Option<&Path>,
    dry_run: bool,
) -> Answer {
    let ledger: Value = serde_json::from_slice(
        &std::fs::read(file).map_err(|e| (2, format!("cannot read the ledger: {e}")))?,
    )
    .map_err(|e| (2, format!("not a ledger: {e}")))?;
    let map: Value = match mapping {
        Some(m) => serde_json::from_slice(
            &std::fs::read(m).map_err(|e| (2, format!("cannot read the mapping: {e}")))?,
        )
        .map_err(|e| (2, format!("the mapping is a JSON object: {e}")))?,
        None => json!({}),
    };
    if !map.is_object() {
        return Err((
            2,
            "the mapping is a JSON object (old fingerprint -> new)".into(),
        ));
    }
    let body = json!({"ledger": ledger, "mapping": map, "dry_run": dry_run});
    call_with(
        cfg,
        reqwest::Method::POST,
        project,
        &["ledger"],
        &[],
        Payload::Json(&body),
    )
    .await
}

/// Writes a file privately (owner-only from creation, atomically replacing any existing
/// file, whatever its access).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    crate::platform::write_private_file(path, bytes)
}

/// `dviscope corpus capture`: adds a local log to a private sample directory as case
/// `<case>`: the log copied as `<case>.log` and a starting `<case>.expect.json` from what
/// the given pipeline extracts today (completion, failing diag_ids with exact counts,
/// families, primary, unclaimed lines), with every failing diag_id in `must_survive`. The
/// user reviews it (expected results are a judgement, not a recording) before uploading.
///
/// # Errors
/// An unreadable log, an existing case (unless `force`), or I/O.
#[allow(clippy::too_many_arguments)] // one case: its log, place, run facts and contract
pub fn capture(
    p: &dviscope_core::packs::Pipeline,
    opts: dviscope_core::extract::ExtractOptions,
    log: &Path,
    dir: &Path,
    case: &str,
    exit_code: Option<i32>,
    expected: Option<dviscope_model::wire::manifest::Expected>,
    force: bool,
) -> Result<Value, String> {
    if case.is_empty()
        || case.len() > 200
        || !case
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        || case.starts_with('.')
    {
        return Err("a case name is 1-200 of A-Z a-z 0-9 - _ . (not starting with .)".into());
    }
    let log_out = dir.join(format!("{case}.log"));
    let exp_out = dir.join(format!("{case}.expect.json"));
    if !force && (log_out.exists() || exp_out.exists()) {
        return Err(format!(
            "case {case} exists in the sample (use --force to replace it)"
        ));
    }
    let simulator = opts.simulator.clone();
    let subject = opts.subject;
    let (ev, _) = crate::rules::extract_file(p, opts, log).map_err(|e| format!("{e:#}"))?;
    let mut failures: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for b in ev.buckets.iter().filter(|b| b.fails_run) {
        *failures.entry(b.diag_id.clone()).or_default() +=
            b.count.as_str().parse::<u64>().unwrap_or(0);
    }
    let mut families: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for f in &ev.families {
        *families.entry(f.diag_id.clone()).or_default() += 1;
    }
    let primary = ev
        .events
        .iter()
        .max_by_key(|e| {
            (
                e.fails_run,
                e.observed_severity,
                std::cmp::Reverse(e.ordinal),
            )
        })
        .map(|e| e.diag_id.clone());
    let completion = serde_json::to_value(ev.completion.state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    let mode = ev
        .completion
        .mode
        .as_ref()
        .and_then(|m| serde_json::to_value(m).ok())
        .and_then(|v| v.as_str().map(str::to_string));
    let design_loaded = serde_json::to_value(ev.design_loaded)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    let x = Expectation {
        format: "dviscope.expect/1".into(),
        log: None,
        subject: (subject == dviscope_core::extract::Subject::Build).then(|| "build".to_string()),
        simulator,
        model_main: false,
        console_at: None,
        completion,
        mode,
        design_loaded,
        verdicts: std::collections::BTreeMap::new(),
        must_survive: failures.keys().cloned().collect(),
        failures,
        failures_exact: true,
        exact_prefixes: vec![],
        simulator_errors: None,
        families,
        primary,
        max_unclaimed: ev.coverage.unclaimed_error_like_lines.as_str().parse().ok(),
        failure_anchored_in: vec![],
        must_remain_distinct: vec![],
        expect_changes: vec![],
        exit_code,
        expected,
    };
    std::fs::create_dir_all(dir).map_err(|e| format!("the sample directory: {e}"))?;
    let bytes = std::fs::read(log).map_err(|e| format!("the log: {e}"))?;
    write_private(&log_out, &bytes).map_err(|e| format!("{case}.log: {e}"))?;
    let text = serde_json::to_vec_pretty(&x).map_err(|e| e.to_string())?;
    write_private(&exp_out, &text).map_err(|e| format!("{case}.expect.json: {e}"))?;
    Ok(json!({
        "case": case,
        "log": log_out.display().to_string(),
        "expect": exp_out.display().to_string(),
        "completion": x.completion,
        "failing": x.failures.len(),
        "must_survive": x.must_survive,
        "review": "check the expectation before `dviscope sample upload`",
    }))
}
