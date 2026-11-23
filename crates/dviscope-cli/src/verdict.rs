//! `dviscope verdict`: evaluates merge readiness on the
//! server and writes the summary **before** exiting. Exit codes: 0 pass (and
//! `accepted_with_exceptions` when the policy passes it), 10 fail, 11 insufficient
//! evidence; 2 usage, 3 rejected, 4 unreachable, 5 internal. On 4 and 5 the summary file
//! says *"no verdict: <reason>"*; nothing is ever written as a pass on an error.

use std::path::Path;

use serde_json::{Value, json};

use crate::client;
use crate::config::CliConfig;

/// What to evaluate.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// Project name.
    pub project: &'a str,
    /// Regression reference.
    pub regression: &'a str,
    /// Expected source digest of the candidate (`sha256:...`).
    pub expect_source: Option<&'a str>,
    /// Whether `accepted_with_exceptions` passes (suite policy; default yes).
    pub exceptions_pass: bool,
    /// `log-free` (default) or `json`.
    pub summary: &'a str,
    /// Where to write the summary.
    pub summary_file: Option<&'a Path>,
    /// `--wait-processed`: until this instant, re-evaluate while the verdict can still
    /// change by waiting (the collection is open or attempts are running) or the server
    /// is unreachable.
    pub wait_until: Option<std::time::Instant>,
    /// Re-evaluation interval while waiting.
    pub poll: std::time::Duration,
    /// `--publish-receipt`: the commit-status target the evaluation is published for.
    pub publish: Option<Target<'a>>,
}

/// A commit-status target (`--publish-receipt`).
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// `owner/name`.
    pub repository: &'a str,
    /// Full commit SHA.
    pub commit: &'a str,
    /// Status context.
    pub context: &'a str,
}

/// Parses a duration: `90s`, `15m`, `2h`, or plain seconds.
///
/// # Errors
/// Anything else.
pub fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    let (n, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => (&s[..i], &s[i..]),
        None => (s, "s"),
    };
    let n: u64 = n.parse().map_err(|_| format!("not a duration: {s:?}"))?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        _ => return Err(format!("not a duration: {s:?} (use 90s, 15m, 2h)")),
    };
    Ok(std::time::Duration::from_secs(secs))
}

/// Runs a request within the deadline (none: unbounded); past it, no request is sent.
async fn within(
    until: Option<std::time::Instant>,
    request: impl std::future::Future<Output = Answer>,
) -> Answer {
    let Some(t) = until else {
        return request.await;
    };
    let Some(left) = t
        .checked_duration_since(std::time::Instant::now())
        .filter(|l| !l.is_zero())
    else {
        return Err((4, "the deadline passed".into()));
    };
    tokio::time::timeout(left, request)
        .await
        .unwrap_or_else(|_| Err((4, "the deadline passed during a request".into())))
}

/// Whether waiting can still change this answer: the collection is open or attempts run.
fn still_settling(body: &Value) -> bool {
    body["blockers"].as_array().is_some_and(|a| {
        a.iter().any(|b| {
            matches!(
                b["kind"]["kind"].as_str(),
                Some("collection_open" | "running")
            )
        })
    })
}

/// Escapes text for Markdown: every punctuation character that Markdown or HTML could
/// interpret is backslash-escaped; line breaks become spaces (verdict Markdown escapes
/// everything).
#[must_use]
pub fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '.'
            | '!' | '|' | '<' | '>' | '~' | '&' | '"' | '\'' | '=' | ':' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => md_escape(s),
        Value::Null => "—".into(),
        other => md_escape(&other.to_string()),
    }
}

/// The log-free summary as Markdown (a CI comment): verdict, candidate, blockers grouped
/// with owners and clearing actions, exceptions used, digest. Every value is escaped.
#[must_use]
pub fn markdown(s: &Value) -> String {
    use std::fmt::Write as _;
    let mut m = String::new();
    let verdict = s["verdict"].as_str().unwrap_or("unknown").replace('_', " ");
    let _ = writeln!(
        m,
        "## DVIScope merge readiness: {}\n",
        md_escape(&verdict.to_uppercase())
    );
    let _ = writeln!(
        m,
        "Regression {} · suite {} · policy {} · evaluated {} · valid until {}\n",
        text(&s["regression"]),
        text(&s["suite"]),
        text(&s["policy"]),
        text(&s["evaluated_at"]),
        text(&s["valid_until"]),
    );
    let c = &s["candidate"];
    let _ = writeln!(
        m,
        "Candidate: {} at {} (bound to the expected source: {})\n",
        text(&c["repository"]),
        text(&c["revision"]),
        if c["bound"] == true { "yes" } else { "no" },
    );
    if let Some(counts) = s["counts"].as_object() {
        let parts: Vec<String> = counts
            .iter()
            .map(|(k, v)| format!("{} {}", md_escape(k), text(v)))
            .collect();
        let _ = writeln!(m, "Slots: {}\n", parts.join(", "));
    }
    let blockers = s["blockers"].as_array().cloned().unwrap_or_default();
    if blockers.is_empty() {
        m.push_str("No blockers.\n\n");
    } else {
        m.push_str("| Blocker | Slots | Signatures | Owner | Exceptable | Clearing action |\n");
        m.push_str("|---|---|---|---|---|---|\n");
        for b in &blockers {
            let mut kind = b["kind"]["kind"].as_str().unwrap_or("?").replace('_', " ");
            if let Some(extra) = b["kind"]
                .as_object()
                .and_then(|o| o.iter().find(|(k, _)| *k != "kind").map(|(_, v)| v.clone()))
            {
                let extra = extra
                    .as_str()
                    .map_or_else(|| extra.to_string(), str::to_string);
                kind = format!("{kind} ({extra})");
            }
            let sigs: Vec<String> = b["signatures"]
                .as_array()
                .map(|a| a.iter().map(text).collect())
                .unwrap_or_default();
            let _ = writeln!(
                m,
                "| {} | {} | {} | {} | {} | {} |",
                md_escape(&kind),
                text(&b["slots"]),
                if sigs.is_empty() {
                    "—".to_string()
                } else {
                    sigs.join(", ")
                },
                text(&b["owner"]),
                if b["exceptable"] == true { "yes" } else { "no" },
                text(&b["clearing_action"]),
            );
        }
        m.push('\n');
    }
    let used = s["exceptions_used"].as_array().cloned().unwrap_or_default();
    if !used.is_empty() {
        m.push_str("Exceptions used:\n\n");
        for e in &used {
            let _ = writeln!(
                m,
                "- exception {} (revision {}), expires {}",
                text(&e["id"]),
                text(&e["revision"]),
                text(&e["expires_at"]),
            );
        }
        m.push('\n');
    }
    let _ = writeln!(m, "Digest: {}", text(&s["digest"]));
    m
}

/// The exit code of a verdict.
#[must_use]
pub fn exit_code(verdict: &str, exceptions_pass: bool) -> u8 {
    match verdict {
        "pass" => 0,
        "accepted_with_exceptions" if exceptions_pass => 0,
        "accepted_with_exceptions" | "fail" => 10,
        "insufficient_evidence" => 11,
        _ => 5,
    }
}

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Writes the summary atomically (a temporary file renamed over the target). On failure
/// the old file is removed, so a stale summary never survives a failed write.
fn write_summary(path: Option<&Path>, v: &Value) -> bool {
    let Some(p) = path else { return true };
    // A unique, exclusively created sibling: concurrent writers never share it.
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = p.with_file_name(format!(".{name}.{}.{nonce}.{seq}.tmp", std::process::id()));
    let ok = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| {
            use std::io::Write as _;
            // Text (Markdown) as is; anything else as JSON.
            let text = match v {
                Value::String(t) => t.clone(),
                _ => serde_json::to_string_pretty(v).unwrap_or_default(),
            };
            f.write_all(text.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, p))
        .is_ok();
    if !ok {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(p);
        eprintln!("error: the summary file cannot be written");
    }
    ok
}

/// A server answer, or the exit code and reason of no verdict.
pub type Answer = Result<Value, (u8, String)>;

/// A request body.
#[derive(Debug, Clone, Copy)]
pub enum Payload<'a> {
    /// None.
    None,
    /// JSON.
    Json(&'a Value),
    /// Raw bytes (`application/octet-stream`).
    Bytes(&'a [u8]),
}

/// Calls the server: `segments` under `/api/v1/projects/{project}/`, with query pairs and an
/// optional JSON body. Unreachable → 4, 4xx → 3, malformed or 5xx → 5, configuration → 2.
pub async fn call(
    cfg: &CliConfig,
    method: reqwest::Method,
    project: &str,
    segments: &[&str],
    query: &[(&str, &str)],
    body: Option<&Value>,
) -> Answer {
    let payload = body.map_or(Payload::None, Payload::Json);
    call_with(cfg, method, project, segments, query, payload).await
}

/// [`call`] with any [`Payload`]. A rejection names the code and the server's message
/// (never log text; control characters removed).
pub async fn call_with(
    cfg: &CliConfig,
    method: reqwest::Method,
    project: &str,
    segments: &[&str],
    query: &[(&str, &str)],
    payload: Payload<'_>,
) -> Answer {
    let mut path = vec!["projects", project];
    path.extend_from_slice(segments);
    call_api(cfg, method, &path, query, payload).await
}

/// [`call_with`] for any `/api/v1/...` path (its segments).
pub async fn call_api(
    cfg: &CliConfig,
    method: reqwest::Method,
    path: &[&str],
    query: &[(&str, &str)],
    payload: Payload<'_>,
) -> Answer {
    let Some(token_file) = cfg.token_file.as_ref() else {
        return Err((2, "no token_file configured".into()));
    };
    let Ok(token) = std::fs::read_to_string(token_file) else {
        return Err((2, "the token file cannot be read".into()));
    };
    let http =
        client::build(&cfg.server_url, cfg.ca_file.as_deref()).map_err(|e| (2, e.to_string()))?;
    let mut url =
        reqwest::Url::parse(&cfg.server_url).map_err(|_| (2, "invalid server URL".to_string()))?;
    if let Ok(mut p) = url.path_segments_mut() {
        p.pop_if_empty();
        p.extend(["api", "v1"]);
        p.extend(path);
    }
    for (k, v) in query {
        url.query_pairs_mut().append_pair(k, v);
    }
    let mut rb = http.request(method, url).bearer_auth(token.trim());
    match payload {
        Payload::None => {}
        Payload::Json(b) => rb = rb.json(b),
        Payload::Bytes(b) => {
            rb = rb
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(b.to_vec());
        }
    }
    let res = rb
        .send()
        .await
        .map_err(|e| (4, format!("server unreachable: {}", e.without_url())))?;
    let status = res.status().as_u16();
    let body: Value = res
        .json()
        .await
        .map_err(|_| (5, format!("malformed answer (HTTP {status})")))?;
    match status {
        200 | 201 => Ok(body),
        400..=499 => Err((
            3,
            format!(
                "rejected (HTTP {status}): {}{}",
                body["code"].as_str().unwrap_or("?"),
                body["message"]
                    .as_str()
                    .map(|m| format!(
                        ": {}",
                        m.chars().filter(|c| !c.is_control()).collect::<String>()
                    ))
                    .unwrap_or_default()
            ),
        )),
        _ => Err((5, format!("server error (HTTP {status})"))),
    }
}

/// Runs the verdict; returns the exit code (the summary is written first).
pub async fn run(cfg: &CliConfig, req: &Request<'_>) -> u8 {
    // Merge gating is always bound to the candidate: without it an unrelated passing
    // regression could gate the merge.
    let Some(expect) = req.expect_source else {
        return no_verdict(
            req.summary_file,
            2,
            "merge gating needs --expect-source (see `dviscope source digest`)".into(),
        );
    };
    let q = vec![("expect_source", expect)];
    let segments = ["regressions", req.regression, "readiness"];
    // The latest answer while waiting: at the deadline it is the answer (never a later,
    // refused request in its place).
    let mut last: Option<Value> = None;
    let body = loop {
        let request = call(cfg, reqwest::Method::GET, req.project, &segments, &q, None);
        // While waiting, no request outlives the deadline (a stalled connection included).
        let answer = within(req.wait_until, request).await;
        let wait = match &answer {
            Ok(b) => still_settling(b),
            Err((code, _)) => *code == 4,
        };
        let remaining = req
            .wait_until
            .and_then(|t| t.checked_duration_since(std::time::Instant::now()))
            .filter(|r| !r.is_zero());
        match (answer, wait, remaining) {
            (Ok(b), true, Some(r)) => {
                last = Some(b);
                tokio::time::sleep(req.poll.min(r)).await;
            }
            (Err(_), true, Some(r)) => tokio::time::sleep(req.poll.min(r)).await,
            (Ok(b), _, _) => break b,
            // The deadline ended the wait (unreachable meanwhile, or a request it cut):
            // the latest answer stands. Any other error is the answer.
            (Err((4, _)), true, None) if last.is_some() => {
                if let Some(b) = last.take() {
                    break b;
                }
            }
            (Err((code, reason)), _, _) => return no_verdict(req.summary_file, code, reason),
        }
    };
    let mut body = body;
    let mut publication = None;
    if let Some(t) = req.publish {
        // A publication receipt (the server evaluates again and stores that evaluation's
        // log-free summary). Its evaluation decides this command's verdict and summary, so
        // the receipt and the exit code can never disagree.
        let pubreq = json!({
            "regression": req.regression, "expect_source": expect,
            "target": {"repository": t.repository, "commit": t.commit, "context": t.context},
        });
        let publish = call(
            cfg,
            reqwest::Method::POST,
            req.project,
            &["readiness", "publications"],
            &[],
            Some(&pubreq),
        );
        match within(req.wait_until, publish).await {
            Ok(r) => {
                let summary = r["receipt"]["summary"].clone();
                if summary["verdict"].as_str().is_none() {
                    return no_verdict(
                        req.summary_file,
                        5,
                        "publication: the receipt has no verdict".into(),
                    );
                }
                let receipt = json!({
                    "action": r["action"],
                    "digest": r["receipt"]["digest"],
                    "status": r["receipt"]["status"]["state"],
                    "receipt_path": r["receipt"]["receipt_path"],
                });
                eprintln!("publication receipt: {receipt}");
                // Only the receipt's evaluation remains (never fields of the earlier one).
                body = json!({"verdict": summary["verdict"], "summary": summary});
                publication = Some(receipt);
            }
            Err((code, reason)) => {
                return no_verdict(req.summary_file, code, format!("publication: {reason}"));
            }
        }
    }
    conclude(req, &body, publication)
}

/// The gate's conclusion from an answer: a well-formed evaluation's summary written and its
/// exit code; anything malformed is exit 5.
fn conclude(req: &Request<'_>, body: &Value, publication: Option<Value>) -> u8 {
    let Some(verdict) = body["verdict"].as_str().map(str::to_string) else {
        return no_verdict(req.summary_file, 5, "the answer has no verdict".into());
    };
    if let Err(reason) = well_formed(body, &verdict, req) {
        return no_verdict(req.summary_file, 5, reason);
    }
    let mut out = match req.summary {
        "json" => body.clone(),
        "markdown" => Value::String(markdown(&body["summary"])),
        _ => body["summary"].clone(),
    };
    if let (Some(p), "json") = (publication, req.summary) {
        out["publication"] = p;
    }
    if !write_summary(req.summary_file, &out) {
        return 5;
    }
    exit_code(&verdict, req.exceptions_pass)
}

/// The answer is an evaluation of this regression whose summary agrees with its verdict;
/// a passing one is bound to the candidate the gate asked about. Anything else is a
/// malformed answer (exit 5), never a pass.
fn well_formed(body: &Value, verdict: &str, req: &Request<'_>) -> Result<(), String> {
    let summary = &body["summary"];
    if !summary.is_object() {
        return Err("the answer has no summary".into());
    }
    if summary["verdict"].as_str() != Some(verdict) {
        return Err("the summary's verdict differs from the answer's".into());
    }
    if summary["regression"].as_str() != Some(req.regression) {
        return Err("the answer evaluates another regression".into());
    }
    if summary["digest"].as_str().is_none_or(str::is_empty) {
        return Err("the answer has no evaluation digest".into());
    }
    if matches!(verdict, "pass" | "accepted_with_exceptions")
        && let Some(expect) = req.expect_source
    {
        let c = &summary["candidate"];
        if c["bound"] != true || c["source_digest"].as_str() != Some(expect) {
            return Err("the passing answer is not bound to the expected source".into());
        }
    }
    Ok(())
}

fn no_verdict(path: Option<&Path>, code: u8, reason: String) -> u8 {
    if write_summary(path, &json!({"verdict": null, "no_verdict": reason})) {
        code
    } else {
        5
    }
}

/// Feature mode: what to evaluate.
#[derive(Debug, Clone)]
pub struct FeatureRequest<'a> {
    /// Project.
    pub project: &'a str,
    /// Checklist ID.
    pub checklist: &'a str,
    /// Version (default: the latest).
    pub version: Option<&'a str>,
    /// Repository-qualified branch.
    pub branch: &'a str,
    /// Where to write the evaluation.
    pub summary_file: Option<&'a Path>,
}

/// The exit code of a feature evaluation: 0 ready for sign-off review, 10 an item failed,
/// 11 otherwise (missing, insufficient, outdated or unreviewed items).
#[must_use]
pub fn feature_exit_code(eval: &Value) -> u8 {
    let items = eval["items"].as_array().cloned().unwrap_or_default();
    if eval["ready"] == true
        && items
            .iter()
            .all(|i| i["state"] == "satisfied" || i["state"] == "not_applicable")
    {
        0
    } else if items.iter().any(|i| i["state"] == "failed") {
        10
    } else if eval["ready"].is_boolean() {
        11
    } else {
        5
    }
}

/// Runs a feature evaluation; the evaluation is written before exiting.
pub async fn run_feature(cfg: &CliConfig, req: &FeatureRequest<'_>) -> u8 {
    let mut q = vec![("branch", req.branch)];
    if let Some(v) = req.version {
        q.push(("version", v));
    }
    match call(
        cfg,
        reqwest::Method::GET,
        req.project,
        &["checklists", req.checklist, "evaluation"],
        &q,
        None,
    )
    .await
    {
        Ok(b) => {
            if !write_summary(req.summary_file, &b) {
                return 5;
            }
            feature_exit_code(&b)
        }
        Err((code, reason)) => no_verdict(req.summary_file, code, reason),
    }
}

/// `dviscope checklist import FILE`: parses the YAML locally and imports it.
///
/// # Errors
/// The file, its YAML, or the server's answer (with the exit code).
pub async fn import_checklist(cfg: &CliConfig, project: &str, file: &Path) -> Answer {
    let text = std::fs::read_to_string(file)
        .map_err(|e| (2, format!("cannot read the checklist: {e}")))?;
    let c = dviscope_core::feature::parse_checklist(&text)
        .map_err(|e| (2, format!("not a checklist: {e}")))?;
    let body = serde_json::to_value(&c).map_err(|e| (5, e.to_string()))?;
    call(
        cfg,
        reqwest::Method::POST,
        project,
        &["checklists"],
        &[],
        Some(&body),
    )
    .await
}

/// Parses and validates a hierarchy file locally (every problem located), then imports it
/// unless `dry_run` (which prints the tree it would import).
///
/// # Errors
/// Unreadable or invalid file (2), and the server's answers.
pub async fn import_hierarchy(
    cfg: &CliConfig,
    project: &str,
    file: &Path,
    dry_run: bool,
) -> Answer {
    let text = std::fs::read_to_string(file)
        .map_err(|e| (2, format!("cannot read the hierarchy: {e}")))?;
    let h = dviscope_core::health::parse_hierarchy(&text)
        .map_err(|e| (2, format!("not a hierarchy: {e}")))?;
    let problems = h.validate();
    if !problems.is_empty() {
        let lines: Vec<String> = problems
            .iter()
            .map(|p| format!("{}: {}", p.at, p.message))
            .collect();
        return Err((
            2,
            format!(
                "invalid hierarchy:
  {}",
                lines.join(
                    "
  "
                )
            ),
        ));
    }
    if dry_run {
        return Ok(json!({
            "valid": true,
            "nodes": h.nodes.iter().map(|n| &n.path).collect::<Vec<_>>(),
            "streams": h.streams.len(),
            "links": h.links.len(),
        }));
    }
    let body = serde_json::to_value(&h).map_err(|e| (5, e.to_string()))?;
    call(
        cfg,
        reqwest::Method::PUT,
        project,
        &["hierarchy"],
        &[],
        Some(&body),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a well-formed evaluation of this regression, its summary
    /// agreeing with its verdict and (for a pass) bound to the expected source, can open
    /// the gate.
    #[test]
    fn a_malformed_answer_never_passes() {
        let req = |src: Option<&'static str>| Request {
            project: "p",
            regression: "r1",
            expect_source: src,
            exceptions_pass: true,
            summary: "log-free",
            summary_file: None,
            wait_until: None,
            poll: std::time::Duration::from_secs(1),
            publish: None,
        };
        let good = json!({"verdict": "pass", "summary": {"verdict": "pass", "regression": "r1",
            "digest": "sha256:d", "candidate": {"bound": true, "source_digest": "sha256:s"}}});
        assert_eq!(well_formed(&good, "pass", &req(Some("sha256:s"))), Ok(()));
        assert_eq!(well_formed(&good, "pass", &req(None)), Ok(()));
        let bad = |f: &dyn Fn(&mut Value)| {
            let mut v = good.clone();
            f(&mut v);
            well_formed(&v, "pass", &req(Some("sha256:s")))
        };
        assert!(bad(&|v| v["summary"] = Value::Null).is_err());
        assert!(bad(&|v| v["summary"]["verdict"] = json!("fail")).is_err());
        assert!(bad(&|v| v["summary"]["regression"] = json!("r2")).is_err());
        assert!(bad(&|v| v["summary"]["digest"] = Value::Null).is_err());
        assert!(bad(&|v| v["summary"]["candidate"]["bound"] = json!(false)).is_err());
        assert!(bad(&|v| v["summary"]["candidate"]["source_digest"] = json!("sha256:x")).is_err());
        // A non-passing answer need not be bound (a source mismatch is itself insufficient).
        let mut ins = good.clone();
        ins["verdict"] = json!("insufficient_evidence");
        ins["summary"]["verdict"] = json!("insufficient_evidence");
        ins["summary"]["candidate"]["bound"] = json!(false);
        assert_eq!(
            well_formed(&ins, "insufficient_evidence", &req(Some("sha256:s"))),
            Ok(())
        );
        // Through the gate's conclusion: a bare pass is exit 5; a well-formed one exit 0.
        assert_eq!(conclude(&req(None), &json!({"verdict": "pass"}), None), 5);
        assert_eq!(conclude(&req(Some("sha256:s")), &good, None), 0);
    }

    #[test]
    fn unwritable_summaries_fail_and_leave_nothing_stale() {
        let d = std::env::temp_dir().join(format!("dvs-sum-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
        let f = d.join("s.json");
        assert!(write_summary(Some(&f), &json!({"verdict": "pass"})));
        assert!(
            std::fs::read_to_string(&f)
                .unwrap_or_default()
                .contains("pass")
        );
        // A directory where the file should be: the write fails.
        let blocked = d.join("dir.json");
        std::fs::create_dir_all(&blocked).unwrap_or_else(|e| panic!("{e}"));
        assert!(!write_summary(
            Some(&blocked.join("x").join("s.json")),
            &json!({})
        ));
        // The no-verdict path reports a failed write as an internal error.
        assert_eq!(
            no_verdict(Some(&blocked.join("x").join("s.json")), 4, "x".into()),
            5
        );
        // Concurrent writers of two outputs in one directory never mix contents.
        let (a, b) = (d.join("v.json"), d.join("v.txt"));
        std::thread::scope(|sc| {
            for i in 0..8 {
                let (a, b) = (&a, &b);
                sc.spawn(move || {
                    assert!(write_summary(Some(a), &json!({"file": "json", "i": i})));
                    assert!(write_summary(Some(b), &json!({"file": "txt", "i": i})));
                });
            }
        });
        assert!(
            std::fs::read_to_string(&a)
                .unwrap_or_default()
                .contains("json")
        );
        assert!(
            !std::fs::read_to_string(&a)
                .unwrap_or_default()
                .contains("txt")
        );
        assert!(
            std::fs::read_to_string(&b)
                .unwrap_or_default()
                .contains("txt")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn feature_exit_codes() {
        let ok =
            json!({"ready": true, "items": [{"state": "satisfied"}, {"state": "not_applicable"}]});
        assert_eq!(feature_exit_code(&ok), 0);
        let failed = json!({"ready": false, "items": [{"state": "missing"}, {"state": "failed"}]});
        assert_eq!(feature_exit_code(&failed), 10);
        let missing = json!({"ready": false, "items": [{"state": "unreviewed"}]});
        assert_eq!(feature_exit_code(&missing), 11);
        // A "ready" that contradicts its items is not trusted.
        let liar = json!({"ready": true, "items": [{"state": "outdated"}]});
        assert_eq!(feature_exit_code(&liar), 11);
        assert_eq!(feature_exit_code(&json!({})), 5);
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code("pass", true), 0);
        assert_eq!(exit_code("accepted_with_exceptions", true), 0);
        assert_eq!(exit_code("accepted_with_exceptions", false), 10);
        assert_eq!(exit_code("fail", true), 10);
        assert_eq!(exit_code("insufficient_evidence", true), 11);
        assert_eq!(exit_code("something else", true), 5);
    }

    /// One absolute deadline: past it nothing is sent, and a stalled
    /// request is cut at it (no grace).
    #[tokio::test]
    async fn requests_never_outlive_the_deadline() {
        let sent = std::sync::atomic::AtomicBool::new(false);
        let r = within(Some(std::time::Instant::now()), async {
            sent.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(json!(1))
        })
        .await;
        assert!(matches!(r, Err((4, _))), "{r:?}");
        assert!(
            !sent.load(std::sync::atomic::Ordering::SeqCst),
            "nothing sent"
        );
        let t0 = std::time::Instant::now();
        let until = t0 + std::time::Duration::from_millis(300);
        let r = within(Some(until), std::future::pending::<Answer>()).await;
        assert!(matches!(r, Err((4, _))));
        assert!(t0.elapsed() < std::time::Duration::from_millis(900));
        assert_eq!(within(None, async { Ok(json!(2)) }).await, Ok(json!(2)));
    }

    #[test]
    fn markdown_escapes_every_value() {
        let s = serde_json::json!({
            "verdict": "fail", "regression": "r*1", "suite": "night_ly", "policy": "strict",
            "evaluated_at": "2026-11-08T01:00:00Z", "valid_until": null,
            "candidate": {"repository": "rtl", "revision": "abc", "bound": true},
            "counts": {"failed": 1},
            "blockers": [{"kind": {"kind": "failed", "reason": "functional"}, "slots": 1,
                          "signatures": [7], "owner": "<img src=x onerror=alert(1)> | [a](javascript:x)\nnext",
                          "exceptable": true, "clearing_action": "fix it"}],
            "exceptions_used": [], "digest": "sha256:ab",
        });
        let m = markdown(&s);
        assert!(m.starts_with("## DVIScope merge readiness: FAIL\n"), "{m}");
        // Nothing interpretable survives in the owner: no tag, no link, no row break.
        assert!(
            m.match_indices('<').all(|(i, _)| m[..i].ends_with('\\')),
            "every < is escaped: {m}"
        );
        assert!(!m.contains("](javascript"), "{m}");
        assert!(
            m.contains(r"\<img src\=x onerror\=alert\(1\)\> \| \[a\]\(javascript\:x\) next"),
            "{m}"
        );
        assert!(m.contains(r"r\*1") && m.contains(r"night\_ly"), "{m}");
        assert_eq!(
            md_escape("a\u{1b}[31mb"),
            r"a\[31mb",
            "control characters dropped"
        );
    }
}
