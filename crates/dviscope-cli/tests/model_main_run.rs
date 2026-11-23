//! A Verilator model with its own main through the real binary. The slot
//! declares `extra.tool.main = "model"`; the collector creates the program log and the
//! console exclusively, hands the console handle to the child, and joins both into one
//! evidence. Invented toy markers; no simulator.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use dviscope_cli::journal::{Journal, kind};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

const MODEL: &str = r#"format: dviscope.rules/1.0
pack: toymodel
version: 1.0.0
tier: project
markers:
  - {id: begin, match: '^TOY MODEL BEGIN$'}
  - {id: stats, match: '^TOY STATS$'}
  - {id: end, match: '^TOY END \d+$'}
verdicts:
  - {id: res, source: test_result, match: '^TOY RESULT PASS$', value: pass}
completion:
  model_main: {start: begin, trailer: [stats, end]}
"#;

const CONSOLE: &str =
    "TOY MODEL BEGIN\\n- rtl/top.sv:12: Verilog $finish\\nTOY STATS\\nTOY END 7\\n";

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-mm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    d
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap_or_default()
}

fn cli(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("DVISCOPE_TEST_CRASH_POINT")
        .output()
        .unwrap_or_else(|e| panic!("{e}"))
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A journal, a launch (declaring the model or not) and the toy pack.
fn setup(name: &str, declared: bool) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let d = tmp(name);
    let j = d.join("journal");
    let o = cli(&["journal", "init", "--dir", s(&j), "--id", name]);
    assert!(o.status.success(), "{}", err(&o));
    let mut exec = json!({"test": "t", "seed": "1"});
    if declared {
        exec["extra"] = json!({"tool": {"main": "model"}});
    }
    let l = d.join("a1.launch.json");
    let spec = json!({
        "producer_id": "pilot", "regression_ref": "r1", "slot_ref": "s1",
        "attempt_ref": "a1", "source_manifest_ref": "sm1", "execution": exec,
    });
    std::fs::write(&l, spec.to_string()).ok();
    let pack = d.join("toymodel.yaml");
    std::fs::write(&pack, MODEL).ok();
    (d, j, l, pack)
}

/// The evidence of the journal's only envelope.
fn evidence(j: &Path) -> Value {
    let jr = Journal::open(j).unwrap_or_else(|e| panic!("{e}"));
    let entries = jr.entries().unwrap_or_else(|e| panic!("{e}"));
    let env = entries
        .into_iter()
        .flatten()
        .find(|e| e.kind == kind::ENVELOPE)
        .unwrap_or_else(|| panic!("no envelope"));
    let body: Value = serde_json::from_slice(&jr.payload(&env).unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or_else(|e| panic!("{e}"));
    body["evidence"].clone()
}

fn run(j: &Path, l: &Path, pack: &Path, files: &[&str], child: &[&str]) -> Output {
    let mut args = vec![
        "run",
        "--journal",
        s(j),
        "--launch",
        s(l),
        "--pack",
        s(pack),
    ];
    args.extend_from_slice(files);
    args.extend_from_slice(&["--", BIN, "__tree", "--children", "0", "--sleep", "0"]);
    args.extend_from_slice(child);
    cli(&args)
}

#[test]
fn a_declared_model_joins_its_program_log_and_console() {
    let (d, j, l, pack) = setup("joined", true);
    let (log, con) = (d.join("program.log"), d.join("console.txt"));
    let o = run(
        &j,
        &l,
        &pack,
        &["--log", s(&log), "--console", s(&con)],
        &["--write", s(&log), "TOY RESULT PASS\\n", "--say", CONSOLE],
    );
    assert!(o.status.success(), "{}", err(&o));
    let ev = evidence(&j);
    assert_eq!(ev["completion"]["profile"], "verilator-model-main", "{ev}");
    assert_eq!(
        ev["completion"]["state"], "complete",
        "{}",
        ev["completion"]
    );
    let segs = &ev["source"]["segments"];
    assert_eq!(segs[0]["name"], "program");
    assert_eq!(segs[1]["name"], "console");
    assert_eq!(segs[0]["line_start"], 1);
    assert_eq!(segs[1]["line_start"], 2);
    assert_eq!(ev["source"]["log_name"], "program.log");
}

#[test]
fn an_undeclared_run_is_unchanged() {
    let (d, j, l, pack) = setup("plain", false);
    let (log, con) = (d.join("program.log"), d.join("console.txt"));
    let o = run(
        &j,
        &l,
        &pack,
        &["--log", s(&log), "--console", s(&con)],
        &["--write", s(&log), "TOY RESULT PASS\\n", "--say", CONSOLE],
    );
    assert!(o.status.success(), "{}", err(&o));
    let ev = evidence(&j);
    assert_ne!(ev["completion"]["profile"], "verilator-model-main", "{ev}");
    assert!(ev["source"].get("segments").is_none(), "{ev}");
}

#[test]
fn a_declared_model_needs_two_distinct_files_and_verilator() {
    let (d, j, l, pack) = setup("refusals", true);
    let both = d.join("both.log");
    let o = run(
        &j,
        &l,
        &pack,
        &["--log", s(&both), "--console", s(&both)],
        &[],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("distinct"), "{}", err(&o));
    let o = run(&j, &l, &pack, &["--log", s(&d.join("only.log"))], &[]);
    assert!(!o.status.success());
    assert!(err(&o).contains("--console"), "{}", err(&o));
    let o = run(
        &j,
        &l,
        &pack,
        &[
            "--log",
            s(&d.join("p.log")),
            "--console",
            s(&d.join("c.txt")),
            "--simulator",
            "vcs",
        ],
        &[],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("Verilator"), "{}", err(&o));
    // Nothing was launched by a refused run.
    let jr = Journal::open(&j).unwrap_or_else(|e| panic!("{e}"));
    let launches = jr
        .entries()
        .unwrap_or_else(|e| panic!("{e}"))
        .into_iter()
        .flatten()
        .filter(|e| e.kind == kind::LAUNCH)
        .count();
    assert_eq!(launches, 0);
}

#[test]
fn an_unknown_main_value_is_refused() {
    let (d, j, l, pack) = setup("value", false);
    let mut spec: Value =
        serde_json::from_slice(&std::fs::read(&l).unwrap_or_default()).unwrap_or(Value::Null);
    spec["execution"]["extra"] = json!({"tool": {"main": "binary"}});
    std::fs::write(&l, spec.to_string()).ok();
    let o = run(&j, &l, &pack, &["--log", s(&d.join("p.log"))], &[]);
    assert!(!o.status.success());
    assert!(err(&o).contains("extra.tool.main"), "{}", err(&o));
}

/// The collector reads the files it created: a program log replaced during the attempt is
/// never its evidence. Unix: the path then names another file and the attempt is recorded
/// as interrupted; Windows: the collector's handle refuses the replacement itself.
#[test]
fn a_replaced_program_log_is_never_evidence() {
    let (d, j, l, pack) = setup("replaced", true);
    let (log, con) = (d.join("program.log"), d.join("console.txt"));
    let src = d.join("src.log");
    std::fs::write(
        &src,
        "TOY RESULT PASS
",
    )
    .ok();
    let o = run(
        &j,
        &l,
        &pack,
        &["--log", s(&log), "--console", s(&con)],
        &["--rename", s(&src), s(&log), "--say", CONSOLE],
    );
    let jr = Journal::open(&j).unwrap_or_else(|e| panic!("{e}"));
    let entries: Vec<_> = jr
        .entries()
        .unwrap_or_else(|e| panic!("{e}"))
        .into_iter()
        .flatten()
        .collect();
    if cfg!(unix) {
        assert!(!o.status.success(), "a replaced log must be refused");
        assert!(err(&o).contains("replaced"), "{}", err(&o));
        // Recorded as interrupted: termination unknown, never a pass.
        let result = entries
            .iter()
            .find(|e| e.kind == kind::RUNNER_RESULT)
            .and_then(|e| e.record.clone())
            .unwrap_or(Value::Null);
        assert_eq!(
            result["runner"]["termination"]["kind"], "unknown",
            "{result}"
        );
    } else {
        // The child's rename fails (no delete sharing): the stale file never becomes the
        // log, and the run is not complete.
        assert!(o.status.success(), "{}", err(&o));
        assert!(src.exists(), "the stale file was not moved");
        let ev = evidence(&j);
        assert_ne!(ev["completion"]["state"], "complete", "{ev}");
    }
}

/// An interrupted declared attempt is recovered under the declared profile (the server's
/// check of profile against declaration holds for recovery evidence too).
#[test]
fn recovery_of_a_declared_attempt_keeps_the_declared_profile() {
    let (d, j, l, pack) = setup("recover", true);
    let (log, con) = (d.join("program.log"), d.join("console.txt"));
    let o = Command::new(BIN)
        .args([
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&l),
            "--pack",
            s(&pack),
            "--log",
            s(&log),
            "--console",
            s(&con),
            "--",
            BIN,
            "__tree",
            "--children",
            "0",
            "--sleep",
            "0",
        ])
        .env("DVISCOPE_TEST_CRASH_POINT", "after_exit")
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(o.status.code(), Some(86), "{}", err(&o));
    let r = cli(&["journal", "recover", "--dir", s(&j)]);
    assert!(r.status.success(), "{}", err(&r));
    let ev = evidence(&j);
    assert_eq!(ev["completion"]["profile"], "verilator-model-main", "{ev}");
    assert_eq!(ev["completion"]["state"], "missing", "{ev}");
    assert!(ev["source"].get("segments").is_none(), "{ev}");
}

/// A program log or console moved away or deleted
/// during the attempt is recorded as interrupted (Unix), or cannot be moved or deleted at
/// all (Windows: no delete sharing).
#[test]
fn moved_or_deleted_files_are_never_evidence() {
    for (n, which, how) in [
        (0, "log", "rename"),
        (1, "log", "remove"),
        (2, "console", "rename"),
        (3, "console", "remove"),
    ] {
        let (d, j, l, pack) = setup(&format!("gone{n}"), true);
        let (log, con) = (d.join("program.log"), d.join("console.txt"));
        let target = if which == "log" { &log } else { &con };
        let away = d.join("away.txt");
        let mut child: Vec<&str> = vec!["--write", s(&log), "TOY RESULT PASS\\n"];
        if how == "rename" {
            child.extend_from_slice(&["--rename", s(target), s(&away)]);
        } else {
            child.extend_from_slice(&["--remove", s(target)]);
        }
        child.extend_from_slice(&["--say", CONSOLE]);
        let o = run(
            &j,
            &l,
            &pack,
            &["--log", s(&log), "--console", s(&con)],
            &child,
        );
        if cfg!(unix) {
            assert!(!o.status.success(), "{which} {how}: must be refused");
            assert!(err(&o).contains("replaced"), "{which} {how}: {}", err(&o));
            let ev = evidence(&j);
            assert_eq!(ev["completion"]["state"], "missing", "{which} {how}: {ev}");
            let jr = Journal::open(&j).unwrap_or_else(|e| panic!("{e}"));
            let result = jr
                .entries()
                .unwrap_or_else(|e| panic!("{e}"))
                .into_iter()
                .flatten()
                .find(|e| e.kind == kind::RUNNER_RESULT)
                .and_then(|e| e.record)
                .unwrap_or(Value::Null);
            assert_eq!(
                result["runner"]["termination"]["kind"], "unknown",
                "{which} {how}: {result}"
            );
        } else {
            assert!(o.status.success(), "{which} {how}: {}", err(&o));
            assert!(target.exists(), "{which} {how}: the file stays");
            let ev = evidence(&j);
            assert_ne!(ev["completion"]["state"], "complete", "{which} {how}: {ev}");
        }
    }
}

/// `rules explain --console` explains the joined pair
/// with the segments and every marker's count and positions.
#[test]
fn rules_explain_joins_the_console() {
    let (d, _j, _l, pack) = setup("explain", true);
    let (log, con) = (d.join("program.log"), d.join("console.txt"));
    std::fs::write(&log, "TOY RESULT PASS\n").ok();
    std::fs::write(&con, CONSOLE.replace("\\n", "\n") + "TOY MODEL BEGIN\n").ok();
    let o = cli(&[
        "rules",
        "explain",
        "--pack",
        s(&pack),
        "--log",
        s(&log),
        "--console",
        s(&con),
        "--line",
        "2",
    ]);
    assert!(o.status.success(), "{}", err(&o));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(v["text"], "TOY MODEL BEGIN", "{v}");
    assert_eq!(v["segments"][1]["name"], "console", "{v}");
    let begin = v["markers"]
        .as_array()
        .and_then(|m| m.iter().find(|x| x["marker"] == "toymodel/begin"))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(begin["count"], 2, "{v}");
    assert_eq!(begin["at"][0], json!(["console", 2]), "{v}");
    assert_eq!(v["completion"]["reasons"], json!(["witness_count"]), "{v}");
}

/// The explanation's marker counts include a final line without a
/// line break (a final trailer; a final duplicate banner).
#[test]
fn rules_explain_counts_an_unterminated_final_line() {
    let (d, _j, _l, pack) = setup("explain-eof", true);
    let (log, con) = (d.join("program.log"), d.join("console.txt"));
    std::fs::write(&log, "TOY RESULT PASS\n").ok();
    let explain = |text: &str| -> Value {
        std::fs::write(&con, text).ok();
        let o = cli(&[
            "rules",
            "explain",
            "--pack",
            s(&pack),
            "--log",
            s(&log),
            "--console",
            s(&con),
            "--line",
            "2",
        ]);
        assert!(o.status.success(), "{}", err(&o));
        serde_json::from_slice(&o.stdout).unwrap_or(Value::Null)
    };
    let count = |v: &Value, m: &str| {
        v["markers"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["marker"] == m))
            .map_or(0, |x| x["count"].as_u64().unwrap_or(0))
    };
    let full = CONSOLE.replace("\\n", "\n");
    let v = explain(full.trim_end_matches('\n'));
    assert_eq!(v["completion"]["state"], "complete", "{v}");
    assert_eq!(count(&v, "toymodel/end"), 1, "{v}");
    let v = explain(&format!("{full}TOY MODEL BEGIN"));
    assert_eq!(count(&v, "toymodel/begin"), 2, "{v}");
    assert_eq!(v["completion"]["reasons"], json!(["witness_count"]), "{v}");
}
