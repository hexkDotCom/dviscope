//! Collector regression tests, through the
//! real binary and the directory-backed receipt endpoint. No simulator.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use dviscope_cli::journal::{Journal, kind};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-fr-{name}-{}", std::process::id()));
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

fn ok(o: &Output) {
    assert!(o.status.success(), "{}", err(o));
}

fn write(d: &Path, name: &str, v: &Value) -> PathBuf {
    let p = d.join(name);
    std::fs::write(&p, v.to_string()).ok();
    p
}

/// K4: chunks flushed before the seal keep their payloads until the seal commits (the seal
/// reads every chunk); the seal's commit reclaims them.
#[test]
fn k4_flushing_before_the_seal_never_strands_the_manifest() {
    let d = tmp("seal");
    let j = d.join("journal");
    let ep = d.join("endpoint");
    ok(&cli(&["journal", "init", "--dir", s(&j), "--id", "j1"]));
    let schema = |b: &str| {
        format!(
            "dviscope.{b}/1.0-dev.{}",
            dviscope_model::schema::DEV_REVISION
        )
    };
    let sm = write(
        &d,
        "sm.json",
        &json!({"schema": schema("ingest"), "producer_id": "pilot",
        "source_manifest_ref": "sm1", "repositories": [{"repository": "rtl", "revision": "a1"}]}),
    );
    let reg = write(
        &d,
        "reg.json",
        &json!({"schema": schema("ingest"), "producer_id": "pilot",
        "regression_ref": "r1", "suite": "nightly", "branch": {"repository": "rtl", "name": "main"},
        "source_manifest_ref": "sm1", "trigger": {"kind": "nightly"},
        "started_at": "2026-11-10T01:00:00Z"}),
    );
    let chunk = write(
        &d,
        "slots.json",
        &json!({"schema": schema("manifest"), "slots": [
        {"slot_ref": "s1", "exec_inputs": {"test": "t1", "seed": "1"}, "required": true}]}),
    );
    ok(&cli(&[
        "source-manifest",
        "--journal",
        s(&j),
        "--body",
        s(&sm),
    ]));
    ok(&cli(&[
        "regression",
        "create",
        "--journal",
        s(&j),
        "--body",
        s(&reg),
    ]));
    ok(&cli(&[
        "manifest",
        "declare",
        "--journal",
        s(&j),
        "--regression",
        "r1",
        "--chunk",
        "1",
        "--body",
        s(&chunk),
    ]));
    let flush = || {
        cli(&[
            "spool",
            "flush",
            "--dir",
            s(&j),
            "--endpoint",
            &format!("dir:{}", s(&ep)),
        ])
    };
    ok(&flush());
    // A second flush (its reclaim sweep runs) still keeps the unsealed chunk.
    ok(&flush());
    // The chunk is committed; sealing still reads it.
    ok(&cli(&[
        "manifest",
        "seal",
        "--journal",
        s(&j),
        "--regression",
        "r1",
    ]));
    ok(&flush());
    let jr = Journal::open(&j).unwrap_or_else(|e| panic!("{e}"));
    let entries: Vec<_> = jr
        .entries()
        .unwrap_or_else(|e| panic!("{e}"))
        .into_iter()
        .flatten()
        .collect();
    let chunk_entry = entries
        .iter()
        .find(|e| e.kind == kind::MANIFEST_CHUNK)
        .unwrap_or_else(|| panic!("chunk entry"));
    let outcomes = jr.outcomes().unwrap_or_else(|e| panic!("{e}"));
    let seal = entries
        .iter()
        .find(|e| e.kind == kind::MANIFEST_SEAL)
        .unwrap_or_else(|| panic!("seal entry"));
    assert!(outcomes.contains_key(&seal.seq), "the seal was delivered");
    // After the seal's commit, the next flush's sweep reclaims the chunk's payload.
    ok(&flush());
    let file = chunk_entry
        .payload
        .as_ref()
        .map(|p| p.file.clone())
        .unwrap_or_default();
    assert!(!j.join("payloads").join(file).exists());
}

/// K1: an ordinary run's log replaced during the attempt (an earlier run's passing log,
/// say) is never this attempt's evidence: Unix records the attempt as interrupted; Windows
/// refuses the replacement itself.
#[test]
fn k1_a_replaced_log_is_never_an_ordinary_runs_evidence() {
    let d = tmp("k1");
    let j = d.join("journal");
    ok(&cli(&["journal", "init", "--dir", s(&j), "--id", "j1"]));
    let l = write(
        &d,
        "a1.launch.json",
        &json!({
        "producer_id": "pilot", "regression_ref": "r1", "slot_ref": "s1", "attempt_ref": "a1",
        "source_manifest_ref": "sm1", "execution": {"test": "t", "seed": "1"}}),
    );
    let (log, stale) = (d.join("sim.log"), d.join("stale.log"));
    std::fs::write(&stale, "an earlier run's log\n").ok();
    let o = cli(&[
        "run",
        "--journal",
        s(&j),
        "--launch",
        s(&l),
        "--log",
        s(&log),
        "--",
        BIN,
        "__tree",
        "--children",
        "0",
        "--sleep",
        "0",
        "--rename",
        s(&stale),
        s(&log),
    ]);
    let jr = Journal::open(&j).unwrap_or_else(|e| panic!("{e}"));
    let entries: Vec<_> = jr
        .entries()
        .unwrap_or_else(|e| panic!("{e}"))
        .into_iter()
        .flatten()
        .collect();
    let env = entries
        .iter()
        .find(|e| e.kind == kind::ENVELOPE)
        .unwrap_or_else(|| panic!("no envelope: {}", err(&o)));
    let body: Value = serde_json::from_slice(&jr.payload(env).unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or(Value::Null);
    // Never the stale bytes.
    assert_eq!(body["evidence"]["source"]["bytes"], 0, "{body}");
    if cfg!(unix) {
        assert!(!o.status.success());
        assert!(err(&o).contains("replaced"), "{}", err(&o));
        assert_eq!(
            body["result"]["runner"]["termination"]["kind"], "unknown",
            "{body}"
        );
    } else {
        assert!(
            stale.exists(),
            "the collector's handle refused the replacement"
        );
    }
}

/// R3: the first-afternoon examples are complete, consistent with each other, of this
/// version's schemas, and accepted by the collector's own commands in the documented order.
#[test]
fn r3_the_documented_nightly_examples_work() {
    let ex = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples");
    let read = |n: &str| -> Value {
        serde_json::from_slice(&std::fs::read(ex.join(n)).unwrap_or_default())
            .unwrap_or(Value::Null)
    };
    let (sm, reg, slots, launch) = (
        read("sm.json"),
        read("regression.json"),
        read("slots.json"),
        read("uart_tx.launch.json"),
    );
    assert_eq!(sm["schema"], dviscope_model::schema::INGEST);
    assert_eq!(reg["schema"], dviscope_model::schema::INGEST);
    assert_eq!(slots["schema"], dviscope_model::schema::MANIFEST);
    assert_eq!(reg["source_manifest_ref"], sm["source_manifest_ref"]);
    assert_eq!(launch["source_manifest_ref"], sm["source_manifest_ref"]);
    assert_eq!(launch["regression_ref"], reg["regression_ref"]);
    assert_eq!(launch["producer_id"], reg["producer_id"]);
    let slot = slots["slots"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["slot_ref"] == launch["slot_ref"]))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(
        slot["exec_inputs"], launch["execution"],
        "the launch runs the slot's inputs"
    );
    // The documented commands accept them, and run the launch.
    let d = tmp("examples");
    let j = d.join("journal");
    ok(&cli(&[
        "journal",
        "init",
        "--dir",
        s(&j),
        "--id",
        "nightly-2026-11-10",
    ]));
    let r = reg["regression_ref"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    ok(&cli(&[
        "source-manifest",
        "--journal",
        s(&j),
        "--body",
        s(&ex.join("sm.json")),
    ]));
    ok(&cli(&[
        "regression",
        "create",
        "--journal",
        s(&j),
        "--body",
        s(&ex.join("regression.json")),
    ]));
    ok(&cli(&[
        "manifest",
        "declare",
        "--journal",
        s(&j),
        "--regression",
        &r,
        "--chunk",
        "1",
        "--body",
        s(&ex.join("slots.json")),
    ]));
    ok(&cli(&[
        "manifest",
        "seal",
        "--journal",
        s(&j),
        "--regression",
        &r,
    ]));
    let log = d.join("uart_tx.log");
    ok(&cli(&[
        "run",
        "--journal",
        s(&j),
        "--launch",
        s(&ex.join("uart_tx.launch.json")),
        "--log",
        s(&log),
        "--",
        BIN,
        "__tree",
        "--children",
        "0",
        "--sleep",
        "0",
    ]));
}
