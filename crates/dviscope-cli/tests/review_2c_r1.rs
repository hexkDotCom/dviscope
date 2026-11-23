//! Regression tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-2c-r1-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    d
}

fn cli(args: &[&str], crash: Option<&str>) -> Output {
    let mut c = Command::new(BIN);
    c.args(args);
    match crash {
        Some(p) => c.env("DVISCOPE_TEST_CRASH_POINT", p),
        None => c.env_remove("DVISCOPE_TEST_CRASH_POINT"),
    };
    c.output().unwrap_or_else(|e| panic!("{e}"))
}

fn out(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or(Value::Null)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap_or_default()
}

fn launch(dir: &Path, attempt: &str, slot: &str) -> PathBuf {
    let p = dir.join(format!("{attempt}.launch.json"));
    let spec = json!({
        "producer_id": "pilot", "regression_ref": "r1", "slot_ref": slot,
        "attempt_ref": attempt, "source_manifest_ref": "sm1",
        "execution": {"test": "t", "seed": "1"},
    });
    std::fs::write(&p, spec.to_string()).ok();
    p
}

fn init(dir: &Path, name: &str) -> PathBuf {
    let j = dir.join(name);
    let o = cli(&["journal", "init", "--dir", s(&j), "--id", name], None);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    j
}

fn run(j: &Path, l: &Path, tree: &[&str]) -> Output {
    let mut args = vec![
        "run",
        "--journal",
        s(j),
        "--launch",
        s(l),
        "--",
        BIN,
        "__tree",
        "--children",
        "0",
        "--sleep",
        "0",
    ];
    args.extend_from_slice(tree);
    cli(&args, None)
}

fn flush(j: &Path, ep: &Path) -> Value {
    out(&cli(
        &[
            "spool",
            "flush",
            "--dir",
            s(j),
            "--endpoint",
            &format!("dir:{}", s(ep)),
        ],
        None,
    ))
}

#[test]
fn f05_a_fault_is_a_crash_never_an_exit() {
    let d = tmp("fault");
    let j = init(&d, "j");
    let o = run(&j, &launch(&d, "a1", "s1"), &["--abort"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(out(&o)["termination"]["kind"], "crash", "{}", out(&o));
    #[cfg(windows)]
    {
        // An access-violation status as the exit code (0xC0000005).
        let o = run(&j, &launch(&d, "a2", "s1"), &["--exit=-1073741819"]);
        assert_eq!(out(&o)["termination"]["kind"], "crash");
        assert_eq!(out(&o)["termination"]["windows_status"], "0xc0000005");
    }
}

#[test]
fn f09_a_corrupt_closure_keeps_the_journal_closed() {
    let d = tmp("corrupt");
    let j = init(&d, "j");
    assert!(run(&j, &launch(&d, "a1", "s1"), &[]).status.success());
    let w = out(&cli(&["journal", "close", "--dir", s(&j)], None));
    assert_eq!(w["watermark"], 1);
    // Corrupt the closure entry.
    let closure = std::fs::read_dir(j.join("entries"))
        .unwrap_or_else(|e| panic!("{e}"))
        .flatten()
        .map(|e| e.path())
        .max()
        .unwrap_or_default();
    let text = std::fs::read_to_string(&closure)
        .unwrap_or_default()
        .replace("\"watermark\": 1", "\"watermark\": 9");
    std::fs::write(&closure, text).ok();
    let o = run(&j, &launch(&d, "a2", "s1"), &[]);
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("corrupt"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn f10_a_reused_pid_is_not_the_same_process() {
    let me = std::process::id();
    assert!(dviscope_cli::platform::alive(
        me,
        dviscope_cli::platform::process_identity(me).as_deref()
    ));
    assert!(!dviscope_cli::platform::alive(me, Some("another-start")));
}

#[test]
fn f12_concurrent_conflicting_deliveries_keep_one_effect() {
    let d = tmp("concurrent");
    let ep = d.join("endpoint");
    let (j1, j2) = (init(&d, "j1"), init(&d, "j2"));
    // Same attempt identity, different slots: different payloads under one identity.
    assert!(run(&j1, &launch(&d, "same", "s1"), &[]).status.success());
    assert!(run(&j2, &launch(&d, "same", "s2"), &[]).status.success());
    let ep2 = ep.clone();
    let j1c = j1.clone();
    let t = std::thread::spawn(move || flush(&j1c, &ep2));
    let b = flush(&j2, &ep);
    let a = t.join().unwrap_or(Value::Null);
    let committed = a["committed"].as_u64().unwrap_or(0) + b["committed"].as_u64().unwrap_or(0);
    let rejected = a["rejected"].as_u64().unwrap_or(0) + b["rejected"].as_u64().unwrap_or(0);
    assert_eq!((committed, rejected), (2, 1), "{a} {b}");
}

#[test]
fn f13_a_corrupt_payload_blocks_only_its_own_chain() {
    let d = tmp("payload");
    let j = init(&d, "j");
    let ep = d.join("endpoint");
    assert!(run(&j, &launch(&d, "a1", "s1"), &[]).status.success());
    assert!(run(&j, &launch(&d, "a2", "s2"), &[]).status.success());
    // Damage the first envelope's payload.
    let first = std::fs::read_dir(j.join("payloads"))
        .unwrap_or_else(|e| panic!("{e}"))
        .flatten()
        .map(|e| e.path())
        .min()
        .unwrap_or_default();
    std::fs::write(&first, b"{}").ok();
    let f = flush(&j, &ep);
    assert_eq!(
        (
            f["committed"].as_u64(),
            f["rejected"].as_u64(),
            f["pending"].as_u64()
        ),
        (Some(3), Some(1), Some(0)),
        "{f}"
    );
}

#[test]
fn f14_journals_are_private() {
    let d = tmp("private");
    let j = init(&d, "j");
    assert!(
        cli(&["journal", "status", "--dir", s(&j)], None)
            .status
            .success()
    );
    // A plain directory holding a journal is refused.
    let plain = d.join("plain");
    std::fs::create_dir_all(plain.join("entries")).ok();
    std::fs::copy(j.join("journal.json"), plain.join("journal.json")).ok();
    let o = cli(&["journal", "status", "--dir", s(&plain)], None);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not private"));
}

#[test]
fn f15_finish_waits_for_every_participant() {
    let d = tmp("finish");
    let ep = d.join("endpoint");
    let coord = init(&d, "coord");
    let side = d.join("side");
    let o = cli(
        &[
            "journal",
            "init",
            "--dir",
            s(&side),
            "--id",
            "side",
            "--coordinator",
            s(&coord),
        ],
        None,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(run(&side, &launch(&d, "a1", "s1"), &[]).status.success());
    let fin = |c: &Path| {
        cli(
            &[
                "journal",
                "finish",
                "--dir",
                s(c),
                "--regression",
                "r1",
                "--participant",
                s(&side),
            ],
            None,
        )
    };
    // Not closed yet.
    let o = fin(&coord);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not closed"));
    assert!(
        cli(&["journal", "close", "--dir", s(&side)], None)
            .status
            .success()
    );
    // Closed, but its start is not committed.
    let o = fin(&coord);
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("not committed"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let _ = flush(&side, &ep);
    let o = fin(&coord);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // The finish closes the coordinator for good.
    assert!(!run(&coord, &launch(&d, "a9", "s9"), &[]).status.success());
}

#[test]
fn f16_an_interrupted_reclaim_is_resumed() {
    let d = tmp("reclaim");
    let j = init(&d, "j");
    let ep = d.join("endpoint");
    assert!(run(&j, &launch(&d, "a1", "s1"), &[]).status.success());
    let o = cli(
        &[
            "spool",
            "flush",
            "--dir",
            s(&j),
            "--endpoint",
            &format!("dir:{}", s(&ep)),
        ],
        Some("after_rename:outcome"),
    );
    assert_eq!(o.status.code(), Some(86));
    let _ = flush(&j, &ep);
    let left = std::fs::read_dir(j.join("payloads"))
        .map(Iterator::count)
        .unwrap_or(99);
    assert_eq!(left, 0);
}
