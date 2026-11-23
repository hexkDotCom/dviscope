//! Regression tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use dviscope_cli::journal::Journal;
use dviscope_model::ids::ExternalKey;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-2c-r3-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    d
}

fn cli(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("DVISCOPE_TEST_CRASH_POINT")
        .output()
        .unwrap_or_else(|e| panic!("{e}"))
}

fn out(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or(Value::Null)
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
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
    let o = cli(&["journal", "init", "--dir", s(&j), "--id", name]);
    assert!(o.status.success(), "{}", err(&o));
    j
}

fn run(j: &Path, l: &Path, extra: &[&str], sleep: &str) -> Output {
    let mut args = vec!["run", "--journal", s(j), "--launch", s(l)];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", BIN, "__tree", "--children", "0", "--sleep", sleep]);
    cli(&args)
}

fn key(s: &str) -> ExternalKey {
    ExternalKey::try_from(s.to_string()).unwrap_or_else(|e| panic!("{e:?}"))
}

#[test]
fn r3_n1_report_ids_never_collide_across_forms() {
    let long = "a".repeat(200);
    let shortened = dviscope_cli::run::report_identity(&key(&long)).unwrap_or_default();
    let id = shortened.trim_start_matches("simulation_attempt:");
    let crafted = id.trim_end_matches(":r1");
    // The round-3 reproduction: a reference shaped like a shortened ID.
    let other = dviscope_cli::run::report_identity(&key(crafted)).unwrap_or_default();
    assert_ne!(shortened, other);
    assert!(id.len() <= ExternalKey::MAX_LEN);
    // Short references keep the readable form.
    assert_eq!(
        dviscope_cli::run::report_identity(&key("a1")).unwrap_or_default(),
        "simulation_attempt:a1:r1"
    );
}

#[test]
fn r3_n1_concurrent_attempts_cannot_share_a_log() {
    let d = tmp("sharedlog");
    let j = init(&d, "j");
    let log = d.join("sim.log");
    let (l1, l2) = (launch(&d, "a1", "s1"), launch(&d, "a2", "s2"));
    let outs: Vec<Output> = std::thread::scope(|sc| {
        let h: Vec<_> = [&l1, &l2]
            .into_iter()
            .map(|l| {
                let (j, log) = (&j, &log);
                sc.spawn(move || run(j, l, &["--log", s(log)], "1"))
            })
            .collect();
        h.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    let ok = outs.iter().filter(|o| o.status.success()).count();
    assert_eq!(ok, 1, "exactly one attempt owns the log path");
    let refused = outs
        .iter()
        .find(|o| !o.status.success())
        .map(err)
        .unwrap_or_default();
    assert!(refused.contains("exists or cannot be created"), "{refused}");
    // The refused attempt launched nothing.
    let st = out(&cli(&["journal", "status", "--dir", s(&j)]));
    let launches = st["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["kind"] == "launch")
        .count();
    assert_eq!(launches, 1);
}

#[test]
fn r3_15_a_participant_launches_only_once_registered() {
    let d = tmp("dormant");
    let coord = init(&d, "coord");
    // Created, not yet registered (the window the round-3 race used): no launch.
    let side = d.join("side");
    let j = Journal::create_with(&side, "side", Some("coord")).unwrap_or_else(|e| panic!("{e}"));
    let o = run(&side, &launch(&d, "a1", "s1"), &[], "0");
    assert!(!o.status.success());
    assert!(err(&o).contains("not registered"), "{}", err(&o));
    // Finished meanwhile: the registration is refused, so the side never launches.
    let o = cli(&[
        "journal",
        "finish",
        "--dir",
        s(&coord),
        "--regression",
        "r1",
    ]);
    assert!(o.status.success(), "{}", err(&o));
    let c = Journal::open(&coord).unwrap_or_else(|e| panic!("{e}"));
    assert!(c.locked(|c| c.register(&side, "side")).is_err());
    drop(j);
    let o = run(&side, &launch(&d, "a2", "s2"), &[], "0");
    assert!(!o.status.success());
}

#[test]
fn r3_15_a_missing_registered_participant_blocks_finish() {
    let d = tmp("missing");
    let coord = init(&d, "coord");
    let side = d.join("side");
    let o = cli(&[
        "journal",
        "init",
        "--dir",
        s(&side),
        "--id",
        "side",
        "--coordinator",
        s(&coord),
    ]);
    assert!(o.status.success(), "{}", err(&o));
    std::fs::remove_dir_all(&side).ok();
    let o = cli(&[
        "journal",
        "finish",
        "--dir",
        s(&coord),
        "--regression",
        "r1",
    ]);
    assert!(!o.status.success());
    assert!(err(&o).contains("cannot be opened"), "{}", err(&o));
}

#[cfg(windows)]
#[test]
fn r3_n2_an_unreadable_entry_is_not_corruption() {
    use std::os::windows::fs::OpenOptionsExt as _;
    let d = tmp("entrylock");
    let j = init(&d, "j");
    let ep = d.join("endpoint");
    assert!(run(&j, &launch(&d, "a1", "s1"), &[], "0").status.success());
    // Lock the launch entry (seq 1) exclusively, then flush: nothing may be recorded.
    let entry = j.join("entries").join("00000001.json");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&entry)
        .unwrap_or_else(|e| panic!("{e}"));
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
    let o = flush();
    assert!(
        !o.status.success(),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(
        std::fs::read_dir(j.join("outcomes")).map_or(0, Iterator::count),
        0,
        "no outcome is recorded while an entry cannot be read"
    );
    drop(held);
    let o = flush();
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o)["committed"].as_u64(), Some(2), "{}", out(&o));
    assert_eq!(out(&o)["blocked"].as_u64(), Some(0));
}

/// `collect` obeys the same registration guard as `run`.
#[test]
fn s5_collect_launches_only_once_registered() {
    let d = tmp("collect-dormant");
    let _coord = init(&d, "coord");
    let side = d.join("side");
    let _j = Journal::create_with(&side, "side", Some("coord")).unwrap_or_else(|e| panic!("{e}"));
    let o = cli(&[
        "collect",
        "--journal",
        s(&side),
        "--launch",
        s(&launch(&d, "c1", "s1")),
        "--started-at",
        "2026-11-08T01:00:00Z",
    ]);
    assert!(!o.status.success());
    assert!(err(&o).contains("not registered"), "{}", err(&o));
}
