//! Regression tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use dviscope_cli::journal::Journal;
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-2c-r4-{name}-{}", std::process::id()));
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
    let o = cli(&["journal", "init", "--dir", s(&j), "--id", name], None);
    assert!(o.status.success(), "{}", err(&o));
    j
}

fn join(side: &Path, coord: &Path, crash: Option<&str>) -> Output {
    cli(
        &[
            "journal",
            "init",
            "--dir",
            s(side),
            "--id",
            "side",
            "--coordinator",
            s(coord),
        ],
        crash,
    )
}

fn run(j: &Path, l: &Path, extra: &[&str], sleep: &str) -> Output {
    let mut args = vec!["run", "--journal", s(j), "--launch", s(l)];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", BIN, "__tree", "--children", "0", "--sleep", sleep]);
    cli(&args, None)
}

#[test]
fn r4_n1_a_console_path_cannot_take_another_attempts_log() {
    let d = tmp("console");
    let j = init(&d, "j");
    let shared = d.join("shared.log");
    let (l1, l2) = (launch(&d, "a1", "s1"), launch(&d, "a2", "s2"));
    let outs: Vec<Output> = std::thread::scope(|sc| {
        let a = sc.spawn(|| run(&j, &l1, &["--log", s(&shared)], "1"));
        let b = sc.spawn(|| run(&j, &l2, &["--console", s(&shared)], "1"));
        [a, b].into_iter().filter_map(|h| h.join().ok()).collect()
    });
    assert_eq!(
        outs.iter().filter(|o| o.status.success()).count(),
        1,
        "one attempt owns the path, as log or as console"
    );
    let refused = outs
        .iter()
        .find(|o| !o.status.success())
        .map(err)
        .unwrap_or_default();
    assert!(refused.contains("exists or cannot be created"), "{refused}");
}

#[test]
fn r4_n1_one_attempt_may_use_one_path_for_log_and_console() {
    let d = tmp("same");
    let j = init(&d, "j");
    let p = d.join("both.log");
    let o = run(
        &j,
        &launch(&d, "a1", "s1"),
        &["--log", s(&p), "--console", s(&p)],
        "0",
    );
    assert!(o.status.success(), "{}", err(&o));
}

#[test]
fn r4_activation_interrupted_by_a_crash_is_resumed() {
    let d = tmp("resume");
    let coord = init(&d, "coord");
    let side = d.join("side");
    let o = join(&side, &coord, Some("before_rename:registered"));
    assert_eq!(o.status.code(), Some(86), "{}", err(&o));
    // Registered but not active: no launch.
    assert!(
        !run(&side, &launch(&d, "a1", "s1"), &[], "0")
            .status
            .success()
    );
    // Re-running the same initialization resumes it.
    let o = join(&side, &coord, None);
    assert!(o.status.success(), "{}", err(&o));
    let o = run(&side, &launch(&d, "a2", "s2"), &[], "0");
    assert!(o.status.success(), "{}", err(&o));
    // The coordinator holds one registration, not two.
    let c = Journal::open(&coord).unwrap_or_else(|e| panic!("{e}"));
    let regs = c
        .intact()
        .unwrap_or_default()
        .iter()
        .filter(|e| e.kind == "participant")
        .count();
    assert_eq!(regs, 1);
    // Another journal at that place is not taken for the participant.
    let o = cli(
        &[
            "journal",
            "init",
            "--dir",
            s(&side),
            "--id",
            "other",
            "--coordinator",
            s(&coord),
        ],
        None,
    );
    assert!(!o.status.success());
}

#[test]
fn r4_activation_is_serialized_with_the_participants_lock() {
    let d = tmp("lock");
    let coord = init(&d, "coord");
    let side = d.join("side");
    // A dormant, registered participant (the state after a crash before activation).
    let j = Journal::create_with(&side, "side", Some("coord")).unwrap_or_else(|e| panic!("{e}"));
    let c = Journal::open(&coord).unwrap_or_else(|e| panic!("{e}"));
    c.locked(|c| c.register(&side, "side"))
        .unwrap_or_else(|e| panic!("{e}"));
    // Someone holds the participant's lock (opening it, a status, a finish check...).
    let held = std::thread::spawn(move || {
        let _ = j.locked(|_| {
            std::thread::sleep(Duration::from_millis(1_500));
            Ok(())
        });
    });
    std::thread::sleep(Duration::from_millis(200));
    let t0 = Instant::now();
    let o = join(&side, &coord, None);
    let _ = held.join();
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        t0.elapsed() >= Duration::from_millis(1_000),
        "activation waited for the lock"
    );
    assert!(side.join("registered").exists());
    let o = run(&side, &launch(&d, "a1", "s1"), &[], "0");
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o)["state"], "spooled");
}

/// A launch and a mark depend on the regression's
/// amendments, which may declare their slots.
#[test]
fn s3_r1_14_launches_and_marks_wait_for_amendments() {
    let d = tmp("amend-deps");
    let j = init(&d, "j");
    let amend = d.join("amend.json");
    std::fs::write(
        &amend,
        json!({"schema": dviscope_model::schema::MANIFEST, "revision": 2,
               "add": [{"slot_ref": "s9", "exec_inputs": {"test": "t", "seed": "1"}, "required": true}]})
        .to_string(),
    )
    .ok();
    let o = cli(
        &[
            "manifest",
            "amend",
            "--journal",
            s(&j),
            "--regression",
            "r1",
            "--body",
            s(&amend),
        ],
        None,
    );
    assert!(o.status.success(), "{}", err(&o));
    let mark = d.join("mark.json");
    std::fs::write(
        &mark,
        json!({"schema": dviscope_model::schema::MANIFEST, "slot_refs": ["s9"],
               "state": "skipped", "reason": "r"})
        .to_string(),
    )
    .ok();
    let o = cli(
        &[
            "manifest",
            "mark",
            "--journal",
            s(&j),
            "--regression",
            "r1",
            "--body",
            s(&mark),
        ],
        None,
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(run(&j, &launch(&d, "a9", "s9"), &[], "0").status.success());
    let jr = Journal::open(&j).unwrap_or_else(|e| panic!("{e}"));
    let entries = jr.intact().unwrap_or_default();
    let amend_seq = entries
        .iter()
        .find(|e| e.kind == "manifest_amend")
        .map(|e| e.seq)
        .unwrap_or(0);
    for k in ["slot_mark", "launch"] {
        let e = entries
            .iter()
            .find(|e| e.kind == k)
            .unwrap_or_else(|| panic!("no {k}"));
        assert!(e.depends_on.contains(&amend_seq), "{k}: {:?}", e.depends_on);
    }
}
