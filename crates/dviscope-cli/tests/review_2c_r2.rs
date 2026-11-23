//! Regression tests.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use dviscope_cli::journal::{Journal, kind};
use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-2c-r2-{name}-{}", std::process::id()));
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
    let p = dir.join(format!("{}.launch.json", &attempt[..attempt.len().min(16)]));
    let spec = json!({
        "producer_id": "pilot", "regression_ref": "r1", "slot_ref": slot,
        "attempt_ref": attempt, "source_manifest_ref": "sm1",
        "execution": {"test": "t", "seed": "1"},
    });
    std::fs::write(&p, spec.to_string()).ok();
    p
}

fn init(dir: &Path, name: &str, coordinator: Option<&Path>) -> PathBuf {
    let j = dir.join(name);
    let mut args = vec!["journal", "init", "--dir", s(&j), "--id", name];
    if let Some(c) = coordinator {
        args.extend_from_slice(&["--coordinator", s(c)]);
    }
    let o = cli(&args);
    assert!(o.status.success(), "{}", err(&o));
    j
}

fn run(j: &Path, l: &Path, extra: &[&str], sleep: &str) -> Output {
    let mut args = vec!["run", "--journal", s(j), "--launch", s(l)];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", BIN, "__tree", "--children", "0", "--sleep", sleep]);
    cli(&args)
}

fn flush(j: &Path, ep: &Path) -> Value {
    out(&cli(&[
        "spool",
        "flush",
        "--dir",
        s(j),
        "--endpoint",
        &format!("dir:{}", s(ep)),
    ]))
}

fn finish(c: &Path, participants: &[&Path]) -> Output {
    let mut args = vec!["journal", "finish", "--dir", s(c), "--regression", "r1"];
    for p in participants {
        args.extend_from_slice(&["--participant", s(p)]);
    }
    cli(&args)
}

#[test]
fn r2_15_finish_covers_every_registered_participant() {
    let d = tmp("finish");
    let ep = d.join("endpoint");
    let coord = init(&d, "coord", None);
    let side = init(&d, "side", Some(&coord));
    assert!(
        run(&side, &launch(&d, "a1", "s1"), &[], "0")
            .status
            .success()
    );
    // The round-2 reproduction: finishing without naming the side journal.
    let o = finish(&coord, &[]);
    assert!(!o.status.success());
    assert!(err(&o).contains("side has not closed"), "{}", err(&o));
    assert!(
        cli(&["journal", "close", "--dir", s(&side)])
            .status
            .success()
    );
    let o = finish(&coord, &[]);
    assert!(err(&o).contains("not committed"), "{}", err(&o));
    let _ = flush(&side, &ep);
    // A journal that never registered is refused as a participant.
    let stray = init(&d, "stray", None);
    let o = finish(&coord, &[&stray]);
    assert!(err(&o).contains("not registered"), "{}", err(&o));
    let o = finish(&coord, &[]);
    assert!(o.status.success(), "{}", err(&o));
    // No one joins a finished regression.
    let o = cli(&[
        "journal",
        "init",
        "--dir",
        s(&d.join("late")),
        "--id",
        "late",
        "--coordinator",
        s(&coord),
    ]);
    assert!(!o.status.success());
    assert!(!d.join("late").exists());
}

#[test]
fn r2_15_build_launches_are_behind_the_barrier() {
    let d = tmp("build");
    let coord = init(&d, "coord", None);
    let j = Journal::open(&coord).unwrap_or_else(|e| panic!("{e}"));
    j.locked(|j| {
        j.append(
            kind::BUILD_LAUNCH,
            Some("build_started:b1".into()),
            Some(json!({"deliver": {"kind": "build_started"}})),
            vec![],
            None,
        )
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let o = finish(&coord, &[]);
    assert!(err(&o).contains("not closed"), "{}", err(&o));
    let o = cli(&["journal", "close", "--dir", s(&coord)]);
    assert_eq!(out(&o)["watermark"], 1);
    let o = finish(&coord, &[]);
    assert!(err(&o).contains("not committed"), "{}", err(&o));
}

#[test]
fn r2_n1_a_log_from_another_execution_is_refused() {
    let d = tmp("stale");
    let j = init(&d, "j", None);
    let log = d.join("sim.log");
    std::fs::write(&log, "an earlier execution\n").ok();
    let o = run(&j, &launch(&d, "a1", "s1"), &["--log", s(&log)], "0");
    assert!(!o.status.success());
    assert!(
        err(&o).contains("exists or cannot be created"),
        "{}",
        err(&o)
    );
    // Nothing was launched.
    let st = out(&cli(&["journal", "status", "--dir", s(&j)]));
    assert_eq!(st["entries"].as_array().map_or(0, Vec::len), 0);
}

#[test]
fn r2_n2_long_attempt_references_get_a_valid_report_identity() {
    let d = tmp("long");
    let j = init(&d, "j", None);
    let ep = d.join("endpoint");
    let attempt = "a".repeat(200);
    let o = run(&j, &launch(&d, &attempt, "s1"), &[], "0");
    assert!(o.status.success(), "{}", err(&o));
    let st = out(&cli(&["journal", "status", "--dir", s(&j)]));
    let ids: Vec<String> = st["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e["identity"].as_str().map(str::to_string))
        .collect();
    let report = ids
        .iter()
        .find(|i| i.starts_with("simulation_attempt:"))
        .unwrap_or_else(|| panic!("{ids:?}"));
    assert!(
        report.len() - "simulation_attempt:".len() <= 200,
        "{report}"
    );
    assert!(report.ends_with(":r1"), "{report}");
    // Deterministic and deliverable.
    assert_eq!(
        dviscope_cli::run::report_identity(
            &attempt
                .clone()
                .try_into()
                .unwrap_or_else(|e| panic!("{e:?}"))
        )
        .unwrap_or_default(),
        *report
    );
    let f = flush(&j, &ep);
    assert_eq!(f["committed"].as_u64(), Some(2), "{f}");
}

#[test]
fn r2_10_records_without_start_identities_are_unverifiable() {
    let d = tmp("legacy");
    let jdir = init(&d, "j", None);
    let j = Journal::open(&jdir).unwrap_or_else(|e| panic!("{e}"));
    let me = std::process::id();
    j.locked(|j| {
        // A launch whose supervisor PID is a live process, without its start identity.
        j.append(
            kind::LAUNCH,
            Some("attempt_started:a1".into()),
            Some(json!({"slot_ref": "s1", "attempt_seq": 1, "supervisor_pid": me})),
            vec![],
            None,
        )
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let rec = j.locked(Journal::recover).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rec.unverifiable, vec![1]);
    assert!(rec.recovered.is_empty() && rec.live_orphans.is_empty());
}

#[test]
fn r2_7_an_unreaped_child_stays_visible_after_its_result() {
    let d = tmp("unreaped");
    let jdir = init(&d, "j", None);
    let j = Journal::open(&jdir).unwrap_or_else(|e| panic!("{e}"));
    let me = std::process::id();
    let start = dviscope_cli::platform::process_identity(me);
    j.locked(|j| {
        let l = j.append(
            kind::LAUNCH,
            Some("attempt_started:a1".into()),
            Some(
                json!({"slot_ref": "s1", "attempt_seq": 1, "supervisor_pid": me,
                        "supervisor_start": "gone"}),
            ),
            vec![],
            None,
        )?;
        // The "child" is this (live) test process.
        j.append(
            kind::CHILD,
            None,
            Some(json!({"launch": l, "pid": me, "start": start})),
            vec![l],
            None,
        )?;
        j.append(
            kind::RUNNER_RESULT,
            None,
            Some(json!({"launch": l, "runner": {}, "unreaped": "not ended after job termination"})),
            vec![l],
            None,
        )
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let rec = j.locked(Journal::recover).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rec.live_orphans, vec![1]);
}

#[test]
fn r2_8_a_held_journal_lock_does_not_delay_the_timeout() {
    // The child sleeps 3 s with a 1 s timeout while the test holds the journal lock for
    // 5 s right after the launch entry: the run must end as a timeout (never as an exit
    // seen after the lock was released).
    let d = tmp("lock");
    let jdir = init(&d, "j", None);
    let l = launch(&d, "a1", "s1");
    let jd = jdir.clone();
    let holder = std::thread::spawn(move || {
        let t0 = Instant::now();
        let entries = jd.join("entries");
        while std::fs::read_dir(&entries).map_or(0, Iterator::count) == 0 {
            if t0.elapsed() > Duration::from_secs(30) {
                return;
            }
            std::thread::yield_now();
        }
        if let Ok(j) = Journal::open(&jd) {
            let _ = j.locked(|_| {
                std::thread::sleep(Duration::from_secs(5));
                Ok(())
            });
        }
    });
    let o = run(&jdir, &l, &["--timeout", "1", "--grace", "1"], "3");
    let _ = holder.join();
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o)["termination"]["kind"], "timeout", "{}", out(&o));
}

#[cfg(windows)]
#[test]
fn r2_n3_an_unreadable_payload_stays_pending() {
    use std::os::windows::fs::OpenOptionsExt as _;
    let d = tmp("sharing");
    let jdir = init(&d, "j", None);
    let ep = d.join("endpoint");
    assert!(
        run(&jdir, &launch(&d, "a1", "s1"), &[], "0")
            .status
            .success()
    );
    let payload = std::fs::read_dir(jdir.join("payloads"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .next()
        .unwrap_or_default();
    // Exclusive open: a sharing violation for every other reader.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&payload)
        .unwrap_or_else(|e| panic!("{e}"));
    let f = flush(&jdir, &ep);
    assert_eq!(f["rejected"].as_u64(), Some(0), "{f}");
    assert!(!f["deferred"].as_array().is_none_or(Vec::is_empty), "{f}");
    drop(held);
    let f = flush(&jdir, &ep);
    assert_eq!(f["rejected"].as_u64(), Some(0), "{f}");
    assert_eq!(f["pending"].as_u64(), Some(0), "{f}");
}
