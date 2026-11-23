//! Supervision, journal and delivery through the real binary, with deterministic
//! crash points and the directory-backed receipt endpoint. No simulator.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-2c-{name}-{}", std::process::id()));
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
    match c.output() {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    }
}

fn json_out(o: &Output) -> Value {
    serde_json::from_slice(&o.stdout).unwrap_or(Value::Null)
}

fn launch(dir: &Path, attempt: &str) -> PathBuf {
    let p = dir.join(format!("{attempt}.launch.json"));
    let spec = json!({
        "producer_id": "pilot", "regression_ref": "r1", "slot_ref": "slot-1",
        "attempt_ref": attempt, "source_manifest_ref": "sm1",
        "execution": {"test": "t", "seed": "1"},
    });
    std::fs::write(&p, spec.to_string()).ok();
    p
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap_or_default()
}

fn init(dir: &Path) -> PathBuf {
    let j = dir.join("journal");
    let o = cli(&["journal", "init", "--dir", s(&j), "--id", "j1"], None);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    j
}

fn flush(j: &Path, ep: &Path, crash: Option<&str>) -> Output {
    cli(
        &[
            "spool",
            "flush",
            "--dir",
            s(j),
            "--endpoint",
            &format!("dir:{}", s(ep)),
        ],
        crash,
    )
}

fn effects(ep: &Path) -> Vec<Value> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(ep.join("effects")) {
        for e in rd.flatten() {
            if let Ok(b) = std::fs::read(e.path()) {
                out.push(serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null));
            }
        }
    }
    out
}

fn termination_of(ep: &Path) -> Vec<String> {
    effects(ep)
        .iter()
        .filter(|e| e["body"]["kind"] == "simulation_attempt")
        .map(|e| {
            e["body"]["result"]["runner"]["termination"]["kind"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

#[test]
fn normal_run_is_delivered_exactly_once() {
    let d = tmp("normal");
    let j = init(&d);
    let ep = d.join("endpoint");
    let o = cli(
        &[
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&launch(&d, "a1")),
            "--",
            BIN,
            "__tree",
            "--children",
            "1",
            "--sleep",
            "0",
        ],
        None,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = cli(
        &[
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&launch(&d, "a2")),
            "--",
            BIN,
            "__tree",
            "--children",
            "0",
            "--sleep",
            "0",
            "--exit",
            "3",
        ],
        None,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v = json_out(&o);
    assert_eq!(v["termination"]["kind"], "exited");
    assert_eq!(v["termination"]["exit_code"], 3);
    assert_eq!(v["attempt_seq"], 2);
    let f = json_out(&flush(&j, &ep, None));
    assert_eq!(
        (f["committed"].as_u64(), f["pending"].as_u64()),
        (Some(4), Some(0)),
        "{f}"
    );
    let f = json_out(&flush(&j, &ep, None));
    assert_eq!(f["committed"].as_u64(), Some(0));
    assert_eq!(effects(&ep).len(), 4);
    // Completed launches are never marked interrupted.
    let st = json_out(&cli(&["journal", "status", "--dir", s(&j)], None));
    assert!(
        st["entries"]
            .as_array()
            .is_some_and(|a| a.iter().all(|e| e.get("interrupted").is_none())),
        "{st}"
    );
}

#[test]
fn timeout_kills_the_whole_tree() {
    let d = tmp("timeout");
    let j = init(&d);
    let pids = d.join("pids.txt");
    let o = cli(
        &[
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&launch(&d, "t1")),
            "--timeout",
            "2",
            "--grace",
            "1",
            "--",
            BIN,
            "__tree",
            "--children",
            "2",
            "--sleep",
            "60",
            "--pids",
            s(&pids),
        ],
        None,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(json_out(&o)["termination"]["kind"], "timeout");
    let list = std::fs::read_to_string(&pids).unwrap_or_default();
    let pids: Vec<u32> = list.lines().filter_map(|l| l.trim().parse().ok()).collect();
    assert_eq!(pids.len(), 3);
    std::thread::sleep(std::time::Duration::from_millis(500));
    for p in pids {
        assert!(
            !dviscope_cli::platform::alive(p, None),
            "process {p} outlived the timeout"
        );
    }
}

const RUN_POINTS: &[&str] = &[
    "before_rename:launch",
    "after_rename:launch",
    "after_launch",
    "after_spawn",
    "after_exit",
    "after_rename:runner_result",
    "before_rename:envelope",
];

#[test]
fn crash_points_of_a_run_lose_and_duplicate_nothing() {
    for point in RUN_POINTS {
        let d = tmp(&format!("crash-{}", point.replace(':', "-")));
        let j = init(&d);
        let ep = d.join("endpoint");
        let o = cli(
            &[
                "run",
                "--journal",
                s(&j),
                "--launch",
                s(&launch(&d, "c1")),
                "--",
                BIN,
                "__tree",
                "--children",
                "0",
                "--sleep",
                "0",
            ],
            Some(point),
        );
        assert_eq!(
            o.status.code(),
            Some(86),
            "{point}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        let r = cli(&["journal", "recover", "--dir", s(&j)], None);
        assert!(
            r.status.success(),
            "{point}: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        let f = json_out(&flush(&j, &ep, None));
        assert_eq!(f["pending"].as_u64(), Some(0), "{point}: {f}");
        let launched = !point.starts_with("before_rename:launch");
        let kinds: Vec<String> = effects(&ep)
            .iter()
            .map(|e| e["body"]["kind"].as_str().unwrap_or_default().to_string())
            .collect();
        if launched {
            assert_eq!(
                kinds.iter().filter(|k| *k == "attempt_started").count(),
                1,
                "{point}"
            );
            let t = termination_of(&ep);
            assert_eq!(t.len(), 1, "{point}: {t:?}");
            // Facts journalled before the crash are kept; otherwise the run is unknown —
            // never a pass.
            let expect =
                if *point == "before_rename:envelope" || *point == "after_rename:runner_result" {
                    "exited"
                } else {
                    "unknown"
                };
            assert_eq!(t[0], expect, "{point}");
        } else {
            assert!(kinds.is_empty(), "{point}: {kinds:?}");
        }
        // A new attempt gets the next sequence.
        let o = cli(
            &[
                "run",
                "--journal",
                s(&j),
                "--launch",
                s(&launch(&d, "c2")),
                "--",
                BIN,
                "__tree",
                "--children",
                "0",
                "--sleep",
                "0",
            ],
            None,
        );
        assert_eq!(
            json_out(&o)["attempt_seq"],
            if launched { 2 } else { 1 },
            "{point}"
        );
    }
}

#[test]
fn crash_points_of_a_flush_lose_and_duplicate_nothing() {
    for point in [
        "after_commit",
        "after_receipt",
        "before_rename:outcome",
        "after_rename:outcome",
    ] {
        let d = tmp(&format!("flush-{}", point.replace(':', "-")));
        let j = init(&d);
        let ep = d.join("endpoint");
        let o = cli(
            &[
                "run",
                "--journal",
                s(&j),
                "--launch",
                s(&launch(&d, "f1")),
                "--",
                BIN,
                "__tree",
                "--children",
                "0",
                "--sleep",
                "0",
            ],
            None,
        );
        assert!(o.status.success());
        let o = flush(&j, &ep, Some(point));
        assert_eq!(o.status.code(), Some(86), "{point}");
        let f = json_out(&flush(&j, &ep, None));
        assert_eq!(f["pending"].as_u64(), Some(0), "{point}: {f}");
        let e = effects(&ep);
        assert_eq!(e.len(), 2, "{point}");
        assert_eq!(termination_of(&ep), ["exited"], "{point}");
    }
}

#[test]
fn a_killed_supervisor_never_yields_a_pass() {
    let d = tmp("killed");
    let j = init(&d);
    let ep = d.join("endpoint");
    let l = launch(&d, "k1");
    let mut sup = match Command::new(BIN)
        .args([
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&l),
            "--",
            BIN,
            "__tree",
            "--children",
            "1",
            "--sleep",
            "30",
        ])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("{e}"),
    };
    // Wait for the child entry, then kill the supervisor.
    for _ in 0..100 {
        let st = json_out(&cli(&["journal", "status", "--dir", s(&j)], None));
        if st["entries"]
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e["kind"] == "child"))
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = sup.kill();
    let _ = sup.wait();
    // On Windows the job closes with the supervisor and ends the tree; on Linux the child
    // may live on as an orphan until it ends.
    let mut recovered = false;
    for _ in 0..400 {
        let r = json_out(&cli(&["journal", "recover", "--dir", s(&j)], None));
        if r["recovered"].as_array().is_some_and(|a| !a.is_empty()) {
            recovered = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(recovered);
    // `journal status` marks the launch as interrupted (a resumed run re-runs its slot).
    let st = json_out(&cli(&["journal", "status", "--dir", s(&j)], None));
    let launches: Vec<&Value> = st["entries"]
        .as_array()
        .map(|a| a.iter().filter(|e| e["kind"] == "launch").collect())
        .unwrap_or_default();
    assert_eq!(launches.len(), 1, "{st}");
    assert_eq!(launches[0]["interrupted"], true, "{st}");
    let _ = flush(&j, &ep, None);
    assert_eq!(termination_of(&ep), ["unknown"]);
}

#[test]
fn closure_refuses_new_launches_and_reports_the_watermark() {
    let d = tmp("closure");
    let j = init(&d);
    let o = cli(
        &[
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&launch(&d, "w1")),
            "--",
            BIN,
            "__tree",
            "--children",
            "0",
            "--sleep",
            "0",
        ],
        None,
    );
    assert!(o.status.success());
    let w = json_out(&cli(&["journal", "close", "--dir", s(&j)], None));
    assert_eq!(w["watermark"], 1);
    let o = cli(
        &[
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&launch(&d, "w2")),
            "--",
            BIN,
            "__tree",
            "--children",
            "0",
            "--sleep",
            "0",
        ],
        None,
    );
    assert!(!o.status.success());
    let w = json_out(&cli(&["journal", "close", "--dir", s(&j)], None));
    assert_eq!(w["watermark"], 1);
}

#[test]
fn a_rejected_record_blocks_its_dependents_only() {
    let d = tmp("reject");
    let j = init(&d);
    let ep = d.join("endpoint");
    std::fs::create_dir_all(&ep).ok();
    std::fs::write(ep.join("reject.txt"), "attempt_started:x1\n").ok();
    for a in ["x1", "x2"] {
        let o = cli(
            &[
                "run",
                "--journal",
                s(&j),
                "--launch",
                s(&launch(&d, a)),
                "--",
                BIN,
                "__tree",
                "--children",
                "0",
                "--sleep",
                "0",
            ],
            None,
        );
        assert!(o.status.success());
    }
    let f = json_out(&flush(&j, &ep, None));
    assert_eq!(
        (
            f["committed"].as_u64(),
            f["rejected"].as_u64(),
            f["blocked"].as_u64()
        ),
        (Some(2), Some(1), Some(1)),
        "{f}"
    );
}

#[test]
fn unsupported_journal_locations_are_refused() {
    let o = cli(
        &["journal", "init", "--dir", "//server/share/j", "--id", "x"],
        None,
    );
    assert!(!o.status.success());
}

#[test]
fn collect_journals_a_finished_run_once() {
    let d = tmp("collect");
    let j = init(&d);
    let ep = d.join("endpoint");
    let log = d.join("run.log");
    std::fs::write(&log, "UVM_INFO @ 1: top [HELLO] hi\n").ok();
    let l = launch(&d, "c1");
    let args = [
        "collect",
        "--journal",
        s(&j),
        "--launch",
        s(&l),
        "--log",
        s(&log),
        "--exit-code",
        "0",
        "--started-at",
        "2026-11-08T01:00:00Z",
        "--finished-at",
        "2026-11-08T01:01:00Z",
        "--simulator",
        "vcs",
    ];
    let o = cli(&args, None);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(json_out(&o)["state"], "spooled");
    // Again: the attempt is journalled already.
    assert_eq!(json_out(&cli(&args, None))["state"], "existing");
    // Without an exit code (another attempt): the termination is unknown, never a pass.
    let l2 = launch(&d, "c2");
    let o = cli(
        &[
            "collect",
            "--journal",
            s(&j),
            "--launch",
            s(&l2),
            "--started-at",
            "2026-11-08T02:00:00Z",
        ],
        None,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let f = json_out(&flush(&j, &ep, None));
    assert_eq!(f["pending"].as_u64(), Some(0), "{f}");
    let mut t = termination_of(&ep);
    t.sort();
    assert_eq!(t, ["exited", "unknown"]);
    assert_eq!(effects(&ep).len(), 4, "two starts, two reports");
}

/// A collect interrupted between its writes is completed (with its
/// original attempt sequence) when the same launch is collected again.
#[test]
fn an_interrupted_collect_is_completed_on_retry() {
    for point in ["import_after_launch", "import_after_runner"] {
        let d = tmp(&format!("collect-{point}"));
        let j = init(&d);
        let ep = d.join("endpoint");
        let l = launch(&d, "c1");
        let args = [
            "collect",
            "--journal",
            s(&j),
            "--launch",
            s(&l),
            "--exit-code",
            "0",
            "--started-at",
            "2026-11-08T01:00:00Z",
        ];
        let o = cli(&args, Some(point));
        assert!(!o.status.success(), "{point}: the crash point fires");
        let o = cli(&args, None);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let r = json_out(&o);
        assert_eq!(r["state"], "spooled", "{point}: {r}");
        assert_eq!(r["resumed"], true);
        assert_eq!(r["attempt_seq"], 1);
        assert_eq!(json_out(&cli(&args, None))["state"], "existing");
        let f = json_out(&flush(&j, &ep, None));
        assert_eq!(f["pending"].as_u64(), Some(0), "{f}");
        assert_eq!(termination_of(&ep), ["exited"], "{point}: one report");
        // Another specification under the same attempt reference is refused.
        let other = d.join("other.launch.json");
        std::fs::write(
            &other,
            json!({"producer_id": "pilot", "regression_ref": "r1", "slot_ref": "slot-2",
                   "attempt_ref": "c1", "source_manifest_ref": "sm1",
                   "execution": {"test": "t", "seed": "1"}})
            .to_string(),
        )
        .ok();
        let mut a2 = args;
        a2[4] = s(&other);
        let _ = std::fs::remove_dir_all(ep.join("effects"));
        assert_eq!(json_out(&cli(&a2, None))["state"], "existing");
    }
}

/// A resumed collect reuses its durable inputs: a retry with other
/// run facts is refused, and a supervised launch is never completed by `collect`.
#[test]
fn a_resumed_collect_keeps_its_durable_inputs() {
    let d = tmp("collect-inputs");
    let j = init(&d);
    let l = launch(&d, "c1");
    let args = |code: &str| {
        cli(
            &[
                "collect",
                "--journal",
                s(&j),
                "--launch",
                s(&l),
                "--exit-code",
                code,
                "--started-at",
                "2026-11-08T01:00:00Z",
            ],
            None,
        )
    };
    let o = cli(
        &[
            "collect",
            "--journal",
            s(&j),
            "--launch",
            s(&l),
            "--exit-code",
            "1",
            "--started-at",
            "2026-11-08T01:00:00Z",
        ],
        Some("import_after_runner"),
    );
    assert!(!o.status.success());
    let o = args("0");
    assert!(!o.status.success(), "a retry claiming success is refused");
    assert!(String::from_utf8_lossy(&o.stderr).contains("other inputs"));
    let o = args("1");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(json_out(&o)["resumed"], true);
    // A supervised launch interrupted after its start is not completed by collect.
    let l2 = launch(&d, "r1a");
    let log = d.join("r1a.log");
    let o = cli(
        &[
            "run",
            "--journal",
            s(&j),
            "--launch",
            s(&l2),
            "--log",
            s(&log),
            "--",
            BIN,
            "__tree",
            "--children",
            "0",
            "--sleep",
            "0",
        ],
        Some("after_launch"),
    );
    assert!(!o.status.success());
    let o = cli(
        &[
            "collect",
            "--journal",
            s(&j),
            "--launch",
            s(&l2),
            "--exit-code",
            "0",
            "--started-at",
            "2026-11-08T01:00:00Z",
        ],
        None,
    );
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("supervised"));
}
