//! `corpus capture` adds a local log to a private sample directory as a
//! case whose starting expectation the local check accepts; existing cases are kept unless
//! replaced explicitly. Invented logs only.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("dviscope-cap-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    d
}

fn cli(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{e}"))
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap_or_default()
}

#[test]
fn capture_then_check() {
    let d = tmp("check");
    let log = d.join("night.log");
    std::fs::write(
        &log,
        "UVM_ERROR @ 5: uvm_test_top.env.sb [SB_MISMATCH] expected 1 got 2\n\
         --- UVM Report Summary ---\nUVM_INFO :    1\nUVM_WARNING :    0\nUVM_ERROR :    1\n\
         UVM_FATAL :    0\n$finish at simulation time 100\n\
         CPU Time:      0.1 seconds;       Data structure size:   0.1Mb\n",
    )
    .ok();
    let sample = d.join("sample");
    let capture = |extra: &[&str]| {
        let mut a = vec![
            "corpus",
            "capture",
            "--log",
            s(&log),
            "--case",
            "mismatch-1",
            "--dir",
            s(&sample),
            "--simulator",
            "vcs",
            "--exit-code",
            "1",
        ];
        a.extend_from_slice(extra);
        cli(&a)
    };
    let o = capture(&[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(out["must_survive"][0], "uvm:SB_MISMATCH", "{out}");
    let x: Value = serde_json::from_slice(
        &std::fs::read(sample.join("mismatch-1.expect.json")).unwrap_or_default(),
    )
    .unwrap_or(Value::Null);
    assert_eq!(x["failures"]["uvm:SB_MISMATCH"], 1, "{x}");
    assert_eq!(x["failures_exact"], true);
    assert!(x.get("log").is_none(), "no local path in the expectation");
    // The local check accepts the captured case as it is.
    let o = cli(&["rules", "check", "--sample", s(&sample)]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    assert_eq!(r["cases_passed"], 1, "{r}");
    // An existing case is kept unless replaced explicitly; names are checked.
    assert!(!capture(&[]).status.success());
    assert!(capture(&["--force"]).status.success());
    let o = cli(&[
        "corpus",
        "capture",
        "--log",
        s(&log),
        "--case",
        "../escape",
        "--dir",
        s(&sample),
    ]);
    assert!(!o.status.success());
    // Private on every platform, also when it replaced a readable file (r1 finding 6).
    for f in ["mismatch-1.log", "mismatch-1.expect.json"] {
        let p = sample.join(f);
        assert!(
            dviscope_cli::platform::check_private(&p).is_ok(),
            "{f}: {:?}",
            dviscope_cli::platform::check_private(&p)
        );
    }
    std::fs::remove_file(sample.join("mismatch-1.log")).ok();
    std::fs::write(sample.join("mismatch-1.log"), "readable").ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            sample.join("mismatch-1.log"),
            std::fs::Permissions::from_mode(0o644),
        )
        .ok();
    }
    assert!(capture(&["--force"]).status.success());
    assert!(dviscope_cli::platform::check_private(&sample.join("mismatch-1.log")).is_ok());
}
