//! `verdict --wait-processed --deadline` bounds every request by the
//! remaining time: a server that accepts and never answers cannot hold it past the deadline.

use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_dviscope");

#[test]
fn a_stalled_server_cannot_hold_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .port();
    // Accept and hold every connection, saying nothing.
    std::thread::spawn(move || {
        let mut held = vec![];
        for c in listener.incoming().flatten() {
            held.push(c);
        }
    });
    let d = std::env::temp_dir().join(format!("dviscope-deadline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    let token = d.join("token");
    std::fs::write(&token, "dvis_test").ok();
    let started = Instant::now();
    let o = Command::new(BIN)
        .args([
            "verdict",
            "--project",
            "p1",
            "--regression",
            "r1",
            "--expect-source",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "--wait-processed",
            "--deadline",
            "1s",
        ])
        .env("DVISCOPE_SERVER_URL", format!("https://127.0.0.1:{port}"))
        .env("DVISCOPE_TOKEN_FILE", &token)
        .env("DVISCOPE_STATE_DIR", d.join("state"))
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let took = started.elapsed();
    assert_eq!(
        o.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(took < Duration::from_millis(2500), "{took:?}");
    let _ = std::fs::remove_dir_all(&d);
}

/// `spool flush --wait committed --deadline` bounds every request.
#[test]
fn a_stalled_server_cannot_hold_the_flush_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .port();
    std::thread::spawn(move || {
        let mut held = vec![];
        for c in listener.incoming().flatten() {
            held.push(c);
        }
    });
    let d = std::env::temp_dir().join(format!("dviscope-flushdl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    let token = d.join("token");
    std::fs::write(&token, "dvis_test").ok();
    let j = d.join("journal");
    let run = |args: &[&str]| {
        Command::new(BIN)
            .args(args)
            .env("DVISCOPE_SERVER_URL", format!("https://127.0.0.1:{port}"))
            .env("DVISCOPE_TOKEN_FILE", &token)
            .env("DVISCOPE_STATE_DIR", d.join("state"))
            .output()
            .unwrap_or_else(|e| panic!("{e}"))
    };
    let js = j.to_string_lossy().into_owned();
    assert!(
        run(&["journal", "init", "--dir", &js, "--id", "j1"])
            .status
            .success()
    );
    let body = d.join("sm.json");
    std::fs::write(
        &body,
        r#"{"schema": "dviscope.ingest/1.0-dev.3", "producer_id": "pilot", "source_manifest_ref": "sm1", "repositories": []}"#,
    )
    .ok();
    let o = run(&[
        "source-manifest",
        "--journal",
        &js,
        "--body",
        &body.to_string_lossy(),
    ]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let started = Instant::now();
    let o = run(&[
        "spool",
        "flush",
        "--dir",
        &js,
        "--wait",
        "committed",
        "--deadline",
        "1s",
    ]);
    let took = started.elapsed();
    assert_eq!(
        o.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(took < Duration::from_millis(2500), "{took:?}");
    let _ = std::fs::remove_dir_all(&d);
}

/// The flush deadline covers waiting for the journal's writer lock.
#[test]
fn a_held_journal_lock_cannot_hold_the_flush_deadline() {
    let d = std::env::temp_dir().join(format!("dviscope-lockdl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).ok();
    let token = d.join("token");
    std::fs::write(&token, "dvis_test").ok();
    let j = d.join("journal");
    let js = j.to_string_lossy().into_owned();
    let o = Command::new(BIN)
        .args(["journal", "init", "--dir", &js, "--id", "j1"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // Another holder of the writer lock, for longer than the deadline.
    let (tx, rx) = std::sync::mpsc::channel();
    let jj = j.clone();
    std::thread::spawn(move || {
        let journal = dviscope_cli::journal::Journal::open(&jj).unwrap_or_else(|e| panic!("{e:#}"));
        let _ = journal.locked(|_| {
            let _ = tx.send(());
            std::thread::sleep(Duration::from_secs(8));
            Ok(())
        });
    });
    rx.recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|e| panic!("{e}"));
    let started = Instant::now();
    let o = Command::new(BIN)
        .args([
            "spool",
            "flush",
            "--dir",
            &js,
            "--wait",
            "committed",
            "--deadline",
            "1s",
        ])
        .env("DVISCOPE_SERVER_URL", "https://127.0.0.1:9")
        .env("DVISCOPE_TOKEN_FILE", &token)
        .env("DVISCOPE_STATE_DIR", d.join("state"))
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let took = started.elapsed();
    assert_eq!(
        o.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(took < Duration::from_millis(3000), "{took:?}");
}
