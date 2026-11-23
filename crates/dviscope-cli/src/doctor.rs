//! `dviscope doctor`: effective configuration with sources, and (with `--server`) TLS reach
//! and capabilities of the server. Output is a structural JSON report (no secrets).

use serde_json::{Value, json};

use crate::client;
use crate::config::CliConfig;

/// The pilot checks (`--pilot`): state location suitability and privacy, the
/// token file, the runner's prerequisite (process identity for recovery), the simulators
/// found on `PATH` (informational) and, with the server, the clock offset to it.
fn pilot_checks(cfg: &CliConfig, checks: &mut Vec<Value>) -> bool {
    let mut ok = true;
    let mut push = |name: &str, good: bool, detail: Value| {
        ok &= good;
        checks.push(json!({"check": name, "ok": good, "detail": detail}));
    };
    match crate::journal::supported_location(&cfg.state_dir) {
        Ok(()) => push("state_location", true, json!(null)),
        Err(e) => push("state_location", false, json!(e.to_string())),
    }
    push(
        "state_private",
        private(&cfg.state_dir),
        json!("owner-only access (POSIX 0700; on Windows the profile's ACL)"),
    );
    match cfg.token_file.as_ref() {
        None => push("token_file", false, json!("no token_file configured")),
        Some(t) => {
            let readable = std::fs::read_to_string(t).is_ok_and(|s| !s.trim().is_empty());
            push(
                "token_file",
                readable && private(t),
                json!(if readable {
                    "readable; owner-only access required"
                } else {
                    "missing, empty or unreadable"
                }),
            );
        }
    }
    push(
        "process_identity",
        crate::platform::process_identity(std::process::id()).is_some(),
        json!("needed to recover interrupted runs"),
    );
    let found: Vec<&str> = ["vsim", "vcs", "verilator", "xrun"]
        .into_iter()
        .filter(|exe| on_path(exe))
        .collect();
    checks.push(json!({"check": "simulators_on_path", "ok": true, "detail": found}));
    ok
}

/// Owner-only access (POSIX: no group or other bits; Windows: a protected DACL for the
/// owner and SYSTEM only).
fn private(p: &std::path::Path) -> bool {
    crate::platform::check_private(p).is_ok()
}

fn on_path(exe: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths)
            .any(|d| d.join(exe).is_file() || d.join(format!("{exe}.exe")).is_file())
    })
}

/// Seconds the server's clock is ahead of this one (from its `Date` header,
/// `Sun, 09 Nov 2026 01:02:03 GMT`).
fn clock_offset(date: &str) -> Option<i64> {
    let f = time::macros::format_description!(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
    );
    let server = time::PrimitiveDateTime::parse(date, &f).ok()?.assume_utc();
    Some((server - time::OffsetDateTime::now_utc()).whole_seconds())
}

/// Runs the checks and returns the report and whether every check passed.
pub async fn run(cfg: &CliConfig, server: bool) -> (Value, bool) {
    run_with(cfg, server, false).await
}

/// [`run`], with the pilot checks.
pub async fn run_with(cfg: &CliConfig, server: bool, pilot: bool) -> (Value, bool) {
    let mut ok = true;
    let effective: serde_json::Map<String, Value> = [
        ("server_url", json!(client::redact_url(&cfg.server_url))),
        (
            "ca_file",
            json!(cfg.ca_file.as_ref().map(|p| p.display().to_string())),
        ),
        ("state_dir", json!(cfg.state_dir.display().to_string())),
        (
            "token_file",
            json!(cfg.token_file.as_ref().map(|p| p.display().to_string())),
        ),
    ]
    .into_iter()
    .map(|(k, v)| {
        (
            k.to_string(),
            json!({"value": v, "source": cfg.sources.get(k).map(|s| s.as_str())}),
        )
    })
    .collect();

    let mut checks = vec![];
    match client::check_url(&cfg.server_url) {
        Ok(()) => checks.push(json!({"check": "server_url_https", "ok": true})),
        Err(e) => {
            ok = false;
            checks.push(json!({"check": "server_url_https", "ok": false, "error": e.to_string()}));
        }
    }

    if pilot {
        ok &= pilot_checks(cfg, &mut checks);
    }
    if server && ok {
        match client::build(&cfg.server_url, cfg.ca_file.as_deref()) {
            Err(e) => {
                ok = false;
                checks.push(json!({"check": "client", "ok": false, "error": e.to_string()}));
            }
            Ok(http) => {
                for (name, path) in [
                    ("healthz", "/healthz"),
                    ("capabilities", "/api/v1/capabilities"),
                ] {
                    let url = format!("{}{}", cfg.server_url.trim_end_matches('/'), path);
                    match http.get(&url).send().await {
                        Ok(r) if r.status().is_success() => {
                            let status = r.status().as_u16();
                            if pilot && name == "healthz" {
                                // The server's clock: report times are compared with it.
                                let offset = r
                                    .headers()
                                    .get("date")
                                    .and_then(|d| d.to_str().ok())
                                    .and_then(clock_offset);
                                let good = offset.is_some_and(|o| o.abs() <= 60);
                                ok &= good;
                                checks.push(json!({"check": "clock_offset_s", "ok": good,
                                                   "detail": offset}));
                                checks.push(json!({"check": "ca_trust", "ok": true}));
                            }
                            let body = if name == "capabilities" {
                                r.json::<Value>().await.unwrap_or(Value::Null)
                            } else {
                                Value::Null
                            };
                            checks.push(
                                json!({"check": name, "ok": true, "status": status, "body": body}),
                            );
                        }
                        Ok(r) => {
                            ok = false;
                            checks.push(
                                json!({"check": name, "ok": false, "status": r.status().as_u16()}),
                            );
                        }
                        Err(e) => {
                            ok = false;
                            // reqwest error text has no secrets; show the chain for TLS problems.
                            let mut msg = e.to_string();
                            let mut src = std::error::Error::source(&e);
                            while let Some(s) = src {
                                msg.push_str(": ");
                                msg.push_str(&s.to_string());
                                src = s.source();
                            }
                            checks.push(json!({"check": name, "ok": false, "error": msg}));
                        }
                    }
                }
            }
        }
    }
    (
        json!({"version": env!("CARGO_PKG_VERSION"), "effective_configuration": effective, "checks": checks, "ok": ok}),
        ok,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_date_header_gives_the_clock_offset() {
        let now = time::OffsetDateTime::now_utc() + time::Duration::seconds(120);
        let f = time::macros::format_description!(
            "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
        );
        let header = now.format(&f).unwrap_or_default();
        let off = clock_offset(&header).unwrap_or(0);
        assert!((118..=121).contains(&off), "{header} -> {off}");
        assert_eq!(clock_offset("yesterday"), None);
    }

    /// Privacy is checked (Windows: the DACL), not assumed.
    #[test]
    fn privacy_is_checked_on_every_platform() {
        let d = std::env::temp_dir().join(format!("dviscope-doc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
        let open = d.join("token");
        std::fs::write(&open, "dvis_x").unwrap_or_else(|e| panic!("{e}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert!(!private(&open), "an ordinary file is not private");
        let closed = d.join("token2");
        crate::platform::write_private_file(&closed, b"dvis_y").unwrap_or_else(|e| panic!("{e}"));
        assert!(private(&closed));
        let _ = std::fs::remove_dir_all(&d);
    }
}
