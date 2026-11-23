//! Deterministic crash points for durability tests (docs/journal.md). Armed once from the
//! CLI configuration (`DVISCOPE_TEST_CRASH_POINT`); a matching point ends the process at
//! once, as a power loss or kill would, without running destructors.

use std::sync::OnceLock;

static ARMED: OnceLock<Option<String>> = OnceLock::new();

/// Arms a crash point (first call wins).
pub fn arm(point: Option<String>) {
    let _ = ARMED.set(point.filter(|p| !p.is_empty()));
}

/// Exit status of a deliberate crash.
pub const CRASH_EXIT: i32 = 86;

/// Ends the process if `name` is the armed point.
pub fn point(name: &str) {
    if ARMED.get().and_then(Option::as_deref) == Some(name) {
        std::process::exit(CRASH_EXIT);
    }
}
