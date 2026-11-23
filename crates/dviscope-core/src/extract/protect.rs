//! The protected pre-pass's fixed recognizers: starts of authoritative
//! simulator diagnostics. Fixed code, not configurable; it only annotates lines.
//!
//! | Form | Simulator |
//! |---|---|
//! | `** Error: ...`, `** Fatal: ...`, `** Warning: ...` (with or without a message ID) | Questa |
//! | `Error-[ID]`, `Warning-[ID]`, `Error: "file", N: scope: at time`, `Fatal: "file", N:` | VCS |
//! | `"file", N: prop: started at T failed at T` (concurrent assertion) | VCS |
//! | `%Error`, `%Fatal`, `%Warning` (also with `[time]`), except `%Error: Exiting due to` | Verilator |

use std::sync::OnceLock;

use dviscope_model::wire::manifest::Severity;
use regex::Regex;

struct Recognizers {
    questa: Regex,
    vcs_tool: Regex,
    vcs_task: Regex,
    vcs_sva: Regex,
    verilator: Regex,
    verilator_exit: Regex,
}

fn recognizers() -> Option<&'static Recognizers> {
    static R: OnceLock<Option<Recognizers>> = OnceLock::new();
    R.get_or_init(|| {
        Some(Recognizers {
            questa: Regex::new(r"^\*\* (Error|Fatal|Warning)(?: \(suppressible\))?: ").ok()?,
            vcs_tool: Regex::new(r"^(Error|Warning)-\[[A-Za-z0-9_-]+\]").ok()?,
            vcs_task: Regex::new(r#"^(Error|Fatal|Warning): "[^"]+", \d+: \S+: at time "#).ok()?,
            vcs_sva: Regex::new(r#"^"[^"]+", \d+: \S+: started at \d+\w* failed at "#).ok()?,
            verilator: Regex::new(r"^(?:\[[\d.]+\w*\] )?%(Error|Fatal|Warning)(?:-[A-Z0-9_]+)?: ")
                .ok()?,
            verilator_exit: Regex::new(r"^%Error: Exiting due to \d+ error").ok()?,
        })
    })
    .as_ref()
}

fn sev(word: &str) -> Severity {
    match word {
        "Fatal" => Severity::Fatal,
        "Warning" => Severity::Warning,
        _ => Severity::Error,
    }
}

/// The severity of an authoritative diagnostic starting on this (framed) line, if any.
#[must_use]
pub fn authoritative(line: &str) -> Option<Severity> {
    let r = recognizers()?;
    let first = line.as_bytes().first()?;
    match first {
        b'*' => r.questa.captures(line).map(|c| sev(&c[1])),
        b'%' | b'[' => {
            if r.verilator_exit.is_match(line) {
                return None;
            }
            r.verilator.captures(line).map(|c| sev(&c[1]))
        }
        b'"' => r.vcs_sva.is_match(line).then_some(Severity::Error),
        b'E' | b'W' | b'F' => r
            .vcs_tool
            .captures(line)
            .or_else(|| r.vcs_task.captures(line))
            .map(|c| sev(&c[1])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms() {
        assert_eq!(authoritative("** Error: (vlog-1) x"), Some(Severity::Error));
        assert_eq!(
            authoritative("** Error (suppressible): a.sv(3): (vopt-2) x"),
            Some(Severity::Error)
        );
        assert_eq!(authoritative("** Note: (vsim-3) x"), None);
        assert_eq!(authoritative("** Report counts by id"), None);
        assert_eq!(
            authoritative("Error-[SE] Syntax error"),
            Some(Severity::Error)
        );
        assert_eq!(authoritative("Warning-[W] x"), Some(Severity::Warning));
        assert_eq!(
            authoritative("Error: \"a.sv\", 4: top: at time 5 ps"),
            Some(Severity::Error)
        );
        assert_eq!(authoritative("Error: plain display text"), None);
        assert_eq!(
            authoritative("[5] %Error: a.sv:3: Assertion failed in t: m"),
            Some(Severity::Error)
        );
        assert_eq!(authoritative("%Fatal: a.sv:3: m"), Some(Severity::Fatal));
        assert_eq!(authoritative("%Error: Exiting due to 2 error(s)"), None);
        assert_eq!(
            authoritative("\"a.sv\", 9: top.p: started at 5ns failed at 9ns"),
            Some(Severity::Error)
        );
        assert_eq!(authoritative(""), None);
    }
}
