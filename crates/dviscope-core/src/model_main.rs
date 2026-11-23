//! Verilator models with their own C++ main: the declaration a slot makes
//! (`extra.tool.main = "model"`) and the consistency checks of evidence against it. The
//! declaration is consistency, not attestation: the producer's collector is trusted to run
//! the executable its sealed inputs declare (docs/packs.md, "Models with their own main").

use dviscope_model::wire::evidence::{EventProvenance, Evidence, LogSegmentName, Span};
use dviscope_model::wire::manifest::ExecInputs;

use crate::packs::MODEL_MAIN_PROFILE;

/// Whether execution inputs declare a model with its own main (`extra.tool.main =
/// "model"`).
///
/// # Errors
/// Any other value of `extra.tool.main`.
pub fn declares(exec: &ExecInputs) -> Result<bool, String> {
    match exec
        .extra
        .get("tool")
        .and_then(|t| t.get("main"))
        .map(String::as_str)
    {
        None => Ok(false),
        Some("model") => Ok(true),
        Some(v) => Err(format!("extra.tool.main is \"model\" or absent, not {v:?}")),
    }
}

/// Simulation evidence against its slot's declaration: the declared profile exactly when
/// the slot declares a model with its own main (a producer cannot switch profile per
/// attempt), segments only then, well formed, and every span inside one segment.
///
/// # Errors
/// The first inconsistency, worded for the producer.
pub fn check_simulation(declared: bool, ev: &Evidence) -> Result<(), String> {
    let profile = ev.completion.profile == MODEL_MAIN_PROFILE;
    if declared != profile {
        return Err(if declared {
            format!(
                "the slot declares a model with its own main: the evidence must use profile {MODEL_MAIN_PROFILE}"
            )
        } else {
            format!(
                "profile {MODEL_MAIN_PROFILE} needs a slot declaring extra.tool.main = \"model\""
            )
        });
    }
    match &ev.source.segments {
        None if declared && ev.source.bytes.get() > 0 => {
            Err("a model with its own main needs the program and console segments".into())
        }
        None => Ok(()),
        Some(_) if !declared => Err("segments are only for a model with its own main".into()),
        Some(_) => check_segments(ev),
    }
}

/// Build evidence never has segments.
///
/// # Errors
/// Segments present.
pub fn check_build(ev: &Evidence) -> Result<(), String> {
    if ev.source.segments.is_some() {
        return Err("build evidence has no segments".into());
    }
    Ok(())
}

/// Segments: program then console, contiguous from byte 0 to the end, line ranges
/// ascending and inside the log (null together for an empty segment), and every verdict,
/// counter, event, suppression and coverage span inside exactly one segment.
fn check_segments(ev: &Evidence) -> Result<(), String> {
    let Some(segs) = &ev.source.segments else {
        return Ok(());
    };
    let names: Vec<LogSegmentName> = segs.iter().map(|s| s.name).collect();
    if names != [LogSegmentName::Program, LogSegmentName::Console] {
        return Err("segments are program, then console".into());
    }
    let mut byte = 0u64;
    let mut last_line = 0u64;
    for s in segs {
        if s.byte_start.get() != byte || s.byte_end.get() < s.byte_start.get() {
            return Err("segments are contiguous byte ranges from 0".into());
        }
        let empty = s.byte_start == s.byte_end;
        byte = s.byte_end.get();
        // Lines are numbered globally without gaps: a segment with bytes holds lines
        // continuing the previous segment's; an empty one holds none (both null).
        match (s.line_start, s.line_end, empty) {
            (None, None, true) => {}
            (Some(a), Some(b), false) if a.get() == last_line + 1 && a.get() <= b.get() => {
                last_line = b.get();
            }
            _ => {
                return Err(
                    "segment lines continue without gaps; an empty segment has none".into(),
                );
            }
        }
    }
    if byte != ev.source.bytes.get() {
        return Err("segments cover every byte of the log".into());
    }
    // A span is ordered and lies wholly inside one segment, lines and bytes.
    let inside = |sp: &Span| {
        let (l0, l1, b0, b1) = (
            sp.line_start.get(),
            sp.line_end.get(),
            sp.byte_start.get(),
            sp.byte_end.get(),
        );
        l0 <= l1
            && b0 <= b1
            && segs.iter().any(|s| {
                s.line_start
                    .zip(s.line_end)
                    .is_some_and(|(a, b)| a.get() <= l0 && l1 <= b.get())
                    && s.byte_start.get() <= b0
                    && b1 <= s.byte_end.get()
            })
    };
    let spans = ev
        .verdict_sources
        .iter()
        .filter_map(|v| v.span.as_ref())
        .chain(ev.counters.iter().map(|c| &c.span))
        .chain(ev.events.iter().filter_map(|e| match &e.provenance {
            EventProvenance::Log { span, .. } => Some(span),
            EventProvenance::Synthetic { .. } => None,
        }))
        .chain(ev.suppressed.iter().flat_map(|s| s.first_spans.iter()))
        .chain(ev.coverage.unclaimed_examples.iter());
    for sp in spans {
        if !inside(sp) {
            return Err("a span crosses or leaves the segments".into());
        }
    }
    Ok(())
}
