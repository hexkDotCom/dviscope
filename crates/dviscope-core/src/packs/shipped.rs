//! Packs shipped with DVIScope (`patterns/`) and the structural self-tests every pack
//! carries (short invented examples in each tool's message format).

use super::{PackError, PackInput, Pipeline, compile};
use crate::extract::{ExtractOptions, Subject, extract_bytes};

/// Shipped packs of the default pipeline: (file name, source).
pub const DEFAULT: &[(&str, &str)] = &[
    ("uvm.yaml", include_str!("../../../../patterns/uvm.yaml")),
    (
        "questa.yaml",
        include_str!("../../../../patterns/questa.yaml"),
    ),
    ("vcs.yaml", include_str!("../../../../patterns/vcs.yaml")),
    (
        "verilator.yaml",
        include_str!("../../../../patterns/verilator.yaml"),
    ),
    (
        "svunit.yaml",
        include_str!("../../../../patterns/svunit.yaml"),
    ),
    (
        "generic.yaml",
        include_str!("../../../../patterns/generic.yaml"),
    ),
];

/// Example project packs, added on request (`--pack builtin:NAME`).
pub const EXAMPLES: &[(&str, &str)] = &[(
    "hexk-report-server",
    include_str!("../../../../patterns/hexk-report-server.yaml"),
)];

/// The default pack inputs.
#[must_use]
pub fn default_inputs() -> Vec<PackInput> {
    DEFAULT
        .iter()
        .map(|(n, t)| PackInput {
            name: (*n).to_string(),
            text: (*t).to_string(),
        })
        .collect()
}

/// An example project pack by name.
#[must_use]
pub fn example(name: &str) -> Option<PackInput> {
    EXAMPLES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(n, t)| PackInput {
            name: format!("{n}.yaml"),
            text: (*t).to_string(),
        })
}

/// The default pipeline.
///
/// # Errors
/// Only if a shipped pack is invalid (a build defect, covered by tests).
pub fn default_pipeline() -> Result<Pipeline, PackError> {
    compile(&default_inputs())
}

/// The shipped packs, compiled once.
fn shipped() -> Option<&'static Pipeline> {
    static P: std::sync::OnceLock<Option<Pipeline>> = std::sync::OnceLock::new();
    P.get_or_init(|| default_pipeline().ok()).as_ref()
}

/// The simulator pack selected during extraction: the shipped pack that declares the
/// evidence's completion profile, provided the evidence used that very pack (same ID and
/// digest). Every pack of the pipeline is listed in the evidence, so the list alone does
/// not say which simulator ran. Profile names are unique in a pipeline.
#[must_use]
pub fn simulator_pack_of(
    ev: &dviscope_model::wire::evidence::Evidence,
) -> Option<&'static super::CompiledPack> {
    let c = shipped()?.pack_of_profile(&ev.completion.profile)?;
    ev.packs
        .iter()
        .any(|r| r.id == c.id && r.digest == c.digest)
        .then_some(c)
}

/// Whether the run's exit code means anything, as ingestion and activation both decide it:
/// the shipped simulator pack's declaration, or (a pack this build cannot resolve exactly,
/// e.g. a customized one) yes: never a pass by default.
#[must_use]
pub fn exit_code_meaningful(ev: &dviscope_model::wire::evidence::Evidence) -> bool {
    simulator_pack_of(ev).is_none_or(|c| c.exit_code_meaningful)
}

/// Runs every pack's self-tests against the pipeline; returns the failures.
#[must_use]
pub fn self_test(p: &Pipeline) -> Vec<String> {
    let mut failures = vec![];
    for pk in &p.packs {
        for t in &pk.tests {
            let mut opts = ExtractOptions::simulation("self-test.log");
            opts.simulator.clone_from(&t.simulator);
            opts.trace = true;
            if t.subject.as_deref() == Some("build") {
                opts.subject = Subject::Build;
            }
            let (ev, trace) = extract_bytes(p, opts, t.input.as_bytes());
            let got: Vec<String> = trace
                .iter()
                .filter_map(|r| r.diag_id.as_ref().map(|d| format!("{d}@{}", r.start_line)))
                .collect();
            if got != t.events {
                failures.push(format!(
                    "{}: test {:?}: records {got:?}, expected {:?}",
                    pk.id, t.name, t.events
                ));
            }
            let cuts = trace.iter().filter(|r| r.cut).count();
            if let Some(want) = t.record_cuts
                && usize::try_from(want).ok() != Some(cuts)
            {
                failures.push(format!(
                    "{}: test {:?}: {cuts} record cuts, expected {want}",
                    pk.id, t.name
                ));
            }
            if let Some(want) = &t.completion {
                let state = serde_json::to_value(ev.completion.state)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default();
                if &state != want {
                    failures.push(format!(
                        "{}: test {:?}: completion {state} ({:?}), expected {want}",
                        pk.id, t.name, ev.completion.reasons
                    ));
                }
            }
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_packs_compile_and_pass_their_self_tests() {
        let mut inputs = default_inputs();
        inputs.extend(EXAMPLES.iter().filter_map(|(n, _)| example(n)));
        let p = match compile(&inputs) {
            Ok(p) => p,
            Err(e) => panic!("{e}"),
        };
        let failures = self_test(&p);
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn default_pipeline_is_stable() {
        let a = default_pipeline().map(|p| p.digest).ok();
        let b = default_pipeline().map(|p| p.digest).ok();
        assert!(a.is_some() && a == b);
    }
}
