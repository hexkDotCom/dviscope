//! Outcome derivation with the B.5 expectation assessment, in the fixed
//! evaluation sequence: (1) observed accounting, (2) reconciliation, (3) base synthetic
//! buckets, (4) observed outcome, (5) expectation assessment, (6) `EXPECTATION_MISMATCH`
//! and display-primary, (7) contradictions. One pass, no feedback: step 5 never sees step
//! 6's bucket. Exit 0 is never evidence of a pass (F1).

use dviscope_model::wire::evidence::{
    CompletionMode, CompletionState, CounterRole, DesignLoaded, DiagKind, Evidence, Phase,
    Provenance, VerdictSourceKind, VerdictValue,
};
use dviscope_model::wire::ingest::{ReportedOutcome, Runner, TerminationKind};
use dviscope_model::wire::manifest::{Expected, Severity};
use serde::Serialize;

use crate::expectation::{Assessment, ContractDiff, assess};

/// Observed outcome of an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Passed.
    Pass,
    /// Failed (functional, or evidence not good enough to pass).
    Fail,
    /// Tool or infrastructure error.
    Error,
    /// The runner's timeout fired.
    Timeout,
    /// Stopped by the runner or externally.
    Killed,
    /// Did not get past compile or elaboration.
    Blocked,
}

impl Outcome {
    /// `error`, `timeout`, `killed` and `blocked` are infrastructure outcomes.
    #[must_use]
    pub fn is_infrastructure(self) -> bool {
        matches!(
            self,
            Self::Error | Self::Timeout | Self::Killed | Self::Blocked
        )
    }
}

/// Phase that blocked a `blocked` attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockingPhase {
    /// Compilation.
    Compile,
    /// Elaboration (incl. a run-time design-load failure, F7).
    Elaborate,
}

/// Synthetic diagnostic IDs (runner family, non-log provenance).
pub mod synthetic {
    /// The supervisor could not record how the run ended.
    pub const RUNNER_UNKNOWN: &str = "dviscope:RUNNER_UNKNOWN";
    /// The runner's timeout fired.
    pub const RUNNER_TIMEOUT: &str = "dviscope:RUNNER_TIMEOUT";
    /// Ended by a fault.
    pub const RUNNER_CRASH: &str = "dviscope:RUNNER_CRASH";
    /// Stopped by the runner or externally.
    pub const RUNNER_KILLED: &str = "dviscope:RUNNER_KILLED";
    /// No log or an empty log.
    pub const NO_LOG: &str = "dviscope:NO_LOG";
    /// A failure indication with no failure bucket to explain it.
    pub const UNEXPLAINED_FAILURE: &str = "dviscope:UNEXPLAINED_FAILURE";
    /// The evidence is not complete.
    pub const INCOMPLETE_EVIDENCE: &str = "dviscope:INCOMPLETE_EVIDENCE";
    /// The profile requires a verdict source and none was seen.
    pub const NO_VERDICT: &str = "dviscope:NO_VERDICT";
    /// The expectation was not met.
    pub const EXPECTATION_MISMATCH: &str = "dviscope:EXPECTATION_MISMATCH";
}

/// A synthetic bucket: `provenance: synthetic`, `fails_run: true`, count 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyntheticBucket {
    /// `dviscope:*` diagnostic ID.
    pub diag_id: String,
    /// What it records.
    pub detail: String,
    /// Whether it decided the outcome (rows 0–4): it then comes first for display.
    pub decides: bool,
}

/// Why the outcome is what it is (all matching rows, in table order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Reason {
    /// Row 0.
    TerminationUnknown,
    /// Row 1.
    Timeout,
    /// Row 2.
    Crash,
    /// Row 3.
    Killed,
    /// Row 4.
    NoLog,
    /// Row 5: the design did not load.
    DesignNotLoaded,
    /// Row 5: a failing compile or elaboration diagnostic.
    BuildDiagnostic {
        /// Its diagnostic ID.
        diag_id: String,
    },
    /// Row 6: a failing diagnostic of an infrastructure kind.
    InfrastructureDiagnostic {
        /// Its diagnostic ID.
        diag_id: String,
    },
    /// Row 6: the producer reported an error.
    ProducerError,
    /// Row 7: a failing bucket.
    FailureBucket {
        /// Its diagnostic ID.
        diag_id: String,
    },
    /// Row 7: a failure-count counter above zero.
    FailureCounter {
        /// `domain:key`.
        counter: String,
    },
    /// Row 7: a verdict source says fail.
    VerdictFail {
        /// The source.
        source: VerdictSourceKind,
    },
    /// Row 7: a non-zero exit with a pack that declares the exit code meaningful.
    ExitCode {
        /// The exit code.
        exit_code: i32,
    },
    /// Row 7: failure indications without a failure bucket to explain them.
    UnexplainedFailure,
    /// Row 8.
    IncompleteEvidence,
    /// Row 9.
    NoVerdict,
}

/// A disagreement between sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Contradiction {
    /// The producer said pass, the derivation says otherwise.
    ProducerPass,
    /// A verdict source says pass while failure buckets exist (F2).
    VerdictPassWithFailures {
        /// The source.
        source: VerdictSourceKind,
    },
    /// A reconciliation template does not hold.
    ReconciliationMismatch {
        /// Template name.
        template: String,
    },
}

/// A contradiction and whether a met expectation explains it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContradictionEntry {
    /// The contradiction.
    #[serde(flatten)]
    pub contradiction: Contradiction,
    /// Explained by a `met` expectation (visible, not a blocker).
    pub explained: bool,
}

/// Result used by settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effective {
    /// Passed (plain pass, or expectation met).
    Passed,
    /// Failed with the observed outcome's reason.
    Failed,
}

/// Inputs of outcome derivation for one simulation attempt.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    /// The log's evidence; `None` when there is no log.
    pub evidence: Option<&'a Evidence>,
    /// Runner facts.
    pub runner: &'a Runner,
    /// The producer's reported outcome.
    pub producer: Option<ReportedOutcome>,
    /// Whether the slot has a build requirement (blocked vs error, row 5).
    pub has_build_requirement: bool,
    /// Whether the simulator pack declares the exit code meaningful (row 7).
    pub exit_code_meaningful: bool,
    /// The slot's expected outcome.
    pub expected: Option<&'a Expected>,
}

/// The derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Derived {
    /// Observed outcome.
    pub outcome: Outcome,
    /// For `blocked`.
    pub blocking_phase: Option<BlockingPhase>,
    /// Every matching row's reason, in table order.
    pub reasons: Vec<Reason>,
    /// Synthetic buckets (count 1 each, failing).
    pub synthetic: Vec<SyntheticBucket>,
    /// Effective completion: `unknown` termination overrides a complete-looking log.
    pub completion_complete: bool,
    /// Expectation assessment (B.5).
    pub assessment: Assessment,
    /// Contract diff when the expectation is not met.
    pub contract: Option<ContractDiff>,
    /// Effective result for settlement.
    pub effective: Effective,
    /// Contradictions.
    pub contradictions: Vec<ContradictionEntry>,
    /// Display-primary: a synthetic ID when one decides, `EXPECTATION_MISMATCH` when not
    /// met, else the first failing bucket by ordinal.
    pub primary: Option<String>,
}

fn sum(s: &str) -> u128 {
    s.parse::<u128>().unwrap_or(u128::MAX / 4)
}

/// Whether a bucket is a termination wrapper (never display-primary).
fn termination_wrapper(diag_id: &str) -> bool {
    diag_id == "vcs:unexpected_termination"
}

/// Derives the observed outcome, the expectation assessment and the effective result.
#[must_use]
#[allow(clippy::too_many_lines)] // the B.6 table, row by row
pub fn derive(input: &Input<'_>) -> Derived {
    let term = &input.runner.termination;
    let ev = input.evidence.filter(|e| e.source.bytes.get() > 0);
    // (1) observed accounting.
    let failing: Vec<_> = ev
        .map(|e| e.buckets.iter().filter(|b| b.fails_run).collect())
        .unwrap_or_default();
    let unsuppressed_failing = failing.iter().any(|b| {
        b.effective_severity >= Severity::Error || b.provenance == Provenance::Authoritative
    });
    let overflow_failing = ev.is_some_and(|e| e.overflow.iter().any(|o| o.fails_run));
    let mut verdicts: Vec<(VerdictSourceKind, VerdictValue)> = ev
        .map(|e| {
            e.verdict_sources
                .iter()
                .map(|v| (v.source, v.value))
                .collect()
        })
        .unwrap_or_default();
    match input.producer {
        Some(ReportedOutcome::Pass) => {
            verdicts.push((VerdictSourceKind::Producer, VerdictValue::Pass));
        }
        Some(ReportedOutcome::Fail) => {
            verdicts.push((VerdictSourceKind::Producer, VerdictValue::Fail));
        }
        Some(ReportedOutcome::Error) | None => {}
    }
    let failure_counters: Vec<String> = ev
        .map(|e| {
            e.counters
                .iter()
                .filter(|c| c.role == CounterRole::FailureCount && c.value.as_str() != "0")
                .map(|c| format!("{}:{}", crate::packs::domain_name(c.domain), c.key))
                .collect()
        })
        .unwrap_or_default();
    // (2) reconciliation: counted > extracted means failures nobody printed.
    let reconciliation_excess = ev.is_some_and(|e| {
        e.reconciliation
            .iter()
            .any(|r| sum(r.counted.as_str()) > sum(r.extracted.as_str()))
    });
    let completion_complete = term.kind != TerminationKind::Unknown
        && ev.is_some_and(|e| e.completion.state == CompletionState::Complete);
    // (3) + (4): the table.
    let mut reasons = vec![];
    let mut synth = vec![];
    let mut outcome: Option<(Outcome, Option<BlockingPhase>)> = None;
    let decide = |o: Outcome,
                  p: Option<BlockingPhase>,
                  out: &mut Option<(Outcome, Option<BlockingPhase>)>| {
        if out.is_none() {
            *out = Some((o, p));
        }
    };
    let add_synth = |id: &str, detail: String, decides: bool, synth: &mut Vec<SyntheticBucket>| {
        synth.push(SyntheticBucket {
            diag_id: id.to_string(),
            detail,
            decides,
        });
    };
    // Row 0.
    if term.kind == TerminationKind::Unknown {
        reasons.push(Reason::TerminationUnknown);
        add_synth(
            synthetic::RUNNER_UNKNOWN,
            "interrupted; outcome not recoverable".into(),
            true,
            &mut synth,
        );
        decide(Outcome::Error, None, &mut outcome);
    }
    // Row 1.
    if term.kind == TerminationKind::Timeout {
        reasons.push(Reason::Timeout);
        let d = outcome.is_none();
        add_synth(
            synthetic::RUNNER_TIMEOUT,
            "the runner's timeout fired".into(),
            d,
            &mut synth,
        );
        decide(Outcome::Timeout, None, &mut outcome);
    }
    // Row 2.
    if term.kind == TerminationKind::Crash {
        reasons.push(Reason::Crash);
        let detail = match (term.posix_signal, &term.windows_status) {
            (Some(s), _) => format!("signal {s}"),
            (None, Some(w)) => format!("status {w}"),
            _ => "fault".to_string(),
        };
        let d = outcome.is_none();
        add_synth(synthetic::RUNNER_CRASH, detail, d, &mut synth);
        decide(Outcome::Error, None, &mut outcome);
    }
    // Row 3.
    if matches!(
        term.kind,
        TerminationKind::TerminatedByRunner | TerminationKind::TerminatedExternally
    ) {
        reasons.push(Reason::Killed);
        let d = outcome.is_none();
        add_synth(
            synthetic::RUNNER_KILLED,
            "stopped before it ended".into(),
            d,
            &mut synth,
        );
        decide(Outcome::Killed, None, &mut outcome);
    }
    // Row 4.
    if ev.is_none() {
        reasons.push(Reason::NoLog);
        let detail = term.exit_code.map_or_else(
            || "no log".to_string(),
            |c| format!("no log; exit code {c}"),
        );
        let d = outcome.is_none();
        add_synth(synthetic::NO_LOG, detail, d, &mut synth);
        decide(Outcome::Error, None, &mut outcome);
    }
    // Row 5.
    let design_not_loaded = ev.is_some_and(|e| e.design_loaded == DesignLoaded::False);
    let build_diag = failing
        .iter()
        .filter(|b| {
            matches!(b.phase, Phase::Compile | Phase::Elaborate) || b.kind == DiagKind::Build
        })
        .min_by_key(|b| b.first_ordinal);
    if design_not_loaded || build_diag.is_some() {
        if design_not_loaded {
            reasons.push(Reason::DesignNotLoaded);
        }
        if let Some(b) = build_diag {
            reasons.push(Reason::BuildDiagnostic {
                diag_id: b.diag_id.clone(),
            });
        }
        let phase = match build_diag.map(|b| b.phase) {
            Some(Phase::Compile) => BlockingPhase::Compile,
            _ => BlockingPhase::Elaborate,
        };
        if input.has_build_requirement {
            decide(Outcome::Blocked, Some(phase), &mut outcome);
        } else {
            decide(Outcome::Error, None, &mut outcome);
        }
    }
    // Row 6.
    let infra = failing
        .iter()
        .filter(|b| {
            matches!(
                b.kind,
                DiagKind::Usage | DiagKind::License | DiagKind::Resource | DiagKind::Crash
            )
        })
        .min_by_key(|b| b.first_ordinal);
    if let Some(b) = infra {
        reasons.push(Reason::InfrastructureDiagnostic {
            diag_id: b.diag_id.clone(),
        });
        decide(Outcome::Error, None, &mut outcome);
    }
    if input.producer == Some(ReportedOutcome::Error) {
        reasons.push(Reason::ProducerError);
        decide(Outcome::Error, None, &mut outcome);
    }
    // Row 7.
    let mut indication = false;
    for b in &failing {
        if !reasons
            .iter()
            .any(|r| matches!(r, Reason::FailureBucket { diag_id } if diag_id == &b.diag_id))
        {
            reasons.push(Reason::FailureBucket {
                diag_id: b.diag_id.clone(),
            });
        }
        indication = true;
    }
    indication |= overflow_failing;
    for c in &failure_counters {
        reasons.push(Reason::FailureCounter { counter: c.clone() });
        indication = true;
    }
    for (src, v) in &verdicts {
        if *v == VerdictValue::Fail {
            reasons.push(Reason::VerdictFail { source: *src });
            indication = true;
        }
    }
    if input.exit_code_meaningful
        && let Some(code) = term.exit_code
        && code != 0
    {
        reasons.push(Reason::ExitCode { exit_code: code });
        indication = true;
    }
    // A counter or verdict says fail but no unsuppressed failure bucket explains it; or a
    // summary counted failures that were never printed.
    let unexplained =
        (indication && !unsuppressed_failing && !overflow_failing) || reconciliation_excess;
    if unexplained {
        reasons.push(Reason::UnexplainedFailure);
        add_synth(
            synthetic::UNEXPLAINED_FAILURE,
            "a failure indication no failure diagnostic explains".into(),
            false,
            &mut synth,
        );
    }
    if indication || unexplained {
        decide(Outcome::Fail, None, &mut outcome);
    }
    // Row 8.
    if !completion_complete {
        reasons.push(Reason::IncompleteEvidence);
        let detail = ev.map_or_else(
            || "no evidence".to_string(),
            |e| {
                format!(
                    "completion {:?} {:?}",
                    e.completion.state, e.completion.reasons
                )
            },
        );
        add_synth(synthetic::INCOMPLETE_EVIDENCE, detail, false, &mut synth);
        decide(Outcome::Fail, None, &mut outcome);
    }
    // Row 9: the profile requires a verdict source and none was seen (an early-fatal log's
    // verdict is its recorded fatal). Usually row 8 already decided; the reason and the
    // synthetic bucket are added anyway.
    let verdict_missing = ev.is_some_and(|e| {
        e.completion.verdict_required
            && e.completion.mode != Some(CompletionMode::EarlyFatal)
            && !e.verdict_sources.iter().any(|v| {
                // A decisive verdict (pass or fail): "not applicable" says nothing passed.
                v.source != VerdictSourceKind::Producer && v.value != VerdictValue::NotApplicable
            })
    });
    if verdict_missing {
        reasons.push(Reason::NoVerdict);
        add_synth(
            synthetic::NO_VERDICT,
            "no verdict source".into(),
            false,
            &mut synth,
        );
        decide(Outcome::Fail, None, &mut outcome);
    }
    // Row 10.
    let (outcome, blocking_phase) = outcome.unwrap_or((Outcome::Pass, None));
    // (5) expectation assessment, over 1–4 only.
    let crash = term.kind == TerminationKind::Crash;
    let (assessment, contract) = assess(
        input.expected,
        ev,
        completion_complete,
        crash,
        outcome,
        &verdicts,
        &synth,
    );
    // (6) EXPECTATION_MISMATCH and display-primary.
    let mut primary = synth.iter().find(|s| s.decides).map(|s| s.diag_id.clone());
    if assessment == Assessment::NotMet {
        synth.push(SyntheticBucket {
            diag_id: synthetic::EXPECTATION_MISMATCH.to_string(),
            detail: "expected outcome not met".to_string(),
            decides: false,
        });
        primary = Some(synthetic::EXPECTATION_MISMATCH.to_string());
    }
    if primary.is_none() {
        primary = failing
            .iter()
            .filter(|b| !termination_wrapper(&b.diag_id))
            .min_by_key(|b| b.first_ordinal)
            .map(|b| b.diag_id.clone())
            .or_else(|| synth.first().map(|s| s.diag_id.clone()));
    }
    let effective = if assessment == Assessment::Met
        || (outcome == Outcome::Pass && assessment == Assessment::NotApplicable)
    {
        Effective::Passed
    } else {
        Effective::Failed
    };
    // (7) contradictions.
    let explained = assessment == Assessment::Met;
    let derived_fail = outcome != Outcome::Pass;
    let mut contradictions = vec![];
    if input.producer == Some(ReportedOutcome::Pass) && derived_fail {
        contradictions.push(Contradiction::ProducerPass);
    }
    if !failing.is_empty() {
        for (src, v) in &verdicts {
            if *v == VerdictValue::Pass && *src != VerdictSourceKind::Producer {
                contradictions.push(Contradiction::VerdictPassWithFailures { source: *src });
            }
        }
    }
    for r in ev.map(|e| e.reconciliation.as_slice()).unwrap_or_default() {
        if !r.holds {
            contradictions.push(Contradiction::ReconciliationMismatch {
                template: r.template.clone(),
            });
        }
    }
    let contradictions = contradictions
        .into_iter()
        .map(|c| ContradictionEntry {
            contradiction: c,
            explained,
        })
        .collect();
    Derived {
        outcome,
        blocking_phase,
        reasons,
        synthetic: synth,
        completion_complete,
        assessment,
        contract,
        effective,
        contradictions,
        primary,
    }
}
