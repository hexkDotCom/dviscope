//! Expected outcomes: selector validation, the assessment truth table, and the
//! contract diff shown on the attempt page.

use dviscope_model::wire::evidence::{
    Bucket, CounterDomain, CounterRole, Evidence, Framework, VerdictSourceKind, VerdictValue,
};
use dviscope_model::wire::manifest::{
    Expected, ExpectedCount, ExpectedDiagnostic, ExpectedVerdict, Extras, Severity,
};
use serde::Serialize;

use crate::outcome::{Outcome, SyntheticBucket};

/// Expectation assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    /// No expectation (or a plain pass expectation).
    NotApplicable,
    /// The evidence is not complete: nothing can be assessed.
    Unassessable,
    /// Met: the disagreement it explains is visible but not a contradiction.
    Met,
    /// Not met: `EXPECTATION_MISMATCH`.
    NotMet,
}

/// One selector's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectorResult {
    /// The selector's diagnostic ID.
    pub diag_id: String,
    /// Expected count as written.
    pub expected: String,
    /// Matched count.
    pub observed: u64,
}

/// What differs between the expected and the observed diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ContractDiff {
    /// Selectors with no matching bucket.
    pub missing: Vec<SelectorResult>,
    /// Selectors whose count does not match.
    pub wrong_count: Vec<SelectorResult>,
    /// Buckets with an expected ID and severity at another site or checker.
    pub wrong_site: Vec<String>,
    /// Buckets with an expected ID at another severity.
    pub wrong_severity: Vec<String>,
    /// Failing (or, with `extras: none`, warning) buckets no selector covers.
    pub extra: Vec<String>,
    /// Failure counters not explained by the selected buckets.
    pub unexplained_counters: Vec<String>,
    /// Synthetic failures present (never explained by an expectation).
    pub synthetic: Vec<String>,
    /// Expected vs observed verdict, when they differ.
    pub verdict: Option<String>,
}

impl ContractDiff {
    fn is_empty(&self) -> bool {
        self.missing.is_empty()
            && self.wrong_count.is_empty()
            && self.extra.is_empty()
            && self.unexplained_counters.is_empty()
            && self.synthetic.is_empty()
            && self.verdict.is_none()
    }
}

/// Why an expectation is rejected at manifest import.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExpectedError {
    /// `verdict: fail` without diagnostics.
    #[error("an expected failure lists at least one diagnostic")]
    FailWithoutDiagnostics,
    /// Info severity cannot be expected.
    #[error("expected diagnostic {0}: severity must be warning, error or fatal")]
    InfoSeverity(String),
    /// A count is not `N` or `>=N`.
    #[error("expected diagnostic {0}: count must be N or \">=N\"")]
    BadCount(String),
    /// Two selectors can match the same bucket.
    #[error("expected diagnostics {0} and {1} can match the same bucket")]
    Overlap(String, String),
}

fn at_least(c: &ExpectedCount) -> Result<(u64, bool), ()> {
    match c {
        ExpectedCount::Exact(n) => Ok((u64::from(*n), false)),
        ExpectedCount::AtLeast(s) => s
            .strip_prefix(">=")
            .and_then(|n| n.trim().parse::<u64>().ok())
            .map(|n| (n, true))
            .ok_or(()),
    }
}

fn count_text(c: &ExpectedCount) -> String {
    match c {
        ExpectedCount::Exact(n) => n.to_string(),
        ExpectedCount::AtLeast(s) => s.clone(),
    }
}

fn may_overlap(a: &ExpectedDiagnostic, b: &ExpectedDiagnostic) -> bool {
    let disjoint =
        |x: &Option<String>, y: &Option<String>| matches!((x, y), (Some(p), Some(q)) if p != q);
    a.diag_id == b.diag_id
        && a.severity == b.severity
        && !disjoint(&a.checker_id, &b.checker_id)
        && !disjoint(&a.site, &b.site)
}

/// Validates an expectation (manifest import).
///
/// # Errors
/// The first problem found.
pub fn validate(x: &Expected) -> Result<(), ExpectedError> {
    if x.verdict == ExpectedVerdict::Fail && x.diagnostics.is_empty() {
        return Err(ExpectedError::FailWithoutDiagnostics);
    }
    for (i, d) in x.diagnostics.iter().enumerate() {
        if d.severity == Severity::Info {
            return Err(ExpectedError::InfoSeverity(d.diag_id.clone()));
        }
        at_least(&d.count).map_err(|()| ExpectedError::BadCount(d.diag_id.clone()))?;
        for e in &x.diagnostics[i + 1..] {
            if may_overlap(d, e) {
                return Err(ExpectedError::Overlap(d.diag_id.clone(), e.diag_id.clone()));
            }
        }
    }
    Ok(())
}

fn matches(sel: &ExpectedDiagnostic, b: &Bucket) -> bool {
    sel.diag_id == b.diag_id
        && sel.severity == b.observed_severity
        && sel
            .checker_id
            .as_ref()
            .is_none_or(|c| b.checker_id.as_ref() == Some(c))
        && sel.site.as_ref().is_none_or(|s| b.site.as_ref() == Some(s))
}

fn count(b: &Bucket) -> u64 {
    b.count.as_str().parse::<u64>().unwrap_or(u64::MAX)
}

/// The population of a reconciliation template.
fn template_population(t: &str) -> (&'static [Framework], &'static [Severity]) {
    match t {
        "uvm_errors" => (&[Framework::Uvm], &[Severity::Error, Severity::Fatal]),
        "questa_sim_errors" => (
            &[Framework::Simulator, Framework::Assertion],
            &[Severity::Error, Severity::Fatal],
        ),
        _ => (&[], &[]),
    }
}

/// Reconciliation templates and the counters they cover.
fn template_of(domain: CounterDomain, key: &str) -> Option<&'static str> {
    match (domain, key) {
        (CounterDomain::UvmSeverity, "UVM_ERROR" | "UVM_FATAL") => Some("uvm_errors"),
        (CounterDomain::SimTool, "errors") => Some("questa_sim_errors"),
        _ => None,
    }
}

/// Assesses the expectation over steps 1–4 of the evaluation sequence.
#[must_use]
#[allow(clippy::too_many_lines)] // the B.5 truth table, one condition after another
pub(crate) fn assess(
    expected: Option<&Expected>,
    ev: Option<&Evidence>,
    complete: bool,
    crash: bool,
    outcome: Outcome,
    verdicts: &[(VerdictSourceKind, VerdictValue)],
    synth: &[SyntheticBucket],
) -> (Assessment, Option<ContractDiff>) {
    let Some(x) = expected else {
        return (Assessment::NotApplicable, None);
    };
    let Some(ev) = ev.filter(|_| complete && !crash) else {
        return (Assessment::Unassessable, None);
    };
    if x.verdict == ExpectedVerdict::Pass && x.diagnostics.is_empty() {
        return (Assessment::NotApplicable, None);
    }
    let mut diff = ContractDiff::default();
    if outcome.is_infrastructure() {
        diff.verdict = Some(format!("expected {:?}, observed {outcome:?}", x.verdict));
        return (Assessment::NotMet, Some(diff));
    }
    // Selectors against buckets.
    let mut selected = vec![false; ev.buckets.len()];
    for sel in &x.diagnostics {
        let mut n = 0u64;
        for (i, b) in ev.buckets.iter().enumerate() {
            if !selected[i] && matches(sel, b) {
                selected[i] = true;
                n = n.saturating_add(count(b));
            }
        }
        let (want, ge) = at_least(&sel.count).unwrap_or((u64::MAX, false));
        let r = SelectorResult {
            diag_id: sel.diag_id.clone(),
            expected: count_text(&sel.count),
            observed: n,
        };
        if n == 0 {
            diff.missing.push(r);
        } else if (ge && n < want) || (!ge && n != want) {
            diff.wrong_count.push(r);
        }
        for b in ev
            .buckets
            .iter()
            .filter(|b| b.diag_id == sel.diag_id && !matches(sel, b))
        {
            let label = format!("{}@{}", b.diag_id, b.site.as_deref().unwrap_or("-"));
            if b.observed_severity == sel.severity {
                diff.wrong_site.push(label);
            } else {
                diff.wrong_severity.push(label);
            }
        }
    }
    // Buckets nobody expected: failures always count; warnings unless allowed.
    for (i, b) in ev.buckets.iter().enumerate() {
        let extra = !selected[i]
            && (b.fails_run
                || (x.extras == Extras::None && b.observed_severity >= Severity::Warning));
        if extra {
            diff.extra.push(b.diag_id.clone());
        }
    }
    if ev.overflow.iter().any(|o| o.fails_run) {
        diff.extra.push("overflow".to_string());
    }
    // Failure counters must be fully explained by the selected buckets.
    let selected_count = |id: &str| -> u64 {
        ev.buckets
            .iter()
            .enumerate()
            .filter(|(i, b)| selected[*i] && b.diag_id == id)
            .map(|(_, b)| count(b))
            .sum()
    };
    for c in ev
        .counters
        .iter()
        .filter(|c| c.role == CounterRole::FailureCount && c.value.as_str() != "0")
    {
        let name = format!("{}:{}", crate::packs::domain_name(c.domain), c.key);
        let value = c.value.as_str().parse::<u64>().unwrap_or(u64::MAX);
        let ok = if let Some(id) = &c.explained_by {
            selected_count(id) == value
        } else if let Some(t) = template_of(c.domain, &c.key) {
            // The template's counted total must equal the *selected* events of its
            // population: a suppressed (dropped) or unselected diagnostic never explains it.
            let (frameworks, severities) = template_population(t);
            let selected_population: u64 = ev
                .buckets
                .iter()
                .enumerate()
                .filter(|(i, b)| {
                    selected[*i]
                        && frameworks.contains(&b.framework)
                        && severities.contains(&b.observed_severity)
                })
                .map(|(_, b)| count(b))
                .sum();
            ev.reconciliation.iter().any(|r| {
                r.template == t
                    && r.holds
                    && r.counted.as_str() == r.extracted.as_str()
                    && r.counted.as_str() == selected_population.to_string()
            })
        } else {
            false
        };
        if !ok {
            diff.unexplained_counters.push(name);
        }
    }
    for r in &ev.reconciliation {
        if r.counted.as_str() != r.extracted.as_str() {
            diff.unexplained_counters
                .push(format!("reconciliation:{}", r.template));
        }
    }
    diff.unexplained_counters.sort();
    diff.unexplained_counters.dedup();
    diff.synthetic = synth.iter().map(|s| s.diag_id.clone()).collect();
    match x.verdict {
        ExpectedVerdict::Fail => {
            if outcome != Outcome::Fail {
                diff.verdict = Some(format!("expected fail, observed {outcome:?}"));
            }
        }
        ExpectedVerdict::Pass => {
            let framework = |s: &VerdictSourceKind| *s != VerdictSourceKind::Producer;
            let any_pass = verdicts
                .iter()
                .any(|(s, v)| framework(s) && *v == VerdictValue::Pass);
            let any_fail = verdicts
                .iter()
                .any(|(s, v)| framework(s) && *v == VerdictValue::Fail);
            if !any_pass || any_fail {
                diff.verdict =
                    Some("expected a passing verdict source and no failing one".to_string());
            }
        }
    }
    if diff.is_empty() {
        (Assessment::Met, None)
    } else {
        (Assessment::NotMet, Some(diff))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sel(id: &str, sev: Severity, site: Option<&str>) -> ExpectedDiagnostic {
        ExpectedDiagnostic {
            diag_id: id.into(),
            severity: sev,
            checker_id: None,
            site: site.map(str::to_string),
            count: ExpectedCount::Exact(1),
        }
    }

    #[test]
    fn overlapping_selectors_are_rejected() {
        let x = |d: Vec<ExpectedDiagnostic>| Expected {
            verdict: ExpectedVerdict::Fail,
            diagnostics: d,
            extras: Extras::None,
            reason: "r".into(),
        };
        assert!(
            validate(&x(vec![
                sel("a", Severity::Error, None),
                sel("a", Severity::Error, Some("f:1"))
            ]))
            .is_err()
        );
        assert!(
            validate(&x(vec![
                sel("a", Severity::Error, Some("f:2")),
                sel("a", Severity::Error, Some("f:1"))
            ]))
            .is_ok()
        );
        assert!(
            validate(&x(vec![
                sel("a", Severity::Error, None),
                sel("a", Severity::Fatal, None)
            ]))
            .is_ok()
        );
        assert_eq!(
            validate(&x(vec![])),
            Err(ExpectedError::FailWithoutDiagnostics)
        );
        let mut bad = sel("a", Severity::Error, None);
        bad.count = ExpectedCount::AtLeast("3".into());
        assert!(validate(&x(vec![bad])).is_err());
    }
}
