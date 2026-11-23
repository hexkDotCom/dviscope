//! Comparison of a regression with its baseline: header counts, one
//! row per signature with currently affected failed slots, and the baseline status of each
//! row. *Absent from baseline* only when the baseline settled a slot with the same
//! configuration digest; otherwise *not observed; affected configuration not run*.

use std::collections::{BTreeMap, BTreeSet};

use dviscope_model::canonical::Digest;
use serde::Serialize;

use crate::settlement::{BlockedBy, SlotState};

/// One settled slot as the comparison reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotView {
    /// Slot key (producer slot ref).
    pub slot: String,
    /// Logical comparison configuration (`config_digest`).
    pub config: Digest,
    /// Simulator label.
    pub simulator: String,
    /// Settled state.
    pub state: SlotState,
    /// Signatures (family fingerprints) of the slot's failing attempts, each with the
    /// number of failing attempts showing it and its diagnostic count in them.
    pub signatures: BTreeMap<Digest, SignatureCounts>,
}

/// Counts of one signature within one slot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignatureCounts {
    /// Failing attempts showing the signature.
    pub attempts: u32,
    /// Its diagnostics in those attempts.
    pub diagnostics: u64,
}

/// Counts of the header (*"25 planned · 7 passed · 18 failed"*).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Header {
    /// Planned slots.
    pub planned: u64,
    /// Passed.
    pub passed: u64,
    /// Failed.
    pub failed: u64,
    /// Blocked.
    pub blocked: u64,
    /// Missing.
    pub missing: u64,
    /// Running.
    pub running: u64,
    /// Cancelled.
    pub cancelled: u64,
    /// Skipped.
    pub skipped: u64,
    /// Distinct signatures over failed slots.
    pub signatures: u64,
    /// Failed slots with at least one signature (signatures can overlap).
    pub slots_with_signatures: u64,
}

/// Baseline status of a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    /// Also seen in the baseline.
    InBaseline,
    /// The baseline settled the same configurations without it: new.
    AbsentFromBaseline,
    /// The baseline did not settle the affected configurations.
    NotObserved,
    /// No baseline.
    NoBaseline,
}

/// One row: a signature, or a group of blocked slots without any signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    /// Signature (for a group row: a fixed digest naming the group).
    pub signature: Digest,
    /// `build` or `elaboration` for a row of blocked slots without a signature; absent
    /// for signature rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<&'static str>,
    /// Currently affected failed slots.
    pub failed_slots: u64,
    /// Failing attempts.
    pub failing_attempts: u64,
    /// Diagnostics.
    pub diagnostics: u64,
    /// Slots of the baseline with the signature.
    pub baseline_slots: u64,
    /// Baseline status.
    pub baseline: BaselineStatus,
    /// Simulators.
    pub simulators: BTreeSet<String>,
    /// Up to 5 affected slots, sorted.
    pub preview: Vec<String>,
}

/// A comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Comparison {
    /// Header counts.
    pub header: Header,
    /// Rows, new before persisting, then by affected slots descending, then signature.
    pub rows: Vec<Row>,
}

fn is_failed(s: SlotState) -> bool {
    matches!(s, SlotState::Failed(_) | SlotState::Blocked(_))
}

/// Baseline status of rows affecting `slots`: also in the baseline, absent although the
/// baseline settled the same configuration, or not observed there.
fn baseline_status(
    slots: &[&SlotView],
    settled: Option<&BTreeSet<&Digest>>,
    baseline_slots: u64,
) -> BaselineStatus {
    match settled {
        None => BaselineStatus::NoBaseline,
        Some(_) if baseline_slots > 0 => BaselineStatus::InBaseline,
        Some(set) => {
            if slots.iter().any(|s| set.contains(&s.config)) {
                BaselineStatus::AbsentFromBaseline
            } else {
                BaselineStatus::NotObserved
            }
        }
    }
}

/// Configurations the baseline settled (any state but missing, running, cancelled or
/// skipped), computed once per comparison.
fn settled_configs(baseline: Option<&[SlotView]>) -> Option<BTreeSet<&Digest>> {
    baseline.map(|b| {
        b.iter()
            .filter(|x| {
                !matches!(
                    x.state,
                    SlotState::Missing
                        | SlotState::Running
                        | SlotState::Cancelled
                        | SlotState::Skipped
                )
            })
            .map(|x| &x.config)
            .collect()
    })
}

/// Rows of blocked slots without any signature.
fn group_rows(
    current: &[SlotView],
    baseline: Option<&[SlotView]>,
    settled: Option<&BTreeSet<&Digest>>,
) -> Vec<Row> {
    let mut rows = vec![];
    // Blocked slots without any signature (a failed build never runs the tests; an
    // elaboration failure may leave no diagnostic): one row per blocking kind.
    for (kind, by) in [
        ("build", BlockedBy::Build),
        ("elaboration", BlockedBy::Elaboration),
    ] {
        let of = |v: &[SlotView]| -> Vec<String> {
            v.iter()
                .filter(|s| s.state == SlotState::Blocked(by) && s.signatures.is_empty())
                .map(|s| s.slot.clone())
                .collect()
        };
        let mut names = of(current);
        if names.is_empty() {
            continue;
        }
        names.sort();
        let slots: Vec<&SlotView> = current
            .iter()
            .filter(|s| s.state == SlotState::Blocked(by) && s.signatures.is_empty())
            .collect();
        let baseline_slots = baseline.map_or(0, |b| of(b).len() as u64);
        let status = baseline_status(&slots, settled, baseline_slots);
        rows.push(Row {
            signature: Digest::of_bytes(format!("dviscope.group/{kind}").as_bytes()),
            group: Some(kind),
            failed_slots: names.len() as u64,
            failing_attempts: 0,
            diagnostics: 0,
            baseline_slots,
            baseline: status,
            simulators: slots.iter().map(|s| s.simulator.clone()).collect(),
            preview: names.into_iter().take(5).collect(),
        });
    }
    rows
}

/// Compares a regression with an optional baseline.
#[must_use]
pub fn compare(current: &[SlotView], baseline: Option<&[SlotView]>) -> Comparison {
    let mut h = Header {
        planned: current.len() as u64,
        ..Header::default()
    };
    for s in current {
        match s.state {
            SlotState::Passed => h.passed += 1,
            SlotState::Failed(_) => h.failed += 1,
            SlotState::Blocked(_) => h.blocked += 1,
            SlotState::Missing => h.missing += 1,
            SlotState::Running => h.running += 1,
            SlotState::Cancelled => h.cancelled += 1,
            SlotState::Skipped => h.skipped += 1,
        }
    }
    let mut by_sig: BTreeMap<&Digest, Vec<&SlotView>> = BTreeMap::new();
    for s in current.iter().filter(|s| is_failed(s.state)) {
        for sig in s.signatures.keys() {
            by_sig.entry(sig).or_default().push(s);
        }
        if !s.signatures.is_empty() {
            h.slots_with_signatures += 1;
        }
    }
    h.signatures = by_sig.len() as u64;
    // The baseline read once: settled configurations and failed slots per signature.
    let settled = settled_configs(baseline);
    let mut base_counts: BTreeMap<&Digest, u64> = BTreeMap::new();
    for s in baseline
        .into_iter()
        .flatten()
        .filter(|s| is_failed(s.state))
    {
        for sig in s.signatures.keys() {
            *base_counts.entry(sig).or_default() += 1;
        }
    }
    let mut rows: Vec<Row> = by_sig
        .into_iter()
        .map(|(sig, slots)| {
            let baseline_slots = base_counts.get(sig).copied().unwrap_or(0);
            let status = baseline_status(&slots, settled.as_ref(), baseline_slots);
            let mut names: Vec<String> = slots.iter().map(|s| s.slot.clone()).collect();
            names.sort();
            Row {
                signature: sig.clone(),
                group: None,
                failed_slots: slots.len() as u64,
                failing_attempts: slots
                    .iter()
                    .map(|s| u64::from(s.signatures.get(sig).map_or(0, |c| c.attempts)))
                    .sum(),
                diagnostics: slots
                    .iter()
                    .map(|s| s.signatures.get(sig).map_or(0, |c| c.diagnostics))
                    .sum(),
                baseline_slots,
                baseline: status,
                simulators: slots.iter().map(|s| s.simulator.clone()).collect(),
                preview: names.into_iter().take(5).collect(),
            }
        })
        .collect();
    rows.extend(group_rows(current, baseline, settled.as_ref()));
    let new_first = |r: &Row| match r.baseline {
        BaselineStatus::AbsentFromBaseline => 0,
        BaselineStatus::NotObserved | BaselineStatus::NoBaseline => 1,
        BaselineStatus::InBaseline => 2,
    };
    rows.sort_by(|a, b| {
        (
            new_first(a),
            std::cmp::Reverse(a.failed_slots),
            &a.signature,
        )
            .cmp(&(
                new_first(b),
                std::cmp::Reverse(b.failed_slots),
                &b.signature,
            ))
    });
    Comparison { header: h, rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::FailReason;

    fn d(s: &str) -> Digest {
        Digest::of_bytes(s.as_bytes())
    }

    fn view(slot: &str, cfg: &str, state: SlotState, sigs: &[&str]) -> SlotView {
        SlotView {
            slot: slot.into(),
            config: d(cfg),
            simulator: "vcs".into(),
            state,
            signatures: sigs
                .iter()
                .map(|s| {
                    (
                        d(s),
                        SignatureCounts {
                            attempts: 1,
                            diagnostics: 10,
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn blocked_slots_without_signatures_form_group_rows() {
        // 25 runtime elaboration failures without a diagnostic: one elaboration row.
        let mut cur: Vec<SlotView> = (0..25)
            .map(|i| {
                view(
                    &format!("e{i:02}"),
                    "c1",
                    SlotState::Blocked(BlockedBy::Elaboration),
                    &[],
                )
            })
            .collect();
        cur.push(view("b1", "c2", SlotState::Blocked(BlockedBy::Build), &[]));
        cur.push(view("b2", "c2", SlotState::Blocked(BlockedBy::Build), &[]));
        // A blocked slot with a signature stays in its signature row.
        cur.push(view(
            "s1",
            "c3",
            SlotState::Blocked(BlockedBy::Elaboration),
            &["elab"],
        ));
        let c = compare(&cur, None);
        let elab: Vec<&Row> = c
            .rows
            .iter()
            .filter(|r| r.group == Some("elaboration"))
            .collect();
        assert_eq!(elab.len(), 1);
        assert_eq!(elab[0].failed_slots, 25);
        assert_eq!(elab[0].preview.len(), 5);
        let build: Vec<&Row> = c.rows.iter().filter(|r| r.group == Some("build")).collect();
        assert_eq!(build[0].failed_slots, 2);
        assert_eq!(c.header.blocked, 28);
        assert_eq!(c.header.signatures, 1, "group rows are not signatures");
        // 25 elaboration failures with one shared diagnostic: one signature row of 25.
        let same: Vec<SlotView> = (0..25)
            .map(|i| {
                view(
                    &format!("e{i:02}"),
                    "c1",
                    SlotState::Blocked(BlockedBy::Elaboration),
                    &["elab"],
                )
            })
            .collect();
        let c = compare(&same, None);
        assert_eq!(c.rows.len(), 1);
        assert_eq!(c.rows[0].failed_slots, 25);
        assert_eq!(c.rows[0].group, None);
    }

    #[test]
    fn baseline_status_and_overlap() {
        let f = SlotState::Failed(FailReason::Functional);
        let cur = vec![
            view("a", "c1", f, &["x", "y"]),
            view("b", "c2", f, &["x"]),
            view("c", "c3", f, &["z"]),
            view("d", "c4", SlotState::Passed, &[]),
        ];
        let base = vec![
            view("a", "c1", f, &["x"]),
            view("b", "c2", SlotState::Passed, &[]),
        ];
        let c = compare(&cur, Some(&base));
        assert_eq!(
            (
                c.header.planned,
                c.header.failed,
                c.header.signatures,
                c.header.slots_with_signatures
            ),
            (4, 3, 3, 3)
        );
        let status: BTreeMap<Digest, BaselineStatus> = c
            .rows
            .iter()
            .map(|r| (r.signature.clone(), r.baseline))
            .collect();
        assert_eq!(status[&d("x")], BaselineStatus::InBaseline);
        assert_eq!(status[&d("y")], BaselineStatus::AbsentFromBaseline);
        assert_eq!(status[&d("z")], BaselineStatus::NotObserved);
        assert_eq!(c.rows[0].signature, d("y"));
    }
}
