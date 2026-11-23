//! Validity first: every attempt and build attempt gets an eligibility
//! before adjudication. Quarantine and withdrawn pipelines are also settlement barriers
//! (B.7.2 rule 1), which are stronger than ineligibility.

use serde::Serialize;

/// Why an attempt is not eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IneligibleReason {
    /// Its source manifest is not the regression's.
    SourceMismatch,
    /// Its evidence names a pipeline the project never accepted.
    PipelineMismatch,
    /// Reported with a quarantined credential.
    Quarantined,
    /// An experiment (never counts).
    PurposeExperiment,
}

/// Eligibility of an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "eligibility", content = "reason", rename_all = "snake_case")]
pub enum Eligibility {
    /// Counts.
    Eligible,
    /// Visible as *"Report received; not eligible: <reason>"*.
    Ineligible(IneligibleReason),
}

/// The status of the pipeline an attempt's evidence names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    /// In the project's accepted set.
    Accepted,
    /// Accepted once, now withdrawn: eligible but a barrier (B.9.5).
    Withdrawn,
    /// Never accepted.
    Unknown,
}

/// Facts eligibility reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    /// Reported with a quarantined credential (not released).
    pub quarantined: bool,
    /// Purpose `experiment`.
    pub experiment: bool,
    /// The attempt's source manifest equals the regression's.
    pub source_matches: bool,
    /// Pipeline status of the evidence (`None` for build attempts without evidence).
    pub pipeline: Option<PipelineStatus>,
}

/// Eligibility, first reason wins: quarantine, experiment, source, pipeline.
#[must_use]
pub fn eligibility(f: &Facts) -> Eligibility {
    if f.quarantined {
        Eligibility::Ineligible(IneligibleReason::Quarantined)
    } else if f.experiment {
        Eligibility::Ineligible(IneligibleReason::PurposeExperiment)
    } else if !f.source_matches {
        Eligibility::Ineligible(IneligibleReason::SourceMismatch)
    } else if f.pipeline == Some(PipelineStatus::Unknown) {
        Eligibility::Ineligible(IneligibleReason::PipelineMismatch)
    } else {
        Eligibility::Eligible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_reason_wins() {
        let base = Facts {
            quarantined: false,
            experiment: false,
            source_matches: true,
            pipeline: Some(PipelineStatus::Accepted),
        };
        assert_eq!(eligibility(&base), Eligibility::Eligible);
        let withdrawn = Facts {
            pipeline: Some(PipelineStatus::Withdrawn),
            ..base
        };
        assert_eq!(eligibility(&withdrawn), Eligibility::Eligible);
        let all = Facts {
            quarantined: true,
            experiment: true,
            source_matches: false,
            pipeline: Some(PipelineStatus::Unknown),
        };
        assert_eq!(
            eligibility(&all),
            Eligibility::Ineligible(IneligibleReason::Quarantined)
        );
        let pipe = Facts {
            pipeline: Some(PipelineStatus::Unknown),
            ..base
        };
        assert_eq!(
            eligibility(&pipe),
            Eligibility::Ineligible(IneligibleReason::PipelineMismatch)
        );
    }
}
