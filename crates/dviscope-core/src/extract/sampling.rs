//! Family accounting, examples and the excerpt, under the bounded-output rules
//! of `docs/packs.md` ("Bounded output").

use std::collections::{BTreeMap, HashMap};

use dviscope_model::canonical::Digest;
use dviscope_model::limits::{
    MAX_ACCOUNTING_BYTES, MAX_BUCKETS, MAX_EVENTS, MAX_EVENTS_BYTES, MAX_EXCERPT_BYTES,
    MAX_FAMILIES,
};
use dviscope_model::values::{DecimalInteger, SafeU64};
use dviscope_model::wire::evidence::{
    Bucket, DiagKind, Event, Excerpt, Family, Framework, OverflowEntry, Phase, Provenance, Segment,
    SegmentKind,
};
use dviscope_model::wire::manifest::Severity;

use super::decode::truncate_utf8;

/// First failure events kept as examples.
pub const FIRST_FAILURES: usize = 100;
/// Lines before the primary record kept in the excerpt.
pub const EXCERPT_BEFORE: usize = 40;
/// Lines of the primary record kept.
pub const EXCERPT_PRIMARY: usize = 200;
/// Lines after the primary record kept.
pub const EXCERPT_AFTER: usize = 20;
/// Last lines of the log kept.
pub const EXCERPT_TAIL: usize = 20;
/// Serialized bytes budgeted per segment (kind, first line, brackets) and for the envelope.
const SEGMENT_OVERHEAD: usize = 96;

/// Maximum bytes of one excerpt line.
pub const EXCERPT_LINE_BYTES: usize = 1024;

pub(crate) fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Fatal => 3,
    }
}

/// Display-primary rank: failures first, then severity; earlier wins ties.
pub(crate) fn primary_rank(e: &Event) -> (bool, u8) {
    (e.fails_run, sev_rank(e.observed_severity))
}

/// Everything accounting needs about one classified event.
#[derive(Debug, Clone)]
pub(crate) struct Classified {
    pub event: Event,
    pub site: Option<String>,
    pub family_kind: String,
    pub checker_scope: Option<String>,
    pub fingerprint: Digest,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    fingerprint: Digest,
    diag_id: String,
    checker_id: Option<String>,
    site: Option<String>,
    observed: Severity,
    effective: Severity,
    framework: Framework,
    phase: Phase,
    kind: DiagKind,
    provenance: Provenance,
    fails_run: bool,
}

#[derive(Debug)]
struct BucketAcc {
    bucket: Bucket,
    count: u64,
    first: Option<Event>,
    last: Option<Event>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OverflowKey {
    framework: Framework,
    phase: Phase,
    kind: DiagKind,
    observed: Severity,
    provenance: Provenance,
    fails_run: bool,
}

/// Exact accounting with bounded buckets, families and examples.
#[derive(Debug, Default)]
pub(crate) struct Accounting {
    buckets: Vec<BucketAcc>,
    index: HashMap<BucketKey, usize>,
    families: Vec<Family>,
    family_index: HashMap<Digest, usize>,
    overflow: Vec<(OverflowKey, u64)>,
    bytes: usize,
    first_failures: Vec<(Option<usize>, Event)>,
    pub(crate) primary: Option<(Option<usize>, Event)>,
}

fn json_len<T: serde::Serialize>(v: &T) -> usize {
    serde_json::to_vec(v).map_or(usize::MAX, |b| b.len())
}

fn safe(n: u64) -> SafeU64 {
    SafeU64::saturating(n)
}

fn decimal(n: u64) -> DecimalInteger {
    DecimalInteger::from_u64(n)
}

impl Accounting {
    /// Records one event; returns whether it became the display-primary candidate.
    pub(crate) fn add(&mut self, c: Classified) -> bool {
        let e = &c.event;
        let key = BucketKey {
            fingerprint: c.fingerprint.clone(),
            diag_id: e.diag_id.clone(),
            checker_id: e.checker_id.clone(),
            site: c.site.clone(),
            observed: e.observed_severity,
            effective: e.effective_severity,
            framework: e.framework,
            phase: e.phase,
            kind: e.kind,
            provenance: c.provenance,
            fails_run: e.fails_run,
        };
        let bucket_idx = match self.index.get(&key) {
            Some(&i) => Some(i),
            None => self.new_bucket(key, &c),
        };
        let e = c.event;
        let first_failure = e.fails_run && self.first_failures.len() < FIRST_FAILURES;
        let better = match &self.primary {
            None => sev_rank(e.observed_severity) >= 1,
            Some((_, p)) => primary_rank(&e) > primary_rank(p),
        };
        if first_failure {
            self.first_failures.push((bucket_idx, e.clone()));
        }
        if better {
            self.primary = Some((bucket_idx, e.clone()));
        }
        if let Some(i) = bucket_idx {
            let b = &mut self.buckets[i];
            b.count += 1;
            if b.first.is_none() {
                b.first = Some(e);
            } else {
                b.last = Some(e);
            }
        } else {
            let ok = OverflowKey {
                framework: e.framework,
                phase: e.phase,
                kind: e.kind,
                observed: e.observed_severity,
                provenance: c.provenance,
                fails_run: e.fails_run,
            };
            match self.overflow.iter_mut().find(|(k, _)| *k == ok) {
                Some((_, n)) => *n += 1,
                None => self.overflow.push((ok, 1)),
            }
        }
        better
    }

    fn new_bucket(&mut self, key: BucketKey, c: &Classified) -> Option<usize> {
        if self.buckets.len() >= MAX_BUCKETS {
            return None;
        }
        let existing = self.family_index.get(&c.fingerprint).copied();
        let new_family = if existing.is_some() {
            None
        } else {
            if self.families.len() >= MAX_FAMILIES {
                return None;
            }
            Some(Family {
                fingerprint: c.fingerprint.clone(),
                family_kind: c.family_kind.clone(),
                diag_id: c.event.diag_id.clone(),
                checker_scope: c.checker_scope.clone(),
                identity_template: c.event.identity_template.clone(),
                significant: c.event.significant.clone(),
                display_template: c.event.display_template.clone(),
                buckets: vec![],
            })
        };
        let bucket = Bucket {
            diag_id: key.diag_id.clone(),
            checker_id: key.checker_id.clone(),
            site: key.site.clone(),
            observed_severity: key.observed,
            effective_severity: key.effective,
            framework: key.framework,
            phase: key.phase,
            kind: key.kind,
            provenance: key.provenance,
            fails_run: key.fails_run,
            count: DecimalInteger::zero(),
            family: c.fingerprint.clone(),
            first_ordinal: c.event.ordinal,
            example_ordinal: None,
        };
        // Room for the count digits and the bucket reference in its family; a new family
        // is only added together with its first bucket (no family without buckets).
        let size = json_len(&bucket) + 24 + new_family.as_ref().map_or(0, json_len);
        if self.bytes + size > MAX_ACCOUNTING_BYTES {
            return None;
        }
        self.bytes += size;
        let fam_idx = match (existing, new_family) {
            (Some(i), _) => i,
            (None, fam) => {
                self.families.extend(fam);
                self.family_index
                    .insert(c.fingerprint.clone(), self.families.len() - 1);
                self.families.len() - 1
            }
        };
        let idx = self.buckets.len();
        self.families[fam_idx].buckets.push(safe(idx as u64));
        self.buckets.push(BucketAcc {
            bucket,
            count: 0,
            first: None,
            last: None,
        });
        self.index.insert(key, idx);
        Some(idx)
    }

    /// Whether some event went to overflow.
    pub(crate) fn has_overflow(&self) -> bool {
        !self.overflow.is_empty()
    }

    /// Finishes: buckets, families, overflow and the bounded example list.
    pub(crate) fn finish(self) -> (Vec<Bucket>, Vec<Family>, Vec<OverflowEntry>, Vec<Event>) {
        let Self {
            mut buckets,
            families,
            overflow,
            first_failures,
            primary,
            ..
        } = self;
        // Example selection order: display-primary, first failures, then each bucket's
        // first and last event. Budgets: MAX_EVENTS events, MAX_EVENTS_BYTES bytes.
        let mut candidates: Vec<(Option<usize>, Event)> = vec![];
        if let Some(p) = primary {
            candidates.push(p);
        }
        candidates.extend(first_failures);
        for (i, b) in buckets.iter_mut().enumerate() {
            if let Some(f) = b.first.take() {
                candidates.push((Some(i), f));
            }
            if let Some(l) = b.last.take() {
                candidates.push((Some(i), l));
            }
        }
        let mut chosen: BTreeMap<u64, (Option<usize>, Event)> = BTreeMap::new();
        let mut bytes = 0usize;
        for (b, e) in candidates {
            if chosen.len() >= MAX_EVENTS {
                break;
            }
            let ord = e.ordinal.get();
            if chosen.contains_key(&ord) {
                continue;
            }
            let size = json_len(&e);
            if bytes + size > MAX_EVENTS_BYTES {
                continue;
            }
            bytes += size;
            chosen.insert(ord, (b, e));
        }
        for (b, e) in chosen.values() {
            if let Some(i) = b
                && buckets[*i].bucket.example_ordinal.is_none()
            {
                buckets[*i].bucket.example_ordinal = Some(e.ordinal);
            }
        }
        let out_buckets = buckets
            .into_iter()
            .map(|b| Bucket {
                count: decimal(b.count),
                ..b.bucket
            })
            .collect();
        let out_overflow = overflow
            .into_iter()
            .map(|(k, n)| OverflowEntry {
                framework: k.framework,
                phase: k.phase,
                kind: k.kind,
                observed_severity: k.observed,
                provenance: k.provenance,
                fails_run: k.fails_run,
                count: decimal(n),
            })
            .collect();
        let events = chosen.into_values().map(|(_, e)| e).collect();
        (out_buckets, families, out_overflow, events)
    }
}

/// A captured excerpt line.
pub(crate) type XLine = (u64, String);

fn clip(s: &str) -> String {
    truncate_utf8(s, EXCERPT_LINE_BYTES).to_string()
}

/// Streaming excerpt: no seeks, works on pipes.
#[derive(Debug, Default)]
pub(crate) struct ExcerptState {
    ring: std::collections::VecDeque<XLine>,
    before: Vec<XLine>,
    primary: Vec<XLine>,
    after: Vec<XLine>,
    collecting_after: bool,
}

impl ExcerptState {
    /// Every line passes here, in order.
    pub(crate) fn push(&mut self, no: u64, text: &str) {
        if self.collecting_after {
            if self.after.len() < EXCERPT_AFTER {
                self.after.push((no, clip(text)));
            } else {
                self.collecting_after = false;
            }
        }
        self.ring.push_back((no, clip(text)));
        if self.ring.len() > EXCERPT_BEFORE {
            self.ring.pop_front();
        }
    }

    /// The lines before a record starting at `start_no` (a snapshot of the ring).
    pub(crate) fn snapshot_before(&self, start_no: u64) -> Vec<XLine> {
        self.ring
            .iter()
            .filter(|(n, _)| *n < start_no)
            .cloned()
            .collect()
    }

    /// A record became the display-primary candidate.
    pub(crate) fn set_primary(&mut self, before: Vec<XLine>, lines: Vec<XLine>) {
        self.before = before;
        // Primary lines are clipped like every other excerpt line.
        self.primary = lines.into_iter().map(|(n, t)| (n, clip(&t))).collect();
        self.after.clear();
        self.collecting_after = true;
    }

    /// Lines already pushed after the primary record (when it closed on a later line).
    pub(crate) fn seed_after(&mut self, from_no: u64) {
        self.after = self
            .ring
            .iter()
            .filter(|(n, _)| *n >= from_no)
            .take(EXCERPT_AFTER)
            .cloned()
            .collect();
    }

    pub(crate) fn finish(self) -> Excerpt {
        let mut segments = vec![];
        let mut last_no = 0u64;
        let mut push = |kind: SegmentKind, lines: Vec<XLine>, last: &mut u64| {
            let lines: Vec<XLine> = lines.into_iter().filter(|(n, _)| *n > *last).collect();
            if let (Some(first), Some(end)) = (lines.first(), lines.last()) {
                *last = end.0;
                segments.push(Segment {
                    kind,
                    first_line: safe(first.0),
                    lines: lines.into_iter().map(|(_, t)| t).collect(),
                });
            }
        };
        push(SegmentKind::BeforePrimary, self.before, &mut last_no);
        push(SegmentKind::Primary, self.primary, &mut last_no);
        push(SegmentKind::AfterPrimary, self.after, &mut last_no);
        push(
            SegmentKind::Tail,
            // The tail is the end of the ring (EXCERPT_TAIL <= EXCERPT_BEFORE).
            self.ring
                .iter()
                .skip(self.ring.len().saturating_sub(EXCERPT_TAIL))
                .cloned()
                .collect(),
            &mut last_no,
        );
        // Budget the serialized form: each line as JSON (escapes included) plus a comma,
        // each segment's own structure, and the envelope.
        let mut truncated = false;
        let mut total = SEGMENT_OVERHEAD;
        for seg in &mut segments {
            total += SEGMENT_OVERHEAD;
            let mut keep = 0;
            for l in &seg.lines {
                let size = json_len(l) + 1;
                if total + size > MAX_EXCERPT_BYTES {
                    truncated = true;
                    break;
                }
                total += size;
                keep += 1;
            }
            seg.lines.truncate(keep);
        }
        segments.retain(|s| !s.lines.is_empty());
        Excerpt {
            segments,
            truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excerpt_segments_do_not_overlap() {
        let mut x = ExcerptState::default();
        for n in 1..=10 {
            x.push(n, &format!("l{n}"));
        }
        x.set_primary(
            x.snapshot_before(5),
            vec![(5, "l5".into()), (6, "l6".into())],
        );
        x.seed_after(7);
        let e = x.finish();
        let kinds: Vec<_> = e
            .segments
            .iter()
            .map(|s| (s.kind, s.first_line.get(), s.lines.len()))
            .collect();
        assert_eq!(
            kinds,
            [
                (SegmentKind::BeforePrimary, 1, 4),
                (SegmentKind::Primary, 5, 2),
                (SegmentKind::AfterPrimary, 7, 4),
            ]
        );
    }
}
