//! Delivery reconciliation:
//! the journal's record identities against the server's receipts, and the journal's
//! started and reported slots against the server's slot counts. Read-only on both sides:
//! it uses the existing entries and envelopes only, and changes nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde_json::{Value, json};

use crate::config::CliConfig;
use crate::journal::{Journal, Outcome, delivered, kind};
use crate::verdict::{Payload, call_api};

/// The most identities per server request (the server's limit).
pub const IDENTITIES_PER_REQUEST: usize = 1000;
/// The most regressions per server request (the server's limit).
pub const REGRESSIONS_PER_REQUEST: usize = 100;

/// What the journal says about one delivered record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Local {
    /// Committed: the server's receipt named this revision and digest.
    Committed {
        /// Receipt revision.
        revision: i64,
        /// Receipt digest.
        digest: String,
    },
    /// Rejected by the server (or locally unusable).
    Rejected,
    /// A dependency was rejected.
    Blocked,
    /// No outcome recorded yet: the digest the server's receipt would carry (SHA-256 of the
    /// record's canonical JSON, as the spool sends it), when the record is readable.
    Undelivered {
        /// Expected receipt digest.
        digest: Option<String>,
    },
}

/// One delivered record of a journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expect {
    /// Journal ID and entry sequence (where it is).
    pub journal: String,
    /// Entry sequence.
    pub seq: u64,
    /// Entry kind.
    pub kind: String,
    /// Receipt identity.
    pub identity: String,
    /// The record's regression, when it names one.
    pub regression: Option<String>,
    /// The record's slot, when it names one.
    pub slot: Option<String>,
    /// Delivery state in the journal.
    pub local: Local,
}

/// The journal at `dir` and every participant journal it registered (a coordinator's
/// reconciliation covers the whole regression).
///
/// # Errors
/// A journal that cannot be opened.
pub fn journals_of(dir: &Path) -> Result<Vec<Journal>> {
    let j = Journal::open(dir).with_context(|| format!("journal {}", dir.display()))?;
    let mut dirs: Vec<PathBuf> = vec![];
    for e in j.intact()? {
        if e.kind == kind::PARTICIPANT
            && let Some(d) = e.record.as_ref().and_then(|r| r["dir"].as_str())
        {
            dirs.push(PathBuf::from(d));
        }
    }
    let mut out = vec![j];
    for d in dirs {
        out.push(
            Journal::open(&d).with_context(|| format!("participant journal {}", d.display()))?,
        );
    }
    Ok(out)
}

/// The delivered records of these journals with their local delivery state.
///
/// # Errors
/// Unreadable entries or payloads.
pub fn expectations(journals: &[Journal]) -> Result<Vec<Expect>> {
    let mut out = vec![];
    for j in journals {
        let outcomes = j.outcomes()?;
        let entries = j.intact()?;
        // The delivered body names its regression and slot: inline under `deliver`, or the
        // payload (as the spool sends it). A committed payload is reclaimed: an envelope
        // then names them through its launch (`record.launch`).
        let body = |e: &crate::journal::Entry| -> Option<Value> {
            if e.payload.is_some() {
                j.payload(e)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            } else {
                e.record.as_ref().and_then(|r| r.get("deliver").cloned())
            }
        };
        let launches: BTreeMap<u64, Value> = entries
            .iter()
            .filter(|e| e.kind == kind::LAUNCH)
            .filter_map(|e| body(e).map(|b| (e.seq, b)))
            .collect();
        for e in &entries {
            if !delivered(&e.kind) {
                continue;
            }
            let Some(identity) = e.identity.clone() else {
                continue;
            };
            let record = body(e).or_else(|| {
                e.record
                    .as_ref()
                    .and_then(|r| r["launch"].as_u64())
                    .and_then(|l| launches.get(&l).cloned())
            });
            let field = |k: &str| {
                record
                    .as_ref()
                    .and_then(|r| r[k].as_str())
                    .map(str::to_string)
            };
            let local = match outcomes.get(&e.seq) {
                Some(Outcome::Committed { receipt }) => Local::Committed {
                    revision: receipt["revision"].as_i64().unwrap_or(0),
                    digest: receipt["digest"].as_str().unwrap_or_default().to_string(),
                },
                Some(Outcome::Rejected { .. }) => Local::Rejected,
                Some(Outcome::BlockedByDependency { .. }) => Local::Blocked,
                None => Local::Undelivered {
                    // This entry's own body only (never its launch's): what was or will be
                    // sent.
                    digest: body(e).and_then(|b| {
                        dviscope_model::canonical::canonical_json(&b).ok().map(|c| {
                            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(c.as_bytes()))
                        })
                    }),
                },
            };
            out.push(Expect {
                journal: j.id().to_string(),
                seq: e.seq,
                kind: e.kind.clone(),
                identity,
                regression: field("regression_ref"),
                slot: field("slot_ref"),
                local,
            });
        }
    }
    Ok(out)
}

/// The server request bodies for these expectations (chunked to the server's limits).
#[must_use]
pub fn requests(exps: &[Expect]) -> Vec<Value> {
    let ids: Vec<&str> = exps
        .iter()
        .map(|e| e.identity.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let regs: Vec<&str> = exps
        .iter()
        .filter_map(|e| e.regression.as_deref())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let n = ids
        .len()
        .div_ceil(IDENTITIES_PER_REQUEST)
        .max(regs.len().div_ceil(REGRESSIONS_PER_REQUEST))
        .max(1);
    (0..n)
        .map(|i| {
            let page = |v: &[&str], per: usize| -> Vec<String> {
                v.iter()
                    .skip(i * per)
                    .take(per)
                    .map(|s| (*s).to_string())
                    .collect()
            };
            json!({"identities": page(&ids, IDENTITIES_PER_REQUEST),
                   "regressions": page(&regs, REGRESSIONS_PER_REQUEST)})
        })
        .collect()
}

/// Merges the server's answers to [`requests`].
#[must_use]
pub fn merge(answers: &[Value]) -> Value {
    let mut receipts = serde_json::Map::new();
    let mut regressions = vec![];
    for a in answers {
        if let Some(m) = a["receipts"].as_object() {
            receipts.extend(m.clone());
        }
        if let Some(r) = a["regressions"].as_array() {
            regressions.extend(r.iter().cloned());
        }
    }
    json!({"receipts": receipts, "regressions": regressions})
}

/// Compares the journal with the server's answer. `ok` is false when a committed record is
/// missing or different on the server, a record was never delivered, or the server counts
/// fewer started or reported slots than the journal committed.
#[must_use]
#[allow(clippy::too_many_lines)] // one pass, then the slot counts
pub fn compare(exps: &[Expect], server: &Value) -> Value {
    let mut lost = vec![];
    let mut conflicts = vec![];
    let mut undelivered = vec![];
    let mut arrived_unrecorded = 0u64;
    let (mut confirmed, mut expired, mut rejected, mut blocked) = (0u64, 0u64, 0u64, 0u64);
    // Per regression: slots with a committed start, and with a committed report.
    let mut started: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut reported: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut created: BTreeSet<&str> = BTreeSet::new();
    let at = |e: &Expect| json!({"journal": e.journal, "seq": e.seq, "kind": e.kind, "identity": e.identity});
    for e in exps {
        let r = &server["receipts"][&e.identity];
        let revisions: Vec<(i64, &str)> = r["revisions"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| {
                        (
                            x["revision"].as_i64().unwrap_or(0),
                            x["digest"].as_str().unwrap_or_default(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let expired_max = r["expired_max_revision"].as_i64();
        match &e.local {
            Local::Committed { revision, digest } => {
                // The server lists a revision's digest, then its aliases (an equivalent body
                // under a later compatible label): any of them confirms the record.
                let alias = revisions.iter().any(|(n, d)| n == revision && d == digest);
                match revisions.iter().find(|(n, _)| n == revision) {
                    Some(_) if alias => confirmed += 1,
                    Some((_, d)) => conflicts.push(json!({
                        "at": at(e), "revision": revision, "journal_digest": digest, "server_digest": d,
                    })),
                    None if expired_max.is_some_and(|m| m >= *revision) => expired += 1,
                    None => lost.push(json!({"at": at(e), "revision": revision})),
                }
                if let Some(reg) = e.regression.as_deref() {
                    if e.kind == kind::REGRESSION_CREATE {
                        created.insert(reg);
                    }
                    if let Some(s) = e.slot.as_deref() {
                        if e.kind == kind::LAUNCH {
                            started.entry(reg).or_default().insert(s);
                        } else if e.kind == kind::ENVELOPE {
                            reported.entry(reg).or_default().insert(s);
                        }
                    }
                }
            }
            Local::Rejected => rejected += 1,
            Local::Blocked => blocked += 1,
            Local::Undelivered { digest } => {
                // Arrived only if the server holds this very record (its digest): another
                // revision of the identity, or a tombstone, proves nothing about it.
                if digest
                    .as_deref()
                    .is_some_and(|d| revisions.iter().any(|(_, x)| *x == d))
                {
                    // Sent, but the outcome was not recorded (an interrupted flush): the next
                    // flush records it as a duplicate.
                    arrived_unrecorded += 1;
                } else {
                    let mut a = at(e);
                    if digest.is_none() {
                        a["unreadable"] = json!(true);
                    }
                    undelivered.push(a);
                }
            }
        }
    }
    let mut slot_problems = vec![];
    let mut regressions = vec![];
    let regs: BTreeSet<&str> = exps
        .iter()
        .filter_map(|e| e.regression.as_deref())
        .collect();
    for reg in regs {
        let s = server["regressions"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["regression_ref"] == reg))
            .cloned()
            .unwrap_or(Value::Null);
        let js = started.get(reg).map_or(0, BTreeSet::len);
        let jr = reported.get(reg).map_or(0, BTreeSet::len);
        let row = json!({"regression_ref": reg, "journal_slots_started": js,
                         "journal_slots_reported": jr, "server": s});
        if s["expired"] == true {
            // Past retention: nothing to compare.
        } else if s["found"] != true {
            if created.contains(reg) || js > 0 || jr > 0 {
                slot_problems.push(
                    json!({"regression_ref": reg, "problem": "the server has no such regression"}),
                );
            }
        } else {
            let ss = usize::try_from(s["slots_started"].as_i64().unwrap_or(0)).unwrap_or(0);
            let sr = usize::try_from(s["slots_reported"].as_i64().unwrap_or(0)).unwrap_or(0);
            if ss < js {
                slot_problems.push(
                    json!({"regression_ref": reg, "problem": "fewer started slots on the server",
                                          "journal": js, "server": ss}),
                );
            }
            if sr < jr {
                slot_problems.push(
                    json!({"regression_ref": reg, "problem": "fewer reported slots on the server",
                                          "journal": jr, "server": sr}),
                );
            }
        }
        regressions.push(row);
    }
    let ok = lost.is_empty()
        && conflicts.is_empty()
        && undelivered.is_empty()
        && slot_problems.is_empty();
    json!({
        "ok": ok,
        "records": exps.len(),
        "confirmed": confirmed,
        "expired": expired,
        "rejected": rejected,
        "blocked": blocked,
        "arrived_unrecorded": arrived_unrecorded,
        "lost": lost,
        "conflicts": conflicts,
        "undelivered": undelivered,
        "slot_problems": slot_problems,
        "regressions": regressions,
    })
}

/// Reconciles the journal at `dir` (and its participants) with the server.
///
/// # Errors
/// `(exit code, message)`: an unreadable journal (2) or the server's answer (3, 4, 5).
pub async fn run(cfg: &CliConfig, dir: &Path) -> Result<Value, (u8, String)> {
    let journals = journals_of(dir).map_err(|e| (2, format!("{e:#}")))?;
    let exps = expectations(&journals).map_err(|e| (2, format!("{e:#}")))?;
    let mut answers = vec![];
    for body in requests(&exps) {
        answers.push(
            call_api(
                cfg,
                reqwest::Method::POST,
                &["reconcile"],
                &[],
                Payload::Json(&body),
            )
            .await?,
        );
    }
    let mut report = compare(&exps, &merge(&answers));
    report["journals"] = json!(journals.iter().map(Journal::id).collect::<Vec<_>>());
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exp(seq: u64, kind: &str, id: &str, slot: Option<&str>, local: Local) -> Expect {
        Expect {
            journal: "j".into(),
            seq,
            kind: kind.into(),
            identity: id.into(),
            regression: Some("r1".into()),
            slot: slot.map(str::to_string),
            local,
        }
    }

    fn committed(rev: i64, d: &str) -> Local {
        Local::Committed {
            revision: rev,
            digest: d.into(),
        }
    }

    /// A revision's aliases (an equivalent body under a later compatible
    /// label) confirm the record as its own digest does; anything else is a conflict naming
    /// the original digest.
    #[test]
    fn an_alias_confirms_a_record() {
        let server = json!({"receipts": {"source_manifest:sm1": {"revisions": [
            {"revision": 1, "digest": "old"}, {"revision": 1, "digest": "new"}],
            "expired_max_revision": null}}, "regressions": []});
        for (d, confirmed) in [("old", 1), ("new", 1), ("other", 0)] {
            let exps = [exp(
                1,
                "source_manifest",
                "source_manifest:sm1",
                None,
                committed(1, d),
            )];
            let r = compare(&exps, &server);
            assert_eq!(r["confirmed"], confirmed, "{d}: {r}");
            if confirmed == 0 {
                assert_eq!(r["conflicts"][0]["server_digest"], "old", "{r}");
            }
        }
    }

    #[test]
    fn every_disagreement_is_named() {
        let exps = [
            exp(
                1,
                kind::REGRESSION_CREATE,
                "regression:r1",
                None,
                committed(1, "a"),
            ),
            exp(
                2,
                kind::LAUNCH,
                "attempt_started:a1",
                Some("s1"),
                committed(1, "b"),
            ),
            exp(
                3,
                kind::ENVELOPE,
                "report:a1",
                Some("s1"),
                committed(2, "c"),
            ),
            exp(
                4,
                kind::LAUNCH,
                "attempt_started:a2",
                Some("s2"),
                committed(1, "d"),
            ),
            exp(
                5,
                kind::ENVELOPE,
                "report:a2",
                Some("s2"),
                Local::Undelivered {
                    digest: Some("f".into()),
                },
            ),
            exp(
                6,
                kind::LAUNCH,
                "attempt_started:a3",
                Some("s3"),
                Local::Undelivered {
                    digest: Some("g".into()),
                },
            ),
            exp(7, kind::ENVELOPE, "report:a9", Some("s9"), Local::Rejected),
            exp(
                8,
                kind::LAUNCH,
                "attempt_started:a8",
                Some("s8"),
                committed(1, "e"),
            ),
        ];
        let server = json!({
            "receipts": {
                "regression:r1": {"revisions": [{"revision": 1, "digest": "a"}], "expired_max_revision": null},
                "attempt_started:a1": {"revisions": [{"revision": 1, "digest": "b"}], "expired_max_revision": null},
                // Revision 2 never arrived (only revision 1).
                "report:a1": {"revisions": [{"revision": 1, "digest": "x"}], "expired_max_revision": null},
                // Another content under the same revision.
                "attempt_started:a2": {"revisions": [{"revision": 1, "digest": "other"}], "expired_max_revision": null},
                // Arrived, outcome not recorded.
                "report:a2": {"revisions": [{"revision": 1, "digest": "f"}], "expired_max_revision": null},
                // Past the deduplication horizon.
                "attempt_started:a8": {"revisions": [], "expired_max_revision": 3},
            },
            "regressions": [{"regression_ref": "r1", "found": true, "expired": false,
                             "state": "open", "slots": 3, "slots_started": 1, "slots_reported": 0}],
        });
        let r = compare(&exps, &server);
        assert_eq!(r["ok"], false);
        assert_eq!(r["confirmed"], 2, "{r}");
        assert_eq!(r["expired"], 1, "{r}");
        assert_eq!(r["rejected"], 1, "{r}");
        assert_eq!(r["arrived_unrecorded"], 1, "{r}");
        assert_eq!(r["lost"][0]["at"]["identity"], "report:a1", "{r}");
        assert_eq!(
            r["conflicts"][0]["at"]["identity"], "attempt_started:a2",
            "{r}"
        );
        assert_eq!(r["undelivered"][0]["identity"], "attempt_started:a3", "{r}");
        // The journal committed starts of s1, s2, s8 (3) and the report of s1 (1).
        let p = r["slot_problems"].to_string();
        assert!(
            p.contains("fewer started slots") && p.contains("fewer reported slots"),
            "{r}"
        );
    }

    /// An undelivered correction is not confirmed by an older revision of its identity, nor
    /// by a tombstone; an unreadable one is unresolved.
    #[test]
    fn undelivered_corrections_need_their_own_receipt() {
        let exps = [
            exp(
                1,
                kind::ENVELOPE,
                "report:a1",
                Some("s1"),
                Local::Undelivered {
                    digest: Some("rev2".into()),
                },
            ),
            exp(
                2,
                kind::ENVELOPE,
                "report:a2",
                Some("s2"),
                Local::Undelivered {
                    digest: Some("new".into()),
                },
            ),
            exp(
                3,
                kind::ENVELOPE,
                "report:a3",
                Some("s3"),
                Local::Undelivered { digest: None },
            ),
        ];
        let server = json!({
            "receipts": {
                "report:a1": {"revisions": [{"revision": 1, "digest": "rev1"}], "expired_max_revision": null},
                "report:a2": {"revisions": [], "expired_max_revision": 4},
                "report:a3": {"revisions": [{"revision": 1, "digest": "x"}], "expired_max_revision": null},
            },
            "regressions": [],
        });
        let r = compare(&exps, &server);
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(r["arrived_unrecorded"], 0, "{r}");
        assert_eq!(r["undelivered"].as_array().map(Vec::len), Some(3), "{r}");
        assert_eq!(r["undelivered"][2]["unreadable"], true, "{r}");
    }

    #[test]
    fn agreement_is_ok_and_expired_regressions_are_not_compared() {
        let exps = [
            exp(
                1,
                kind::REGRESSION_CREATE,
                "regression:r1",
                None,
                committed(1, "a"),
            ),
            exp(
                2,
                kind::LAUNCH,
                "attempt_started:a1",
                Some("s1"),
                committed(1, "b"),
            ),
        ];
        let mut server = json!({
            "receipts": {
                "regression:r1": {"revisions": [{"revision": 1, "digest": "a"}], "expired_max_revision": null},
                "attempt_started:a1": {"revisions": [{"revision": 1, "digest": "b"}], "expired_max_revision": null},
            },
            "regressions": [{"regression_ref": "r1", "found": true, "expired": false,
                             "state": "open", "slots": 1, "slots_started": 1, "slots_reported": 0}],
        });
        assert_eq!(compare(&exps, &server)["ok"], true);
        server["regressions"] = json!([{"regression_ref": "r1", "found": false, "expired": false}]);
        assert_eq!(compare(&exps, &server)["ok"], false);
        server["regressions"] = json!([{"regression_ref": "r1", "found": false, "expired": true}]);
        assert_eq!(compare(&exps, &server)["ok"], true);
    }

    #[test]
    fn requests_respect_the_server_limits() {
        let exps: Vec<Expect> = (0..2500)
            .map(|i| {
                exp(
                    i,
                    kind::LAUNCH,
                    &format!("attempt_started:a{i}"),
                    Some("s"),
                    Local::Undelivered { digest: None },
                )
            })
            .collect();
        let r = requests(&exps);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0]["identities"].as_array().map(Vec::len), Some(1000));
        assert_eq!(r[2]["identities"].as_array().map(Vec::len), Some(500));
        assert_eq!(r[0]["regressions"], json!(["r1"]));
        assert_eq!(r[1]["regressions"], json!([]));
        assert_eq!(requests(&[]).len(), 1);
    }
}
