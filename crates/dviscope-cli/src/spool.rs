//! Delivery: the spool is the journal entries without a durable outcome. A
//! flush sends ready entries (dependencies committed) in batches, records outcomes, and
//! leaves everything ambiguous pending for replay. At-least-once delivery, exactly-once
//! server effects (the server answers a replay with the original receipt).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::{Value, json};

use crate::crash;
use crate::journal::{Entry, Journal, Outcome, PayloadError, delivered};

/// Records per batch.
pub const MAX_BATCH: usize = 1_000;

/// One record sent.
#[derive(Debug, Clone)]
pub struct Outgoing {
    /// Journal seq.
    pub seq: u64,
    /// Server identity (idempotency key).
    pub identity: String,
    /// SHA-256 of the canonical body.
    pub digest: String,
    /// Wire body.
    pub body: Value,
}

/// The server's answer for one record.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// Committed (or a replay of a committed record): the receipt.
    Committed(Value),
    /// Rejected: 400, 409, 410.
    Rejected {
        /// HTTP status.
        status: u16,
        /// Error body.
        error: Value,
    },
    /// Back off and retry later (429, 503, 507).
    Retry,
}

/// A batch-level failure.
#[derive(Debug, Clone, PartialEq)]
pub enum BatchError {
    /// 401/403: stop flushing and alert.
    Auth(u16),
    /// Network error, lost or malformed response: ambiguous, replay later.
    Transient(String),
}

/// A receipt endpoint.
pub trait Transport {
    /// Delivers a batch; one response per record, in order.
    ///
    /// # Errors
    /// A batch-level failure.
    fn deliver(&mut self, batch: &[Outgoing]) -> std::result::Result<Vec<Response>, BatchError>;
}

/// Result of a flush.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Committed in this flush.
    pub committed: u64,
    /// Rejected in this flush.
    pub rejected: u64,
    /// Blocked by a dependency in this flush.
    pub blocked: u64,
    /// Still pending after it.
    pub pending: u64,
    /// Corrupt entries (never delivered).
    pub corrupt: Vec<u64>,
    /// Payloads that could not be read now (kept pending, retried by the next flush).
    pub deferred: Vec<String>,
    /// Why the flush stopped early, if it did.
    pub stopped: Option<String>,
}

/// Why an entry's body is not available.
enum BodyError {
    /// Confirmed damage: the entry is rejected locally.
    Damaged(String),
    /// A read that may succeed later: the entry stays pending.
    Retry(String),
}

fn body_of(j: &Journal, e: &Entry) -> std::result::Result<Value, BodyError> {
    if e.payload.is_some() {
        let bytes = j.payload_checked(e).map_err(|err| match err {
            PayloadError::Unreadable(..) => BodyError::Retry(err.to_string()),
            _ => BodyError::Damaged(err.to_string()),
        })?;
        return serde_json::from_slice(&bytes).map_err(|err| BodyError::Damaged(err.to_string()));
    }
    e.record
        .as_ref()
        .and_then(|r| r.get("deliver").cloned())
        .ok_or_else(|| BodyError::Damaged(format!("entry {} has nothing to deliver", e.seq)))
}

/// Flushes the spool once (under the writer lock).
///
/// # Errors
/// I/O, or an authentication failure (401/403) from the transport.
pub fn flush(j: &Journal, t: &mut dyn Transport) -> Result<Summary> {
    let mut sum = Summary::default();
    // A reclaim interrupted by a crash is resumed first.
    j.locked(Journal::reclaim)?;
    loop {
        // Phase 1 (under the writer lock): blocked outcomes, then the next ready batch.
        let batch: Vec<(Entry, Outgoing)> = j.locked(|j| {
            let mut entries: BTreeMap<u64, Entry> = BTreeMap::new();
            sum.corrupt.clear();
            for e in j.entries()? {
                match e {
                    Ok(e) => {
                        entries.insert(e.seq, e);
                    }
                    Err(seq) => sum.corrupt.push(seq),
                }
            }
            loop {
                let outcomes = j.outcomes()?;
                let mut ready = vec![];
                let mut progressed = false;
                for e in entries
                    .values()
                    .filter(|e| delivered(&e.kind) && !outcomes.contains_key(&e.seq))
                {
                    let mut waiting = false;
                    let mut blocked_by = None;
                    for d in &e.depends_on {
                        match (outcomes.get(d), entries.get(d)) {
                            (Some(Outcome::Committed { .. }), _) => {}
                            (Some(_), _) => blocked_by = Some(*d),
                            (None, Some(dep)) if !delivered(&dep.kind) => {}
                            (None, Some(_)) => waiting = true,
                            // A missing or corrupt dependency never commits.
                            (None, None) => blocked_by = Some(*d),
                        }
                    }
                    if let Some(d) = blocked_by {
                        j.record_outcome(e, &Outcome::BlockedByDependency { dependency: d })?;
                        sum.blocked += 1;
                        progressed = true;
                        continue;
                    }
                    if waiting || ready.len() >= MAX_BATCH {
                        continue;
                    }
                    // A missing or corrupt payload is this entry's problem only: it is
                    // rejected locally (its dependents are then blocked), the rest flows.
                    match body_of(j, e).and_then(|body| {
                        let canonical = dviscope_model::canonical::canonical_json(&body)
                            .map_err(|err| BodyError::Damaged(err.to_string()))?;
                        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                            canonical.as_bytes(),
                        ));
                        Ok((body, digest))
                    }) {
                        Ok((body, digest)) => ready.push((
                            e.clone(),
                            Outgoing {
                                seq: e.seq,
                                identity: e
                                    .identity
                                    .clone()
                                    .unwrap_or_else(|| format!("{}:{}", j.id(), e.seq)),
                                digest,
                                body,
                            },
                        )),
                        // Pending: it and its dependents wait for the next flush.
                        Err(BodyError::Retry(why)) => {
                            if !sum.deferred.contains(&why) {
                                sum.deferred.push(why);
                            }
                        }
                        Err(BodyError::Damaged(err)) => {
                            j.record_outcome(
                                e,
                                &Outcome::Rejected {
                                    status: 0,
                                    error: json!({"code": "E_LOCAL_CORRUPT", "message": err}),
                                },
                            )?;
                            sum.rejected += 1;
                            progressed = true;
                        }
                    }
                }
                if !ready.is_empty() || !progressed {
                    return Ok(ready);
                }
            }
        })?;
        if batch.is_empty() {
            break;
        }
        // Phase 2 (no lock): the transport. Launches and supervision are never blocked by it.
        let outgoing: Vec<Outgoing> = batch.iter().map(|(_, o)| o.clone()).collect();
        let responses = match t.deliver(&outgoing) {
            Ok(r) => r,
            Err(BatchError::Auth(status)) => {
                bail!("the server refused the credential ({status}): flushing stopped")
            }
            Err(BatchError::Transient(why)) => {
                sum.stopped = Some(why);
                break;
            }
        };
        if responses.len() != batch.len() {
            // A malformed response is ambiguous: everything stays pending.
            sum.stopped = Some("malformed response".into());
            break;
        }
        // Phase 3 (under the lock): outcomes, only for valid receipts.
        let any = j.locked(|j| {
            let outcomes = j.outcomes()?;
            let mut any = false;
            for ((e, o), r) in batch.iter().zip(responses) {
                if outcomes.contains_key(&e.seq) {
                    continue;
                }
                match r {
                    Response::Committed(receipt) => {
                        if !receipt_matches(&receipt, o) {
                            // Ambiguous: never committed (nor reclaimed) on a receipt that
                            // does not name this record.
                            sum.stopped =
                                Some(format!("receipt for entry {} does not match it", e.seq));
                            continue;
                        }
                        crash::point("after_receipt");
                        j.record_outcome(e, &Outcome::Committed { receipt })?;
                        sum.committed += 1;
                        any = true;
                    }
                    Response::Rejected { status, error } => {
                        j.record_outcome(e, &Outcome::Rejected { status, error })?;
                        sum.rejected += 1;
                        any = true;
                    }
                    Response::Retry => {}
                }
            }
            Ok(any)
        })?;
        if !any {
            sum.stopped
                .get_or_insert_with(|| "server asked to retry later".into());
            break;
        }
    }
    let outcomes = j.outcomes()?;
    sum.pending = j
        .entries()?
        .into_iter()
        .flatten()
        .filter(|e| delivered(&e.kind) && !outcomes.contains_key(&e.seq))
        .count() as u64;
    Ok(sum)
}

/// A receipt must name the record sent: same identity, same digest, revision 1 (the only
/// revision the journal sends in 0.1), and a known result.
/// A receipt authorizes the commit (and the payload's reclaim) only when it is exactly the
/// receipt of the record sent: identity, digest, revision 1 (journal records are first
/// revisions), a commit result, and the server's IDs. Anything else stays pending.
fn receipt_matches(receipt: &Value, o: &Outgoing) -> bool {
    receipt["identity"].as_str() == Some(o.identity.as_str())
        && receipt["digest"].as_str() == Some(o.digest.as_str())
        && receipt["revision"].as_u64() == Some(1)
        && matches!(receipt["result"].as_str(), Some("committed" | "duplicate"))
        && receipt["server_ids"]
            .as_object()
            .is_some_and(|m| !m.is_empty())
}

/// A receipt endpoint backed by a directory: the 2c stand-in for the server. It keeps one
/// effect per identity (exactly-once), answers a replay with the original receipt, and a
/// different payload under the same identity with 409. Deliveries are serialized by a lock
/// file (several journals may share one endpoint), and an effect is durable before it is
/// acknowledged.
#[derive(Debug)]
pub struct DirEndpoint {
    dir: PathBuf,
}

/// A bounded file name for an identity: a readable prefix and a hash of all of it.
fn file_key(identity: &str) -> String {
    identity
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        + "-"
        + &hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(identity.as_bytes())[..12])
}

impl DirEndpoint {
    /// Opens (creates) the endpoint directory.
    ///
    /// # Errors
    /// I/O.
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir.join("effects"))?;
        if !dir.join("lock").exists() {
            fs::File::create(dir.join("lock"))?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Every stored effect: identity → body.
    ///
    /// # Errors
    /// I/O.
    pub fn effects(&self) -> Result<BTreeMap<String, Value>> {
        let mut out = BTreeMap::new();
        for e in fs::read_dir(self.dir.join("effects"))? {
            let path = e?.path();
            if path.extension().is_some_and(|x| x == "json") {
                let v: Value = serde_json::from_slice(&fs::read(path)?)?;
                out.insert(
                    v["identity"].as_str().unwrap_or_default().to_string(),
                    v["body"].clone(),
                );
            }
        }
        Ok(out)
    }

    fn install(&self, path: &Path, v: &Value) -> std::io::Result<()> {
        use std::io::Write as _;
        let tmp = path.with_extension("tmp");
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec(v).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
        drop(f);
        #[cfg(windows)]
        crate::platform::windows::rename_durable(&tmp, path)?;
        #[cfg(not(windows))]
        {
            fs::rename(&tmp, path)?;
            fs::File::open(self.dir.join("effects"))?.sync_all()?;
        }
        Ok(())
    }
}

impl Transport for DirEndpoint {
    fn deliver(&mut self, batch: &[Outgoing]) -> std::result::Result<Vec<Response>, BatchError> {
        let transient = |e: &dyn std::fmt::Display| BatchError::Transient(e.to_string());
        let lock_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join("lock"))
            .map_err(|e| transient(&e))?;
        let mut lock = fd_lock::RwLock::new(lock_file);
        let _guard = lock.write().map_err(|e| transient(&e))?;
        let reject: Vec<String> = fs::read_to_string(self.dir.join("reject.txt"))
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default();
        let mut out = vec![];
        for o in batch {
            if reject.iter().any(|r| r == &o.identity) {
                out.push(Response::Rejected {
                    status: 400,
                    error: json!({"code": "E_INVALID", "message": "rejected by the test endpoint"}),
                });
                continue;
            }
            let path = self
                .dir
                .join("effects")
                .join(file_key(&o.identity) + ".json");
            // Only a missing effect may be created; an effect that exists but cannot be
            // read now is never replaced (the delivery waits).
            let existing = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(transient(&e)),
            };
            if let Some(bytes) = existing {
                let v: Value = serde_json::from_slice(&bytes).map_err(|e| transient(&e))?;
                if v["digest"] == o.digest.as_str() {
                    // A replay: the original receipt, marked as a duplicate.
                    let mut receipt = v["receipt"].clone();
                    receipt["result"] = json!("duplicate");
                    out.push(Response::Committed(receipt));
                } else {
                    out.push(Response::Rejected {
                        status: 409,
                        error: json!({"code": "E_REVISION_CONFLICT"}),
                    });
                }
                continue;
            }
            let n = fs::read_dir(self.dir.join("effects")).map_or(0, Iterator::count) + 1;
            let receipt = json!({"identity": o.identity, "revision": 1, "digest": o.digest,
                "result": "committed", "server_ids": {"record": format!("srv-{n:06}")}});
            let v = json!({"identity": o.identity, "digest": o.digest, "receipt": receipt, "body": o.body});
            self.install(&path, &v).map_err(|e| transient(&e))?;
            // The server committed; the client may die before it reads the response.
            crash::point("after_commit");
            out.push(Response::Committed(receipt));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::kind;

    struct Liar;

    impl Transport for Liar {
        fn deliver(
            &mut self,
            batch: &[Outgoing],
        ) -> std::result::Result<Vec<Response>, BatchError> {
            // A receipt that names another record.
            Ok(batch
                .iter()
                .map(|_| {
                    Response::Committed(
                        json!({"identity": "other", "digest": "x", "result": "committed"}),
                    )
                })
                .collect())
        }
    }

    /// Answers every record with its own identity and digest, patched by `edit`.
    struct Patched(fn(&mut Value));

    impl Transport for Patched {
        fn deliver(
            &mut self,
            batch: &[Outgoing],
        ) -> std::result::Result<Vec<Response>, BatchError> {
            Ok(batch
                .iter()
                .map(|o| {
                    let mut r = json!({"identity": o.identity, "revision": 1, "digest": o.digest,
                        "result": "committed", "server_ids": {"record": "srv-1"}});
                    (self.0)(&mut r);
                    Response::Committed(r)
                })
                .collect())
        }
    }

    #[test]
    fn r2_11_malformed_receipts_commit_nothing() {
        let cases: [fn(&mut Value); 6] = [
            |r| {
                r.as_object_mut().map(|o| o.remove("revision"));
            },
            |r| r["revision"] = json!("wrong"),
            |r| r["revision"] = json!(-1),
            |r| r["revision"] = json!(2),
            |r| {
                r.as_object_mut().map(|o| o.remove("server_ids"));
            },
            |r| r["server_ids"] = json!({}),
        ];
        for (i, edit) in cases.into_iter().enumerate() {
            let dir = std::env::temp_dir().join(format!(
                "dviscope-spool-malformed-{i}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            let j = Journal::create(&dir, "j").unwrap_or_else(|e| panic!("{e}"));
            j.locked(|j| {
                j.append(
                    kind::ENVELOPE,
                    Some("x:1".into()),
                    None,
                    vec![],
                    Some(b"{\"a\":1}"),
                )
            })
            .unwrap_or_else(|e| panic!("{e}"));
            let sum = flush(&j, &mut Patched(edit)).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!((sum.committed, sum.pending), (0, 1), "case {i}");
            assert_eq!(
                fs::read_dir(dir.join("payloads"))
                    .map(Iterator::count)
                    .unwrap_or(0),
                1,
                "case {i}: the payload must stay"
            );
            let _ = fs::remove_dir_all(&dir);
        }
        // The well-formed receipt commits.
        let dir =
            std::env::temp_dir().join(format!("dviscope-spool-wellformed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let j = Journal::create(&dir, "j").unwrap_or_else(|e| panic!("{e}"));
        j.locked(|j| {
            j.append(
                kind::ENVELOPE,
                Some("x:1".into()),
                None,
                vec![],
                Some(b"{}"),
            )
        })
        .unwrap_or_else(|e| panic!("{e}"));
        let sum = flush(&j, &mut Patched(|_| {})).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sum.committed, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Makes `path` unreadable until the returned guard is dropped.
    #[cfg(windows)]
    fn unreadable(path: &Path) -> Option<fs::File> {
        use std::os::windows::fs::OpenOptionsExt as _;
        fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .ok()
    }

    #[cfg(unix)]
    fn unreadable(path: &Path) -> Option<impl Drop> {
        use std::os::unix::fs::PermissionsExt as _;
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o600));
            }
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).ok()?;
        // Root reads anything: the case cannot be produced, the test checks nothing.
        if fs::read(path).is_ok() {
            return None;
        }
        Some(Restore(path.to_path_buf()))
    }

    #[test]
    fn r5_an_unreadable_effect_is_never_replaced() {
        let dir =
            std::env::temp_dir().join(format!("dviscope-ep-unreadable-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut ep = DirEndpoint::new(&dir).unwrap_or_else(|e| panic!("{e}"));
        let rec = |digest: &str| Outgoing {
            seq: 1,
            identity: "x:1".into(),
            digest: digest.into(),
            body: json!({"d": digest}),
        };
        let first = ep
            .deliver(&[rec("aaa")])
            .unwrap_or_else(|e| panic!("{e:?}"));
        let Response::Committed(original) = &first[0] else {
            panic!("{first:?}")
        };
        let path = dir.join("effects").join(file_key("x:1") + ".json");
        let before = fs::read(&path).unwrap_or_default();
        if let Some(guard) = unreadable(&path) {
            // Neither a conflicting delivery nor a replay may replace it while unreadable.
            assert!(matches!(
                ep.deliver(&[rec("bbb")]),
                Err(BatchError::Transient(_))
            ));
            assert!(matches!(
                ep.deliver(&[rec("aaa")]),
                Err(BatchError::Transient(_))
            ));
            drop(guard);
        }
        assert_eq!(
            fs::read(&path).unwrap_or_default(),
            before,
            "the effect is unchanged"
        );
        // Readable again: the original receipt, or a conflict.
        let again = ep
            .deliver(&[rec("aaa")])
            .unwrap_or_else(|e| panic!("{e:?}"));
        let Response::Committed(r) = &again[0] else {
            panic!("{again:?}")
        };
        assert_eq!(r["server_ids"], original["server_ids"]);
        assert_eq!(r["result"], "duplicate");
        let other = ep
            .deliver(&[rec("bbb")])
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(matches!(other[0], Response::Rejected { status: 409, .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_receipt_that_does_not_match_commits_nothing() {
        let dir = std::env::temp_dir().join(format!("dviscope-spool-liar-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let j = Journal::create(&dir, "j").unwrap_or_else(|e| panic!("{e}"));
        j.locked(|j| {
            j.append(
                kind::ENVELOPE,
                Some("x:1".into()),
                None,
                vec![],
                Some(b"{\"a\":1}"),
            )
        })
        .unwrap_or_else(|e| panic!("{e}"));
        let sum = flush(&j, &mut Liar).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((sum.committed, sum.pending), (0, 1));
        assert!(sum.stopped.is_some());
        // The payload is still there.
        assert_eq!(
            fs::read_dir(dir.join("payloads"))
                .map(Iterator::count)
                .unwrap_or(0),
            1
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
