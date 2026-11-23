//! The delivery journal (`docs/journal.md`): immutable entries written durably before the
//! operation they describe, delivery outcomes appended later, recovery, closure.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use dviscope_model::canonical::{Digest, canonical_json};
use dviscope_model::schema::JOURNAL;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::crash;

/// Entry kinds.
pub mod kind {
    /// Regression creation.
    pub const REGRESSION_CREATE: &str = "regression_create";
    /// Manifest chunk.
    pub const MANIFEST_CHUNK: &str = "manifest_chunk";
    /// Seal.
    pub const MANIFEST_SEAL: &str = "manifest_seal";
    /// Source manifest.
    pub const SOURCE_MANIFEST: &str = "source_manifest";
    /// Manifest amendment.
    pub const MANIFEST_AMEND: &str = "manifest_amend";
    /// Slot marks (cancelled or skipped).
    pub const SLOT_MARK: &str = "slot_mark";
    /// Attempt identity before the child starts (delivered as `attempt_started`).
    pub const LAUNCH: &str = "launch";
    /// Child identity after the spawn (not delivered).
    pub const CHILD: &str = "child";
    /// Runner facts after the child ended (not delivered; merged into the envelope).
    pub const RUNNER_RESULT: &str = "runner_result";
    /// Simulation attempt record with its evidence.
    pub const ENVELOPE: &str = "envelope";
    /// Launch closure with its watermark (not delivered).
    pub const CLOSURE: &str = "closure";
    /// Regression finish.
    pub const FINISH: &str = "finish";
    /// Build attempt identity before the build starts (delivered as `build_started`).
    pub const BUILD_LAUNCH: &str = "build_launch";
    /// A journal registered with this coordinator for the regression (not delivered).
    pub const PARTICIPANT: &str = "participant";
}

/// Whether an entry kind launches a process (closures and the finish barrier cover both).
#[must_use]
pub fn is_launch(k: &str) -> bool {
    k == kind::LAUNCH || k == kind::BUILD_LAUNCH
}

/// Kinds that are delivered to the server.
#[must_use]
pub fn delivered(k: &str) -> bool {
    !matches!(
        k,
        kind::CHILD | kind::RUNNER_RESULT | kind::CLOSURE | kind::PARTICIPANT
    )
}

/// Why a payload could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// The payload file is gone (confirmed).
    #[error("payload of entry {0} is missing")]
    Missing(u64),
    /// The payload does not match its recorded hash (confirmed).
    #[error("payload of entry {0} is corrupt")]
    Corrupt(u64),
    /// The read failed in a way that may pass (sharing violation, I/O error).
    #[error("payload of entry {0} cannot be read now: {1}")]
    Unreadable(u64, String),
}

/// A payload stored beside its entry (reclaimable after commit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadRef {
    /// File name in `payloads/`.
    pub file: String,
    /// SHA-256 (hex) of the bytes.
    pub sha256: String,
    /// Size.
    pub bytes: u64,
}

/// One immutable entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// `dviscope.journal/1.0-dev.N`.
    pub schema: String,
    /// Journal ID.
    pub journal_id: String,
    /// Sequence number.
    pub seq: u64,
    /// Kind.
    pub kind: String,
    /// Record identity at the server (idempotency key), for delivered kinds.
    #[serde(default)]
    pub identity: Option<String>,
    /// Inline record or facts.
    #[serde(default)]
    pub record: Option<Value>,
    /// Entries that must be committed first.
    #[serde(default)]
    pub depends_on: Vec<u64>,
    /// Large payload (the record, when not inline).
    #[serde(default)]
    pub payload: Option<PayloadRef>,
    /// Creation time (UTC, RFC 3339).
    pub created_at: String,
    /// `sha256:` of the canonical JSON of the entry without this field.
    #[serde(default)]
    pub checksum: String,
}

impl Entry {
    fn compute_checksum(&self) -> Result<String> {
        let mut v = serde_json::to_value(self)?;
        if let Some(o) = v.as_object_mut() {
            o.remove("checksum");
        }
        Ok(Digest::of_bytes(canonical_json(&v)?.as_bytes()).to_string())
    }

    /// Whether the stored checksum verifies.
    #[must_use]
    pub fn verifies(&self) -> bool {
        self.compute_checksum().is_ok_and(|c| c == self.checksum)
    }
}

/// A delivery outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    /// Committed by the server.
    Committed {
        /// The server receipt.
        receipt: Value,
    },
    /// Rejected by the server.
    Rejected {
        /// HTTP status.
        status: u16,
        /// Error body.
        error: Value,
    },
    /// A dependency was rejected or blocked.
    BlockedByDependency {
        /// The dependency.
        dependency: u64,
    },
}

/// A journal directory.
#[derive(Debug, Clone)]
pub struct Journal {
    dir: PathBuf,
    id: String,
}

fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn name(seq: u64) -> String {
    format!("{seq:08}.json")
}

/// Writes a file durably: exclusive temp file, flush, fsync, rename into place
/// (write-through on Windows; directory fsync on Linux).
fn write_durable(dir: &Path, sub: &str, file: &str, bytes: &[u8], point: &str) -> Result<()> {
    let tmp = dir.join("tmp").join(format!("{sub}-{file}.tmp"));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    crash::point(&format!("before_rename:{point}"));
    let dest = dir.join(sub).join(file);
    #[cfg(windows)]
    crate::platform::windows::rename_durable(&tmp, &dest)?;
    #[cfg(not(windows))]
    {
        fs::rename(&tmp, &dest)?;
        File::open(dir.join(sub))?.sync_all()?;
    }
    crash::point(&format!("after_rename:{point}"));
    Ok(())
}

/// Refuses state locations the plan does not support (network and cross-OS paths).
///
/// # Errors
/// The location is not supported.
pub fn supported_location(dir: &Path) -> Result<()> {
    let s = dir
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if s.starts_with("/mnt/")
        || s.starts_with("//")
        || s.contains("wsl.localhost")
        || s.contains("wsl$")
    {
        bail!(
            "journal location {} is not supported (local disk only)",
            dir.display()
        );
    }
    Ok(())
}

impl Journal {
    /// Creates a journal (fails if it exists).
    ///
    /// # Errors
    /// I/O, unsupported location, or an existing journal.
    pub fn create(dir: &Path, id: &str) -> Result<Self> {
        Self::create_with(dir, id, None)
    }

    /// Creates a journal; with a coordinator, the journal is a **dormant participant**: it
    /// refuses launches until [`Journal::activate`] records its registration. The order is
    /// create → register with the coordinator → activate, so a coordinator's finish either
    /// sees the participant (and waits for its closure) or refuses the registration.
    ///
    /// # Errors
    /// I/O, unsupported location, or an existing journal.
    pub fn create_with(dir: &Path, id: &str, coordinator: Option<&str>) -> Result<Self> {
        supported_location(dir)?;
        if dir.exists() {
            bail!(
                "{} already exists (a journal is created in a new directory)",
                dir.display()
            );
        }
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent)?;
        }
        // Owner-only from the first byte; everything inside inherits it.
        crate::platform::create_private_dir(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        for sub in ["entries", "payloads", "outcomes", "tmp"] {
            crate::platform::create_private_dir(&dir.join(sub))?;
        }
        File::create(dir.join("lock"))?;
        let j = Self {
            dir: dir.to_path_buf(),
            id: id.to_string(),
        };
        let mut header = json!({"schema": JOURNAL, "journal_id": id, "created_at": now()});
        if let Some(c) = coordinator {
            header["coordinator_id"] = json!(c);
        }
        write_durable(
            dir,
            ".",
            "journal.json",
            &serde_json::to_vec_pretty(&header)?,
            "header",
        )?;
        Ok(j)
    }

    /// Records that this participant is registered with its coordinator (durable, under
    /// this journal's writer lock, so opening the journal never removes the write in
    /// progress). Call only after the coordinator's `participant` entry is written.
    /// Idempotent.
    ///
    /// # Errors
    /// I/O.
    pub fn activate(&self) -> Result<()> {
        self.locked(|j| {
            if j.dir.join("registered").exists() {
                return Ok(());
            }
            write_durable(&j.dir, ".", "registered", b"registered\n", "registered")
        })
    }

    /// The coordinator ID a participant was created for (`None` for a coordinator or a
    /// standalone journal).
    ///
    /// # Errors
    /// I/O or an unreadable header.
    pub fn coordinator_id(&self) -> Result<Option<String>> {
        let header: Value = serde_json::from_slice(&fs::read(self.dir.join("journal.json"))?)?;
        Ok(header["coordinator_id"].as_str().map(str::to_string))
    }

    /// Whether this journal may launch: a participant only once it is registered.
    ///
    /// # Errors
    /// An unregistered participant, or I/O.
    pub fn check_may_launch(&self) -> Result<()> {
        let header: Value = serde_json::from_slice(&fs::read(self.dir.join("journal.json"))?)?;
        if let Some(c) = header["coordinator_id"].as_str()
            && !self.dir.join("registered").exists()
        {
            bail!(
                "journal {} is not registered with its coordinator {c} yet (re-run `journal init` or close it)",
                self.id
            );
        }
        Ok(())
    }

    /// Opens a journal; removes interrupted temp files (under the lock).
    ///
    /// # Errors
    /// I/O or a missing header.
    pub fn open(dir: &Path) -> Result<Self> {
        supported_location(dir)?;
        crate::platform::check_private(dir)
            .with_context(|| format!("journal {} is not private", dir.display()))?;
        let header: Value = serde_json::from_slice(
            &fs::read(dir.join("journal.json"))
                .with_context(|| format!("no journal in {}", dir.display()))?,
        )?;
        if header["schema"] != JOURNAL {
            bail!("journal schema {} is not {JOURNAL}", header["schema"]);
        }
        let j = Self {
            dir: dir.to_path_buf(),
            id: header["journal_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        };
        j.locked(|_| {
            for e in fs::read_dir(dir.join("tmp"))? {
                let _ = fs::remove_file(e?.path());
            }
            Ok(())
        })?;
        Ok(j)
    }

    /// Journal ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Runs `f` under the writer lock (released on process death).
    ///
    /// # Errors
    /// Lock or `f` errors.
    pub fn locked<R>(&self, f: impl FnOnce(&Self) -> Result<R>) -> Result<R> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join("lock"))?;
        let mut lock = fd_lock::RwLock::new(file);
        let _guard = lock.write().context("journal writer lock")?;
        f(self)
    }

    fn seqs(&self, sub: &str) -> Result<BTreeSet<u64>> {
        let mut out = BTreeSet::new();
        for e in fs::read_dir(self.dir.join(sub))? {
            let n = e?.file_name().to_string_lossy().into_owned();
            if let Some(s) = n.strip_suffix(".json").and_then(|s| s.parse::<u64>().ok()) {
                out.insert(s);
            }
        }
        Ok(out)
    }

    /// Appends an entry (call under [`Journal::locked`]). Returns its seq.
    ///
    /// # Errors
    /// I/O.
    pub fn append(
        &self,
        kind: &str,
        identity: Option<String>,
        record: Option<Value>,
        depends_on: Vec<u64>,
        payload: Option<&[u8]>,
    ) -> Result<u64> {
        let seq = self.seqs("entries")?.last().copied().unwrap_or(0) + 1;
        let payload = match payload {
            Some(bytes) => {
                let file = name(seq);
                write_durable(
                    &self.dir,
                    "payloads",
                    &file,
                    bytes,
                    &format!("payload:{kind}"),
                )?;
                Some(PayloadRef {
                    file,
                    sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes)),
                    bytes: bytes.len() as u64,
                })
            }
            None => None,
        };
        let mut e = Entry {
            schema: JOURNAL.to_string(),
            journal_id: self.id.clone(),
            seq,
            kind: kind.to_string(),
            identity,
            record,
            depends_on,
            payload,
            created_at: now(),
            checksum: String::new(),
        };
        e.checksum = e.compute_checksum()?;
        write_durable(
            &self.dir,
            "entries",
            &name(seq),
            &serde_json::to_vec_pretty(&e)?,
            kind,
        )?;
        Ok(seq)
    }

    /// Every entry, in order; corrupt ones are reported as `Err` items.
    ///
    /// # Errors
    /// I/O.
    pub fn entries(&self) -> Result<Vec<std::result::Result<Entry, u64>>> {
        let mut out = vec![];
        for seq in self.seqs("entries")? {
            let bytes = match fs::read(self.dir.join("entries").join(name(seq))) {
                Ok(b) => Some(b),
                // Listed, then gone: damage.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                // A sharing violation or I/O error may pass: the whole operation fails and
                // records nothing (never a corrupt verdict that would block dependents).
                Err(e) => bail!("entry {seq} cannot be read now ({e}); retry later"),
            };
            let parsed = bytes
                .and_then(|b| serde_json::from_slice::<Entry>(&b).ok())
                .filter(|e| e.seq == seq && e.verifies());
            out.push(parsed.ok_or(seq));
        }
        Ok(out)
    }

    /// Every entry, failing when any is corrupt: lifecycle operations (sequence allocation,
    /// closure, finish, recovery) never treat a corrupt entry as absent.
    ///
    /// # Errors
    /// I/O, or corrupt entries (named).
    pub fn intact(&self) -> Result<Vec<Entry>> {
        let mut out = vec![];
        let mut corrupt = vec![];
        for e in self.entries()? {
            match e {
                Ok(e) => out.push(e),
                Err(seq) => corrupt.push(seq),
            }
        }
        if !corrupt.is_empty() {
            bail!("journal has corrupt entries {corrupt:?}: see `dviscope journal status`");
        }
        Ok(out)
    }

    /// Deletes the payloads of committed entries that are still on disk (a reclaim
    /// interrupted by a crash is resumed).
    ///
    /// # Errors
    /// I/O.
    pub fn reclaim(&self) -> Result<u64> {
        let outcomes = self.outcomes()?;
        let entries: Vec<Entry> = self.entries()?.into_iter().flatten().collect();
        // A manifest chunk is kept until its regression's seal is journalled (the seal reads
        // every chunk to compute its digest).
        let sealed: std::collections::BTreeSet<String> = entries
            .iter()
            .filter(|e| e.kind == kind::MANIFEST_SEAL)
            .filter_map(|e| {
                e.identity
                    .as_deref()
                    .and_then(|i| i.strip_prefix("manifest_seal:"))
                    .map(str::to_string)
            })
            .collect();
        let mut n = 0;
        for e in entries {
            if e.kind == kind::MANIFEST_CHUNK {
                let regression = e
                    .identity
                    .as_deref()
                    .and_then(|i| i.strip_prefix("manifest_chunk:"))
                    .and_then(|r| r.rsplit_once('/'))
                    .filter(|(_, n)| n.parse::<u32>().is_ok())
                    .map(|(r, _)| r.to_string());
                if !regression.is_some_and(|r| sealed.contains(&r)) {
                    continue;
                }
            }
            if let (Some(Outcome::Committed { .. }), Some(p)) = (outcomes.get(&e.seq), &e.payload) {
                let path = self.dir.join("payloads").join(&p.file);
                if path.exists() {
                    fs::remove_file(path)?;
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    /// The journal directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The payload of an entry, verified.
    ///
    /// # Errors
    /// Missing (reclaimed) or corrupt payload.
    pub fn payload(&self, e: &Entry) -> Result<Vec<u8>> {
        Ok(self.payload_checked(e)?)
    }

    /// Reads and verifies an entry's payload, telling confirmed damage (missing file, hash
    /// mismatch) from a read that may succeed later (sharing violation, I/O error).
    ///
    /// # Errors
    /// See [`PayloadError`].
    pub fn payload_checked(&self, e: &Entry) -> std::result::Result<Vec<u8>, PayloadError> {
        let p = e.payload.as_ref().ok_or(PayloadError::Missing(e.seq))?;
        let bytes = match fs::read(self.dir.join("payloads").join(&p.file)) {
            Ok(b) => b,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(PayloadError::Missing(e.seq));
            }
            Err(err) => return Err(PayloadError::Unreadable(e.seq, err.to_string())),
        };
        if hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)) != p.sha256 {
            return Err(PayloadError::Corrupt(e.seq));
        }
        Ok(bytes)
    }

    /// Delivery outcomes by seq.
    ///
    /// # Errors
    /// I/O or unreadable outcome files.
    pub fn outcomes(&self) -> Result<BTreeMap<u64, Outcome>> {
        let mut out = BTreeMap::new();
        for seq in self.seqs("outcomes")? {
            let o: Outcome =
                serde_json::from_slice(&fs::read(self.dir.join("outcomes").join(name(seq)))?)?;
            out.insert(seq, o);
        }
        Ok(out)
    }

    /// Records a delivery outcome (call under the lock); a committed payload is reclaimed
    /// only after the outcome is durable.
    ///
    /// # Errors
    /// I/O.
    pub fn record_outcome(&self, e: &Entry, o: &Outcome) -> Result<()> {
        if self.dir.join("outcomes").join(name(e.seq)).exists() {
            return Ok(());
        }
        let mut v = serde_json::to_value(o)?;
        if let Some(m) = v.as_object_mut() {
            m.insert("seq".into(), json!(e.seq));
            m.insert("at".into(), json!(now()));
        }
        write_durable(
            &self.dir,
            "outcomes",
            &name(e.seq),
            &serde_json::to_vec_pretty(&v)?,
            "outcome",
        )?;
        if matches!(o, Outcome::Committed { .. }) {
            // A manifest chunk's payload is kept until its regression's seal is journalled:
            // the seal reads every chunk, and a flush may commit chunks before the seal is
            // written. The reclaim sweep removes it after the seal.
            if e.kind != kind::MANIFEST_CHUNK
                && let Some(p) = &e.payload
            {
                let _ = fs::remove_file(self.dir.join("payloads").join(&p.file));
            }
        }
        Ok(())
    }

    /// The `attempt_seq` to use for a new launch of `slot` (call under the lock).
    ///
    /// # Errors
    /// I/O.
    pub fn next_attempt_seq(&self, slot: &str) -> Result<u32> {
        let mut max = 0u32;
        for e in self.intact()? {
            if e.kind == kind::LAUNCH
                && let Some(r) = &e.record
                && r["slot_ref"] == slot
            {
                max = max
                    .max(u32::try_from(r["attempt_seq"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX));
            }
        }
        Ok(max + 1)
    }

    /// Whether launches are closed (a closure or finish entry exists).
    ///
    /// # Errors
    /// I/O.
    pub fn closed(&self) -> Result<bool> {
        Ok(self
            .intact()?
            .iter()
            .any(|e| e.kind == kind::CLOSURE || e.kind == kind::FINISH))
    }

    /// Closes launches and returns the watermark (call under the lock; idempotent).
    ///
    /// # Errors
    /// I/O.
    pub fn close(&self) -> Result<u64> {
        let entries: Vec<Entry> = self.intact()?;
        if let Some(c) = entries.iter().find(|e| e.kind == kind::CLOSURE) {
            return Ok(c
                .record
                .as_ref()
                .and_then(|r| r["watermark"].as_u64())
                .unwrap_or(0));
        }
        let watermark = entries
            .iter()
            .filter(|e| is_launch(&e.kind))
            .map(|e| e.seq)
            .max()
            .unwrap_or(0);
        self.append(
            kind::CLOSURE,
            None,
            Some(json!({"watermark": watermark})),
            vec![],
            None,
        )?;
        Ok(watermark)
    }

    /// Registers a participating journal with this coordinator (call under this journal's
    /// lock), before the participant exists: a journal can only launch once it is
    /// registered, so the finish barrier always knows every participant.
    ///
    /// # Errors
    /// A finished coordinator, a duplicate ID, or I/O.
    pub fn register(&self, dir: &Path, id: &str) -> Result<u64> {
        let entries = self.intact()?;
        // Resuming an interrupted initialization: the same participant at the same place
        // is already registered.
        let abs = std::path::absolute(dir)?;
        if let Some(e) = entries.iter().find(|e| {
            e.kind == kind::PARTICIPANT
                && e.record.as_ref().is_some_and(|r| {
                    r["journal_id"] == id && r["dir"] == abs.to_string_lossy().as_ref()
                })
        }) {
            return Ok(e.seq);
        }
        if entries.iter().any(|e| e.kind == kind::FINISH) {
            bail!("journal {} is finished: no participant can join", self.id);
        }
        if id == self.id
            || entries.iter().any(|e| {
                e.kind == kind::PARTICIPANT
                    && e.record.as_ref().is_some_and(|r| r["journal_id"] == id)
            })
        {
            bail!("journal ID {id} is already part of this regression");
        }
        self.append(
            kind::PARTICIPANT,
            None,
            Some(json!({"journal_id": id, "dir": abs.to_string_lossy()})),
            vec![],
            None,
        )
    }

    /// The guarded finish (docs/journal.md "finish barrier"): every registered participant
    /// and this journal have closed their launches (simulation and build), and every launch
    /// up to each watermark has a committed start. Then the finish entry is written (it
    /// closes this journal for good). `extra` participants given on the command line must
    /// be registered ones. Call under this journal's lock.
    ///
    /// # Errors
    /// A participant not closed or not registered, a start not committed, corrupt entries,
    /// or I/O.
    pub fn finish(&self, extra: &[Journal], record: Value) -> Result<u64> {
        let mine = self.intact()?;
        if mine.iter().any(|e| e.kind == kind::FINISH) {
            bail!("journal {} is already finished", self.id);
        }
        let registered: Vec<(String, PathBuf)> = mine
            .iter()
            .filter(|e| e.kind == kind::PARTICIPANT)
            .filter_map(|e| e.record.as_ref())
            .map(|r| {
                (
                    r["journal_id"].as_str().unwrap_or_default().to_string(),
                    PathBuf::from(r["dir"].as_str().unwrap_or_default()),
                )
            })
            .collect();
        for x in extra {
            if x.dir != self.dir && !registered.iter().any(|(id, _)| *id == x.id) {
                bail!(
                    "journal {} is not registered with this coordinator (`journal init --coordinator`)",
                    x.id
                );
            }
        }
        let mut acks = vec![];
        let mut all: Vec<Journal> = vec![Journal {
            dir: self.dir.clone(),
            id: self.id.clone(),
        }];
        for (id, dir) in &registered {
            // Participants exist before they register: a missing one is never presumed
            // empty.
            let j = Journal::open(dir).with_context(|| {
                format!(
                    "registered participant {id} cannot be opened at {}",
                    dir.display()
                )
            })?;
            if j.id != *id {
                bail!(
                    "{} holds journal {}, not the registered {id}",
                    dir.display(),
                    j.id
                );
            }
            all.push(j);
        }
        for j in &all {
            let entries = j.intact()?;
            let launches: Vec<&Entry> = entries.iter().filter(|e| is_launch(&e.kind)).collect();
            let closure = entries.iter().find(|e| e.kind == kind::CLOSURE);
            let watermark = match closure {
                Some(c) => c
                    .record
                    .as_ref()
                    .and_then(|r| r["watermark"].as_u64())
                    .unwrap_or(0),
                None if launches.is_empty() && j.dir == self.dir => 0,
                None => bail!(
                    "journal {} has not closed its launches (`dviscope journal close`)",
                    j.id
                ),
            };
            let outcomes = j.outcomes()?;
            for l in launches.iter().filter(|l| l.seq <= watermark) {
                if !matches!(outcomes.get(&l.seq), Some(Outcome::Committed { .. })) {
                    bail!(
                        "journal {}: the start of launch {} is not committed yet (flush first)",
                        j.id,
                        l.seq
                    );
                }
            }
            if launches.iter().any(|l| l.seq > watermark) {
                bail!("journal {} launched after its closure", j.id);
            }
            acks.push(json!({"journal_id": j.id, "watermark": watermark}));
        }
        let mut rec = record;
        if let Some(o) = rec.as_object_mut() {
            o.insert("participants".into(), Value::Array(acks));
        }
        let identity = rec["deliver"]["regression_ref"]
            .as_str()
            .map(|r| format!("finish:{r}"));
        self.append(kind::FINISH, identity, Some(rec), vec![], None)
    }

    /// Recovery (call under the lock): every launch without runner facts whose child and
    /// supervisor are provably gone gets termination `unknown`. Launches left alone are
    /// returned: live ones (a running child or supervisor, or a child that could not be
    /// reaped), and unverifiable ones (a record without a start identity, so a reused
    /// process ID could not be told apart; never presumed alive or dead).
    ///
    /// # Errors
    /// I/O.
    pub fn recover(&self) -> Result<Recovery> {
        let entries: Vec<Entry> = self.intact()?;
        let mut out = Recovery::default();
        for launch in entries.iter().filter(|e| is_launch(&e.kind)) {
            let has = |k: &str| {
                entries.iter().find(|e| {
                    e.kind == k && e.record.as_ref().is_some_and(|r| r["launch"] == launch.seq)
                })
            };
            let child = has(kind::CHILD).and_then(|c| c.record.as_ref());
            if let Some(result) = has(kind::RUNNER_RESULT) {
                // A forced stop that could not be confirmed stays visible while the child
                // still runs.
                let unreaped = result
                    .record
                    .as_ref()
                    .is_some_and(|r| !r["unreaped"].is_null());
                if unreaped && liveness(child, "pid", "start", false) != Live::No {
                    out.live_orphans.push(launch.seq);
                }
                continue;
            }
            let child_live = match child {
                Some(c) => liveness(Some(c), "pid", "start", false),
                None => Live::No,
            };
            let supervisor_live = liveness(
                launch.record.as_ref(),
                "supervisor_pid",
                "supervisor_start",
                true,
            );
            if child_live == Live::Yes || supervisor_live == Live::Yes {
                out.live_orphans.push(launch.seq);
                continue;
            }
            if child_live == Live::Unverifiable || supervisor_live == Live::Unverifiable {
                out.unverifiable.push(launch.seq);
                continue;
            }
            let started = launch
                .record
                .as_ref()
                .map_or(Value::Null, |r| r["started_at"].clone());
            self.append(
                kind::RUNNER_RESULT,
                None,
                Some(json!({"launch": launch.seq, "recovered": true, "runner": {
                    "termination": {"kind": "unknown"}, "started_at": started}})),
                vec![launch.seq],
                None,
            )?;
            out.recovered.push(launch.seq);
        }
        Ok(out)
    }
}

/// What recovery did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Recovery {
    /// Launches given termination `unknown`.
    pub recovered: Vec<u64>,
    /// Launches whose child or supervisor still runs (or could not be reaped).
    pub live_orphans: Vec<u64>,
    /// Launches whose records carry no start identity: left alone and reported.
    pub unverifiable: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Live {
    Yes,
    No,
    Unverifiable,
}

/// Liveness of the process a record names. A process is alive only with the same start
/// identity (a reused ID is another process). A record without the identity member is
/// unverifiable; a `null` identity means the process was already gone when it was
/// recorded, except for the supervisor (`identity_required`), which always records one.
fn liveness(r: Option<&Value>, pid: &str, start: &str, identity_required: bool) -> Live {
    let Some(r) = r else { return Live::No };
    let Some(p) = r[pid].as_u64().and_then(|p| u32::try_from(p).ok()) else {
        return Live::No;
    };
    match r.get(start) {
        Some(Value::String(s)) => {
            if crate::platform::alive(p, Some(s)) {
                Live::Yes
            } else {
                Live::No
            }
        }
        Some(Value::Null) if !identity_required => Live::No,
        _ => Live::Unverifiable,
    }
}
