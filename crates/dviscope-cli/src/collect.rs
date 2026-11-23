//! Regression and manifest operations as journal entries: each is
//! validated against its wire type, gets the server identity of `docs/api.md`, and
//! depends on the entries it builds on (the source manifest, the regression, the chunks,
//! the seal), so the spool delivers them in a valid order. The seal is computed from the
//! journal's own chunks.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use dviscope_model::canonical::digest_of;
use dviscope_model::schema::MANIFEST;
use dviscope_model::wire::manifest::{ManifestAmend, ManifestChunk, SlotDecl, SlotMark};
use dviscope_model::wire::regression::{RegressionCreate, SourceManifest};
use serde_json::{Value, json};

use crate::journal::{Entry, Journal, Outcome, PayloadError, kind};

fn read_body(file: &Path) -> Result<Value> {
    serde_json::from_slice(
        &std::fs::read(file).with_context(|| format!("reading {}", file.display()))?,
    )
    .with_context(|| format!("{} is not JSON", file.display()))
}

fn typed<T: serde::de::DeserializeOwned>(v: &Value, what: &str) -> Result<T> {
    serde_json::from_value(v.clone()).with_context(|| format!("not a valid {what}"))
}

fn digest_hex(v: &Value) -> Result<String> {
    Ok(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        dviscope_model::canonical::canonical_json(v)?.as_bytes(),
    )))
}

/// Entries of this journal with the given kind and identity.
fn find(entries: &[Entry], k: &str, identity: &str) -> Vec<u64> {
    entries
        .iter()
        .filter(|e| e.kind == k && e.identity.as_deref() == Some(identity))
        .map(|e| e.seq)
        .collect()
}

/// Appends one operation (under the lock), refusing a second entry with the same identity
/// and other content (an identical one is returned as is).
fn append_op(
    j: &Journal,
    k: &str,
    identity: &str,
    body: &Value,
    depends: Vec<u64>,
    as_payload: bool,
) -> Result<Value> {
    j.locked(|j| {
        let entries = j.intact()?;
        let digest = digest_hex(body)?;
        // At most one entry per identity: the first one found decides.
        if let Some(seq) = find(&entries, k, identity).first().copied() {
            let e = entries
                .iter()
                .find(|e| e.seq == seq)
                .context("entry vanished")?;
            let old = if let Some(p) = &e.payload {
                match j.payload_checked(e) {
                    Ok(bytes) => serde_json::from_slice::<Value>(&bytes)?,
                    // Delivered and reclaimed: the entry still records the payload's
                    // SHA-256, so a resumed run re-declaring the same content matches it.
                    Err(PayloadError::Missing(_))
                        if matches!(j.outcomes()?.get(&seq), Some(Outcome::Committed { .. })) =>
                    {
                        let same = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                            serde_json::to_vec(body)?,
                        )) == p.sha256;
                        if same {
                            return Ok(json!({"seq": seq, "identity": identity, "existing": true}));
                        }
                        bail!("{identity} is already journalled with other content (entry {seq})");
                    }
                    Err(err) => return Err(err.into()),
                }
            } else {
                e.record
                    .as_ref()
                    .map_or(Value::Null, |r| r["deliver"].clone())
            };
            if digest_hex(&old)? == digest {
                return Ok(json!({"seq": seq, "identity": identity, "existing": true}));
            }
            bail!("{identity} is already journalled with other content (entry {seq})");
        }
        let seq = if as_payload {
            j.append(
                k,
                Some(identity.to_string()),
                Some(json!({"identity": identity})),
                depends,
                Some(&serde_json::to_vec(body)?),
            )?
        } else {
            j.append(
                k,
                Some(identity.to_string()),
                Some(json!({"deliver": body})),
                depends,
                None,
            )?
        };
        Ok(json!({"seq": seq, "identity": identity, "existing": false}))
    })
}

fn entries(j: &Journal) -> Result<Vec<Entry>> {
    j.locked(Journal::intact)
}

/// `dviscope source-manifest`.
///
/// # Errors
/// Invalid body, a conflicting entry, journal I/O.
pub fn source_manifest(j: &Journal, file: &Path) -> Result<Value> {
    source_manifest_body(j, &read_body(file)?)
}

/// [`source_manifest`] with the body as a value.
///
/// # Errors
/// Invalid body, a conflicting entry, journal I/O.
pub fn source_manifest_body(j: &Journal, body: &Value) -> Result<Value> {
    let body = body.clone();
    let m: SourceManifest = typed(&body, "source manifest")?;
    let identity = format!("source_manifest:{}", m.source_manifest_ref.as_str());
    append_op(j, kind::SOURCE_MANIFEST, &identity, &body, vec![], false)
}

/// `dviscope regression create`.
///
/// # Errors
/// Invalid body, a conflicting entry, journal I/O.
pub fn regression_create(j: &Journal, file: &Path) -> Result<Value> {
    regression_create_body(j, &read_body(file)?)
}

/// [`regression_create`] with the body as a value.
///
/// # Errors
/// Invalid body, a conflicting entry, journal I/O.
pub fn regression_create_body(j: &Journal, body: &Value) -> Result<Value> {
    let body = body.clone();
    let c: RegressionCreate = typed(&body, "regression")?;
    let identity = format!("regression:{}", c.regression_ref.as_str());
    let deps = find(
        &entries(j)?,
        kind::SOURCE_MANIFEST,
        &format!("source_manifest:{}", c.source_manifest_ref.as_str()),
    );
    append_op(j, kind::REGRESSION_CREATE, &identity, &body, deps, false)
}

fn regression_deps(entries: &[Entry], regression: &str) -> Vec<u64> {
    find(
        entries,
        kind::REGRESSION_CREATE,
        &format!("regression:{regression}"),
    )
}

/// `dviscope manifest declare`: one chunk (stored as a payload).
///
/// # Errors
/// Invalid body or chunk number, a conflicting entry, journal I/O.
pub fn declare(j: &Journal, regression: &str, n: u32, file: &Path) -> Result<Value> {
    declare_body(j, regression, n, &read_body(file)?)
}

/// [`declare`] with the body as a value.
///
/// # Errors
/// Invalid body or chunk number, a conflicting entry, journal I/O.
pub fn declare_body(j: &Journal, regression: &str, n: u32, body: &Value) -> Result<Value> {
    if n == 0 {
        bail!("chunk numbers start at 1");
    }
    let body = body.clone();
    let _: ManifestChunk = typed(&body, "manifest chunk")?;
    let identity = format!("manifest_chunk:{regression}/{n}");
    let deps = regression_deps(&entries(j)?, regression);
    append_op(j, kind::MANIFEST_CHUNK, &identity, &body, deps, true)
}

/// `dviscope manifest seal`: count and digest computed from the journal's chunks of the
/// regression (contiguous from 1), as the server checks them.
///
/// # Errors
/// No chunks, a gap, a slot declared twice, journal I/O.
pub fn seal(j: &Journal, regression: &str) -> Result<Value> {
    let all = entries(j)?;
    // Already sealed (a resumed run): the seal stands; its chunks may be delivered and
    // reclaimed, so they are not read again.
    if let Some(seq) = seal_deps(&all, regression).first().copied() {
        return Ok(
            json!({"seq": seq, "identity": format!("manifest_seal:{regression}"),
                         "existing": true}),
        );
    }
    let prefix = format!("manifest_chunk:{regression}/");
    let mut chunks: Vec<(u32, &Entry)> = all
        .iter()
        .filter(|e| e.kind == kind::MANIFEST_CHUNK)
        .filter_map(|e| {
            let n = e.identity.as_deref()?.strip_prefix(&prefix)?.parse().ok()?;
            Some((n, e))
        })
        .collect();
    chunks.sort_by_key(|(n, _)| *n);
    if chunks.is_empty() {
        bail!("no chunks of {regression} in this journal");
    }
    if chunks.iter().zip(1u32..).any(|((n, _), want)| *n != want) {
        bail!("the chunks of {regression} are not numbered 1..N without gaps");
    }
    let mut slots: Vec<SlotDecl> = vec![];
    for (_, e) in &chunks {
        let c: ManifestChunk = serde_json::from_slice(&j.payload(e)?)?;
        slots.extend(c.slots);
    }
    slots.sort_by(|a, b| a.slot_ref.as_str().cmp(b.slot_ref.as_str()));
    if let Some(w) = slots.windows(2).find(|w| w[0].slot_ref == w[1].slot_ref) {
        bail!("slot {} is declared twice", w[0].slot_ref.as_str());
    }
    let body = json!({
        "schema": MANIFEST,
        "revision": 1,
        "slot_count": slots.len(),
        "manifest_digest": digest_of(&slots)?,
    });
    let deps = chunks.iter().map(|(_, e)| e.seq).collect();
    append_op(
        j,
        kind::MANIFEST_SEAL,
        &format!("manifest_seal:{regression}"),
        &body,
        deps,
        false,
    )
}

fn seal_deps(entries: &[Entry], regression: &str) -> Vec<u64> {
    find(
        entries,
        kind::MANIFEST_SEAL,
        &format!("manifest_seal:{regression}"),
    )
}

/// The seal and every amendment of the regression (marks may name amended slots).
fn manifest_deps(entries: &[Entry], regression: &str) -> Vec<u64> {
    let prefix = format!("manifest_amend:{regression}/");
    let mut deps = seal_deps(entries, regression);
    deps.extend(
        entries
            .iter()
            .filter(|e| {
                e.kind == kind::MANIFEST_AMEND
                    && e.identity
                        .as_deref()
                        .is_some_and(|i| i.starts_with(&prefix))
            })
            .map(|e| e.seq),
    );
    deps
}

/// `dviscope manifest amend`.
///
/// # Errors
/// Invalid body, a conflicting entry, journal I/O.
pub fn amend(j: &Journal, regression: &str, file: &Path) -> Result<Value> {
    let body = read_body(file)?;
    let a: ManifestAmend = typed(&body, "manifest amendment")?;
    let identity = format!("manifest_amend:{regression}/{}", a.revision);
    let all = entries(j)?;
    let mut deps = seal_deps(&all, regression);
    // Amendments apply in revision order.
    deps.extend(find(
        &all,
        kind::MANIFEST_AMEND,
        &format!(
            "manifest_amend:{regression}/{}",
            a.revision.saturating_sub(1)
        ),
    ));
    append_op(j, kind::MANIFEST_AMEND, &identity, &body, deps, true)
}

/// `dviscope manifest mark`.
///
/// # Errors
/// Invalid body, journal I/O.
pub fn mark(j: &Journal, regression: &str, file: &Path) -> Result<Value> {
    let body = read_body(file)?;
    let _: SlotMark = typed(&body, "slot mark")?;
    let identity = format!("slot_mark:{regression}/{}", digest_hex(&body)?);
    let deps = manifest_deps(&entries(j)?, regression);
    append_op(j, kind::SLOT_MARK, &identity, &body, deps, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pilot finding: a resumed run re-declares chunks that were
    /// delivered and whose payloads were reclaimed; the same content is accepted (by the
    /// recorded hash), other content is still refused, and the seal stands.
    #[test]
    fn a_resumed_run_redeclares_delivered_chunks() {
        let dir = std::env::temp_dir().join(format!("dviscope-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        let j = Journal::create(&dir.join("j"), "r1").unwrap_or_else(|e| panic!("{e:#}"));
        let write = |name: &str, test: &str| {
            let p = dir.join(name);
            let body = json!({"schema": MANIFEST, "slots": [{"slot_ref": "s1",
                "exec_inputs": {"test": test, "seed": "1"}, "required": true}]});
            std::fs::write(&p, serde_json::to_vec(&body).unwrap_or_default())
                .unwrap_or_else(|e| panic!("{e}"));
            p
        };
        let c1 = write("c1.json", "t1");
        let first = declare(&j, "r1", 1, &c1).unwrap_or_else(|e| panic!("{e:#}"));
        seal(&j, "r1").unwrap_or_else(|e| panic!("{e:#}"));
        // Delivered: every entry committed, the chunk's payload reclaimed.
        j.locked(|j| {
            for e in j.intact()? {
                j.record_outcome(&e, &Outcome::Committed { receipt: json!({}) })?;
            }
            // The sealed regression's chunks are reclaimed by the sweep (a chunk is kept
            // until its seal is journalled).
            j.reclaim()?;
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{e:#}"));
        let chunk = j
            .intact()
            .unwrap_or_else(|e| panic!("{e:#}"))
            .into_iter()
            .find(|e| e.kind == kind::MANIFEST_CHUNK)
            .unwrap_or_else(|| panic!("no chunk entry"));
        assert!(matches!(
            j.payload_checked(&chunk),
            Err(PayloadError::Missing(_))
        ));
        let again = declare(&j, "r1", 1, &c1).unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(again["seq"], first["seq"]);
        assert_eq!(again["existing"], true);
        let other = write("c2.json", "t2");
        assert!(declare(&j, "r1", 1, &other).is_err(), "other content");
        let s = seal(&j, "r1").unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(s["existing"], true);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
