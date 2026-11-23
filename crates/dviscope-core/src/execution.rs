//! Execution identity: the canonical digest objects.
//!
//! | Digest | Covers |
//! |---|---|
//! | `source_digest` | sorted `(repository, revision)` pairs, ancestry excluded |
//! | `build_config_digest` | simulator, UVM version, options, sorted unique defines, file list |
//! | `build_req` | source digest + build config digest |
//! | `exec_digest` | test, sorted build requirement digests, seed, plusargs as given, modes |
//! | `config_digest` | as `exec_digest` without seed, seed-like plusargs and source |

use std::collections::BTreeMap;

use dviscope_model::canonical::{CanonicalError, Digest, digest_of};
use dviscope_model::wire::manifest::{BuildConfig, ExecInputs};
use dviscope_model::wire::regression::SourceEntry;
use serde_json::{Value, json};

/// Why an identity cannot be computed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// The same repository/revision pair appears twice.
    #[error("duplicate source entry {0}@{1}")]
    DuplicateSource(String, String),
    /// The same repository appears with two revisions.
    #[error("repository {0} appears twice in the source manifest")]
    DuplicateRepository(String),
    /// A define appears twice.
    #[error("duplicate define {0}")]
    DuplicateDefine(String),
    /// Canonicalization failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

/// Default seed-like options removed from the logical comparison configuration.
pub const DEFAULT_SEED_LIKE: &[&str] = &["+ntb_random_seed", "-sv_seed", "+seed", "+UVM_VERBOSITY"];

/// `source_digest`: sorted by repository then revision; ancestry is not part of identity.
///
/// # Errors
/// A repository listed twice.
pub fn source_digest(entries: &[SourceEntry]) -> Result<Digest, IdentityError> {
    let mut pairs: Vec<(&str, &str)> = entries
        .iter()
        .map(|e| (e.repository.as_str(), e.revision.as_str()))
        .collect();
    pairs.sort_unstable();
    for w in pairs.windows(2) {
        if w[0] == w[1] {
            return Err(IdentityError::DuplicateSource(
                w[0].0.to_string(),
                w[0].1.to_string(),
            ));
        }
        if w[0].0 == w[1].0 {
            return Err(IdentityError::DuplicateRepository(w[0].0.to_string()));
        }
    }
    let repos: Vec<Value> = pairs
        .iter()
        .map(|(r, v)| json!({"repository": r, "revision": v}))
        .collect();
    Ok(digest_of(
        &json!({"schema": "dviscope.source/1", "repositories": repos}),
    )?)
}

/// `build_config_digest`: defines sorted and unique, options as given.
///
/// # Errors
/// A define listed twice.
pub fn build_config_digest(cfg: &BuildConfig) -> Result<Digest, IdentityError> {
    let mut defines: Vec<&str> = cfg.defines.iter().map(String::as_str).collect();
    defines.sort_unstable();
    for w in defines.windows(2) {
        if w[0] == w[1] {
            return Err(IdentityError::DuplicateDefine(w[0].to_string()));
        }
    }
    let mut obj = serde_json::Map::new();
    obj.insert("schema".into(), json!("dviscope.build_config/1"));
    obj.insert(
        "simulator".into(),
        json!({"vendor": cfg.simulator.vendor, "version": cfg.simulator.version}),
    );
    if let Some(uvm) = &cfg.uvm_version {
        obj.insert("uvm_version".into(), json!(uvm));
    }
    obj.insert("options".into(), json!(cfg.options));
    obj.insert("defines".into(), json!(defines));
    if let Some(fl) = &cfg.file_list_digest {
        obj.insert("file_list_digest".into(), json!(fl.as_str()));
    }
    Ok(digest_of(&Value::Object(obj))?)
}

/// `build_req`: the pair of source and build configuration digests.
///
/// # Errors
/// Canonicalization failure (not expected for valid digests).
pub fn build_req_digest(source: &Digest, build_config: &Digest) -> Result<Digest, IdentityError> {
    Ok(digest_of(&json!({
        "schema": "dviscope.build_req/1",
        "source": source.as_str(),
        "build_config": build_config.as_str(),
    }))?)
}

fn modes_value(modes: &BTreeMap<String, String>) -> Value {
    Value::Object(modes.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}

fn extra_value(extra: &BTreeMap<String, BTreeMap<String, String>>) -> Value {
    Value::Object(
        extra
            .iter()
            .map(|(ns, m)| (ns.clone(), modes_value(m)))
            .collect(),
    )
}

/// `exec_digest` over exact inputs and the slot's build requirement digests.
///
/// # Errors
/// Canonicalization failure.
pub fn exec_digest(inputs: &ExecInputs, build_reqs: &[Digest]) -> Result<Digest, IdentityError> {
    let mut reqs: Vec<&str> = build_reqs.iter().map(Digest::as_str).collect();
    reqs.sort_unstable();
    Ok(digest_of(&json!({
        "schema": "dviscope.exec/1",
        "test": inputs.test,
        "build_reqs": reqs,
        "seed": inputs.seed.as_str(),
        "plusargs": inputs.plusargs,
        "modes": modes_value(&inputs.modes),
        "elaboration_modes": modes_value(&inputs.elaboration_modes),
        "extra": extra_value(&inputs.extra),
    }))?)
}

/// Removes seed-like options: `+NAME` and `+NAME=VALUE` tokens,
/// `-NAME VALUE` pairs and `-NAME=VALUE` tokens whose `NAME` is listed. Exact, case-sensitive.
#[must_use]
pub fn strip_seed_like(args: &[String], seed_like: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let name = arg.split_once('=').map_or(arg.as_str(), |(n, _)| n);
        if seed_like.contains(&name) {
            // `-NAME VALUE`: a dash option without `=` consumes the next token.
            if name.starts_with('-') && !arg.contains('=') {
                skip_next = true;
            }
            continue;
        }
        out.push(arg.clone());
    }
    out
}

/// `config_digest`: logical comparison configuration (no seed, no source).
///
/// # Errors
/// Canonicalization failure.
pub fn config_digest(
    inputs: &ExecInputs,
    build_configs: &[Digest],
    seed_like: &[&str],
) -> Result<Digest, IdentityError> {
    let mut cfgs: Vec<&str> = build_configs.iter().map(Digest::as_str).collect();
    cfgs.sort_unstable();
    Ok(digest_of(&json!({
        "schema": "dviscope.config/1",
        "test": inputs.test,
        "build_configs": cfgs,
        "plusargs": strip_seed_like(&inputs.plusargs, seed_like),
        "modes": modes_value(&inputs.modes),
        "elaboration_modes": modes_value(&inputs.elaboration_modes),
        "extra": extra_value(&inputs.extra),
    }))?)
}

/// Why a manifest digest cannot be computed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestDigestError {
    /// The same slot appears twice.
    #[error("duplicate slot {0}")]
    DuplicateSlot(String),
    /// Canonicalization failed.
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

/// Manifest digest: `{"schema":"dviscope.manifest/1","regression_ref","revision","slots"}`
/// with slots (their wire form) sorted by `slot_ref`.
///
/// # Errors
/// Duplicate slots; canonicalization failure.
pub fn manifest_digest(
    regression_ref: &str,
    revision: u32,
    slots: &[dviscope_model::wire::manifest::SlotDecl],
) -> Result<Digest, ManifestDigestError> {
    let mut sorted: Vec<&dviscope_model::wire::manifest::SlotDecl> = slots.iter().collect();
    sorted.sort_by(|a, b| a.slot_ref.as_str().cmp(b.slot_ref.as_str()));
    for w in sorted.windows(2) {
        if w[0].slot_ref == w[1].slot_ref {
            return Err(ManifestDigestError::DuplicateSlot(
                w[0].slot_ref.to_string(),
            ));
        }
    }
    Ok(digest_of(&json!({
        "schema": "dviscope.manifest/1",
        "regression_ref": regression_ref,
        "revision": revision,
        "slots": sorted,
    }))?)
}

/// Operation digest: the digest of the canonical form of a request body.
///
/// # Errors
/// Canonicalization failure.
pub fn operation_digest<T: serde::Serialize>(body: &T) -> Result<Digest, CanonicalError> {
    digest_of(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dviscope_model::values::DecimalInteger;
    use dviscope_model::wire::manifest::Simulator;

    fn ok<T, E: std::fmt::Display>(r: Result<T, E>) -> T {
        r.unwrap_or_else(|e| panic!("{e}"))
    }

    fn src(repo: &str, rev: &str) -> SourceEntry {
        SourceEntry {
            repository: repo.into(),
            revision: rev.into(),
            ancestry: vec![],
        }
    }

    fn questa() -> BuildConfig {
        BuildConfig {
            simulator: Simulator {
                vendor: "questa".into(),
                version: "2024.1".into(),
            },
            uvm_version: Some("1.2".into()),
            options: vec!["-sv".into(), "-timescale".into(), "1ns/1ps".into()],
            defines: vec!["B=2".into(), "A".into()],
            file_list_digest: None,
        }
    }

    fn inputs(seed: &str, plusargs: &[&str]) -> ExecInputs {
        ExecInputs {
            test: "hexk_ref_pass_test".into(),
            seed: ok(DecimalInteger::try_from(seed)),
            plusargs: plusargs.iter().map(|s| (*s).to_string()).collect(),
            modes: BTreeMap::new(),
            elaboration_modes: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    // Golden vectors: any change here is a contract change (bump the schema version).
    #[test]
    fn golden_source_digest() {
        let d = ok(source_digest(&[
            src("hexk-sv-lib", "7eab3ca"),
            src("dvicode", "abc123"),
        ]));
        let again = ok(source_digest(&[
            src("dvicode", "abc123"),
            src("hexk-sv-lib", "7eab3ca"),
        ]));
        assert_eq!(d, again, "order of entries must not matter");
        assert_eq!(
            d,
            Digest::of_bytes(
                br#"{"repositories":[{"repository":"dvicode","revision":"abc123"},{"repository":"hexk-sv-lib","revision":"7eab3ca"}],"schema":"dviscope.source/1"}"#
            )
        );
    }

    #[test]
    fn ancestry_is_not_identity() {
        let mut with = src("r", "v");
        with.ancestry = vec!["p".into()];
        assert_eq!(
            ok(source_digest(&[with])),
            ok(source_digest(&[src("r", "v")]))
        );
    }

    #[test]
    fn duplicates_rejected() {
        assert!(matches!(
            source_digest(&[src("r", "v"), src("r", "w")]),
            Err(IdentityError::DuplicateRepository(_))
        ));
        let mut cfg = questa();
        cfg.defines.push("A".into());
        assert!(matches!(
            build_config_digest(&cfg),
            Err(IdentityError::DuplicateDefine(_))
        ));
    }

    #[test]
    fn golden_build_config_digest_sorts_defines_only() {
        let d = ok(build_config_digest(&questa()));
        assert_eq!(
            d,
            Digest::of_bytes(
                br#"{"defines":["A","B=2"],"options":["-sv","-timescale","1ns/1ps"],"schema":"dviscope.build_config/1","simulator":{"vendor":"questa","version":"2024.1"},"uvm_version":"1.2"}"#
            )
        );
        let mut reordered = questa();
        reordered.options.swap(0, 1);
        assert_ne!(
            ok(build_config_digest(&reordered)),
            d,
            "option order is significant"
        );
    }

    #[test]
    fn two_producers_same_requirement() {
        let s = ok(source_digest(&[src("hexk-sv-lib", "7eab3ca")]));
        let c = ok(build_config_digest(&questa()));
        assert_eq!(ok(build_req_digest(&s, &c)), ok(build_req_digest(&s, &c)));
    }

    #[test]
    fn seed_changes_exec_but_not_config() {
        let cfg = ok(build_config_digest(&questa()));
        let req_a = ok(build_req_digest(
            &ok(source_digest(&[src("r", "rev1")])),
            &cfg,
        ));
        let req_b = ok(build_req_digest(
            &ok(source_digest(&[src("r", "rev2")])),
            &cfg,
        ));
        let a = inputs("11", &["+ref_mode=mixed", "+ntb_random_seed=11"]);
        let b = inputs("12", &["+ref_mode=mixed", "+ntb_random_seed=12"]);
        assert_ne!(
            ok(exec_digest(&a, std::slice::from_ref(&req_a))),
            ok(exec_digest(&b, std::slice::from_ref(&req_a)))
        );
        // Same comparison configuration across seeds and source revisions.
        assert_eq!(
            ok(config_digest(
                &a,
                std::slice::from_ref(&cfg),
                DEFAULT_SEED_LIKE
            )),
            ok(config_digest(
                &b,
                std::slice::from_ref(&cfg),
                DEFAULT_SEED_LIKE
            ))
        );
        // Different source → different exec digest even with the same seed.
        assert_ne!(ok(exec_digest(&a, &[req_a])), ok(exec_digest(&a, &[req_b])));
    }

    #[test]
    fn seed_like_removal_grammar() {
        let args: Vec<String> = [
            "-sv_seed",
            "5",
            "+x=1",
            "-sv_seed=6",
            "+seed",
            "+UVM_VERBOSITY=UVM_LOW",
            "+seedling=1",
            "-SV_SEED",
            "7",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        assert_eq!(
            strip_seed_like(&args, DEFAULT_SEED_LIKE),
            vec!["+x=1", "+seedling=1", "-SV_SEED", "7"]
        );
    }

    // Golden vectors: exact canonical bytes.
    fn dg(tag: &[u8]) -> Digest {
        Digest::of_bytes(tag)
    }

    #[test]
    fn golden_build_req_bytes() {
        let (s, c) = (dg(b"source"), dg(b"config"));
        let expected =
            format!(r#"{{"build_config":"{c}","schema":"dviscope.build_req/1","source":"{s}"}}"#);
        assert_eq!(
            ok(build_req_digest(&s, &c)),
            Digest::of_bytes(expected.as_bytes())
        );
    }

    #[test]
    fn golden_exec_and_config_bytes() {
        let mut inp = inputs("11", &["+ref_mode=mixed", "-sv_seed", "11"]);
        inp.modes.insert("state".into(), "4-state".into());
        inp.elaboration_modes
            .insert("voptargs".into(), "+acc".into());
        let (r1, r2) = (dg(b"req-b"), dg(b"req-a"));
        let mut reqs = [r1.as_str(), r2.as_str()];
        reqs.sort_unstable();
        let exec = format!(
            r#"{{"build_reqs":["{}","{}"],"elaboration_modes":{{"voptargs":"+acc"}},"extra":{{}},"modes":{{"state":"4-state"}},"plusargs":["+ref_mode=mixed","-sv_seed","11"],"schema":"dviscope.exec/1","seed":"11","test":"hexk_ref_pass_test"}}"#,
            reqs[0], reqs[1]
        );
        assert_eq!(
            ok(exec_digest(&inp, &[r1, r2])),
            Digest::of_bytes(exec.as_bytes())
        );
        let cfg = dg(b"cfg");
        let config = format!(
            r#"{{"build_configs":["{cfg}"],"elaboration_modes":{{"voptargs":"+acc"}},"extra":{{}},"modes":{{"state":"4-state"}},"plusargs":["+ref_mode=mixed"],"schema":"dviscope.config/1","test":"hexk_ref_pass_test"}}"#
        );
        assert_eq!(
            ok(config_digest(&inp, &[cfg], DEFAULT_SEED_LIKE)),
            Digest::of_bytes(config.as_bytes())
        );
    }

    #[test]
    fn golden_manifest_bytes_and_duplicates() {
        use dviscope_model::ids::ExternalKey;
        use dviscope_model::wire::manifest::SlotDecl;
        let slot = |r: &str| SlotDecl {
            slot_ref: ok(ExternalKey::try_from(r)),
            exec_inputs: inputs("1", &[]),
            required: true,
            build_reqs: vec![],
            expected: None,
        };
        let one = r#"{"build_reqs":[],"exec_inputs":{"elaboration_modes":{},"extra":{},"modes":{},"plusargs":[],"seed":"1","test":"hexk_ref_pass_test"},"required":true,"slot_ref":"#;
        let expected = format!(
            r#"{{"regression_ref":"nightly-1","revision":1,"schema":"dviscope.manifest/1","slots":[{one}"a"}},{one}"b"}}]}}"#
        );
        assert_eq!(
            ok(manifest_digest("nightly-1", 1, &[slot("b"), slot("a")])),
            Digest::of_bytes(expected.as_bytes())
        );
        assert!(matches!(
            manifest_digest("n", 1, &[slot("a"), slot("a")]),
            Err(ManifestDigestError::DuplicateSlot(_))
        ));
    }

    #[test]
    fn golden_operation_bytes() {
        let body = serde_json::json!({"revision": 2, "add": [], "remove": [{"slot_ref": "s", "reason": "r"}]});
        assert_eq!(
            ok(operation_digest(&body)),
            Digest::of_bytes(
                br#"{"add":[],"remove":[{"reason":"r","slot_ref":"s"}],"revision":2}"#
            )
        );
    }
}
