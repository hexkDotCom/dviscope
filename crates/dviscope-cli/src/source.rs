//! `dviscope source digest`: the candidate's source digest,
//! from local checkouts (`--repo NAME=PATH`, the checkout's `HEAD`) or explicit revisions
//! (`--rev NAME=REVISION`). A checkout with uncommitted changes is not its `HEAD` revision,
//! so it is refused unless `--allow-dirty` says the caller knows.

use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, anyhow, bail};
use dviscope_core::execution::source_digest;
use dviscope_model::wire::regression::SourceEntry;

/// One `NAME=VALUE` argument.
fn split(arg: &str, what: &str) -> Result<(String, String)> {
    let (n, v) = arg
        .split_once('=')
        .ok_or_else(|| anyhow!("{what} is NAME=VALUE: {arg}"))?;
    if n.is_empty() || v.is_empty() {
        bail!("{what} is NAME=VALUE: {arg}");
    }
    Ok((n.to_string(), v.to_string()))
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git {} failed in the checkout of a repository",
            args.join(" ")
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The `HEAD` revision of a checkout; refuses uncommitted changes unless allowed.
///
/// # Errors
/// Not a git checkout, git missing, or uncommitted changes.
pub fn head_revision(dir: &Path, allow_dirty: bool) -> Result<String> {
    let rev = git(dir, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if !allow_dirty && !git(dir, &["status", "--porcelain", "--untracked-files=no"])?.is_empty() {
        bail!(
            "the checkout has uncommitted changes: it is not revision {rev} (use --allow-dirty to digest HEAD anyway)"
        );
    }
    Ok(rev)
}

/// The source entries of `--repo NAME=PATH` and `--rev NAME=REVISION` arguments.
///
/// # Errors
/// Malformed arguments, unreadable checkouts.
pub fn entries(repos: &[String], revs: &[String], allow_dirty: bool) -> Result<Vec<SourceEntry>> {
    let mut out = vec![];
    for r in repos {
        let (name, path) = split(r, "--repo")?;
        let revision = head_revision(Path::new(&path), allow_dirty)
            .with_context(|| format!("repository {name}"))?;
        out.push(SourceEntry {
            repository: name,
            revision,
            ancestry: vec![],
        });
    }
    for r in revs {
        let (name, revision) = split(r, "--rev")?;
        out.push(SourceEntry {
            repository: name,
            revision,
            ancestry: vec![],
        });
    }
    if out.is_empty() {
        bail!("name at least one --repo NAME=PATH or --rev NAME=REVISION");
    }
    Ok(out)
}

/// The digest and the entries it covers.
///
/// # Errors
/// As [`entries`], and a repository named twice.
pub fn digest(repos: &[String], revs: &[String], allow_dirty: bool) -> Result<serde_json::Value> {
    let e = entries(repos, revs, allow_dirty)?;
    let d = source_digest(&e).map_err(|x| anyhow!("{x}"))?;
    Ok(serde_json::json!({
        "source_digest": d.as_str(),
        "repositories": e.iter().map(|x| serde_json::json!({"repository": x.repository, "revision": x.revision})).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_revisions_match_the_core_digest_in_any_order() {
        let a = digest(&[], &["rtl=abc".into(), "dv=def".into()], false)
            .unwrap_or_else(|e| panic!("{e}"));
        let b = digest(&[], &["dv=def".into(), "rtl=abc".into()], false)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(a["source_digest"], b["source_digest"]);
        let core = source_digest(&[
            SourceEntry {
                repository: "rtl".into(),
                revision: "abc".into(),
                ancestry: vec![],
            },
            SourceEntry {
                repository: "dv".into(),
                revision: "def".into(),
                ancestry: vec![],
            },
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(a["source_digest"], core.as_str());
    }

    #[test]
    fn rejects_bad_arguments_and_duplicates() {
        assert!(digest(&[], &[], false).is_err());
        assert!(digest(&[], &["rtl".into()], false).is_err());
        assert!(digest(&[], &["=x".into()], false).is_err());
        assert!(digest(&[], &["rtl=a".into(), "rtl=b".into()], false).is_err());
    }

    #[test]
    fn checkout_head_and_dirty_refusal() {
        let d = std::env::temp_dir().join(format!("dvs-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
        let run = |args: &[&str]| {
            let ok = Command::new("git")
                .arg("-C")
                .arg(&d)
                .args(args)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?}");
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "t@example.invalid"]);
        run(&["config", "user.name", "t"]);
        std::fs::write(d.join("a.sv"), "module a; endmodule\n").unwrap_or_else(|e| panic!("{e}"));
        run(&["add", "a.sv"]);
        run(&["commit", "-q", "-m", "a"]);
        let repo = format!("rtl={}", d.display());
        let v = digest(std::slice::from_ref(&repo), &[], false).unwrap_or_else(|e| panic!("{e}"));
        let rev = v["repositories"][0]["revision"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert_eq!(rev.len(), 40, "{v}");
        let same = digest(&[], &[format!("rtl={rev}")], false).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(v["source_digest"], same["source_digest"]);
        std::fs::write(d.join("a.sv"), "module a2; endmodule\n").unwrap_or_else(|e| panic!("{e}"));
        let dirty = digest(std::slice::from_ref(&repo), &[], false);
        assert!(dirty.is_err());
        assert!(digest(std::slice::from_ref(&repo), &[], true).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }
}
