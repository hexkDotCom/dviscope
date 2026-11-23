//! Third-party licenses of what a release ships: the Rust crates linked
//! into the two binaries for a target (normal dependencies, from `cargo metadata`) and the
//! npm packages of the built web UI (production entries of `web/package-lock.json`), each
//! with its declared license and the license and notice files it ships. A package with
//! neither is an error: nothing is distributed without its terms.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use serde_json::Value;

/// Where the release archive holds the licenses of the Rust standard library's components.
pub const RUST_LIBRARY_NOTICES: &str = "licenses/rust-library-COPYRIGHT.html";

/// The license notice of musl libc, linked statically into the Linux binaries (the version
/// the pinned Rust toolchain ships for the musl target).
const MUSL_NOTICE: &str = include_str!("../licenses/musl-1.2.5-copyright.txt");

/// One third-party package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// `rust` or `npm`.
    pub ecosystem: &'static str,
    /// Name.
    pub name: String,
    /// Version.
    pub version: String,
    /// Declared license expression (empty when only a file is given).
    pub license: String,
    /// License and notice files: (file name, text).
    pub texts: Vec<(String, String)>,
}

/// Whether a file name is a license or notice file.
fn is_license_name(name: &str) -> bool {
    let n = name.to_uppercase();
    [
        "LICENSE",
        "LICENCE",
        "COPYING",
        "NOTICE",
        "UNLICENSE",
        "COPYRIGHT",
    ]
    .iter()
    .any(|k| n.starts_with(k))
}

/// A license "file" that only names another file (a symlink packaged as its target's path,
/// as `../LICENSE-MIT`): the named file's text when it exists, else nothing (a path is not
/// terms).
fn resolve_reference(file: &Path, text: &str) -> Option<String> {
    let t = text.trim();
    let reference = !t.is_empty()
        && !t.contains(char::is_whitespace)
        && t.len() < 256
        && (t.contains('/') || t.contains('\\'));
    if !reference {
        return Some(text.to_string());
    }
    let target = file.parent()?.join(t);
    let target_text = std::fs::read_to_string(target).ok()?;
    // A reference to a reference is not followed further.
    let tt = target_text.trim();
    (!tt.is_empty() && tt.contains(char::is_whitespace)).then_some(target_text)
}

/// The license and notice files of a package directory and of all its subdirectories (some
/// packages keep the terms of bundled code beside it, as `ring`'s
/// `src/polyfill/once_cell/LICENSE-MIT`), relative names. A file that only names another
/// file is replaced by that file's text, or left out when it cannot be found.
fn license_files(dir: &Path) -> Vec<(String, String)> {
    fn walk(base: &Path, dir: &Path, depth: u32, out: &mut Vec<(String, String)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        paths.sort();
        for p in paths {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if p.is_dir() {
                // Deep enough for any package layout; symlinked directories are not followed.
                let link = std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink());
                if depth < 32
                    && !link
                    && !matches!(name.as_str(), "node_modules" | "target" | ".git")
                {
                    walk(base, &p, depth + 1, out);
                }
            } else if is_license_name(&name)
                && let Ok(raw) = std::fs::read_to_string(&p)
                && let Some(t) = resolve_reference(&p, &raw)
            {
                let rel = p
                    .strip_prefix(base)
                    .map_or(name.clone(), |r| r.to_string_lossy().replace('\\', "/"));
                out.push((rel, t));
            }
        }
    }
    let mut out = vec![];
    walk(dir, dir, 0, &mut out);
    out
}

/// The third-party crates reachable from the workspace binaries through normal
/// dependencies for `target`, from a `cargo metadata` document.
///
/// # Errors
/// A malformed document.
pub fn rust_packages(meta: &Value, roots: &[&str]) -> Result<Vec<Package>> {
    let pkgs: BTreeMap<&str, &Value> = meta["packages"]
        .as_array()
        .context("metadata packages")?
        .iter()
        .filter_map(|p| p["id"].as_str().map(|id| (id, p)))
        .collect();
    let nodes: BTreeMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .context("metadata resolve")?
        .iter()
        .filter_map(|n| n["id"].as_str().map(|id| (id, n)))
        .collect();
    let mut todo: Vec<&str> = pkgs
        .iter()
        .filter(|(_, p)| roots.contains(&p["name"].as_str().unwrap_or_default()))
        .map(|(id, _)| *id)
        .collect();
    let mut seen = BTreeSet::new();
    while let Some(id) = todo.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(n) = nodes.get(id) else { continue };
        for d in n["deps"].as_array().into_iter().flatten() {
            // Normal dependencies only (build scripts and tests are not shipped); the
            // metadata was filtered to the target's platform.
            let normal = d["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k["kind"].is_null());
            if normal && let Some(p) = d["pkg"].as_str() {
                todo.push(p);
            }
        }
    }
    let mut out = vec![];
    for id in seen {
        let Some(p) = pkgs.get(id) else { continue };
        if p["source"].is_null() {
            continue; // the workspace's own crates
        }
        let dir = Path::new(p["manifest_path"].as_str().unwrap_or_default())
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let mut texts = license_files(&dir);
        // A declared `license-file` outside the names searched for is read too.
        if let Some(f) = p["license_file"].as_str() {
            let path = dir.join(f);
            let rel = f.replace('\\', "/");
            if !texts.iter().any(|(n, _)| *n == rel)
                && let Ok(raw) = std::fs::read_to_string(&path)
                && let Some(t) = resolve_reference(&path, &raw)
            {
                texts.push((rel, t));
            }
        }
        out.push(Package {
            ecosystem: "rust",
            name: p["name"].as_str().unwrap_or_default().to_string(),
            version: p["version"].as_str().unwrap_or_default().to_string(),
            license: p["license"].as_str().unwrap_or_default().to_string(),
            texts,
        });
    }
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(out)
}

/// The production npm packages of the web UI, from its lock file and `node_modules`.
///
/// # Errors
/// A malformed lock file.
pub fn npm_packages(web: &Path, lock: &Value) -> Result<Vec<Package>> {
    let mut out = vec![];
    for (path, e) in lock["packages"].as_object().context("lock packages")? {
        if path.is_empty() || e["dev"] == true || e["link"] == true {
            continue;
        }
        let name = path
            .rsplit_once("node_modules/")
            .map_or(path.as_str(), |(_, n)| n)
            .to_string();
        out.push(Package {
            ecosystem: "npm",
            name,
            version: e["version"].as_str().unwrap_or_default().to_string(),
            license: e["license"].as_str().unwrap_or_default().to_string(),
            texts: license_files(&web.join(path)),
        });
    }
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(out)
}

/// The document shipped as `THIRD_PARTY_LICENSES.md`.
///
/// # Errors
/// A package without a declared license and without a license file.
pub fn render(pkgs: &[Package]) -> Result<String> {
    // Every shipped package comes with license text (a declared license alone is not the
    // terms).
    if let Some(p) = pkgs.iter().find(|p| p.texts.is_empty()) {
        bail!(
            "{} {} {}: no license text (declared: {:?}); add it to the release's fallbacks",
            p.ecosystem,
            p.name,
            p.version,
            p.license
        );
    }
    let mut s = String::from(
        "# Third-party licenses\n\nThe Rust crates linked into the binaries and the npm packages built into the web UI, with\ntheir licenses and the license and notice files they ship.\n",
    );
    for eco in ["rust", "npm"] {
        let list: Vec<&Package> = pkgs.iter().filter(|p| p.ecosystem == eco).collect();
        if list.is_empty() {
            continue;
        }
        s.push_str(&format!(
            "\n## {} ({})\n",
            if eco == "rust" {
                "Rust crates"
            } else {
                "npm packages"
            },
            list.len()
        ));
        for p in list {
            s.push_str(&format!(
                "\n### {} {}\n\nLicense: {}\n",
                p.name,
                p.version,
                if p.license.is_empty() {
                    "see file"
                } else {
                    &p.license
                }
            ));
            for (n, t) in &p.texts {
                s.push_str(&format!("\n`{n}`:\n\n~~~~text\n{}\n~~~~\n", t.trim_end()));
            }
        }
    }
    Ok(s)
}

/// Collects and renders the third-party licenses of a release for `target`.
///
/// # Errors
/// `cargo metadata`, the lock file, or a package without license information.
pub fn collect(root: &Path, target: &str, with_ui: bool) -> Result<String> {
    let out = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            target,
        ])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let meta: Value = serde_json::from_slice(&out.stdout)?;
    let mut pkgs = rust_packages(&meta, &["dviscope-cli", "dviscope-server"])?;
    if with_ui {
        let web = root.join("web");
        let lock: Value = serde_json::from_slice(
            &std::fs::read(web.join("package-lock.json"))
                .context("reading web/package-lock.json")?,
        )?;
        pkgs.extend(npm_packages(&web, &lock)?);
    }
    // A package that ships no license file but offers Apache-2.0 is distributed under it:
    // that text is the same for every project (this repository's LICENSE).
    let apache = std::fs::read_to_string(root.join("LICENSE")).context("reading LICENSE")?;
    for p in &mut pkgs {
        if p.texts.is_empty() && offers_apache(&p.license) {
            p.texts.push((
                "Apache-2.0 (the package ships no license file; the standard text)".into(),
                apache.clone(),
            ));
        }
    }
    rust_library_notices(root)?;
    let mut doc = render(&pkgs)?;
    doc.push_str(&runtime_section(target));
    Ok(doc)
}

/// The pinned toolchain's inventory of the Rust standard library's component licenses.
///
/// # Errors
/// `rustc` cannot be run, or the toolchain has no such file (the `rust-docs` component).
pub fn rust_library_notices(root: &Path) -> Result<PathBuf> {
    let out = Command::new("rustc")
        .args(["--print", "sysroot"])
        .current_dir(root)
        .output()
        .context("running rustc --print sysroot")?;
    if !out.status.success() {
        bail!("rustc --print sysroot failed");
    }
    let file = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
        .join("share/doc/rust/COPYRIGHT-library.html");
    if !file.is_file() {
        bail!("{} is missing (the rust-docs component)", file.display());
    }
    Ok(file)
}

/// What is linked into the binaries without being a Cargo or npm package.
fn runtime_section(target: &str) -> String {
    let mut s = format!(
        "\n## Statically linked runtime\n\n### Rust standard library\n\nLicense: MIT OR \
         Apache-2.0, with the terms of each component in `{RUST_LIBRARY_NOTICES}`.\n"
    );
    if target.contains("musl") {
        s.push_str(&format!(
            "\n### musl libc 1.2.5\n\nLicense: MIT, with the notices below.\n\n~~~~text\n{}\n~~~~\n",
            MUSL_NOTICE.trim_end()
        ));
    }
    s
}

/// Whether a license expression offers Apache-2.0 (alone, or as an `OR` alternative; also
/// the legacy `/` separator).
fn offers_apache(expr: &str) -> bool {
    expr.split(|c: char| c == '/' || c.is_whitespace() || c == '(' || c == ')')
        .any(|t| t == "Apache-2.0")
        && !expr.contains(" AND ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_shipped_dependencies_are_listed_and_each_needs_terms() {
        let meta = json!({
            "packages": [
                {"id": "a", "name": "dviscope-cli", "version": "0.1.0", "source": null, "license": "Apache-2.0", "manifest_path": "/nowhere/a/Cargo.toml"},
                {"id": "b", "name": "serde", "version": "1.0.0", "source": "registry", "license": "MIT OR Apache-2.0", "manifest_path": "/nowhere/b/Cargo.toml"},
                {"id": "c", "name": "cc", "version": "1.0.0", "source": "registry", "license": "MIT", "manifest_path": "/nowhere/c/Cargo.toml"},
                {"id": "d", "name": "proptest", "version": "1.0.0", "source": "registry", "license": "MIT", "manifest_path": "/nowhere/d/Cargo.toml"}
            ],
            "resolve": {"nodes": [
                {"id": "a", "deps": [
                    {"pkg": "b", "dep_kinds": [{"kind": null}]},
                    {"pkg": "c", "dep_kinds": [{"kind": "build"}]},
                    {"pkg": "d", "dep_kinds": [{"kind": "dev"}]}
                ]},
                {"id": "b", "deps": []}, {"id": "c", "deps": []}, {"id": "d", "deps": []}
            ]}
        });
        let p = rust_packages(&meta, &["dviscope-cli"]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            p.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["serde"]
        );
        let lock = json!({"packages": {
            "": {"name": "web"},
            "node_modules/react": {"version": "18.3.1", "license": "MIT"},
            "node_modules/vitest": {"version": "2.0.0", "license": "MIT", "dev": true}
        }});
        let n = npm_packages(Path::new("/nowhere"), &lock).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            n.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["react"]
        );
        let mut all = [p, n].concat();
        for x in &mut all {
            x.texts.push(("LICENSE".into(), "terms".into()));
        }
        let doc = render(&all).unwrap_or_else(|e| panic!("{e}"));
        assert!(doc.contains("### serde 1.0.0") && doc.contains("### react 18.3.1"));
        assert!(
            render(&[Package {
                ecosystem: "rust",
                name: "declared-only".into(),
                version: "1".into(),
                license: "MIT".into(),
                texts: vec![],
            }])
            .is_err()
        );
        assert!(offers_apache("MIT OR Apache-2.0"));
        assert!(offers_apache("MIT/Apache-2.0"));
        assert!(!offers_apache("MIT"));
        assert!(!offers_apache("Apache-2.0 AND MIT"));
        let bare = Package {
            ecosystem: "npm",
            name: "x".into(),
            version: "1".into(),
            license: String::new(),
            texts: vec![],
        };
        assert!(render(&[bare]).is_err());
    }

    /// Terms kept deep in a package are collected; a file that
    /// only names another file is replaced by it, or left out when that file is missing
    /// (so the package needs a fallback, never ships a path as its terms).
    #[test]
    fn the_static_runtime_is_listed_for_each_target() {
        let linux = runtime_section("x86_64-unknown-linux-musl");
        assert!(linux.contains(RUST_LIBRARY_NOTICES));
        assert!(linux.contains("musl libc") && linux.contains("Permission is hereby granted"));
        let windows = runtime_section("x86_64-pc-windows-msvc");
        assert!(windows.contains(RUST_LIBRARY_NOTICES));
        assert!(!windows.contains("musl libc"));
    }

    #[test]
    fn deep_files_are_collected_and_references_resolved() {
        let d = std::env::temp_dir().join(format!("dviscope-tpl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let deep = d.join("pkg/src/polyfill/once_cell");
        std::fs::create_dir_all(&deep).unwrap_or_else(|e| panic!("{e}"));
        let w = |p: PathBuf, t: &str| std::fs::write(p, t).unwrap_or_else(|e| panic!("{e}"));
        w(d.join("pkg/LICENSE"), "The ring terms.\n");
        w(deep.join("LICENSE-MIT"), "Permission is hereby granted.\n");
        let f = license_files(&d.join("pkg"));
        assert_eq!(
            f.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["LICENSE", "src/polyfill/once_cell/LICENSE-MIT"]
        );
        // `../LICENSE-APACHE` beside an existing file is resolved; a missing one is dropped.
        std::fs::create_dir_all(d.join("ws/core")).unwrap_or_else(|e| panic!("{e}"));
        w(d.join("ws/LICENSE-APACHE"), "Apache License Version 2.0\n");
        w(d.join("ws/core/LICENSE-APACHE"), "../LICENSE-APACHE");
        w(d.join("ws/core/LICENSE-MIT"), "../LICENSE-MIT\n");
        let f = license_files(&d.join("ws/core"));
        assert_eq!(
            f,
            [(
                "LICENSE-APACHE".to_string(),
                "Apache License Version 2.0\n".to_string()
            )]
        );
        std::fs::remove_file(d.join("ws/LICENSE-APACHE")).ok();
        assert!(license_files(&d.join("ws/core")).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
