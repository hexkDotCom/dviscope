//! Classification: typed fields, significance, normalization, identity and
//! fingerprint.

pub mod normalize;

use std::collections::BTreeMap;

use dviscope_model::canonical::{Digest, digest_of};
use dviscope_model::wire::evidence::{AnchorForm, FieldValue, SourceAnchor};
use serde_json::json;

use crate::packs::{FINGERPRINT_SCHEMA, FieldKind, Significance};

/// Parses a typed field value.
#[must_use]
pub(crate) fn typed(kind: FieldKind, raw: &str) -> FieldValue {
    match kind {
        FieldKind::Text => FieldValue::Text(raw.to_string()),
        FieldKind::Integer => raw
            .parse::<u64>()
            .ok()
            .and_then(|v| v.try_into().ok())
            .map_or_else(|| FieldValue::Text(raw.to_string()), FieldValue::Integer),
        FieldKind::SvLiteral => FieldValue::SvLiteral(raw.to_string()),
        FieldKind::Time => {
            let split = raw
                .find(|c: char| c.is_ascii_alphabetic())
                .unwrap_or(raw.len());
            FieldValue::Time {
                value: raw[..split].trim().to_string(),
                unit: raw[split..].trim().to_string(),
            }
        }
    }
}

fn field_text(v: &FieldValue) -> String {
    match v {
        FieldValue::Text(s) | FieldValue::SvLiteral(s) => s.clone(),
        FieldValue::Integer(n) => n.get().to_string(),
        FieldValue::Time { value, unit } => format!("{value}{unit}"),
    }
}

/// Numeric class of a literal: `zero`, `nonzero`, `x` (X/Z digits) or `other`.
fn numeric_class(raw: &str) -> &'static str {
    let s = raw.trim();
    // Unbased unsized literals: '0, '1, 'x, 'z.
    if let Some(rest) = s.strip_prefix('\'')
        && rest.len() == 1
    {
        return match rest {
            "0" => "zero",
            "1" => "nonzero",
            "x" | "X" | "z" | "Z" => "x",
            _ => "other",
        };
    }
    let digits: &str = if let Some(pos) = s.find('\'') {
        // SystemVerilog literal: drop size, sign and radix.
        let rest = &s[pos + 1..];
        let rest = rest.strip_prefix(['s', 'S']).unwrap_or(rest);
        rest.get(1..).unwrap_or("")
    } else if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        h
    } else {
        s
    };
    let digits: String = digits.chars().filter(|c| *c != '_').collect();
    if digits.is_empty() {
        return "other";
    }
    if digits
        .chars()
        .any(|c| matches!(c, 'x' | 'X' | 'z' | 'Z' | '?'))
    {
        return "x";
    }
    if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return "other";
    }
    if digits.chars().all(|c| c == '0') {
        "zero"
    } else {
        "nonzero"
    }
}

/// The significant class of a field; a missing field is `missing`.
#[must_use]
pub(crate) fn significant_class(sig: &Significance, value: Option<&FieldValue>) -> String {
    let Some(v) = value else {
        return "missing".to_string();
    };
    let text = field_text(v);
    match sig {
        Significance::Verbatim => text,
        Significance::ZeroVsNonzero => numeric_class(&text).to_string(),
        Significance::XVsKnown => {
            if numeric_class(&text) == "x" {
                "x".to_string()
            } else {
                "known".to_string()
            }
        }
        Significance::Class(list) => {
            if list.contains(&text) {
                text
            } else {
                "other".to_string()
            }
        }
    }
}

/// Builds a source anchor from a written path; `source_roots` make it repository-relative.
#[must_use]
pub fn anchor(path: &str, line: Option<u64>, form: &str, source_roots: &[String]) -> SourceAnchor {
    let p = path.trim();
    let line = line.and_then(|l| l.try_into().ok());
    let truncated = form == "truncated" || (form == "auto" && p.starts_with(".."));
    if truncated {
        return SourceAnchor {
            path: p.to_string(),
            form: AnchorForm::Truncated,
            line,
        };
    }
    let unified = p.replace('\\', "/");
    for root in source_roots {
        let r = root.replace('\\', "/");
        let r = r.trim_end_matches('/');
        if !r.is_empty()
            && let Some(rest) = unified.strip_prefix(r)
            && let Some(rel) = rest.strip_prefix('/')
        {
            return SourceAnchor {
                path: rel.to_string(),
                form: AnchorForm::RepoRelative,
                line,
            };
        }
    }
    SourceAnchor {
        path: p.to_string(),
        form: AnchorForm::Full,
        line,
    }
}

/// The family key of a failure signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyKey {
    /// Family kind.
    pub family: String,
    /// Diagnostic ID.
    pub diag_id: String,
    /// Checker scope.
    pub checker_scope: Option<String>,
    /// Identity template.
    pub identity_template: String,
    /// Significant classes.
    pub significant: BTreeMap<String, String>,
    /// Source anchor, only when no checker identity exists.
    pub anchor: Option<SourceAnchor>,
}

/// Fingerprint v1 = `sha256(JCS({schema: "fp/1", key}))`.
#[must_use]
pub fn fingerprint(key: &FamilyKey) -> Digest {
    let anchor = key.anchor.as_ref().map(|a| {
        let form = match a.form {
            AnchorForm::Full => "full",
            AnchorForm::RepoRelative => "repo_relative",
            AnchorForm::Truncated => "truncated",
            AnchorForm::Unavailable => "unavailable",
        };
        json!({"path": a.path, "line": a.line.map(dviscope_model::values::SafeU64::get), "form": form})
    });
    let v = json!({
        "schema": FINGERPRINT_SCHEMA,
        "key": {
            "family": key.family,
            "diag_id": key.diag_id,
            "checker_scope": key.checker_scope,
            "identity_template": key.identity_template,
            "significant": key.significant,
            "anchor": anchor,
        }
    });
    // The JSON above contains only strings, integers and nulls: canonicalization cannot fail.
    digest_of(&v).unwrap_or_else(|_| Digest::of_bytes(v.to_string().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_classes() {
        for (v, c) in [
            ("0x0", "zero"),
            ("0xa", "nonzero"),
            ("'h0", "zero"),
            ("8'hff", "nonzero"),
            ("4'b10x1", "x"),
            ("0", "zero"),
            ("12", "nonzero"),
            ("abc", "nonzero"),
            ("zz", "x"),
            ("", "other"),
            ("ghi", "other"),
            ("'0", "zero"),
            ("'1", "nonzero"),
            ("'x", "x"),
            ("'z", "x"),
        ] {
            assert_eq!(numeric_class(v), c, "{v}");
        }
    }

    #[test]
    fn missing_field_never_equals_a_value() {
        let s = Significance::ZeroVsNonzero;
        assert_eq!(significant_class(&s, None), "missing");
        assert_ne!(
            significant_class(&s, None),
            significant_class(&s, Some(&FieldValue::Text("0".into())))
        );
    }

    #[test]
    fn anchors() {
        let roots = vec!["/home/u/repo/".to_string(), r"D:\w\repo".to_string()];
        assert_eq!(
            anchor("/home/u/repo/tb/a.sv", Some(3), "auto", &roots).path,
            "tb/a.sv"
        );
        let w = anchor(r"D:\w\repo\tb\a.sv", Some(3), "auto", &roots);
        assert_eq!(
            (w.path.as_str(), w.form),
            ("tb/a.sv", AnchorForm::RepoRelative)
        );
        assert_eq!(
            anchor("..ong.sv", Some(3), "auto", &roots).form,
            AnchorForm::Truncated
        );
        assert_eq!(
            anchor("/elsewhere/a.sv", None, "auto", &roots).form,
            AnchorForm::Full
        );
    }

    #[test]
    fn fingerprint_depends_on_every_key_part() {
        let base = FamilyKey {
            family: "uvm-app".into(),
            diag_id: "uvm:X".into(),
            checker_scope: Some("env".into()),
            identity_template: "m".into(),
            significant: BTreeMap::new(),
            anchor: None,
        };
        let mut other = base.clone();
        other.significant.insert("act".into(), "zero".into());
        assert_ne!(fingerprint(&base), fingerprint(&other));
        let mut scope = base.clone();
        scope.checker_scope = None;
        assert_ne!(fingerprint(&base), fingerprint(&scope));
        assert_eq!(fingerprint(&base), fingerprint(&base.clone()));
    }
}
