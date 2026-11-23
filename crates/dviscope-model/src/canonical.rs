//! Canonical JSON (RFC 8785, JCS) and `sha256:` digests.
//!
//! DVIScope digests only objects built from strings, booleans, `null`, integers, arrays and
//! objects. Non-integer numbers are rejected instead of being formatted: decimal measures
//! travel as strings (`"0.130"`), so the ECMAScript number formatting of RFC 8785 §3.2.2.3
//! is never needed and cannot drift between implementations.

use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Why a value cannot be canonicalized.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonicalError {
    /// A number that is not an integer in the exact range of an IEEE double.
    #[error("non-integer or out-of-range number {0}; send decimals as strings")]
    UnsupportedNumber(String),
    /// The value could not be serialized to JSON.
    #[error("cannot serialize value: {0}")]
    Serialize(String),
}

/// Largest integer an IEEE double represents exactly (2^53 - 1).
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// The canonical JSON text of `value` (RFC 8785).
///
/// # Errors
/// [`CanonicalError::UnsupportedNumber`] for non-integer numbers or integers beyond 2^53 - 1.
pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // RFC 8785 §3.2.3: sort by the UTF-16 code units of the keys.
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), CanonicalError> {
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            return Err(CanonicalError::UnsupportedNumber(n.to_string()));
        }
        out.push_str(&u.to_string());
    } else if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(CanonicalError::UnsupportedNumber(n.to_string()));
        }
        out.push_str(&i.to_string());
    } else {
        return Err(CanonicalError::UnsupportedNumber(n.to_string()));
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2: ECMAScript `JSON.stringify` string escaping.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A `sha256:<64 lowercase hex>` digest.
#[derive(
    Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);

impl Digest {
    /// The digest of raw bytes.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }

    /// The textual form, `sha256:...`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Digest {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        let hex_part = s
            .strip_prefix("sha256:")
            .ok_or_else(|| format!("digest must start with sha256: ({s})"))?;
        if hex_part.len() == 64
            && hex_part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(s))
        } else {
            Err(format!(
                "digest must be sha256: followed by 64 lowercase hex digits ({s})"
            ))
        }
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> Self {
        d.0
    }
}

/// Incremental SHA-256 of streamed bytes (log sources).
#[derive(Clone, Default)]
pub struct StreamDigest(Sha256);

impl StreamDigest {
    /// A new, empty digest.
    #[must_use]
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    /// Adds bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Lowercase hex of the digest.
    #[must_use]
    pub fn finish_hex(self) -> String {
        hex::encode(self.0.finalize())
    }
}

impl fmt::Debug for StreamDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamDigest")
    }
}

/// The digest of the canonical JSON of any serializable value.
///
/// # Errors
/// See [`canonical_json`]; also fails if `value` cannot be serialized.
pub fn digest_of<T: Serialize>(value: &T) -> Result<Digest, CanonicalError> {
    let v = serde_json::to_value(value).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    Ok(Digest::of_bytes(canonical_json(&v)?.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: &Value) -> String {
        canonical_json(v).unwrap_or_else(|e| panic!("{e}"))
    }

    // RFC 8785 §3.2.3, property sorting example.
    #[test]
    fn rfc8785_key_sorting() {
        let v: Value = serde_json::from_str(
            r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(canon(&v), expected);
    }

    // RFC 8785 §3.2.2.2, string escaping example.
    #[test]
    fn rfc8785_string_escaping() {
        let v: Value = serde_json::from_str(r#""\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/""#)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(canon(&v), "\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"");
    }

    #[test]
    fn literals_arrays_and_nesting() {
        let v = json!({"b": [true, false, null, 0, -1, 9_007_199_254_740_991_u64], "a": {"z": "", "y": []}});
        assert_eq!(
            canon(&v),
            r#"{"a":{"y":[],"z":""},"b":[true,false,null,0,-1,9007199254740991]}"#
        );
    }

    #[test]
    fn rejects_non_integers_and_large_integers() {
        assert!(matches!(
            canonical_json(&json!(1.5)),
            Err(CanonicalError::UnsupportedNumber(_))
        ));
        assert!(matches!(
            canonical_json(&json!(9_007_199_254_740_992_u64)),
            Err(CanonicalError::UnsupportedNumber(_))
        ));
    }

    #[test]
    fn digest_format_and_validation() {
        let d = Digest::of_bytes(b"");
        assert_eq!(
            d.as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(Digest::try_from("sha256:E3B0".to_string()).is_err());
        assert!(Digest::try_from(d.as_str().to_string()).is_ok());
    }

    proptest::proptest! {
        // Key order of the input never changes the canonical form.
        #[test]
        fn key_order_independent(keys in proptest::collection::btree_set("[a-z\u{80}-\u{2000}]{1,6}", 1..8)) {
            let forward: serde_json::Map<String, Value> = keys.iter().map(|k| (k.clone(), json!(k.len()))).collect();
            let backward: serde_json::Map<String, Value> = keys.iter().rev().map(|k| (k.clone(), json!(k.len()))).collect();
            proptest::prop_assert_eq!(canon(&Value::Object(forward)), canon(&Value::Object(backward)));
        }
    }
}
