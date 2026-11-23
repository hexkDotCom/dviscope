//! Wire types of the ingest and evidence schemas. Provisional until the
//! 0.1 contracts are frozen.
//!
//! Conventions: `snake_case` fields and enum values; optional scalars are
//! absent when unknown; arrays are always present (possibly empty); unknown fields are
//! rejected except inside `ext` (namespaced keys); counts, sizes and offsets are
//! [`SafeU64`](crate::values::SafeU64); seeds are decimal strings.

pub mod checklist;
pub mod evidence;
pub mod hierarchy;
pub mod ingest;
pub mod manifest;
pub mod regression;

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// A namespaced extension key, `namespace.name` (lowercase namespace; letters, digits, `-`,
/// `_`, `.` in the name).
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct ExtKey(String);

impl TryFrom<String> for ExtKey {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let (ns, name) = s
            .split_once('.')
            .ok_or_else(|| format!("extension key must be namespace.name: {s:?}"))?;
        let ns_ok = !ns.is_empty()
            && ns.len() <= 64
            && ns
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let name_ok = !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if ns_ok && name_ok {
            Ok(Self(s))
        } else {
            Err(format!("invalid extension key {s:?}"))
        }
    }
}

impl From<ExtKey> for String {
    fn from(k: ExtKey) -> String {
        k.0
    }
}

impl fmt::Debug for ExtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An extension value: any JSON whose numbers are integers within ±(2^53 − 1), so every
/// accepted record has a defined canonical digest (decimals travel as strings).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "serde_json::Value", into = "serde_json::Value")]
pub struct ExtValue(serde_json::Value);

impl ExtValue {
    /// The value.
    #[must_use]
    pub fn get(&self) -> &serde_json::Value {
        &self.0
    }
}

impl TryFrom<serde_json::Value> for ExtValue {
    type Error = String;
    fn try_from(v: serde_json::Value) -> Result<Self, String> {
        crate::canonical::canonical_json(&v).map_err(|e| format!("extension value: {e}"))?;
        Ok(Self(v))
    }
}

impl From<ExtValue> for serde_json::Value {
    fn from(v: ExtValue) -> Self {
        v.0
    }
}

impl fmt::Debug for ExtValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Namespaced extension data, preserved but never interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ext(pub BTreeMap<ExtKey, ExtValue>);

impl schemars::JsonSchema for Ext {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Ext".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "description": "Namespaced extension data (namespace.name keys); numbers must be integers within +/-(2^53-1)",
            "propertyNames": {"pattern": "^[a-z0-9-]{1,64}\\.[A-Za-z0-9_.-]{1,128}$"},
            "additionalProperties": {"$ref": "#/$defs/ExtValue"},
            "$defs": {
                "ExtValue": {
                    "anyOf": [
                        {"type": "null"},
                        {"type": "boolean"},
                        {"type": "string"},
                        {"type": "integer", "minimum": -9_007_199_254_740_991_i64, "maximum": 9_007_199_254_740_991_i64},
                        {"type": "array", "items": {"$ref": "#/$defs/ExtValue"}},
                        {"type": "object", "additionalProperties": {"$ref": "#/$defs/ExtValue"}}
                    ]
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_keys_are_namespaced() {
        assert!(ExtKey::try_from("acme.queue_name".to_string()).is_ok());
        assert!(ExtKey::try_from("queue".to_string()).is_err());
        assert!(ExtKey::try_from("ACME.x".to_string()).is_err());
        let v: Result<Ext, _> = serde_json::from_str(r#"{"bad key": 1}"#);
        assert!(v.is_err());
    }

    #[test]
    fn ext_values_are_canonicalizable() {
        let ok: Result<Ext, _> = serde_json::from_str(r#"{"acme.n": 3, "acme.s": "1.5"}"#);
        assert!(ok.is_ok());
        let float: Result<Ext, _> = serde_json::from_str(r#"{"acme.measure": 1.5}"#);
        assert!(float.is_err());
        let big: Result<Ext, _> = serde_json::from_str(r#"{"acme.n": 9007199254740992}"#);
        assert!(big.is_err());
    }

    #[test]
    fn schema_pattern_agrees_with_ext_key() {
        let schema = serde_json::to_value(schemars::schema_for!(Ext)).unwrap_or_default();
        let pattern = schema["propertyNames"]["pattern"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(pattern.starts_with('^') && pattern.ends_with('$'));
        // Values: integers only (no "number"), within the safe range, recursively.
        let any_of = schema["$defs"]["ExtValue"]["anyOf"].clone();
        let types: Vec<String> = any_of
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x["type"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        assert!(types.contains(&"integer".to_string()) && !types.contains(&"number".to_string()));
        let int = any_of
            .as_array()
            .and_then(|a| a.iter().find(|x| x["type"] == "integer"))
            .cloned()
            .unwrap_or_default();
        assert_eq!(int["maximum"], 9_007_199_254_740_991_i64);
        for (key, valid) in [
            ("acme.queue_name", true),
            ("queue", false),
            ("ACME.x", false),
            ("a.b.c", true),
        ] {
            assert_eq!(ExtKey::try_from(key.to_string()).is_ok(), valid, "{key}");
        }
    }
}
