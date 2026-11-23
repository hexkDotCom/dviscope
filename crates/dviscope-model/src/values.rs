//! Scalar wire values with validated text forms: decimal integers (seeds, large counters),
//! decimal measures (`"0.130"`), and UTC timestamps.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Validation error for scalar values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ValueError(pub String);

/// A non-negative JSON integer no larger than 2^53 − 1, so it is exact in every JSON
/// implementation and always canonicalizable. Counts, sizes, offsets and ordinals use it;
/// values that may exceed it (seeds) use [`DecimalInteger`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(try_from = "u64", into = "u64")]
pub struct SafeU64(u64);

impl SafeU64 {
    /// A value, saturated at [`SafeU64::MAX`].
    #[must_use]
    pub fn saturating(v: u64) -> Self {
        Self(v.min(Self::MAX))
    }

    /// 2^53 − 1.
    pub const MAX: u64 = 9_007_199_254_740_991;

    /// The value.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SafeU64 {
    type Error = ValueError;
    fn try_from(v: u64) -> Result<Self, ValueError> {
        if v <= Self::MAX {
            Ok(Self(v))
        } else {
            Err(ValueError(format!("{v} exceeds 2^53 - 1")))
        }
    }
}

impl From<SafeU64> for u64 {
    fn from(v: SafeU64) -> u64 {
        v.0
    }
}

impl schemars::JsonSchema for SafeU64 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SafeU64".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({"type": "integer", "minimum": 0, "maximum": 9_007_199_254_740_991_u64})
    }
}

/// A non-negative decimal integer of up to 39 digits, as a string (seeds, large counters).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct DecimalInteger(String);

impl DecimalInteger {
    /// Zero.
    #[must_use]
    pub fn zero() -> Self {
        Self("0".to_string())
    }

    /// From a count.
    #[must_use]
    pub fn from_u64(n: u64) -> Self {
        Self(n.to_string())
    }

    /// The textual form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DecimalInteger {
    type Error = ValueError;
    fn try_from(s: String) -> Result<Self, ValueError> {
        let ok = !s.is_empty()
            && s.len() <= 39
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'));
        if ok {
            Ok(Self(s))
        } else {
            Err(ValueError(format!(
                "not a canonical decimal integer: {s:?}"
            )))
        }
    }
}

impl TryFrom<&str> for DecimalInteger {
    type Error = ValueError;
    fn try_from(s: &str) -> Result<Self, ValueError> {
        Self::try_from(s.to_string())
    }
}

impl From<DecimalInteger> for String {
    fn from(v: DecimalInteger) -> String {
        v.0
    }
}

impl fmt::Debug for DecimalInteger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A non-negative decimal measure with an optional fraction, as a string (`"812.4"`).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct Measure(String);

impl TryFrom<String> for Measure {
    type Error = ValueError;
    fn try_from(s: String) -> Result<Self, ValueError> {
        let (int, frac) = s
            .split_once('.')
            .map_or((s.as_str(), None), |(a, b)| (a, Some(b)));
        let int_ok = !int.is_empty() && int.len() <= 20 && int.bytes().all(|b| b.is_ascii_digit());
        let frac_ok = frac
            .is_none_or(|f| !f.is_empty() && f.len() <= 9 && f.bytes().all(|b| b.is_ascii_digit()));
        if int_ok && frac_ok {
            Ok(Self(s))
        } else {
            Err(ValueError(format!("not a decimal measure: {s:?}")))
        }
    }
}

impl TryFrom<&str> for Measure {
    type Error = ValueError;
    fn try_from(s: &str) -> Result<Self, ValueError> {
        Self::try_from(s.to_string())
    }
}

impl From<Measure> for String {
    fn from(v: Measure) -> String {
        v.0
    }
}

impl fmt::Debug for Measure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A UTC timestamp, RFC 3339 with `Z` and millisecond precision on output.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UtcTime(OffsetDateTime);

impl UtcTime {
    /// Wraps a time, converting it to UTC.
    #[must_use]
    pub fn new(t: OffsetDateTime) -> Self {
        Self(t.to_offset(time::UtcOffset::UTC))
    }

    /// The wrapped time.
    #[must_use]
    pub fn get(self) -> OffsetDateTime {
        self.0
    }
}

impl TryFrom<String> for UtcTime {
    type Error = ValueError;
    fn try_from(s: String) -> Result<Self, ValueError> {
        if !s.ends_with('Z') {
            return Err(ValueError(format!("timestamp must be UTC with Z: {s:?}")));
        }
        OffsetDateTime::parse(&s, &Rfc3339)
            .map(Self::new)
            .map_err(|e| ValueError(format!("not an RFC 3339 timestamp: {s:?} ({e})")))
    }
}

impl From<UtcTime> for String {
    fn from(t: UtcTime) -> String {
        let ms = t.0.millisecond();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            t.0.year(),
            u8::from(t.0.month()),
            t.0.day(),
            t.0.hour(),
            t.0.minute(),
            t.0.second(),
            ms
        )
    }
}

impl fmt::Debug for UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from(*self))
    }
}

impl schemars::JsonSchema for UtcTime {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "UtcTime".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "format": "date-time",
            "pattern": "Z$",
            "description": "RFC 3339 UTC timestamp ending in Z"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_integer_rules() {
        assert!(DecimalInteger::try_from("18446744073709551615").is_ok());
        assert!(DecimalInteger::try_from("0").is_ok());
        assert!(DecimalInteger::try_from("012").is_err());
        assert!(DecimalInteger::try_from("-1").is_err());
        assert!(DecimalInteger::try_from("").is_err());
    }

    #[test]
    fn measure_rules() {
        assert!(Measure::try_from("812.4").is_ok());
        assert!(Measure::try_from("0.130").is_ok());
        assert!(Measure::try_from("1.").is_err());
        assert!(Measure::try_from("1e3").is_err());
    }

    #[test]
    fn utc_time_round_trip() {
        let t =
            UtcTime::try_from("2026-11-07T02:14:00Z".to_string()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(String::from(t), "2026-11-07T02:14:00.000Z");
        assert!(UtcTime::try_from("2026-11-07T02:14:00+01:00".to_string()).is_err());
    }
}
