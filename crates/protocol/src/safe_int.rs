//! JSON-safe counters (PROTOCOL.md §0).
//!
//! `seq`, `revision` and log indexes travel as JSON numbers. They are limited
//! to 2^53 − 1 so that JavaScript clients (the browser extension) read them
//! exactly. Use with `#[serde(with = "crate::safe_int")]` on `u64` fields.

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serializer};

/// Largest value a counter may have: `Number.MAX_SAFE_INTEGER`.
pub const MAX: u64 = (1 << 53) - 1;

pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    if *value > MAX {
        return Err(S::Error::custom("counter exceeds 2^53 - 1"));
    }
    serializer.serialize_u64(*value)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value > MAX {
        return Err(D::Error::custom("counter exceeds 2^53 - 1"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::MAX;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Counter {
        #[serde(with = "super")]
        n: u64,
    }

    #[test]
    fn accepts_up_to_max() {
        let json = format!(r#"{{"n":{MAX}}}"#);
        let c: Counter = serde_json::from_str(&json).unwrap();
        assert_eq!(c.n, MAX);
        assert_eq!(serde_json::to_string(&c).unwrap(), json);
    }

    #[test]
    fn rejects_above_max() {
        assert!(serde_json::from_str::<Counter>(r#"{"n":9007199254740992}"#).is_err());
        assert!(serde_json::from_str::<Counter>(r#"{"n":18446744073709551615}"#).is_err());
        assert!(serde_json::to_string(&Counter { n: MAX + 1 }).is_err());
    }

    #[test]
    fn rejects_negative_and_fractional() {
        assert!(serde_json::from_str::<Counter>(r#"{"n":-1}"#).is_err());
        assert!(serde_json::from_str::<Counter>(r#"{"n":1.5}"#).is_err());
    }
}
