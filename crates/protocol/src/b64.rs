//! Binary fields in JSON: base64url without padding (PROTOCOL.md §0).
//!
//! [`B64`] is used for opaque binary values: ciphertexts, envelopes,
//! signatures and public keys. Decoding is strict. Padding, the standard
//! alphabet (`+` and `/`), whitespace and non-canonical trailing bits are all
//! rejected, so every byte string has exactly one JSON spelling.

use core::fmt;
use core::ops::Deref;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The text was not unpadded base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct B64Error(base64::DecodeError);

impl fmt::Display for B64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid unpadded base64url: {}", self.0)
    }
}

impl core::error::Error for B64Error {}

/// Bytes that serialize as an unpadded base64url string.
///
/// Not for secrets: `Debug` prints only the length, but the buffer is not
/// zeroized and `==` is not constant-time.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct B64(Vec<u8>);

impl B64 {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Encodes `bytes` as unpadded base64url.
    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Strictly decodes unpadded base64url.
    pub fn decode(text: &str) -> Result<Self, B64Error> {
        URL_SAFE_NO_PAD.decode(text).map(Self).map_err(B64Error)
    }
}

impl fmt::Debug for B64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "B64(<{} bytes>)", self.0.len())
    }
}

impl fmt::Display for B64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Self::encode(&self.0))
    }
}

impl Deref for B64 {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for B64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for B64 {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for B64 {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for B64 {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for B64 {
    fn from(bytes: &[u8; N]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<B64> for Vec<u8> {
    fn from(b: B64) -> Self {
        b.0
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&Self::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct B64Visitor;

        impl Visitor<'_> for B64Visitor {
            type Value = B64;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an unpadded base64url string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<B64, E> {
                B64::decode(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(B64Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        for bytes in [
            &b""[..],
            &b"f"[..],
            &b"fo"[..],
            &b"foo"[..],
            &[0xfb, 0xff, 0xfe][..],
            &[0u8; 33][..],
        ] {
            let value = B64::from(bytes);
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(serde_json::from_str::<B64>(&json).unwrap(), value);
        }
    }

    #[test]
    fn known_vectors() {
        // RFC 4648 §10 with the padding removed.
        assert_eq!(B64::encode(b""), "");
        assert_eq!(B64::encode(b"f"), "Zg");
        assert_eq!(B64::encode(b"fo"), "Zm8");
        assert_eq!(B64::encode(b"foo"), "Zm9v");
        assert_eq!(B64::encode(b"foob"), "Zm9vYg");
        // Bytes that differ between the URL-safe and standard alphabets.
        assert_eq!(B64::encode(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(
            serde_json::to_string(&B64::from(b"foo")).unwrap(),
            "\"Zm9v\""
        );
    }

    #[test]
    fn rejects_padding() {
        for text in ["Zg==", "Zm8=", "Zm9v=", "=="] {
            assert!(B64::decode(text).is_err(), "accepted {text:?}");
            let json = serde_json::to_string(text).unwrap();
            assert!(serde_json::from_str::<B64>(&json).is_err());
        }
    }

    #[test]
    fn rejects_standard_alphabet_and_junk() {
        for text in [
            "+/+/", "-__+", " Zm9v", "Zm9v ", "Zm 9v", "Zm9v\n", "Zm9", "Z", "Zm9v!", "é",
        ] {
            assert!(B64::decode(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // "Zh" decodes to the same byte as "Zg" unless trailing bits are checked.
        assert!(B64::decode("Zg").is_ok());
        assert!(B64::decode("Zh").is_err());
    }

    #[test]
    fn rejects_non_string_json() {
        assert!(serde_json::from_str::<B64>("12").is_err());
        assert!(serde_json::from_str::<B64>("null").is_err());
        assert!(serde_json::from_str::<B64>("[1,2]").is_err());
    }

    #[test]
    fn debug_hides_contents() {
        let shown = format!("{:?}", B64::from(b"hunter2"));
        assert_eq!(shown, "B64(<7 bytes>)");
    }

    #[test]
    fn accessors() {
        let b = B64::from([1u8, 2, 3]);
        assert_eq!(b.len(), 3);
        assert_eq!(b.as_slice(), &[1, 2, 3]);
        assert_eq!(b.to_string(), "AQID");
        assert_eq!(Vec::from(b), vec![1, 2, 3]);
    }
}
