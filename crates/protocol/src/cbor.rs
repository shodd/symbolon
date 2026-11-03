//! Deterministic CBOR (RFC 8949 §4.2.1, "core deterministic encoding").
//!
//! Only the subset the protocol uses is supported: unsigned and negative
//! integers, byte strings, text strings, `false`/`true`/`null`, arrays and maps.
//! Tags, floats, `undefined`, other simple values and indefinite lengths are
//! not part of the protocol and are rejected.
//!
//! - [`Value::encode`] always produces the deterministic encoding: shortest-form
//!   heads, definite lengths, map keys sorted bytewise by their encoded form.
//! - [`decode`] is strict: it accepts *only* deterministic encodings, so for any
//!   accepted input `decode(x)?.encode()? == x`. Signed and authenticated data
//!   (PROTOCOL.md §0) relies on this.
//!
//! `Value` can carry secrets (item plaintext, wrapped key material). It
//! implements [`Zeroize`] so callers can hold it in `Zeroizing<Value>`, its
//! `Debug` output redacts all string contents, and [`Value::encode`] allocates
//! the output once at its final size so no partial copies are left behind by
//! reallocation. `PartialEq` is *not* constant time; don't use it on secrets.

use core::cmp::Ordering;
use core::fmt;

use zeroize::Zeroize;

/// Maximum nesting depth of arrays and maps, for both encoding and decoding.
/// The top-level value is depth 0; `[[1]]` has depth 2.
pub const MAX_DEPTH: usize = 64;

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;

/// A CBOR data item from the protocol's subset.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0: an integer in `0..=u64::MAX`.
    Unsigned(u64),
    /// Major type 1: the integer `-1 - n`, so `Negative(0)` is `-1` and
    /// `Negative(u64::MAX)` is `-2^64`.
    Negative(u64),
    /// Major type 2: a byte string (`bstr`).
    Bytes(Vec<u8>),
    /// Major type 3: a UTF-8 text string (`tstr`).
    Text(String),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// Major type 4: an array.
    Array(Vec<Value>),
    /// Major type 5: a map. Entries may be given in any order; encoding sorts
    /// them. Duplicate keys are an encoding error.
    Map(Vec<(Value, Value)>),
}

/// Why a value could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// A map contains the same key twice.
    DuplicateMapKey,
    /// Arrays and maps are nested deeper than [`MAX_DEPTH`].
    DepthLimitExceeded,
}

/// Why input was rejected by the strict decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ended in the middle of a data item.
    UnexpectedEnd,
    /// Extra bytes follow the top-level data item.
    TrailingBytes,
    /// An integer, length or count was not encoded in its shortest form.
    NonCanonicalInteger,
    /// Indefinite-length strings, arrays and maps are not allowed.
    IndefiniteLength,
    /// A tag, float, `undefined` or other simple value: valid CBOR, but not
    /// part of the protocol.
    UnsupportedType,
    /// Not well-formed CBOR (reserved additional information, stray "break").
    Malformed,
    /// A text string is not valid UTF-8.
    InvalidUtf8,
    /// Map keys are not in ascending bytewise order of their encoding.
    UnsortedMapKeys,
    /// A map contains the same key twice.
    DuplicateMapKey,
    /// Arrays and maps are nested deeper than [`MAX_DEPTH`].
    DepthLimitExceeded,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DuplicateMapKey => "CBOR map contains a duplicate key",
            Self::DepthLimitExceeded => "CBOR value is nested too deeply",
        })
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnexpectedEnd => "CBOR input ends unexpectedly",
            Self::TrailingBytes => "CBOR input has trailing bytes",
            Self::NonCanonicalInteger => "CBOR integer or length is not in shortest form",
            Self::IndefiniteLength => "CBOR indefinite lengths are not allowed",
            Self::UnsupportedType => "CBOR type is not supported by the protocol",
            Self::Malformed => "CBOR input is malformed",
            Self::InvalidUtf8 => "CBOR text string is not valid UTF-8",
            Self::UnsortedMapKeys => "CBOR map keys are not in canonical order",
            Self::DuplicateMapKey => "CBOR map contains a duplicate key",
            Self::DepthLimitExceeded => "CBOR value is nested too deeply",
        })
    }
}

impl core::error::Error for EncodeError {}
impl core::error::Error for DecodeError {}

// ---------------------------------------------------------------------------
// Encoding

impl Value {
    /// Encodes this value deterministically (RFC 8949 §4.2.1).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        self.check_depth(0)?;
        let len = self.encoded_len();
        let mut out = Vec::with_capacity(len);
        if let Err(e) = self.encode_into(&mut out) {
            // A partial encoding may already hold secret bytes.
            out.zeroize();
            return Err(e);
        }
        debug_assert_eq!(out.len(), len);
        Ok(out)
    }

    /// Length in bytes of the deterministic encoding.
    ///
    /// Recursion is unbounded here, so this is only called after `check_depth`.
    fn encoded_len(&self) -> usize {
        match self {
            Self::Unsigned(n) | Self::Negative(n) => head_len(*n),
            Self::Bytes(b) => head_len(b.len() as u64) + b.len(),
            Self::Text(s) => head_len(s.len() as u64) + s.len(),
            Self::Bool(_) | Self::Null => 1,
            Self::Array(items) => {
                head_len(items.len() as u64) + items.iter().map(Value::encoded_len).sum::<usize>()
            }
            Self::Map(entries) => {
                head_len(entries.len() as u64)
                    + entries
                        .iter()
                        .map(|(k, v)| k.encoded_len() + v.encoded_len())
                        .sum::<usize>()
            }
        }
    }

    fn check_depth(&self, depth: usize) -> Result<(), EncodeError> {
        match self {
            Self::Array(_) | Self::Map(_) if depth >= MAX_DEPTH => {
                Err(EncodeError::DepthLimitExceeded)
            }
            Self::Array(items) => items.iter().try_for_each(|v| v.check_depth(depth + 1)),
            Self::Map(entries) => entries.iter().try_for_each(|(k, v)| {
                k.check_depth(depth + 1)?;
                v.check_depth(depth + 1)
            }),
            _ => Ok(()),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Unsigned(n) => write_head(out, MAJOR_UNSIGNED, *n),
            Self::Negative(n) => write_head(out, MAJOR_NEGATIVE, *n),
            Self::Bytes(b) => {
                write_head(out, MAJOR_BYTES, b.len() as u64);
                out.extend_from_slice(b);
            }
            Self::Text(s) => {
                write_head(out, MAJOR_TEXT, s.len() as u64);
                out.extend_from_slice(s.as_bytes());
            }
            Self::Bool(false) => out.push(FALSE),
            Self::Bool(true) => out.push(TRUE),
            Self::Null => out.push(NULL),
            Self::Array(items) => {
                write_head(out, MAJOR_ARRAY, items.len() as u64);
                for item in items {
                    item.encode_into(out)?;
                }
            }
            Self::Map(entries) => {
                // Sort by encoded key. The key buffers are wiped afterwards
                // because keys may in principle be secret.
                let mut keyed: Vec<(Vec<u8>, &Value)> = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    let mut kb = Vec::with_capacity(k.encoded_len());
                    k.encode_into(&mut kb)?;
                    keyed.push((kb, v));
                }
                keyed.sort_by(|a, b| a.0.cmp(&b.0));
                let duplicate = keyed.windows(2).any(|w| w[0].0 == w[1].0);
                if !duplicate {
                    write_head(out, MAJOR_MAP, keyed.len() as u64);
                }
                let mut result = if duplicate {
                    Err(EncodeError::DuplicateMapKey)
                } else {
                    Ok(())
                };
                for (kb, v) in &mut keyed {
                    if result.is_ok() {
                        out.extend_from_slice(kb);
                        result = v.encode_into(out);
                    }
                    kb.zeroize();
                }
                result?;
            }
        }
        Ok(())
    }
}

fn head_len(arg: u64) -> usize {
    match arg {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    match arg {
        0..=23 => out.push(mt | arg as u8),
        24..=0xff => out.extend_from_slice(&[mt | 24, arg as u8]),
        0x100..=0xffff => {
            out.push(mt | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(mt | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(mt | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding

/// Decodes exactly one deterministically encoded data item, rejecting any
/// input that is not in deterministic form or contains trailing bytes.
pub fn decode(input: &[u8]) -> Result<Value, DecodeError> {
    let mut d = Decoder { input, pos: 0 };
    let value = d.value(0)?;
    if d.pos != input.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::UnexpectedEnd);
        }
        let s = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// Reads the argument for additional information `ai` and enforces the
    /// shortest-form rule.
    fn argument(&mut self, ai: u8) -> Result<u64, DecodeError> {
        let (arg, min) = match ai {
            0..=23 => return Ok(u64::from(ai)),
            24 => (u64::from(self.byte()?), 24),
            25 => {
                let b = self.take(2)?;
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 0x100)
            }
            26 => {
                let b = self.take(4)?;
                (
                    u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                    0x1_0000,
                )
            }
            27 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(self.take(8)?);
                (u64::from_be_bytes(a), 0x1_0000_0000)
            }
            31 => return Err(DecodeError::IndefiniteLength),
            _ => return Err(DecodeError::Malformed), // 28..=30 are reserved
        };
        if arg < min {
            return Err(DecodeError::NonCanonicalInteger);
        }
        Ok(arg)
    }

    /// A length or count that must fit in the remaining input, where every
    /// counted element takes at least `min_bytes_each` bytes. Checking this
    /// up front stops huge allocations from tiny inputs.
    fn length(&mut self, ai: u8, min_bytes_each: usize) -> Result<usize, DecodeError> {
        let arg = self.argument(ai)?;
        let needed = usize::try_from(arg)
            .ok()
            .and_then(|n| n.checked_mul(min_bytes_each))
            .ok_or(DecodeError::UnexpectedEnd)?;
        if needed > self.remaining() {
            return Err(DecodeError::UnexpectedEnd);
        }
        Ok(arg as usize)
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;
        match major {
            MAJOR_UNSIGNED => Ok(Value::Unsigned(self.argument(ai)?)),
            MAJOR_NEGATIVE => Ok(Value::Negative(self.argument(ai)?)),
            MAJOR_BYTES => {
                let len = self.length(ai, 1)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            MAJOR_TEXT => {
                let len = self.length(ai, 1)?;
                let s =
                    core::str::from_utf8(self.take(len)?).map_err(|_| DecodeError::InvalidUtf8)?;
                Ok(Value::Text(s.into()))
            }
            MAJOR_ARRAY | MAJOR_MAP => {
                if depth >= MAX_DEPTH {
                    return Err(DecodeError::DepthLimitExceeded);
                }
                if major == MAJOR_ARRAY {
                    self.array(ai, depth)
                } else {
                    self.map(ai, depth)
                }
            }
            MAJOR_TAG => Err(DecodeError::UnsupportedType),
            MAJOR_SIMPLE => match initial {
                FALSE => Ok(Value::Bool(false)),
                TRUE => Ok(Value::Bool(true)),
                NULL => Ok(Value::Null),
                0xff => Err(DecodeError::Malformed), // "break" outside an indefinite item
                0xfc..=0xfe => Err(DecodeError::Malformed), // reserved
                // Other simple values, `undefined` and floats.
                _ => Err(DecodeError::UnsupportedType),
            },
            _ => unreachable!("major type is three bits"),
        }
    }

    fn array(&mut self, ai: u8, depth: usize) -> Result<Value, DecodeError> {
        let count = self.length(ai, 1)?;
        // Capacity is capped so an adversarial count can't force a large
        // allocation before the elements are actually read.
        let mut items = Vec::with_capacity(count.min(256));
        for _ in 0..count {
            match self.value(depth + 1) {
                Ok(v) => items.push(v),
                Err(e) => {
                    // Already decoded elements may be secrets.
                    items.zeroize();
                    return Err(e);
                }
            }
        }
        Ok(Value::Array(items))
    }

    fn map(&mut self, ai: u8, depth: usize) -> Result<Value, DecodeError> {
        let count = self.length(ai, 2)?;
        let mut entries = Vec::with_capacity(count.min(256));
        let result = self.map_entries(count, depth, &mut entries);
        if let Err(e) = result {
            // Already decoded entries may be secrets.
            for (k, v) in &mut entries {
                k.zeroize();
                v.zeroize();
            }
            return Err(e);
        }
        Ok(Value::Map(entries))
    }

    fn map_entries(
        &mut self,
        count: usize,
        depth: usize,
        entries: &mut Vec<(Value, Value)>,
    ) -> Result<(), DecodeError> {
        let mut prev_key: Option<&[u8]> = None;
        for _ in 0..count {
            let start = self.pos;
            let mut key = self.value(depth + 1)?;
            // The key was decoded strictly, so its input bytes are its
            // deterministic encoding and can be compared directly.
            let key_bytes = &self.input[start..self.pos];
            let order = prev_key.map_or(Ordering::Less, |prev| prev.cmp(key_bytes));
            if order != Ordering::Less {
                key.zeroize();
                return Err(if order == Ordering::Equal {
                    DecodeError::DuplicateMapKey
                } else {
                    DecodeError::UnsortedMapKeys
                });
            }
            prev_key = Some(key_bytes);
            match self.value(depth + 1) {
                Ok(value) => entries.push((key, value)),
                Err(e) => {
                    key.zeroize();
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Convenience

impl Value {
    /// A text string.
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    /// A byte string.
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(b.into())
    }

    /// Decodes `input` strictly; see [`decode`].
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        decode(input)
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(n) => Some(*n),
            _ => None,
        }
    }

    /// The integer value if it fits in an `i64`.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Unsigned(n) => i64::try_from(*n).ok(),
            Self::Negative(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Looks up a text key in a map. Returns `None` for non-maps.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Self::Unsigned(n)
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Self::Unsigned(n.into())
    }
}

impl From<u16> for Value {
    fn from(n: u16) -> Self {
        Self::Unsigned(n.into())
    }
}

impl From<u8> for Value {
    fn from(n: u8) -> Self {
        Self::Unsigned(n.into())
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        if n >= 0 {
            Self::Unsigned(n as u64)
        } else {
            // -1 - n without overflow: !n == -1 - n in two's complement.
            Self::Negative(!n as u64)
        }
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Text(s.into())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::Text(s)
    }
}

/// Byte vectors become byte strings, not arrays.
impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Self::Bytes(b)
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Self::Bytes(b.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Value {
    fn from(b: [u8; N]) -> Self {
        Self::Bytes(b.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Value {
    fn from(b: &[u8; N]) -> Self {
        Self::Bytes(b.to_vec())
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Self {
        Self::Array(items)
    }
}

impl Zeroize for Value {
    fn zeroize(&mut self) {
        match self {
            Self::Unsigned(n) | Self::Negative(n) => n.zeroize(),
            Self::Bytes(b) => b.zeroize(),
            Self::Text(s) => s.zeroize(),
            Self::Bool(b) => *b = false,
            Self::Null => {}
            Self::Array(items) => items.zeroize(),
            Self::Map(entries) => {
                for (k, v) in entries.iter_mut() {
                    k.zeroize();
                    v.zeroize();
                }
                entries.clear();
            }
        }
        *self = Self::Null;
    }
}

/// Redacts string contents, which may be secrets; shows structure, lengths,
/// integers and booleans.
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(n) => write!(f, "{n}"),
            Self::Negative(n) => write!(f, "-{}", u128::from(*n) + 1),
            Self::Bytes(b) => write!(f, "h'<{} bytes>'", b.len()),
            Self::Text(s) => write!(f, "\"<{} bytes>\"", s.len()),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Null => f.write_str("null"),
            Self::Array(items) => f.debug_list().entries(items).finish(),
            Self::Map(entries) => f
                .debug_map()
                .entries(entries.iter().map(|(k, v)| (k, v)))
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn enc(v: &Value) -> Vec<u8> {
        v.encode().unwrap()
    }

    fn t(s: &str) -> Value {
        Value::text(s)
    }

    fn map(entries: Vec<(Value, Value)>) -> Value {
        Value::Map(entries)
    }

    /// Encodes, checks the expected bytes, and checks the strict decoder
    /// round-trips them.
    fn check(v: Value, expected_hex: &str) {
        let bytes = enc(&v);
        assert_eq!(bytes, hex(expected_hex), "encoding of {v:?}");
        assert_eq!(decode(&bytes).unwrap(), v, "decoding of {expected_hex}");
    }

    #[test]
    fn rfc8949_appendix_a_integers() {
        check(Value::Unsigned(0), "00");
        check(Value::Unsigned(1), "01");
        check(Value::Unsigned(10), "0a");
        check(Value::Unsigned(23), "17");
        check(Value::Unsigned(24), "1818");
        check(Value::Unsigned(25), "1819");
        check(Value::Unsigned(100), "1864");
        check(Value::Unsigned(1000), "1903e8");
        check(Value::Unsigned(1_000_000), "1a000f4240");
        check(Value::Unsigned(1_000_000_000_000), "1b000000e8d4a51000");
        check(Value::Unsigned(u64::MAX), "1bffffffffffffffff");
        check(Value::Negative(u64::MAX), "3bffffffffffffffff");
        check(Value::from(-1i64), "20");
        check(Value::from(-10i64), "29");
        check(Value::from(-100i64), "3863");
        check(Value::from(-1000i64), "3903e7");
        check(Value::from(i64::MIN), "3b7fffffffffffffff");
        // Boundaries of each head size.
        check(Value::Unsigned(0xff), "18ff");
        check(Value::Unsigned(0x100), "190100");
        check(Value::Unsigned(0xffff), "19ffff");
        check(Value::Unsigned(0x1_0000), "1a00010000");
        check(Value::Unsigned(0xffff_ffff), "1affffffff");
        check(Value::Unsigned(0x1_0000_0000), "1b0000000100000000");
    }

    #[test]
    fn rfc8949_appendix_a_simple_and_strings() {
        check(Value::Bool(false), "f4");
        check(Value::Bool(true), "f5");
        check(Value::Null, "f6");
        check(Value::bytes(vec![]), "40");
        check(Value::bytes(vec![1, 2, 3, 4]), "4401020304");
        check(t(""), "60");
        check(t("a"), "6161");
        check(t("IETF"), "6449455446");
        check(t("\"\\"), "62225c");
        check(t("\u{00fc}"), "62c3bc");
        check(t("\u{6c34}"), "63e6b0b4");
        check(t("\u{10151}"), "64f0908591");
        check(
            Value::bytes(vec![0xaa; 24]),
            &format!("5818{}", "aa".repeat(24)),
        );
        check(
            Value::bytes(vec![0xbb; 256]),
            &format!("590100{}", "bb".repeat(256)),
        );
    }

    #[test]
    fn rfc8949_appendix_a_arrays_and_maps() {
        let n = |x: u64| Value::Unsigned(x);
        check(Value::Array(vec![]), "80");
        check(Value::Array(vec![n(1), n(2), n(3)]), "83010203");
        check(
            Value::Array(vec![
                n(1),
                Value::Array(vec![n(2), n(3)]),
                Value::Array(vec![n(4), n(5)]),
            ]),
            "8301820203820405",
        );
        check(
            Value::Array((1..=25).map(n).collect()),
            "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
        );
        check(map(vec![]), "a0");
        check(map(vec![(n(1), n(2)), (n(3), n(4))]), "a201020304");
        check(
            map(vec![
                (t("a"), n(1)),
                (t("b"), Value::Array(vec![n(2), n(3)])),
            ]),
            "a26161016162820203",
        );
        check(
            Value::Array(vec![t("a"), map(vec![(t("b"), t("c"))])]),
            "826161a161626163",
        );
        check(
            map(vec![
                (t("a"), t("A")),
                (t("b"), t("B")),
                (t("c"), t("C")),
                (t("d"), t("D")),
                (t("e"), t("E")),
            ]),
            "a56161614161626142616361436164614461656145",
        );
    }

    #[test]
    fn map_keys_are_sorted_by_encoded_bytes() {
        // RFC 8949 §4.2.1 example ordering: 10, 100, -1, "z", "aa", [100], [-1], false.
        let keys = [
            Value::Bool(false),
            Value::Array(vec![Value::from(-1i64)]),
            Value::Array(vec![Value::Unsigned(100)]),
            t("aa"),
            t("z"),
            Value::from(-1i64),
            Value::Unsigned(100),
            Value::Unsigned(10),
        ];
        let m = map(keys.iter().cloned().map(|k| (k, Value::Null)).collect());
        assert_eq!(
            enc(&m),
            hex("a80af61864f620f6617af6626161f6811864f68120f6f4f6"),
        );
        // Shorter text keys sort first even if they compare later as strings.
        let m = map(vec![(t("aa"), Value::Null), (t("b"), Value::Null)]);
        assert_eq!(enc(&m), hex("a26162f6626161f6"));
    }

    #[test]
    fn encode_rejects_duplicate_keys() {
        let m = map(vec![
            (t("a"), Value::Unsigned(1)),
            (t("a"), Value::Unsigned(2)),
        ]);
        assert_eq!(m.encode(), Err(EncodeError::DuplicateMapKey));
        let nested = Value::Array(vec![m]);
        assert_eq!(nested.encode(), Err(EncodeError::DuplicateMapKey));
    }

    fn nested_arrays(depth: usize) -> Value {
        let mut v = Value::Array(vec![]);
        for _ in 1..depth {
            v = Value::Array(vec![v]);
        }
        v
    }

    #[test]
    fn depth_limit_is_enforced_both_ways() {
        // MAX_DEPTH nested arrays are fine, one more is not.
        let ok = nested_arrays(MAX_DEPTH);
        let bytes = enc(&ok);
        assert_eq!(decode(&bytes).unwrap(), ok);
        assert_eq!(
            nested_arrays(MAX_DEPTH + 1).encode(),
            Err(EncodeError::DepthLimitExceeded)
        );
        let mut too_deep = vec![0x81; MAX_DEPTH];
        too_deep.push(0x80);
        assert_eq!(decode(&too_deep), Err(DecodeError::DepthLimitExceeded));
        // A very deep input must fail cleanly rather than overflow the stack.
        let mut huge = vec![0x81; 100_000];
        huge.push(0x80);
        assert_eq!(decode(&huge), Err(DecodeError::DepthLimitExceeded));
    }

    #[test]
    fn decode_rejects_non_canonical_heads() {
        for h in [
            "1800",               // 0 in one extra byte
            "1817",               // 23 in one extra byte
            "190001",             // 1 in two bytes
            "1900ff",             // 255 in two bytes
            "1a0000ffff",         // in four bytes
            "1b00000000ffffffff", // in eight bytes
            "3800",               // -1 in one extra byte
            "5801aa",             // bstr length 1 in one extra byte
            "780161",             // tstr length 1 in one extra byte
            "980101",             // array count in one extra byte
            "b8010101",           // map count in one extra byte
        ] {
            assert_eq!(
                decode(&hex(h)),
                Err(DecodeError::NonCanonicalInteger),
                "{h}"
            );
        }
    }

    #[test]
    fn decode_rejects_indefinite_lengths() {
        for h in ["5f4101ff", "7f6161ff", "9f01ff", "bf6161 01ff"] {
            let h = h.replace(' ', "");
            assert_eq!(decode(&hex(&h)), Err(DecodeError::IndefiniteLength), "{h}");
        }
    }

    #[test]
    fn decode_rejects_unsupported_types() {
        for h in [
            "c074323031332d30332d32315432303a30343a30305a", // tag 0
            "d82401",                                       // tag 36
            "f93c00",                                       // half float 1.0
            "fa47c35000",                                   // single float
            "fb3ff199999999999a",                           // double float
            "f7",                                           // undefined
            "f0",                                           // simple(16)
            "f820",                                         // simple(32)
        ] {
            assert_eq!(decode(&hex(h)), Err(DecodeError::UnsupportedType), "{h}");
        }
    }

    #[test]
    fn decode_rejects_malformed_input() {
        for h in ["1c", "1d", "1e", "5c", "ff", "fc", "fd", "fe", "81ff"] {
            assert_eq!(decode(&hex(h)), Err(DecodeError::Malformed), "{h}");
        }
        for h in [
            "",
            "18",
            "1901",
            "1b000000",
            "44010203",
            "62c3",
            "8301",
            "a16161",
            "5affffffff",
            "5bffffffffffffffff00",
            "9bffffffffffffffff",
            "bbffffffffffffffff",
            "ba80000000",
        ] {
            assert_eq!(decode(&hex(h)), Err(DecodeError::UnexpectedEnd), "{h:?}");
        }
        assert_eq!(decode(&hex("0000")), Err(DecodeError::TrailingBytes));
        assert_eq!(decode(&hex("8000")), Err(DecodeError::TrailingBytes));
        assert_eq!(decode(&hex("62c328")), Err(DecodeError::InvalidUtf8));
        assert_eq!(decode(&hex("63eda080")), Err(DecodeError::InvalidUtf8)); // surrogate
    }

    #[test]
    fn decode_rejects_unsorted_or_duplicate_keys() {
        assert_eq!(
            decode(&hex("a2616201616102")),
            Err(DecodeError::UnsortedMapKeys)
        );
        // "aa" before "b" is required (shorter encoding first).
        assert_eq!(
            decode(&hex("a2626161f66162f6")),
            Err(DecodeError::UnsortedMapKeys)
        );
        assert_eq!(
            decode(&hex("a2616101616102")),
            Err(DecodeError::DuplicateMapKey)
        );
        assert_eq!(
            decode(&hex("a201f601f6")),
            Err(DecodeError::DuplicateMapKey)
        );
        // Nested maps are checked too.
        assert_eq!(
            decode(&hex("81a2616201616102")),
            Err(DecodeError::UnsortedMapKeys)
        );
    }

    #[test]
    fn accessors_and_conversions() {
        let v = map(vec![
            (t("n"), Value::from(-5i64)),
            (t("b"), Value::from([1u8, 2])),
            (t("s"), Value::from("x")),
            (t("t"), Value::from(true)),
            (t("z"), Value::Null),
        ]);
        let v = decode(&enc(&v)).unwrap();
        assert_eq!(v.get("n").and_then(Value::as_i64), Some(-5));
        assert_eq!(v.get("b").and_then(Value::as_bytes), Some(&[1u8, 2][..]));
        assert_eq!(v.get("s").and_then(Value::as_text), Some("x"));
        assert_eq!(v.get("t").and_then(Value::as_bool), Some(true));
        assert!(v.get("z").is_some_and(Value::is_null));
        assert!(v.get("missing").is_none());
        assert_eq!(Value::Negative(u64::MAX).as_i64(), None);
        assert_eq!(Value::Unsigned(u64::MAX).as_i64(), None);
        assert_eq!(Value::from(i64::MIN).as_i64(), Some(i64::MIN));
    }

    #[test]
    fn debug_redacts_strings() {
        let v = map(vec![
            (t("password"), t("hunter2")),
            (t("k"), Value::bytes(vec![7; 3])),
        ]);
        let s = format!("{v:?}");
        assert!(!s.contains("hunter2") && !s.contains("password"), "{s}");
        assert!(s.contains("<7 bytes>") && s.contains("<3 bytes>"), "{s}");
    }

    #[test]
    fn zeroize_clears_value() {
        let mut v = Value::Array(vec![
            t("secret"),
            map(vec![(t("k"), Value::bytes(vec![1; 4]))]),
        ]);
        v.zeroize();
        assert_eq!(v, Value::Null);
    }

    /// Small deterministic PRNG so the property tests need no dependencies.
    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn random_value(rng: &mut XorShift, depth: usize) -> Value {
        let interesting = [
            0,
            1,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u64::MAX,
        ];
        let leaf_only = depth >= 4;
        match rng.below(if leaf_only { 6 } else { 8 }) {
            0 => Value::Unsigned(if rng.below(2) == 0 {
                interesting[rng.below(10) as usize]
            } else {
                rng.next() >> rng.below(64)
            }),
            1 => Value::Negative(rng.next() >> rng.below(64)),
            2 => Value::Bytes((0..rng.below(40)).map(|_| rng.next() as u8).collect()),
            3 => Value::Text(
                (0..rng.below(10))
                    .map(|_| ['a', 'Z', 'ü', '水', '😀'][rng.below(5) as usize])
                    .collect(),
            ),
            4 => Value::Bool(rng.below(2) == 0),
            5 => Value::Null,
            6 => Value::Array(
                (0..rng.below(5))
                    .map(|_| random_value(rng, depth + 1))
                    .collect(),
            ),
            _ => {
                let mut entries: Vec<(Value, Value)> = Vec::new();
                for _ in 0..rng.below(5) {
                    let k = random_value(rng, depth + 1);
                    if entries.iter().all(|(e, _)| *e != k) {
                        entries.push((k, random_value(rng, depth + 1)));
                    }
                }
                Value::Map(entries)
            }
        }
    }

    /// Sorts map entries the way the encoder does, so decoded values compare
    /// equal to the original.
    fn canonicalize(v: &mut Value) {
        match v {
            Value::Array(items) => items.iter_mut().for_each(canonicalize),
            Value::Map(entries) => {
                for (k, v) in entries.iter_mut() {
                    canonicalize(k);
                    canonicalize(v);
                }
                entries.sort_by_key(|(k, _)| k.encode().unwrap());
            }
            _ => {}
        }
    }

    #[test]
    fn random_values_round_trip() {
        let mut rng = XorShift(0x5359_4d42_4f4c_4f4e);
        for _ in 0..5_000 {
            let mut v = random_value(&mut rng, 0);
            let bytes = enc(&v);
            let decoded = decode(&bytes).unwrap();
            canonicalize(&mut v);
            assert_eq!(decoded, v);
            assert_eq!(enc(&decoded), bytes);
        }
    }

    #[test]
    fn accepted_inputs_are_canonical() {
        // Any input the strict decoder accepts must re-encode to itself.
        // Mutate valid encodings and feed random bytes; nothing may panic.
        let mut rng = XorShift(0x0123_4567_89ab_cdef);
        let mut accepted = 0;
        for i in 0..20_000 {
            let mut bytes = if i % 2 == 0 {
                enc(&random_value(&mut rng, 0))
            } else {
                (0..rng.below(12)).map(|_| rng.next() as u8).collect()
            };
            if !bytes.is_empty() && rng.below(2) == 0 {
                let idx = rng.below(bytes.len() as u64) as usize;
                bytes[idx] ^= 1 << rng.below(8);
            }
            if let Ok(v) = decode(&bytes) {
                accepted += 1;
                assert_eq!(enc(&v), bytes);
            }
        }
        assert!(accepted > 1000);
    }
}
