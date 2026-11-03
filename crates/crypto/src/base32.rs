//! Crockford base32 helpers for the Secret Key (§3.1) and fingerprints (§3.3).
//!
//! Symbol lookups scan the whole table with constant-time comparisons instead
//! of indexing, because Secret Key symbols are secret.

use subtle::{ConditionallySelectable, ConstantTimeEq};

/// Crockford data symbols, values 0..32.
#[cfg(test)]
pub(crate) const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Crockford check symbols, values 0..37 (the data symbols plus `*~$=U`).
pub(crate) const CHECK_ALPHABET: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

/// Maps a value in `0..37` to its upper-case check-alphabet symbol (data
/// symbols are a prefix of it) without secret-dependent indexing.
pub(crate) fn symbol(value: u8) -> u8 {
    debug_assert!(value < 37);
    let mut out = 0u8;
    for (i, &c) in CHECK_ALPHABET.iter().enumerate() {
        out.conditional_assign(&c, (i as u8).ct_eq(&value));
    }
    out
}

/// Lenient decoding (§3.1): case-insensitive, `I`/`L` → 1, `O` → 0.
/// Returns the value in `0..37`, or `None` for characters outside the
/// alphabet. Callers decide whether check-only values (32..37) are allowed.
pub(crate) fn lenient_value(c: u8) -> Option<u8> {
    let upper = c.to_ascii_uppercase();
    let mut value = 0u8;
    let mut found = subtle::Choice::from(0);
    for (i, &s) in CHECK_ALPHABET.iter().enumerate() {
        let hit = s.ct_eq(&upper);
        value.conditional_assign(&(i as u8), hit);
        found |= hit;
    }
    let one = upper.ct_eq(&b'I') | upper.ct_eq(&b'L');
    value.conditional_assign(&1, one);
    found |= one;
    let zero = upper.ct_eq(&b'O');
    value.conditional_assign(&0, zero);
    found |= zero;
    bool::from(found).then_some(value)
}

/// Writes the big-endian integer in `bytes` as `out.len()` base32 values,
/// left-padding with zero bits. `out.len() * 5` must be at least
/// `bytes.len() * 8` and less than that plus 5.
pub(crate) fn to_values(bytes: &[u8], out: &mut [u8]) {
    let total_bits = out.len() * 5;
    let pad = total_bits - bytes.len() * 8;
    debug_assert!(pad < 5);
    for (k, o) in out.iter_mut().enumerate() {
        let mut v = 0u8;
        for j in 0..5 {
            let pos = k * 5 + j; // position in the padded bit string
            let bit = if pos < pad {
                0
            } else {
                let p = pos - pad;
                (bytes[p / 8] >> (7 - p % 8)) & 1
            };
            v = (v << 1) | bit;
        }
        *o = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_matches_table() {
        for (i, &c) in CHECK_ALPHABET.iter().enumerate() {
            assert_eq!(symbol(i as u8), c);
            assert_eq!(lenient_value(c), Some(i as u8));
            assert_eq!(lenient_value(c.to_ascii_lowercase()), Some(i as u8));
        }
        assert_eq!(&CHECK_ALPHABET[..32], ALPHABET);
    }

    #[test]
    fn lenient_aliases() {
        for c in *b"IiLl" {
            assert_eq!(lenient_value(c), Some(1));
        }
        for c in *b"Oo" {
            assert_eq!(lenient_value(c), Some(0));
        }
        for c in *b"!-_ @#%&+/\0\xff" {
            assert_eq!(lenient_value(c), None, "{c}");
        }
    }

    #[test]
    fn to_values_pads_on_the_left() {
        let mut out = [0u8; 2];
        // 10 bits: 2 zero padding bits, then 0xff.
        to_values(&[0xff], &mut out);
        assert_eq!(out, [0b00111, 0b11111]);
        let mut out = [0u8; 8];
        to_values(&[0x80, 0, 0, 0, 1], &mut out);
        assert_eq!(out, [16, 0, 0, 0, 0, 0, 0, 1]);
    }
}
