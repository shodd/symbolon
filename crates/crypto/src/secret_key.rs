//! Secret Key (PROTOCOL.md §3.1): 16 random bytes, written as
//! `S1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX`, i.e. 26 Crockford base32 symbols
//! (the 128-bit value with 2 leading zero bits) plus one mod-37 check symbol.

use alloc::string::String;

use rand_core::CryptoRng;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, base32};

const DATA_SYMBOLS: usize = 26;
/// Data symbols plus the check symbol.
const SYMBOLS: usize = DATA_SYMBOLS + 1;
/// Symbols per display group.
const GROUP: usize = 5;
/// `"S1"` + a hyphen before each of the 6 groups + 27 symbols.
const TEXT_LEN: usize = 2 + SYMBOLS.div_ceil(GROUP) + SYMBOLS;
/// The prefix `S1` as base32 values (`S` = 25, `1` = 1).
const PREFIX_VALUES: [u8; 2] = [25, 1];

/// The 128-bit Secret Key. It is only ever an input to key derivation
/// (ARCHITECTURE §5). Wiped on drop; deliberately has no `Debug`.
pub struct SecretKey([u8; 16]);

impl SecretKey {
    pub const LEN: usize = 16;

    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut key = Self([0u8; 16]);
        rng.fill_bytes(&mut key.0);
        key
    }

    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The display form, e.g. `S1-00000-00000-00000-00000-00000-00`.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut values = Zeroizing::new([0u8; SYMBOLS]);
        base32::to_values(&self.0, &mut values[..DATA_SYMBOLS]);
        values[DATA_SYMBOLS] = check_value(&self.0);

        let mut text = Zeroizing::new(String::with_capacity(TEXT_LEN));
        text.push_str("S1");
        for (i, &v) in values.iter().enumerate() {
            if i % GROUP == 0 {
                text.push('-');
            }
            text.push(char::from(base32::symbol(v)));
        }
        debug_assert_eq!(text.len(), TEXT_LEN);
        text
    }

    /// Parses the text form leniently: case is ignored, hyphens and ASCII
    /// whitespace are skipped anywhere, and `I`/`L` read as `1`, `O` as `0`.
    /// The `S1` prefix and a valid check symbol are required.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut values = Zeroizing::new([0u8; 2 + SYMBOLS]);
        let mut n = 0;
        for &c in text.as_bytes() {
            if matches!(c, b'-' | b' ' | b'\t' | b'\r' | b'\n') {
                continue;
            }
            let v = base32::lenient_value(c).ok_or(Error::SecretKeyFormat)?;
            let slot = values.get_mut(n).ok_or(Error::SecretKeyFormat)?;
            *slot = v;
            n += 1;
        }
        if n != values.len() || values[..2] != PREFIX_VALUES {
            return Err(Error::SecretKeyFormat);
        }

        let data = &values[2..2 + DATA_SYMBOLS];
        // 26 symbols hold 130 bits; the top two are padding and must be zero,
        // and check-only symbols (`*~$=U`) can't appear in the data part.
        if data[0] >= 8 || data.iter().any(|&v| v >= 32) {
            return Err(Error::SecretKeyFormat);
        }
        let mut acc: u128 = 0;
        for &v in data {
            acc = (acc << 5) | u128::from(v);
        }
        let key = Self(acc.to_be_bytes());
        acc.zeroize();

        let check = values[2 + DATA_SYMBOLS];
        if !bool::from(check.ct_eq(&check_value(&key.0))) {
            return Err(Error::SecretKeyChecksum);
        }
        Ok(key)
    }
}

/// The 128-bit value mod 37, computed bytewise so no variable-time 128-bit
/// division runs on the secret.
fn check_value(bytes: &[u8; 16]) -> u8 {
    let mut r: u32 = 0;
    for &b in bytes {
        r = (r * 256 + u32::from(b)) % 37;
    }
    r as u8
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([7; 32])
    }

    #[test]
    fn prefix_values_match_alphabet() {
        assert_eq!(base32::lenient_value(b'S'), Some(PREFIX_VALUES[0]));
        assert_eq!(base32::lenient_value(b'1'), Some(PREFIX_VALUES[1]));
    }

    #[test]
    fn known_texts() {
        let zero = SecretKey::from_bytes(&[0; 16]);
        assert_eq!(&*zero.to_text(), "S1-00000-00000-00000-00000-00000-00");
        let max = SecretKey::from_bytes(&[0xff; 16]);
        let check = (u128::MAX % 37) as usize;
        let expected = format!(
            "S1-7ZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-Z{}",
            base32::CHECK_ALPHABET[check] as char
        );
        assert_eq!(*max.to_text(), expected);
        let one = SecretKey::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // The last group is the final data symbol plus the check symbol.
        assert_eq!(&*one.to_text(), "S1-00000-00000-00000-00000-00000-11");
    }

    #[test]
    fn text_layout() {
        let mut rng = rng();
        for _ in 0..200 {
            let key = SecretKey::generate(&mut rng);
            let text = key.to_text();
            assert_eq!(text.len(), 35);
            assert!(text.starts_with("S1-"));
            for (i, c) in text.char_indices() {
                assert_eq!(c == '-', [2, 8, 14, 20, 26, 32].contains(&i), "{}", *text);
            }
            assert!(SecretKey::parse(&text).unwrap() == key);
        }
    }

    #[test]
    fn check_value_matches_u128_mod() {
        let mut rng = rng();
        for _ in 0..1000 {
            let mut b = [0u8; 16];
            rng.fill_bytes(&mut b);
            assert_eq!(u128::from(check_value(&b)), u128::from_be_bytes(b) % 37);
        }
    }

    #[test]
    fn lenient_parsing() {
        let mut rng = rng();
        for _ in 0..200 {
            let key = SecretKey::generate(&mut rng);
            let text = key.to_text();
            let variants = [
                text.to_lowercase(),
                text.replace('-', ""),
                text.replace('-', " "),
                format!("  {}\n", text.replace('-', " - ")),
                text.replace('1', "l"),
                text.replace('1', "I"),
                text.replace('1', "i"),
                text.replace('1', "L"),
                text.replace('0', "O"),
                text.replace('0', "o"),
                text.replacen("-", "", 1),
            ];
            for v in &variants {
                assert!(SecretKey::parse(v).unwrap() == key, "{v}");
            }
        }
    }

    #[test]
    fn all_check_symbols_parse() {
        // Find keys whose check symbol is each of the 37 symbols, including
        // the check-only ones `*~$=U`.
        let mut rng = rng();
        let mut seen = [false; 37];
        while seen.iter().any(|s| !s) {
            let key = SecretKey::generate(&mut rng);
            let c = check_value(key.as_bytes()) as usize;
            if seen[c] {
                continue;
            }
            seen[c] = true;
            let text = key.to_text();
            assert_eq!(text.as_bytes()[34], base32::CHECK_ALPHABET[c]);
            assert!(SecretKey::parse(&text).unwrap() == key);
            assert!(SecretKey::parse(&text.to_lowercase()).unwrap() == key);
        }
    }

    #[test]
    fn rejects_wrong_check_symbol() {
        let key = SecretKey::generate(&mut rng());
        let text = key.to_text();
        let good = text.as_bytes()[34];
        for &c in base32::CHECK_ALPHABET.iter().filter(|&&c| c != good) {
            let mut bad = text.as_bytes().to_vec();
            bad[34] = c;
            let bad = String::from_utf8(bad).unwrap();
            // '1'/'I'/'L' and '0'/'O' are the same symbol, so only distinct
            // values are tried here.
            assert_eq!(
                SecretKey::parse(&bad).err(),
                Some(Error::SecretKeyChecksum),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_single_symbol_errors() {
        // Mod-37 detects every single-symbol substitution in the data part.
        let key = SecretKey::generate(&mut rng());
        let text = key.to_text();
        for pos in (3..34).filter(|&p| text.as_bytes()[p] != b'-') {
            for &c in base32::ALPHABET {
                if c == text.as_bytes()[pos] || (pos == 3 && base32::lenient_value(c).unwrap() >= 8)
                {
                    continue;
                }
                let mut bad = text.as_bytes().to_vec();
                bad[pos] = c;
                let bad = String::from_utf8(bad).unwrap();
                assert_eq!(
                    SecretKey::parse(&bad).err(),
                    Some(Error::SecretKeyChecksum),
                    "{bad}"
                );
            }
        }
    }

    #[test]
    fn rejects_malformed_text() {
        let key = SecretKey::generate(&mut rng());
        let text = key.to_text();
        let body = &text[3..];
        let cases = [
            String::new(),
            "S1".into(),
            body.to_string(),                          // missing prefix
            format!("S2-{body}"),                      // wrong version
            format!("X1-{body}"),                      // wrong prefix
            format!("S1-{}", &body[..body.len() - 1]), // too short
            format!("{}0", *text),                     // too long
            format!("S1-S1-{body}"),                   // doubled prefix
            format!("S1-U{}", &body[1..]),             // check-only symbol in data part
            format!("S1-*{}", &body[1..]),
            format!("S1-8{}", &body[1..]), // value doesn't fit in 128 bits
            format!("S1-Z{}", &body[1..]),
            format!("S1-!{}", &body[1..]), // not in the alphabet
            format!("S1_{body}"),          // underscore isn't a separator
            format!("S1-{}", body.replacen('-', "\u{2010}", 1)), // Unicode hyphen
            format!("S1-é{}", &body[2..]),
        ];
        for bad in &cases {
            assert_eq!(
                SecretKey::parse(bad).err(),
                Some(Error::SecretKeyFormat),
                "{bad}"
            );
        }
    }
}
