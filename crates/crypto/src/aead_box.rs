//! `AeadBox` (PROTOCOL.md §2):
//!
//! ```text
//! AeadBox = [ 1, 1, nonce: bstr (24 bytes), ct: bstr (ciphertext || tag) ]
//! ```
//!
//! XChaCha20-Poly1305 with a random 24-byte nonce. The AAD is never stored;
//! the receiver rebuilds it from context.

use alloc::vec;
use alloc::vec::Vec;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand_core::CryptoRng;
use symbolon_protocol::cbor::{self, Value};
use zeroize::Zeroizing;

use crate::{Error, SymmetricKey};

/// Envelope version.
pub const VERSION: u64 = 1;
/// `alg` value for XChaCha20-Poly1305.
pub const ALG_XCHACHA20_POLY1305: u64 = 1;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// An encrypted, authenticated value. Holds only public data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadBox {
    nonce: [u8; NONCE_LEN],
    ct: Vec<u8>,
}

impl AeadBox {
    /// Encrypts `plaintext` under `key`, binding it to `aad`.
    pub fn seal(
        key: &SymmetricKey,
        plaintext: &[u8],
        aad: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Self, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        Self::seal_with_nonce(key, &nonce, plaintext, aad)
    }

    /// Deterministic sealing for test vectors. Never reuse a nonce.
    pub(crate) fn seal_with_nonce(
        key: &SymmetricKey,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Self, Error> {
        let ct = xchacha_seal(key, nonce, plaintext, aad)?;
        Ok(Self { nonce: *nonce, ct })
    }

    /// Decrypts and authenticates. Any mismatch in key, AAD or ciphertext
    /// gives [`Error::Decryption`].
    pub fn open(&self, key: &SymmetricKey, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        xchacha_open(key, &self.nonce, &self.ct, aad)
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Ciphertext followed by the 16-byte tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ct
    }

    /// `cbor(AeadBox)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        Value::Array(vec![
            Value::Unsigned(VERSION),
            Value::Unsigned(ALG_XCHACHA20_POLY1305),
            Value::bytes(self.nonce),
            Value::bytes(self.ct.as_slice()),
        ])
        .encode()
        .expect("an AeadBox has no maps")
    }

    /// Parses `cbor(AeadBox)`, rejecting non-canonical CBOR, unknown
    /// versions and algorithms, and wrong field sizes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let fields = parse_envelope(bytes, ALG_XCHACHA20_POLY1305)?;
        let [nonce, ct] = fields;
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::MalformedEnvelope)?;
        if ct.len() < TAG_LEN {
            return Err(Error::MalformedEnvelope);
        }
        Ok(Self { nonce, ct })
    }
}

/// Parses `[version, alg, bstr, bstr]`, checking the version before anything
/// else so later versions are free to change the layout.
pub(crate) fn parse_envelope(bytes: &[u8], expected_alg: u64) -> Result<[Vec<u8>; 2], Error> {
    let value = cbor::decode(bytes).map_err(|_| Error::MalformedEnvelope)?;
    let Value::Array(items) = value else {
        return Err(Error::MalformedEnvelope);
    };
    match items.first() {
        Some(Value::Unsigned(VERSION)) => {}
        Some(Value::Unsigned(_)) => return Err(Error::UnsupportedVersion),
        _ => return Err(Error::MalformedEnvelope),
    }
    let Ok([_, alg, a, b]) = <[Value; 4]>::try_from(items) else {
        return Err(Error::MalformedEnvelope);
    };
    match alg {
        Value::Unsigned(n) if n == expected_alg => {}
        Value::Unsigned(_) => return Err(Error::UnsupportedAlgorithm),
        _ => return Err(Error::MalformedEnvelope),
    }
    match (a, b) {
        (Value::Bytes(a), Value::Bytes(b)) => Ok([a, b]),
        _ => Err(Error::MalformedEnvelope),
    }
}

/// XChaCha20-Poly1305 encryption into one exactly-sized buffer.
pub(crate) fn xchacha_seal(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut buf = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LEN));
    buf.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, buf.as_mut_slice().into())
        .map_err(|_| Error::Encryption)?;
    buf.extend_from_slice(&tag);
    // `buf` now holds only ciphertext, so it can leave the zeroizing wrapper.
    Ok(core::mem::take(&mut *buf))
}

/// XChaCha20-Poly1305 decryption. The tag is checked before any plaintext
/// is produced.
pub(crate) fn xchacha_open(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_LEN],
    ct: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let body_len = ct.len().checked_sub(TAG_LEN).ok_or(Error::Decryption)?;
    let (body, tag) = ct.split_at(body_len);
    let tag = Tag::try_from(tag).map_err(|_| Error::Decryption)?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut buf = Zeroizing::new(body.to_vec());
    cipher
        .decrypt_inout_detached(&XNonce::from(*nonce), aad, buf.as_mut_slice().into(), &tag)
        .map_err(|_| Error::Decryption)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup() -> (SymmetricKey, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        (SymmetricKey::generate(&mut rng), rng)
    }

    #[test]
    fn round_trip() {
        let (key, mut rng) = setup();
        for len in [0, 1, 15, 16, 17, 64, 1000] {
            let pt = vec![0xa5; len];
            let b = AeadBox::seal(&key, &pt, b"aad", &mut rng).unwrap();
            assert_eq!(b.ciphertext().len(), len + TAG_LEN);
            let parsed = AeadBox::from_bytes(&b.to_bytes()).unwrap();
            assert_eq!(parsed, b);
            assert_eq!(&*parsed.open(&key, b"aad").unwrap(), &pt[..]);
        }
    }

    #[test]
    fn nonces_are_random() {
        let (key, mut rng) = setup();
        let a = AeadBox::seal(&key, b"x", b"", &mut rng).unwrap();
        let b = AeadBox::seal(&key, b"x", b"", &mut rng).unwrap();
        assert_ne!(a.nonce(), b.nonce());
        assert_ne!(a.ciphertext(), b.ciphertext());
    }

    #[test]
    fn rejects_wrong_key_and_aad() {
        let (key, mut rng) = setup();
        let b = AeadBox::seal(&key, b"secret", b"context", &mut rng).unwrap();
        let other = SymmetricKey::generate(&mut rng);
        assert_eq!(b.open(&other, b"context").err(), Some(Error::Decryption));
        for aad in [&b""[..], b"contex", b"context!", b"Context"] {
            assert_eq!(b.open(&key, aad).err(), Some(Error::Decryption));
        }
    }

    #[test]
    fn rejects_tampering() {
        let (key, mut rng) = setup();
        let b = AeadBox::seal(&key, b"secret value", b"aad", &mut rng).unwrap();
        for i in 0..b.ct.len() {
            let mut t = b.clone();
            t.ct[i] ^= 0x01;
            assert_eq!(
                t.open(&key, b"aad").err(),
                Some(Error::Decryption),
                "ct byte {i}"
            );
        }
        for i in 0..NONCE_LEN {
            let mut t = b.clone();
            t.nonce[i] ^= 0x80;
            assert_eq!(
                t.open(&key, b"aad").err(),
                Some(Error::Decryption),
                "nonce byte {i}"
            );
        }
        let mut t = b.clone();
        t.ct.pop();
        assert_eq!(t.open(&key, b"aad").err(), Some(Error::Decryption));
        let mut t = b.clone();
        t.ct.push(0);
        assert_eq!(t.open(&key, b"aad").err(), Some(Error::Decryption));
    }

    fn envelope(items: Vec<Value>) -> Vec<u8> {
        Value::Array(items).encode().unwrap()
    }

    #[test]
    fn rejects_bad_envelopes() {
        let n = |x| Value::Unsigned(x);
        let nonce = Value::bytes([0u8; 24]);
        let ct = Value::bytes([0u8; 16]);
        let cases: Vec<(Vec<u8>, Error)> = vec![
            (
                envelope(vec![n(2), n(1), nonce.clone(), ct.clone()]),
                Error::UnsupportedVersion,
            ),
            (
                envelope(vec![n(0), n(1), nonce.clone(), ct.clone()]),
                Error::UnsupportedVersion,
            ),
            (envelope(vec![n(2)]), Error::UnsupportedVersion),
            (
                envelope(vec![n(1), n(2), nonce.clone(), ct.clone()]),
                Error::UnsupportedAlgorithm,
            ),
            (
                envelope(vec![n(1), n(0), nonce.clone(), ct.clone()]),
                Error::UnsupportedAlgorithm,
            ),
            (envelope(vec![]), Error::MalformedEnvelope),
            (
                envelope(vec![Value::text("1"), n(1), nonce.clone(), ct.clone()]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![Value::from(-1i64), n(1), nonce.clone(), ct.clone()]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![n(1), Value::Null, nonce.clone(), ct.clone()]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![n(1), n(1), nonce.clone()]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![n(1), n(1), nonce.clone(), ct.clone(), Value::Null]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![n(1), n(1), Value::bytes([0u8; 23]), ct.clone()]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![n(1), n(1), Value::bytes([0u8; 25]), ct.clone()]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![n(1), n(1), nonce.clone(), Value::bytes([0u8; 15])]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![n(1), n(1), Value::text("x"), ct.clone()]),
                Error::MalformedEnvelope,
            ),
            (
                envelope(vec![n(1), n(1), nonce.clone(), Value::Array(vec![])]),
                Error::MalformedEnvelope,
            ),
            (
                Value::bytes([0u8; 40]).encode().unwrap(),
                Error::MalformedEnvelope,
            ),
            (vec![], Error::MalformedEnvelope),
        ];
        for (bytes, err) in cases {
            assert_eq!(
                AeadBox::from_bytes(&bytes).err(),
                Some(err),
                "{}",
                hex::encode(&bytes)
            );
        }
    }

    #[test]
    fn rejects_non_canonical_and_truncated_encodings() {
        let (key, mut rng) = setup();
        let good = AeadBox::seal(&key, b"hello", b"", &mut rng)
            .unwrap()
            .to_bytes();
        // Version as a two-byte integer: same value, not canonical.
        let mut bad = vec![0x84, 0x18, 0x01];
        bad.extend_from_slice(&good[2..]);
        assert_eq!(
            AeadBox::from_bytes(&bad).err(),
            Some(Error::MalformedEnvelope)
        );
        // Indefinite-length array.
        let mut bad = vec![0x9f];
        bad.extend_from_slice(&good[1..]);
        bad.push(0xff);
        assert_eq!(
            AeadBox::from_bytes(&bad).err(),
            Some(Error::MalformedEnvelope)
        );
        // Trailing byte.
        let mut bad = good.clone();
        bad.push(0);
        assert_eq!(
            AeadBox::from_bytes(&bad).err(),
            Some(Error::MalformedEnvelope)
        );
        // Every truncation.
        for len in 0..good.len() {
            assert!(AeadBox::from_bytes(&good[..len]).is_err(), "len {len}");
        }
    }
}
