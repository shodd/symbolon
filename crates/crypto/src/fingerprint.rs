//! Identity fingerprint (PROTOCOL.md §3.3):
//!
//! ```text
//! fingerprint = SHA-256(cbor(["symbolon/v1/fingerprint", sig_pk, enc_pk]))[0..20]
//! ```
//!
//! Displayed as 32 upper-case Crockford base32 symbols in 8 groups of 4.
//! The spec says "8 groups of 5", which would need 200 bits; see the PR's
//! spec questions. Only the display form is affected, never the 20 bytes.

use alloc::string::String;
use alloc::vec;

use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use symbolon_protocol::cbor::Value;
use symbolon_protocol::domain;

use crate::{Ed25519PublicKey, XWingPublicKey, base32};

const SYMBOLS: usize = 32;
const GROUP: usize = 4;

/// The 20-byte fingerprint of an identity's public keys. Equality is
/// constant time.
#[derive(Debug, Clone, Copy)]
pub struct Fingerprint([u8; 20]);

impl Fingerprint {
    pub const LEN: usize = 20;

    pub fn compute(sig_pk: &Ed25519PublicKey, enc_pk: &XWingPublicKey) -> Self {
        Self::from_key_bytes(sig_pk.as_bytes(), &enc_pk.to_bytes())
    }

    fn from_key_bytes(sig_pk: &[u8], enc_pk: &[u8]) -> Self {
        let input = Value::Array(vec![
            Value::text(domain::FINGERPRINT),
            Value::bytes(sig_pk),
            Value::bytes(enc_pk),
        ])
        .encode()
        .expect("no maps");
        let digest = Sha256::digest(&input);
        let mut fp = [0u8; 20];
        fp.copy_from_slice(&digest[..20]);
        Self(fp)
    }

    pub fn from_bytes(bytes: &[u8; 20]) -> Self {
        Self(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// `XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX`.
    pub fn to_display(&self) -> String {
        let mut values = [0u8; SYMBOLS];
        base32::to_values(&self.0, &mut values);
        let mut out = String::with_capacity(SYMBOLS + SYMBOLS / GROUP - 1);
        for (i, &v) in values.iter().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push(' ');
            }
            out.push(char::from(base32::symbol(v)));
        }
        out
    }
}

impl ConstantTimeEq for Fingerprint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Fingerprint {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ed25519SigningKey, XWingSecretKey};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn display_format() {
        assert_eq!(
            Fingerprint::from_bytes(&[0; 20]).to_display(),
            "0000 0000 0000 0000 0000 0000 0000 0000"
        );
        assert_eq!(
            Fingerprint::from_bytes(&[0xff; 20]).to_display(),
            "ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ"
        );
        let mut b = [0u8; 20];
        b[19] = 1;
        b[0] = 0x80;
        assert_eq!(
            Fingerprint::from_bytes(&b).to_display(),
            "G000 0000 0000 0000 0000 0000 0000 0001"
        );
    }

    #[test]
    fn depends_on_both_keys_in_order() {
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let sig = Ed25519SigningKey::generate(&mut rng).public_key();
        let sig2 = Ed25519SigningKey::generate(&mut rng).public_key();
        let enc = XWingSecretKey::generate(&mut rng).public_key();
        let enc2 = XWingSecretKey::generate(&mut rng).public_key();
        let fp = Fingerprint::compute(&sig, &enc);
        assert_eq!(fp, Fingerprint::compute(&sig, &enc));
        assert_ne!(fp, Fingerprint::compute(&sig2, &enc));
        assert_ne!(fp, Fingerprint::compute(&sig, &enc2));
        // The CBOR framing keeps (a, b) and (b, a) apart.
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(
            Fingerprint::from_key_bytes(&a, &b),
            Fingerprint::from_key_bytes(&b, &a)
        );
    }
}
