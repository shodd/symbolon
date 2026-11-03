//! `HpkeBox` (PROTOCOL.md §1, §2): HPKE (RFC 9180) base mode with suite 1 =
//! X-Wing KEM (`0x647a`), HKDF-SHA256 (`0x0001`), ChaCha20-Poly1305
//! (`0x0003`).
//!
//! ```text
//! HpkeBox = [ 1, 1, enc: bstr (1120 bytes), ct: bstr ]
//! ```
//!
//! The `info` value is rebuilt by the receiver from context and never
//! stored. The spec defines no AAD for `HpkeBox`, so the AAD is empty.
//!
//! All HPKE and X-Wing logic comes from the `hpke` crate (which builds on
//! RustCrypto `x-wing` / `ml-kem`); this module only fixes the suite and the
//! envelope format.

use alloc::vec;
use alloc::vec::Vec;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};
use rand_core::CryptoRng;
use symbolon_protocol::cbor::Value;
use zeroize::Zeroizing;

use crate::Error;
use crate::aead_box::{TAG_LEN, VERSION, parse_envelope};

/// `suite` value for X-Wing / HKDF-SHA256 / ChaCha20-Poly1305.
pub const SUITE_XWING_HKDF_SHA256_CHACHA20_POLY1305: u64 = 1;
/// X-Wing decapsulation key (seed) length.
pub const SECRET_KEY_LEN: usize = 32;
/// X-Wing encapsulation key length.
pub const PUBLIC_KEY_LEN: usize = 1216;
/// X-Wing ciphertext (HPKE `enc`) length.
pub const ENC_LEN: usize = 1120;

type PrivateKey = <XWing as hpke::Kem>::PrivateKey;
type PublicKey = <XWing as hpke::Kem>::PublicKey;
type EncappedKey = <XWing as hpke::Kem>::EncappedKey;

/// HPKE limits `info` to fewer than 2^16 - 5 bytes in base mode and panics
/// beyond that, so longer values are rejected up front.
const MAX_INFO_LEN: usize = (1 << 16) - 6;

/// An identity encryption private key: the 32-byte X-Wing seed (the form
/// stored in `wrapped_ik`). Wiped on drop; deliberately has no `Debug`.
pub struct XWingSecretKey(PrivateKey);

/// An identity encryption public key (`enc_pk`, 1216 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XWingPublicKey(PublicKey);

impl XWingSecretKey {
    /// A fresh key: 32 random bytes, as in X-Wing's `GenerateKeyPair`.
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut seed = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        rng.fill_bytes(&mut *seed);
        Self::from_bytes(&seed)
    }

    pub fn from_bytes(seed: &[u8; SECRET_KEY_LEN]) -> Self {
        Self(PrivateKey::from_bytes(seed).expect("any 32 bytes are an X-Wing seed"))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_LEN]> {
        let mut out = Zeroizing::new([0u8; SECRET_KEY_LEN]);
        self.0.write_exact(&mut *out);
        out
    }

    pub fn public_key(&self) -> XWingPublicKey {
        XWingPublicKey(XWing::sk_to_pk(&self.0))
    }
}

impl XWingPublicKey {
    /// Parses and validates an encapsulation key (including the ML-KEM
    /// modulus check).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidPublicKey);
        }
        PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// A value encrypted to an X-Wing public key. Holds only public data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeBox {
    enc: Vec<u8>,
    ct: Vec<u8>,
}

impl HpkeBox {
    /// Single-shot HPKE `Seal` in base mode, with empty AAD.
    pub fn seal(
        recipient: &XWingPublicKey,
        info: &[u8],
        plaintext: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Self, Error> {
        if info.len() > MAX_INFO_LEN {
            return Err(Error::TooLarge);
        }
        let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Base,
            &recipient.0,
            info,
            plaintext,
            &[],
            rng,
        )
        .map_err(|_| Error::Encryption)?;
        Ok(Self {
            enc: enc.to_bytes().to_vec(),
            ct,
        })
    }

    /// Single-shot HPKE `Open`. A wrong key, wrong `info` or tampered box
    /// gives [`Error::Decryption`].
    pub fn open(
        &self,
        recipient: &XWingSecretKey,
        info: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if info.len() > MAX_INFO_LEN {
            return Err(Error::Decryption);
        }
        let enc = EncappedKey::from_bytes(&self.enc).map_err(|_| Error::Decryption)?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &recipient.0,
            &enc,
            info,
            &self.ct,
            &[],
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decryption)
    }

    /// The encapsulated key (`enc`).
    pub fn enc(&self) -> &[u8] {
        &self.enc
    }

    /// Ciphertext followed by the 16-byte tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ct
    }

    /// `cbor(HpkeBox)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        Value::Array(vec![
            Value::Unsigned(VERSION),
            Value::Unsigned(SUITE_XWING_HKDF_SHA256_CHACHA20_POLY1305),
            Value::bytes(self.enc.as_slice()),
            Value::bytes(self.ct.as_slice()),
        ])
        .encode()
        .expect("an HpkeBox has no maps")
    }

    /// Parses `cbor(HpkeBox)`, rejecting non-canonical CBOR, unknown
    /// versions and suites, and wrong field sizes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let [enc, ct] = parse_envelope(bytes, SUITE_XWING_HKDF_SHA256_CHACHA20_POLY1305)?;
        if enc.len() != ENC_LEN || ct.len() < TAG_LEN {
            return Err(Error::MalformedEnvelope);
        }
        Ok(Self { enc, ct })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup() -> (XWingSecretKey, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::from_seed([5; 32]);
        (XWingSecretKey::generate(&mut rng), rng)
    }

    #[test]
    fn round_trip() {
        let (sk, mut rng) = setup();
        let pk = sk.public_key();
        assert_eq!(pk.to_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(XWingPublicKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
        for len in [0, 32, 1000] {
            let pt = vec![0x5a; len];
            let b = HpkeBox::seal(&pk, b"info", &pt, &mut rng).unwrap();
            assert_eq!(b.enc().len(), ENC_LEN);
            assert_eq!(b.ciphertext().len(), len + TAG_LEN);
            let parsed = HpkeBox::from_bytes(&b.to_bytes()).unwrap();
            assert_eq!(parsed, b);
            assert_eq!(&*parsed.open(&sk, b"info").unwrap(), &pt[..]);
        }
    }

    #[test]
    fn secret_key_round_trip() {
        let (sk, _) = setup();
        let again = XWingSecretKey::from_bytes(&sk.to_bytes());
        assert_eq!(again.public_key(), sk.public_key());
    }

    #[test]
    fn rejects_wrong_key_info_and_tampering() {
        let (sk, mut rng) = setup();
        let b = HpkeBox::seal(&sk.public_key(), b"grant", b"vault key", &mut rng).unwrap();
        let other = XWingSecretKey::generate(&mut rng);
        assert_eq!(b.open(&other, b"grant").err(), Some(Error::Decryption));
        for info in [&b""[..], b"gran", b"grant!"] {
            assert_eq!(b.open(&sk, info).err(), Some(Error::Decryption));
        }
        for i in (0..b.ct.len()).step_by(3) {
            let mut t = b.clone();
            t.ct[i] ^= 1;
            assert_eq!(
                t.open(&sk, b"grant").err(),
                Some(Error::Decryption),
                "ct {i}"
            );
        }
        // X-Wing decapsulation is implicitly rejecting: a modified `enc`
        // yields a different shared secret and the AEAD fails.
        for i in [0, 1, 500, 1087, 1088, 1100, ENC_LEN - 1] {
            let mut t = b.clone();
            t.enc[i] ^= 1;
            assert_eq!(
                t.open(&sk, b"grant").err(),
                Some(Error::Decryption),
                "enc {i}"
            );
        }
        let mut t = b.clone();
        t.ct.truncate(TAG_LEN - 1);
        assert_eq!(t.open(&sk, b"grant").err(), Some(Error::Decryption));
    }

    #[test]
    fn rejects_bad_envelopes() {
        let (sk, mut rng) = setup();
        let b = HpkeBox::seal(&sk.public_key(), b"", b"x", &mut rng).unwrap();
        let n = |x| Value::Unsigned(x);
        let enc = || Value::bytes(b.enc.as_slice());
        let ct = || Value::bytes(b.ct.as_slice());
        let cases = [
            (vec![n(2), n(1), enc(), ct()], Error::UnsupportedVersion),
            (vec![n(1), n(2), enc(), ct()], Error::UnsupportedAlgorithm),
            (
                vec![n(1), n(1), Value::bytes(&b.enc[1..]), ct()],
                Error::MalformedEnvelope,
            ),
            (
                vec![n(1), n(1), enc(), Value::bytes([0u8; 15])],
                Error::MalformedEnvelope,
            ),
            (vec![n(1), n(1), enc()], Error::MalformedEnvelope),
            (vec![n(1), n(1), ct(), enc()], Error::MalformedEnvelope),
        ];
        for (items, err) in cases {
            let bytes = Value::Array(items).encode().unwrap();
            assert_eq!(HpkeBox::from_bytes(&bytes).err(), Some(err));
        }
        let good = b.to_bytes();
        for len in [0, 1, 4, good.len() - 1] {
            assert!(HpkeBox::from_bytes(&good[..len]).is_err());
        }
        // An AeadBox is not an HpkeBox.
        let key = crate::SymmetricKey::generate(&mut rng);
        let aead = crate::AeadBox::seal(&key, b"x", b"", &mut rng)
            .unwrap()
            .to_bytes();
        assert_eq!(
            HpkeBox::from_bytes(&aead).err(),
            Some(Error::MalformedEnvelope)
        );
    }

    #[test]
    fn rejects_invalid_public_keys() {
        let (sk, _) = setup();
        let pk = sk.public_key().to_bytes();
        assert_eq!(
            XWingPublicKey::from_bytes(&pk[1..]),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            XWingPublicKey::from_bytes(&[]),
            Err(Error::InvalidPublicKey)
        );
        // ML-KEM coefficients must be < q = 3329; 0xff 0xff encodes 4095.
        let mut bad = pk.clone();
        bad[0] = 0xff;
        bad[1] = 0xff;
        assert_eq!(
            XWingPublicKey::from_bytes(&bad),
            Err(Error::InvalidPublicKey)
        );
    }

    #[test]
    fn rejects_oversized_info() {
        let (sk, mut rng) = setup();
        let info = vec![0u8; MAX_INFO_LEN + 1];
        assert_eq!(
            HpkeBox::seal(&sk.public_key(), &info, b"x", &mut rng).err(),
            Some(Error::TooLarge)
        );
        let max = vec![0u8; MAX_INFO_LEN];
        let b = HpkeBox::seal(&sk.public_key(), &max, b"x", &mut rng).unwrap();
        assert_eq!(&*b.open(&sk, &max).unwrap(), b"x");
        assert_eq!(b.open(&sk, &info).err(), Some(Error::Decryption));
    }
}
