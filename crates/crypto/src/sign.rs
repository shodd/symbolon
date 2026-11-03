//! Signatures (PROTOCOL.md §1).
//!
//! - Ed25519 (RFC 8032, pure) for the auth key and the identity signing key.
//!   Verification uses `verify_strict`, which also rejects non-canonical
//!   signatures and small-order public keys.
//! - ECDSA P-256 with SHA-256 for device keys: DER-encoded signatures and
//!   33-byte SEC1 compressed public keys. Signing goes through the
//!   [`DeviceSigner`] trait so platform keystores (Secure Enclave, StrongBox,
//!   TPM) can provide it; [`SoftwareDeviceKey`] is the in-memory fallback.
//!
//! Messages are the caller-built `cbor([...])` bytes of §4 and §6.

use alloc::vec::Vec;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::elliptic_curve::Generate as _;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::Error;

// ---------------------------------------------------------------------------
// Ed25519

/// An Ed25519 signing key (auth key or identity `sig` key). Wiped on drop;
/// deliberately has no `Debug`.
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

/// An Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKey(ed25519_dalek::VerifyingKey);

/// A 64-byte Ed25519 signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519SigningKey {
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        Self::from_seed(&seed)
    }

    /// From the 32-byte RFC 8032 seed (the form stored in `wrapped_ik`).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(message).to_bytes())
    }
}

impl Ed25519PublicKey {
    pub const LEN: usize = 32;

    /// Parses a public key, rejecting invalid points, small-order points
    /// and non-canonical encodings (`y >= p`, or `x = 0` with the sign bit
    /// set). Without the last check one key would have two encodings and
    /// so two fingerprints.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: &[u8; 32] = bytes.try_into().map_err(|_| Error::InvalidPublicKey)?;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(arr).map_err(|_| Error::InvalidPublicKey)?;
        if key.is_weak() || key.to_edwards().compress().as_bytes() != arr {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Strict verification ([`Error::InvalidSignature`] on failure).
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0
            .verify_strict(message, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl Ed25519Signature {
    pub const LEN: usize = 64;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; 64] = bytes.try_into().map_err(|_| Error::MalformedSignature)?;
        Ok(Self(arr))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-256 device keys

/// A device public key: a SEC1 compressed P-256 point (33 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePublicKey(p256::ecdsa::VerifyingKey);

/// A DER-encoded ECDSA P-256 signature, validated on construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSignature {
    der: Vec<u8>,
    sig: p256::ecdsa::Signature,
}

/// Something that holds a device private key and signs with ECDSA P-256 /
/// SHA-256. Hardware-backed implementations live in the platform apps; the
/// key never leaves the hardware.
///
/// `sign` receives the full message (not a digest) and must hash it with
/// SHA-256, as Secure Enclave's
/// `ecdsaSignatureMessageX962SHA256` and Android's `SHA256withECDSA` do.
pub trait DeviceSigner {
    fn public_key(&self) -> DevicePublicKey;

    /// Signs `message`. Implementations map platform failures (user
    /// cancelled, key invalidated) to [`Error::DeviceSigner`].
    fn sign(&self, message: &[u8]) -> Result<DeviceSignature, Error>;
}

/// A device key held in memory, for platforms without a usable keystore.
/// Signatures are deterministic (RFC 6979). Wiped on drop; deliberately has
/// no `Debug`.
pub struct SoftwareDeviceKey(p256::ecdsa::SigningKey);

impl SoftwareDeviceKey {
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        Self(p256::ecdsa::SigningKey::generate_from_rng(rng))
    }

    /// From a 32-byte big-endian scalar; rejects zero and values ≥ n.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        p256::ecdsa::SigningKey::from_slice(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPrivateKey)
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        let mut fb = self.0.to_bytes();
        out.copy_from_slice(&fb);
        zeroize::Zeroize::zeroize(fb.as_mut_slice());
        out
    }
}

impl DeviceSigner for SoftwareDeviceKey {
    fn public_key(&self) -> DevicePublicKey {
        DevicePublicKey(*self.0.verifying_key())
    }

    fn sign(&self, message: &[u8]) -> Result<DeviceSignature, Error> {
        let sig: p256::ecdsa::Signature = self.0.sign(message);
        Ok(DeviceSignature {
            der: sig.to_der().as_bytes().to_vec(),
            sig,
        })
    }
}

impl DevicePublicKey {
    pub const LEN: usize = 33;

    /// Parses a SEC1 compressed point. Uncompressed points, the identity and
    /// points not on the curve are rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::LEN || !matches!(bytes[0], 0x02 | 0x03) {
            return Err(Error::InvalidPublicKey);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidPublicKey)
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        let point = self.0.to_sec1_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Verifies a signature over `message` (hashed with SHA-256). Both low-
    /// and high-S signatures are accepted, because hardware keystores don't
    /// normalize S.
    pub fn verify(&self, message: &[u8], signature: &DeviceSignature) -> Result<(), Error> {
        self.0
            .verify(message, &signature.sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl DeviceSignature {
    /// Parses a strict DER `ECDSA-Sig-Value` with `0 < r, s < n`. The input
    /// must be exactly the canonical DER encoding of `(r, s)`.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let sig = p256::ecdsa::Signature::from_der(der).map_err(|_| Error::MalformedSignature)?;
        if sig.to_der().as_bytes() != der {
            return Err(Error::MalformedSignature);
        }
        Ok(Self {
            der: der.to_vec(),
            sig,
        })
    }

    pub fn as_der(&self) -> &[u8] {
        &self.der
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([3; 32])
    }

    #[test]
    fn ed25519_rfc8032_test_1() {
        // RFC 8032 §7.1, TEST 1 (empty message).
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let key = Ed25519SigningKey::from_seed(&seed.try_into().unwrap());
        assert_eq!(
            hex::encode(key.public_key().to_bytes()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = key.sign(b"");
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        key.public_key().verify(b"", &sig).unwrap();
    }

    #[test]
    fn ed25519_negative() {
        let mut rng = rng();
        let key = Ed25519SigningKey::generate(&mut rng);
        let pk = key.public_key();
        let sig = key.sign(b"message");
        pk.verify(b"message", &sig).unwrap();
        assert_eq!(pk.verify(b"messagE", &sig), Err(Error::InvalidSignature));
        assert_eq!(pk.verify(b"", &sig), Err(Error::InvalidSignature));
        let other = Ed25519SigningKey::generate(&mut rng).public_key();
        assert_eq!(other.verify(b"message", &sig), Err(Error::InvalidSignature));
        for i in 0..64 {
            let mut b = sig.to_bytes();
            b[i] ^= 1;
            let bad = Ed25519Signature::from_bytes(&b).unwrap();
            assert_eq!(
                pk.verify(b"message", &bad),
                Err(Error::InvalidSignature),
                "byte {i}"
            );
        }
        // Non-canonical S (S + L) must be rejected.
        let mut b = sig.to_bytes();
        let l: [u8; 32] =
            hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .unwrap()
                .try_into()
                .unwrap();
        let mut carry = 0u16;
        for i in 0..32 {
            let s = u16::from(b[32 + i]) + u16::from(l[i]) + carry;
            b[32 + i] = s as u8;
            carry = s >> 8;
        }
        if carry == 0 {
            let bad = Ed25519Signature::from_bytes(&b).unwrap();
            assert_eq!(pk.verify(b"message", &bad), Err(Error::InvalidSignature));
        }
        assert_eq!(
            Ed25519Signature::from_bytes(&[0; 63]),
            Err(Error::MalformedSignature)
        );
        assert_eq!(
            Ed25519Signature::from_bytes(&[0; 65]),
            Err(Error::MalformedSignature)
        );
    }

    #[test]
    fn ed25519_public_key_parsing() {
        assert_eq!(
            Ed25519PublicKey::from_bytes(&[0; 31]),
            Err(Error::InvalidPublicKey)
        );
        // The identity point (small order) is rejected.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            Ed25519PublicKey::from_bytes(&identity),
            Err(Error::InvalidPublicKey)
        );
        // y = 2 is not on the curve.
        let mut bad = [0u8; 32];
        bad[0] = 2;
        assert_eq!(
            Ed25519PublicKey::from_bytes(&bad),
            Err(Error::InvalidPublicKey)
        );
        let pk = Ed25519SigningKey::generate(&mut rng()).public_key();
        assert_eq!(Ed25519PublicKey::from_bytes(&pk.to_bytes()), Ok(pk));
    }

    #[test]
    fn ed25519_rejects_non_canonical_public_keys() {
        // p = 2^255 - 19. For a small y on the curve, y + p encodes the same
        // point non-canonically. Try both signs of x.
        let mut tried = 0;
        for y in 2u8..19 {
            for sign in [0u8, 0x80] {
                let mut canonical = [0u8; 32];
                canonical[0] = y;
                canonical[31] = sign;
                let Ok(pk) = Ed25519PublicKey::from_bytes(&canonical) else {
                    continue;
                };
                let mut alias = [0xffu8; 32];
                alias[0] = 0xed + y; // y + p, little-endian; no carry for y < 19
                alias[31] = 0x7f | sign;
                let dalek = ed25519_dalek::VerifyingKey::from_bytes(&alias).unwrap();
                assert_eq!(dalek.to_edwards(), pk.0.to_edwards(), "same point");
                assert_eq!(
                    Ed25519PublicKey::from_bytes(&alias),
                    Err(Error::InvalidPublicKey)
                );
                tried += 1;
            }
        }
        assert!(tried > 0, "no small y on the curve");
    }

    #[test]
    fn ed25519_seed_round_trip() {
        let key = Ed25519SigningKey::generate(&mut rng());
        let again = Ed25519SigningKey::from_seed(&key.to_seed());
        assert_eq!(again.public_key(), key.public_key());
    }

    #[test]
    fn p256_sign_verify() {
        let mut rng = rng();
        let key = SoftwareDeviceKey::generate(&mut rng);
        let pk = key.public_key();
        let bytes = pk.to_bytes();
        assert!(matches!(bytes[0], 2 | 3));
        assert_eq!(DevicePublicKey::from_bytes(&bytes), Ok(pk));
        let sig = key.sign(b"challenge").unwrap();
        assert_eq!(sig.as_der()[0], 0x30);
        pk.verify(b"challenge", &sig).unwrap();
        let parsed = DeviceSignature::from_der(sig.as_der()).unwrap();
        pk.verify(b"challenge", &parsed).unwrap();
        // Deterministic (RFC 6979).
        assert_eq!(key.sign(b"challenge").unwrap(), sig);
        // Private key round trip.
        let again = SoftwareDeviceKey::from_bytes(&key.to_bytes()).unwrap();
        assert_eq!(again.public_key(), pk);
    }

    #[test]
    fn p256_negative() {
        let mut rng = rng();
        let key = SoftwareDeviceKey::generate(&mut rng);
        let pk = key.public_key();
        let sig = key.sign(b"challenge").unwrap();
        assert_eq!(pk.verify(b"challengE", &sig), Err(Error::InvalidSignature));
        let other = SoftwareDeviceKey::generate(&mut rng).public_key();
        assert_eq!(
            other.verify(b"challenge", &sig),
            Err(Error::InvalidSignature)
        );
        // Flipping any bit either breaks the DER or the signature.
        for i in 0..sig.as_der().len() {
            let mut der = sig.as_der().to_vec();
            der[i] ^= 1;
            if let Ok(bad) = DeviceSignature::from_der(&der) {
                assert_eq!(
                    pk.verify(b"challenge", &bad),
                    Err(Error::InvalidSignature),
                    "byte {i}"
                );
            }
        }
        // Truncated, extended and raw (r || s) forms are not DER.
        let der = sig.as_der();
        assert!(DeviceSignature::from_der(&der[..der.len() - 1]).is_err());
        let mut long = der.to_vec();
        long.push(0);
        assert!(DeviceSignature::from_der(&long).is_err());
        assert!(DeviceSignature::from_der(&sig.sig.to_bytes()).is_err());
        assert!(DeviceSignature::from_der(&[]).is_err());
        // r = 0 is rejected.
        assert!(DeviceSignature::from_der(&hex::decode("3006020100020101").unwrap()).is_err());
        // Non-minimal integer encoding (leading zero) is rejected.
        let (r, s) = sig.sig.split_bytes();
        let mut nonmin = vec![0x30, 0, 0x02, 34, 0, 0];
        nonmin.extend_from_slice(&r);
        nonmin.extend_from_slice(&[0x02, 33, 0]);
        nonmin.extend_from_slice(&s);
        nonmin[1] = (nonmin.len() - 2) as u8;
        assert!(DeviceSignature::from_der(&nonmin).is_err());
    }

    #[test]
    fn p256_accepts_high_s() {
        // Hardware keystores produce high-S signatures half the time.
        let key = SoftwareDeviceKey::generate(&mut rng());
        let pk = key.public_key();
        let sig = key.sign(b"msg").unwrap();
        let (r, s) = sig.sig.split_scalars();
        let flipped = p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
        let high = DeviceSignature::from_der(flipped.to_der().as_bytes()).unwrap();
        assert_ne!(high, sig);
        pk.verify(b"msg", &high).unwrap();
    }

    #[test]
    fn p256_public_key_parsing() {
        let pk = SoftwareDeviceKey::generate(&mut rng()).public_key();
        let compressed = pk.to_bytes();
        let uncompressed = pk.0.to_sec1_point(false);
        assert_eq!(
            DevicePublicKey::from_bytes(uncompressed.as_bytes()),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            DevicePublicKey::from_bytes(&compressed[..32]),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            DevicePublicKey::from_bytes(&[0]),
            Err(Error::InvalidPublicKey)
        );
        let mut bad = compressed;
        bad[0] = 0x04;
        assert_eq!(
            DevicePublicKey::from_bytes(&bad),
            Err(Error::InvalidPublicKey)
        );
        // About half of all x coordinates are not on the curve.
        let mut found_invalid = false;
        for x in 0u8..=255 {
            let mut b = [0u8; 33];
            b[0] = 2;
            b[32] = x;
            if DevicePublicKey::from_bytes(&b).is_err() {
                found_invalid = true;
                break;
            }
        }
        assert!(found_invalid);
        assert!(SoftwareDeviceKey::from_bytes(&[0; 32]).is_err());
        assert!(SoftwareDeviceKey::from_bytes(&[0xff; 32]).is_err());
    }

    #[test]
    fn device_signer_is_object_safe() {
        let key = SoftwareDeviceKey::generate(&mut rng());
        let signer: &dyn DeviceSigner = &key;
        let sig = signer.sign(b"m").unwrap();
        signer.public_key().verify(b"m", &sig).unwrap();
    }
}
