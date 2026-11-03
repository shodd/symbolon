//! Symbolon's cryptographic constructions, exactly as specified in
//! `docs/PROTOCOL.md`:
//!
//! | Module | Spec |
//! |---|---|
//! | [`secret_key`] | §3.1 Secret Key and its text form |
//! | [`kdf`] | §1 Argon2id parameter floor, §3.2 key derivation |
//! | [`aead_box`] | §2 `AeadBox` (XChaCha20-Poly1305) |
//! | [`hpke_box`] | §1, §2 `HpkeBox` (HPKE base mode, X-Wing, HKDF-SHA256, ChaCha20-Poly1305) |
//! | [`sign`] | §1 Ed25519 and ECDSA P-256 signatures |
//! | [`fingerprint`] | §3.3 identity fingerprint |
//! | [`pow`] | §4.1 sign-up proof-of-work |
//! | [`padding`] | §8.1 record padding |
//! | [`blob`] | §9 attachment STREAM encryption |
//!
//! Callers build AAD and HPKE `info` values themselves (with
//! `symbolon_protocol::cbor`); this crate only takes them as bytes.
//!
//! Every function that needs randomness takes an explicit RNG. In production
//! pass [`OsRng`] (see [`os_rng`]); tests pass a seeded RNG.
//!
//! The crate is `no_std` (with `alloc`) so it can't touch threads, the file
//! system or the clock, and builds for `wasm32-unknown-unknown`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod aead_box;
mod base32;
pub mod blob;
mod error;
pub mod fingerprint;
pub mod hpke_box;
pub mod kdf;
mod keys;
pub mod padding;
pub mod pow;
mod rng;
pub mod secret_key;
pub mod sign;

#[cfg(test)]
mod test_vectors;

pub use aead_box::AeadBox;
pub use error::Error;
pub use fingerprint::Fingerprint;
pub use hpke_box::{HpkeBox, XWingPublicKey, XWingSecretKey};
pub use kdf::{AccountSecrets, KdfParams, Salt, derive_account_secrets};
pub use keys::SymmetricKey;
pub use rng::{OsRng, os_rng};
pub use secret_key::SecretKey;
pub use sign::{
    DevicePublicKey, DeviceSignature, DeviceSigner, Ed25519PublicKey, Ed25519Signature,
    Ed25519SigningKey, SoftwareDeviceKey,
};

/// Re-exported so callers can name the RNG bound without depending on
/// `rand_core` themselves.
pub use rand_core::CryptoRng;
