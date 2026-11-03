//! Account key derivation (PROTOCOL.md §3.2) and the Argon2id parameter
//! floor (§1).
//!
//! ```text
//! pw        = UTF-8(NFKC(password))                  ; no trimming
//! s_pw      = Argon2id(pw, salt, m, t, p, 32)
//! master    = HKDF-Extract(salt = salt, ikm = s_pw || secret_key)
//! auth_seed = HKDF-Expand(master, "symbolon/v1/auth-key", 32)
//! kek       = HKDF-Expand(master, "symbolon/v1/kek", 32)
//! ```

use alloc::string::String;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha2::Sha256;
use symbolon_protocol::domain;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::{Ed25519SigningKey, Error, SecretKey, SymmetricKey};

/// Argon2id cost parameters as sent in the `kdf` object (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl KdfParams {
    /// The defaults for new accounts: `m = 65536` KiB, `t = 3`, `p = 4`.
    pub const DEFAULT: Self = Self {
        m: 65536,
        t: 3,
        p: 4,
    };

    /// The floor every client enforces, so a malicious server can't
    /// downgrade the KDF: `m = 65536`, `t = 3`, `p = 1`.
    pub const MINIMUM: Self = Self {
        m: 65536,
        t: 3,
        p: 1,
    };

    /// Errors with [`Error::WeakKdfParameters`] if any parameter is below
    /// [`KdfParams::MINIMUM`]. Parameters are never raised silently.
    pub fn check_minimum(&self) -> Result<(), Error> {
        let min = Self::MINIMUM;
        if self.m < min.m || self.t < min.t || self.p < min.p {
            return Err(Error::WeakKdfParameters);
        }
        Ok(())
    }

    /// PROTOCOL.md §1: clients SHOULD refuse parameters lower than the ones
    /// last seen for the account. Errors with [`Error::WeakKdfParameters`]
    /// if any of `m`, `t`, `p` is below `last_seen`.
    pub fn check_not_below(&self, last_seen: &Self) -> Result<(), Error> {
        if self.m < last_seen.m || self.t < last_seen.t || self.p < last_seen.p {
            return Err(Error::WeakKdfParameters);
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The per-account KDF salt: 16 random bytes, renewed on every credential
/// change. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Salt([u8; 16]);

impl Salt {
    pub const LEN: usize = 16;

    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        Self(salt)
    }

    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The keys derived from password + Secret Key.
pub struct AccountSecrets {
    auth_key: Ed25519SigningKey,
    kek: SymmetricKey,
}

impl AccountSecrets {
    /// The Ed25519 auth key; the server stores only its public key.
    pub fn auth_key(&self) -> &Ed25519SigningKey {
        &self.auth_key
    }

    /// The key-encryption key that wraps the Account Key.
    pub fn kek(&self) -> &SymmetricKey {
        &self.kek
    }

    pub fn into_parts(self) -> (Ed25519SigningKey, SymmetricKey) {
        (self.auth_key, self.kek)
    }
}

/// Derives the auth keypair and KEK. Fails with
/// [`Error::WeakKdfParameters`] below the floor of PROTOCOL.md §1.
///
/// This runs Argon2id with `params.m` KiB of memory; call it off the UI
/// thread.
pub fn derive_account_secrets(
    password: &str,
    secret_key: &SecretKey,
    salt: &Salt,
    params: &KdfParams,
) -> Result<AccountSecrets, Error> {
    let s_pw = stretch_password(password, salt, params)?;
    let master = extract_master(&s_pw, secret_key, salt);
    Ok(expand_master(&master))
}

/// `UTF-8(NFKC(password))` without trimming, in a single exactly-sized
/// allocation so no stray copies are left by reallocation.
pub(crate) fn normalize_password(password: &str) -> Zeroizing<String> {
    // NFKC is the identity on ASCII; skip the normalizer's internal buffers.
    if password.is_ascii() {
        return Zeroizing::new(String::from(password));
    }
    let len: usize = password.nfkc().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    out.extend(password.nfkc());
    debug_assert_eq!(out.len(), len);
    out
}

/// `s_pw = Argon2id(pw, salt, m, t, p, 32)`, version 0x13, no secret or
/// associated data.
pub(crate) fn stretch_password(
    password: &str,
    salt: &Salt,
    params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    params.check_minimum()?;
    let argon_params = Params::new(params.m, params.t, params.p, Some(32))
        .map_err(|_| Error::InvalidKdfParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let pw = normalize_password(password);
    let mut s_pw = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pw.as_bytes(), salt.as_bytes(), &mut *s_pw)
        .map_err(|_| Error::InvalidKdfParameters)?;
    Ok(s_pw)
}

/// `master = HKDF-Extract(salt, s_pw || secret_key)`.
pub(crate) fn extract_master(
    s_pw: &[u8; 32],
    secret_key: &SecretKey,
    salt: &Salt,
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 48]);
    ikm[..32].copy_from_slice(s_pw);
    ikm[32..].copy_from_slice(secret_key.as_bytes());
    let (mut prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_bytes()), &*ikm);
    let mut master = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&prk);
    prk.as_mut_slice().zeroize();
    master
}

/// `auth_seed` and `kek` from the master secret.
pub(crate) fn expand_master(master: &[u8; 32]) -> AccountSecrets {
    let hk = Hkdf::<Sha256>::from_prk(master).expect("PRK is exactly one SHA-256 output");
    let mut auth_seed = Zeroizing::new([0u8; 32]);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(domain::AUTH_KEY.as_bytes(), &mut *auth_seed)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    hk.expand(domain::KEK.as_bytes(), &mut *kek)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    AccountSecrets {
        auth_key: Ed25519SigningKey::from_seed(&auth_seed),
        kek: SymmetricKey::from_bytes(&kek),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SK: [u8; 16] = [0x42; 16];

    fn salt() -> Salt {
        Salt::from_bytes(&[0x24; 16])
    }

    #[test]
    fn parameter_floor_is_enforced_not_clamped() {
        let weak = [
            KdfParams {
                m: 65535,
                t: 3,
                p: 1,
            },
            KdfParams {
                m: 65536,
                t: 2,
                p: 1,
            },
            KdfParams {
                m: 65536,
                t: 3,
                p: 0,
            },
            KdfParams {
                m: 19456,
                t: 2,
                p: 1,
            }, // argon2 crate defaults
            KdfParams { m: 0, t: 0, p: 0 },
        ];
        for params in weak {
            assert_eq!(params.check_minimum(), Err(Error::WeakKdfParameters));
            let r = derive_account_secrets("pw", &SecretKey::from_bytes(&SK), &salt(), &params);
            assert_eq!(r.err(), Some(Error::WeakKdfParameters), "{params:?}");
        }
        assert_eq!(KdfParams::MINIMUM.check_minimum(), Ok(()));
        assert_eq!(KdfParams::DEFAULT.check_minimum(), Ok(()));
        assert_eq!(KdfParams::default(), KdfParams::DEFAULT);
    }

    #[test]
    fn parameters_never_go_below_last_seen() {
        let seen = KdfParams {
            m: 131072,
            t: 4,
            p: 4,
        };
        assert_eq!(seen.check_not_below(&seen), Ok(()));
        let higher = KdfParams {
            m: 262144,
            t: 4,
            p: 4,
        };
        assert_eq!(higher.check_not_below(&seen), Ok(()));
        for lower in [
            KdfParams {
                m: 131071,
                t: 4,
                p: 4,
            },
            KdfParams {
                m: 131072,
                t: 3,
                p: 4,
            },
            KdfParams {
                m: 131072,
                t: 4,
                p: 3,
            },
            KdfParams::DEFAULT,
        ] {
            assert_eq!(
                lower.check_not_below(&seen),
                Err(Error::WeakKdfParameters),
                "{lower:?}"
            );
        }
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        // Argon2 needs at least 8 KiB per lane.
        let params = KdfParams {
            m: 65536,
            t: 3,
            p: 10_000,
        };
        let r = stretch_password("pw", &salt(), &params);
        assert_eq!(r.err(), Some(Error::InvalidKdfParameters));
    }

    #[test]
    fn nfkc_normalization() {
        // Compatibility ligature, composed vs decomposed, full-width forms.
        assert_eq!(&*normalize_password("\u{fb01}"), "fi");
        assert_eq!(&*normalize_password("A\u{030a}"), "\u{00c5}");
        assert_eq!(&*normalize_password("\u{212b}"), "\u{00c5}"); // Angstrom sign
        assert_eq!(&*normalize_password("\u{ff50}\u{ff57}"), "pw");
        // No trimming, case folding or other changes.
        assert_eq!(&*normalize_password(" Pw \t"), " Pw \t");
        assert_eq!(&*normalize_password(""), "");
        // Exact allocation, including for expanding input (U+FDFA → 18 chars).
        let s = normalize_password("\u{fdfa}");
        assert_eq!(s.capacity(), s.len());
        assert_eq!(s.chars().count(), 18);
    }

    #[test]
    fn derivation_properties() {
        let params = KdfParams::MINIMUM;
        let sk = SecretKey::from_bytes(&SK);
        let base = derive_account_secrets("correct horse", &sk, &salt(), &params).unwrap();
        // Equivalent spellings under NFKC derive the same keys.
        let a = derive_account_secrets("\u{fb01}x", &sk, &salt(), &params).unwrap();
        let b = derive_account_secrets("fix", &sk, &salt(), &params).unwrap();
        assert!(a.kek() == b.kek());
        assert_eq!(a.auth_key().public_key(), b.auth_key().public_key());
        // Auth key and KEK are independent outputs.
        assert_ne!(base.kek().as_bytes(), &base.auth_key().to_seed()[..]);
        // Every input matters.
        let others = [
            derive_account_secrets("correct horse ", &sk, &salt(), &params).unwrap(),
            derive_account_secrets(
                "correct horse",
                &SecretKey::from_bytes(&[0x43; 16]),
                &salt(),
                &params,
            )
            .unwrap(),
            derive_account_secrets(
                "correct horse",
                &sk,
                &Salt::from_bytes(&[0x25; 16]),
                &params,
            )
            .unwrap(),
            derive_account_secrets(
                "correct horse",
                &sk,
                &salt(),
                &KdfParams {
                    m: 65536,
                    t: 4,
                    p: 1,
                },
            )
            .unwrap(),
        ];
        for o in &others {
            assert!(o.kek() != base.kek());
            assert_ne!(o.auth_key().public_key(), base.auth_key().public_key());
        }
    }
}
