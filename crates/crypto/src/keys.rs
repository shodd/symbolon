use rand_core::CryptoRng;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A 256-bit symmetric key: KEK, Account Key, vault key, file key or pairing
/// key. Wiped on drop. Deliberately has no `Debug`.
#[derive(Clone)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    pub const LEN: usize = 32;

    /// A fresh random key.
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut key = Self([0u8; 32]);
        rng.fill_bytes(&mut key.0);
        key
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// Copies a key out of a slice, for example a decrypted grant.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr: &[u8; 32] = bytes.try_into().ok()?;
        Some(Self(*arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A zeroizing copy of the key bytes, for wrapping or storage.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SymmetricKey {}

impl ConstantTimeEq for SymmetricKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SymmetricKey {}
