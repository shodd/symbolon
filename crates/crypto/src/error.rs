use core::fmt;

/// Errors from this crate. Decryption failures are deliberately not more
/// specific than [`Error::Decryption`]: wrong key, wrong AAD or `info`, and
/// tampered ciphertext all look the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Secret Key text has the wrong prefix, length or symbols.
    SecretKeyFormat,
    /// Secret Key text is well-formed but its check symbol doesn't match.
    SecretKeyChecksum,
    /// Argon2id parameters are below the floor in PROTOCOL.md §1.
    WeakKdfParameters,
    /// Argon2id rejected the parameters (for example `m < 8 * p`).
    InvalidKdfParameters,
    /// Authenticated decryption failed.
    Decryption,
    /// Encryption failed because the input is too long for the cipher.
    Encryption,
    /// An envelope or blob header is not structurally valid.
    MalformedEnvelope,
    /// An envelope or blob has a version this implementation doesn't know.
    UnsupportedVersion,
    /// An envelope names an algorithm or suite this implementation doesn't know.
    UnsupportedAlgorithm,
    /// A public key is not a valid encoding or not a valid point.
    InvalidPublicKey,
    /// Private key bytes are not a valid key.
    InvalidPrivateKey,
    /// A signature is not a valid encoding.
    MalformedSignature,
    /// A signature does not verify.
    InvalidSignature,
    /// Padding is missing or not in canonical form.
    InvalidPadding,
    /// Proof-of-work difficulty is above 256 bits.
    InvalidPowDifficulty,
    /// No proof-of-work nonce was found in the searched range.
    PowNotFound,
    /// A blob ended early: the last chunk is missing or incomplete.
    BlobTruncated,
    /// An input is too large for the construction.
    TooLarge,
    /// The device signer (for example a hardware keystore) failed.
    DeviceSigner,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SecretKeyFormat => "Secret Key is not well-formed",
            Self::SecretKeyChecksum => "Secret Key check symbol does not match",
            Self::WeakKdfParameters => "KDF parameters are below the allowed minimum",
            Self::InvalidKdfParameters => "KDF parameters are invalid",
            Self::Decryption => "decryption failed",
            Self::Encryption => "encryption failed",
            Self::MalformedEnvelope => "envelope is malformed",
            Self::UnsupportedVersion => "unsupported version",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::InvalidPublicKey => "invalid public key",
            Self::InvalidPrivateKey => "invalid private key",
            Self::MalformedSignature => "malformed signature",
            Self::InvalidSignature => "signature does not verify",
            Self::InvalidPadding => "invalid padding",
            Self::InvalidPowDifficulty => "proof-of-work difficulty is out of range",
            Self::PowNotFound => "no proof-of-work nonce found",
            Self::BlobTruncated => "blob is truncated",
            Self::TooLarge => "input is too large",
            Self::DeviceSigner => "device signer failed",
        })
    }
}

impl core::error::Error for Error {}
