//! Attachment encryption (PROTOCOL.md §9), a STREAM construction:
//!
//! ```text
//! header  = 0x01 || nonce_prefix (19 random bytes)
//! chunk_i = plaintext[i*65536 .. (i+1)*65536]          ; last chunk may be shorter
//! nonce_i = nonce_prefix || u32be(i) || (0x01 if last else 0x00)
//! ct_i    = XChaCha20-Poly1305(file_key, nonce_i, chunk_i, aad)
//! blob    = header || ct_0 || ct_1 || …
//! ```
//!
//! The chunk index stops reordering, and the last-chunk flag stops
//! truncation and appended data. An empty file is one empty last chunk; a
//! non-empty file never ends with an empty chunk (a 65536-byte file is one
//! full last chunk).
//!
//! Both directions stream: they buffer at most one chunk.
//! [`BlobDecryptor::update`] returns plaintext of chunks that are known not
//! to be the last one, so data arrives before the whole blob is checked.
//! Treat the output as incomplete until [`BlobDecryptor::finish`] succeeds.

use alloc::vec::Vec;

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::aead_box::{NONCE_LEN, TAG_LEN};
use crate::{Error, SymmetricKey};

/// Blob format version (first header byte).
pub const VERSION: u8 = 1;
pub const NONCE_PREFIX_LEN: usize = 19;
pub const HEADER_LEN: usize = 1 + NONCE_PREFIX_LEN;
/// Plaintext bytes per chunk.
pub const CHUNK_LEN: usize = 65536;
/// Ciphertext bytes per full chunk.
pub const CT_CHUNK_LEN: usize = CHUNK_LEN + TAG_LEN;
/// Chunk indices are 32 bits.
pub const MAX_CHUNKS: u64 = 1 << 32;

/// The blob size for a file of `plaintext_len` bytes (the `size` to reserve
/// in §9 step 1), or `None` if the file is too large for 2^32 chunks.
pub fn ciphertext_len(plaintext_len: u64) -> Option<u64> {
    let chunks = plaintext_len.div_ceil(CHUNK_LEN as u64).max(1);
    if chunks > MAX_CHUNKS {
        return None;
    }
    (HEADER_LEN as u64)
        .checked_add(plaintext_len)?
        .checked_add(chunks * TAG_LEN as u64)
}

fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u64, last: bool) -> Result<XNonce, Error> {
    let index = u32::try_from(index).map_err(|_| Error::TooLarge)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..NONCE_LEN - 1].copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(last);
    Ok(XNonce::from(nonce))
}

/// Encrypts a blob incrementally. Feed plaintext with [`update`] and end
/// with [`finish`]; concatenating all returned bytes gives the blob.
///
/// [`update`]: BlobEncryptor::update
/// [`finish`]: BlobEncryptor::finish
pub struct BlobEncryptor {
    cipher: XChaCha20Poly1305,
    aad: Vec<u8>,
    prefix: [u8; NONCE_PREFIX_LEN],
    index: u64,
    /// Pending plaintext; at most one chunk, plus room for in-place encryption.
    buf: Zeroizing<Vec<u8>>,
    header_written: bool,
}

impl BlobEncryptor {
    /// Starts a blob with a fresh random nonce prefix. `aad` is the caller's
    /// `cbor(["symbolon/v1/blob", vault_id, blob_id])`.
    pub fn new(file_key: &SymmetricKey, aad: &[u8], rng: &mut impl CryptoRng) -> Self {
        let mut prefix = [0u8; NONCE_PREFIX_LEN];
        rng.fill_bytes(&mut prefix);
        Self::with_nonce_prefix(file_key, aad, prefix)
    }

    /// Deterministic variant for test vectors. Never reuse a prefix with
    /// the same key.
    pub(crate) fn with_nonce_prefix(
        file_key: &SymmetricKey,
        aad: &[u8],
        prefix: [u8; NONCE_PREFIX_LEN],
    ) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(file_key.as_bytes().into()),
            aad: aad.to_vec(),
            prefix,
            index: 0,
            buf: Zeroizing::new(Vec::with_capacity(CT_CHUNK_LEN)),
            header_written: false,
        }
    }

    fn take_header(&mut self, out: &mut Vec<u8>) {
        if !self.header_written {
            out.push(VERSION);
            out.extend_from_slice(&self.prefix);
            self.header_written = true;
        }
    }

    /// Encrypts the pending chunk and appends it to `out`.
    fn seal_chunk(&mut self, last: bool, out: &mut Vec<u8>) -> Result<(), Error> {
        let nonce = chunk_nonce(&self.prefix, self.index, last)?;
        let tag = self
            .cipher
            .encrypt_inout_detached(&nonce, &self.aad, self.buf.as_mut_slice().into())
            .map_err(|_| Error::Encryption)?;
        out.extend_from_slice(&self.buf);
        out.extend_from_slice(&tag);
        self.buf.clear();
        self.index += 1;
        Ok(())
    }

    /// Adds plaintext and returns the ciphertext that is ready (the header
    /// on the first call, then whole chunks). Output lags input by up to one
    /// chunk, because a full chunk can't be sealed until it's known not to
    /// be the last.
    pub fn update(&mut self, mut data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.take_header(&mut out);
        while !data.is_empty() {
            if self.buf.len() == CHUNK_LEN {
                self.seal_chunk(false, &mut out)?;
            }
            let take = (CHUNK_LEN - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(out)
    }

    /// Seals the last chunk and returns the remaining ciphertext.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(HEADER_LEN + CT_CHUNK_LEN);
        self.take_header(&mut out);
        self.seal_chunk(true, &mut out)?;
        Ok(out)
    }
}

/// Decrypts a blob incrementally. Feed ciphertext with [`update`] (any
/// slicing works) and end with [`finish`], which detects truncation. After
/// any error the decryptor stays failed.
///
/// [`update`]: BlobDecryptor::update
/// [`finish`]: BlobDecryptor::finish
pub struct BlobDecryptor {
    cipher: XChaCha20Poly1305,
    aad: Vec<u8>,
    header: [u8; HEADER_LEN],
    header_len: usize,
    index: u64,
    /// Up to one ciphertext chunk plus one byte, which proves the chunk is
    /// not the last. Decrypted in place, so it is zeroizing.
    buf: Zeroizing<Vec<u8>>,
    failed: bool,
}

impl BlobDecryptor {
    pub fn new(file_key: &SymmetricKey, aad: &[u8]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(file_key.as_bytes().into()),
            aad: aad.to_vec(),
            header: [0u8; HEADER_LEN],
            header_len: 0,
            index: 0,
            buf: Zeroizing::new(Vec::with_capacity(CT_CHUNK_LEN + 1)),
            failed: false,
        }
    }

    fn prefix(&self) -> [u8; NONCE_PREFIX_LEN] {
        let mut p = [0u8; NONCE_PREFIX_LEN];
        p.copy_from_slice(&self.header[1..]);
        p
    }

    /// Decrypts the first `len` buffered bytes as chunk `index` and appends
    /// the plaintext to `out`.
    fn open_chunk(&mut self, len: usize, last: bool, out: &mut Vec<u8>) -> Result<(), Error> {
        let nonce = chunk_nonce(&self.prefix(), self.index, last)?;
        let (body, tag) = self.buf[..len].split_at_mut(len - TAG_LEN);
        let tag = Tag::try_from(&*tag).map_err(|_| Error::Decryption)?;
        self.cipher
            .decrypt_inout_detached(&nonce, &self.aad, body.into(), &tag)
            .map_err(|_| Error::Decryption)?;
        out.extend_from_slice(body);
        self.index += 1;
        Ok(())
    }

    /// Adds ciphertext and returns the plaintext of every chunk that is now
    /// known not to be the last. Errors are final.
    pub fn update(&mut self, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.failed {
            return Err(Error::Decryption);
        }
        let result = self.update_inner(data);
        self.failed = result.is_err();
        result
    }

    fn update_inner(&mut self, mut data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.header_len < HEADER_LEN {
            let take = (HEADER_LEN - self.header_len).min(data.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&data[..take]);
            self.header_len += take;
            data = &data[take..];
            if self.header_len > 0 && self.header[0] != VERSION {
                return Err(Error::UnsupportedVersion);
            }
        }

        // Each chunk is opened once one more byte is buffered after it, so
        // from `available` bytes, (available - 1) / CT_CHUNK_LEN chunks open.
        let available = self.buf.len() + data.len();
        let chunks = available.saturating_sub(1) / CT_CHUNK_LEN;
        let mut out = Zeroizing::new(Vec::with_capacity(chunks * CHUNK_LEN));

        while !data.is_empty() {
            let take = (CT_CHUNK_LEN + 1 - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == CT_CHUNK_LEN + 1 {
                self.open_chunk(CT_CHUNK_LEN, false, &mut out)?;
                let next = self.buf[CT_CHUNK_LEN];
                self.buf.clear();
                self.buf.push(next);
            }
        }
        Ok(out)
    }

    /// Opens the last chunk and returns its plaintext. Fails if the blob is
    /// truncated, has trailing data, or was tampered with.
    pub fn finish(mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.failed {
            return Err(Error::Decryption);
        }
        if self.header_len < HEADER_LEN || self.buf.len() < TAG_LEN {
            return Err(Error::BlobTruncated);
        }
        // Only an empty file ends with an empty chunk.
        if self.buf.len() == TAG_LEN && self.index > 0 {
            return Err(Error::MalformedEnvelope);
        }
        let len = self.buf.len();
        let mut out = Zeroizing::new(Vec::with_capacity(len - TAG_LEN));
        self.open_chunk(len, true, &mut out)?;
        Ok(out)
    }
}

/// Encrypts a whole file in memory. Prefer [`BlobEncryptor`] for large
/// files.
pub fn encrypt(
    file_key: &SymmetricKey,
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Vec<u8>, Error> {
    let mut enc = BlobEncryptor::new(file_key, aad, rng);
    let mut out = enc.update(plaintext)?;
    out.extend_from_slice(&enc.finish()?);
    Ok(out)
}

/// Decrypts a whole blob in memory. Prefer [`BlobDecryptor`] for large
/// files.
pub fn decrypt(
    file_key: &SymmetricKey,
    aad: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut dec = BlobDecryptor::new(file_key, aad);
    let mut out = dec.update(blob)?;
    let tail = dec.finish()?;
    out.extend_from_slice(&tail);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};

    const AAD: &[u8] = b"blob aad";

    fn setup() -> (SymmetricKey, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::from_seed([4; 32]);
        (SymmetricKey::generate(&mut rng), rng)
    }

    fn data(len: usize) -> Vec<u8> {
        let mut rng = ChaCha20Rng::from_seed([len as u8; 32]);
        let mut v = vec![0u8; len];
        rng.fill_bytes(&mut v);
        v
    }

    fn encrypt_sliced(enc: &mut BlobEncryptor, pt: &[u8], step: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in pt.chunks(step.max(1)) {
            out.extend_from_slice(&enc.update(part).unwrap());
        }
        out
    }

    fn decrypt_sliced(key: &SymmetricKey, blob: &[u8], step: usize) -> Result<Vec<u8>, Error> {
        let mut dec = BlobDecryptor::new(key, AAD);
        let mut out = Vec::new();
        for part in blob.chunks(step) {
            out.extend_from_slice(&dec.update(part)?);
        }
        out.extend_from_slice(&dec.finish()?);
        Ok(out)
    }

    const LENGTHS: [usize; 9] = [
        0,
        1,
        CHUNK_LEN - 1,
        CHUNK_LEN,
        CHUNK_LEN + 1,
        2 * CHUNK_LEN,
        2 * CHUNK_LEN + 1,
        3 * CHUNK_LEN + 12345,
        100_000,
    ];

    #[test]
    fn round_trip_with_any_slicing() {
        let (key, _) = setup();
        let prefix = [0x77; NONCE_PREFIX_LEN];
        for len in LENGTHS {
            let pt = data(len);
            let mut enc = BlobEncryptor::with_nonce_prefix(&key, AAD, prefix);
            let mut blob = enc.update(&pt).unwrap();
            blob.extend_from_slice(&enc.finish().unwrap());
            assert_eq!(
                blob.len() as u64,
                ciphertext_len(len as u64).unwrap(),
                "len {len}"
            );
            for step in [1000, 7, CT_CHUNK_LEN, CT_CHUNK_LEN + 1, blob.len()] {
                // Encryption output doesn't depend on how input is sliced.
                let mut enc = BlobEncryptor::with_nonce_prefix(&key, AAD, prefix);
                let mut again = encrypt_sliced(&mut enc, &pt, step);
                again.extend_from_slice(&enc.finish().unwrap());
                assert_eq!(again, blob, "len {len} step {step}");
                assert_eq!(
                    decrypt_sliced(&key, &blob, step).unwrap(),
                    pt,
                    "len {len} step {step}"
                );
            }
        }
    }

    #[test]
    fn byte_at_a_time() {
        let (key, mut rng) = setup();
        let pt = data(CHUNK_LEN + 3);
        let blob = encrypt(&key, AAD, &pt, &mut rng).unwrap();
        assert_eq!(decrypt_sliced(&key, &blob, 1).unwrap(), pt);
    }

    #[test]
    fn layout() {
        let (key, mut rng) = setup();
        let empty = encrypt(&key, AAD, b"", &mut rng).unwrap();
        assert_eq!(empty.len(), HEADER_LEN + TAG_LEN);
        assert_eq!(empty[0], VERSION);
        assert_eq!(&*decrypt(&key, AAD, &empty).unwrap(), b"");
        assert_eq!(ciphertext_len(0), Some(36));
        assert_eq!(ciphertext_len(CHUNK_LEN as u64), Some(20 + 65536 + 16));
        assert_eq!(ciphertext_len(CHUNK_LEN as u64 + 1), Some(20 + 65537 + 32));
        assert_eq!(
            ciphertext_len(MAX_CHUNKS * CHUNK_LEN as u64).map(|_| ()),
            Some(())
        );
        assert_eq!(ciphertext_len(MAX_CHUNKS * CHUNK_LEN as u64 + 1), None);
        assert_eq!(ciphertext_len(u64::MAX), None);
        // Fresh nonce prefixes.
        let again = encrypt(&key, AAD, b"", &mut rng).unwrap();
        assert_ne!(empty[1..HEADER_LEN], again[1..HEADER_LEN]);
    }

    /// Splits a blob into header and ciphertext chunks.
    fn split(blob: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let (h, rest) = blob.split_at(HEADER_LEN);
        (
            h.to_vec(),
            rest.chunks(CT_CHUNK_LEN).map(<[u8]>::to_vec).collect(),
        )
    }

    fn join(header: &[u8], chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut v = header.to_vec();
        for c in chunks {
            v.extend_from_slice(c);
        }
        v
    }

    #[test]
    fn detects_truncation() {
        let (key, mut rng) = setup();
        let pt = data(2 * CHUNK_LEN + 100);
        let blob = encrypt(&key, AAD, &pt, &mut rng).unwrap();
        let boundaries = [
            0,
            1,
            HEADER_LEN - 1,
            HEADER_LEN,
            HEADER_LEN + 15,
            HEADER_LEN + 16,
            HEADER_LEN + CT_CHUNK_LEN,
            HEADER_LEN + CT_CHUNK_LEN + 1,
            HEADER_LEN + 2 * CT_CHUNK_LEN,
            HEADER_LEN + 2 * CT_CHUNK_LEN + 16,
            blob.len() - 1,
        ];
        for len in boundaries {
            let r = decrypt_sliced(&key, &blob[..len], 4096);
            assert!(
                matches!(
                    r,
                    Err(Error::BlobTruncated | Error::Decryption | Error::MalformedEnvelope)
                ),
                "len {len}: {r:?}"
            );
        }
        // Dropping whole trailing chunks is caught by the last-chunk flag.
        let (h, chunks) = split(&blob);
        for keep in 1..chunks.len() {
            let r = decrypt_sliced(&key, &join(&h, &chunks[..keep]), 4096);
            assert_eq!(r, Err(Error::Decryption), "keep {keep}");
        }
    }

    #[test]
    fn detects_reordering_duplication_and_appending() {
        let (key, mut rng) = setup();
        let pt = data(3 * CHUNK_LEN + 5);
        let blob = encrypt(&key, AAD, &pt, &mut rng).unwrap();
        let (h, c) = split(&blob);
        let variants = [
            vec![c[1].clone(), c[0].clone(), c[2].clone(), c[3].clone()],
            vec![c[0].clone(), c[2].clone(), c[1].clone(), c[3].clone()],
            vec![
                c[0].clone(),
                c[0].clone(),
                c[1].clone(),
                c[2].clone(),
                c[3].clone(),
            ],
            vec![c[0].clone(), c[1].clone(), c[3].clone()],
            vec![
                c[0].clone(),
                c[1].clone(),
                c[2].clone(),
                c[3].clone(),
                c[3].clone(),
            ],
            vec![
                c[0].clone(),
                c[1].clone(),
                c[2].clone(),
                c[3].clone(),
                vec![0],
            ],
            vec![
                c[0].clone(),
                c[1].clone(),
                c[2].clone(),
                c[3].clone(),
                vec![0; 16],
            ],
            vec![
                c[0].clone(),
                c[1].clone(),
                c[2].clone(),
                c[3].clone(),
                c[0].clone(),
            ],
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_eq!(
                decrypt_sliced(&key, &join(&h, v), 10_000),
                Err(Error::Decryption),
                "variant {i}"
            );
        }
        // Chunks from another blob under the same key don't fit either.
        let other = encrypt(&key, AAD, &pt, &mut rng).unwrap();
        let (_, oc) = split(&other);
        let mixed = [c[0].clone(), oc[1].clone(), c[2].clone(), c[3].clone()];
        assert_eq!(
            decrypt_sliced(&key, &join(&h, &mixed), 10_000),
            Err(Error::Decryption)
        );
    }

    #[test]
    fn rejects_wrong_key_aad_and_tampering() {
        let (key, mut rng) = setup();
        let pt = data(CHUNK_LEN + 10);
        let blob = encrypt(&key, AAD, &pt, &mut rng).unwrap();
        let other = SymmetricKey::generate(&mut rng);
        assert_eq!(decrypt(&other, AAD, &blob).err(), Some(Error::Decryption));
        assert_eq!(
            decrypt(&key, b"other aad", &blob).err(),
            Some(Error::Decryption)
        );
        assert_eq!(decrypt(&key, b"", &blob).err(), Some(Error::Decryption));
        for pos in [
            1,
            10,
            HEADER_LEN - 1,
            HEADER_LEN,
            HEADER_LEN + CT_CHUNK_LEN + 3,
            blob.len() - 1,
        ] {
            let mut bad = blob.clone();
            bad[pos] ^= 1;
            assert_eq!(
                decrypt(&key, AAD, &bad).err(),
                Some(Error::Decryption),
                "pos {pos}"
            );
        }
        for version in [0u8, 2, 0xff] {
            let mut bad = blob.clone();
            bad[0] = version;
            assert_eq!(
                decrypt(&key, AAD, &bad).err(),
                Some(Error::UnsupportedVersion)
            );
        }
    }

    #[test]
    fn rejects_empty_last_chunk_after_data() {
        // Hand-build the non-canonical encoding of a 65536-byte file: one full
        // non-last chunk followed by an empty last chunk.
        let (key, _) = setup();
        let prefix = [9u8; NONCE_PREFIX_LEN];
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let seal = |i, last, pt: &[u8]| {
            let mut buf = pt.to_vec();
            let tag = cipher
                .encrypt_inout_detached(
                    &chunk_nonce(&prefix, i, last).unwrap(),
                    AAD,
                    buf.as_mut_slice().into(),
                )
                .unwrap();
            buf.extend_from_slice(&tag);
            buf
        };
        let mut blob = vec![VERSION];
        blob.extend_from_slice(&prefix);
        blob.extend_from_slice(&seal(0, false, &data(CHUNK_LEN)));
        blob.extend_from_slice(&seal(1, true, b""));
        assert_eq!(
            decrypt(&key, AAD, &blob).err(),
            Some(Error::MalformedEnvelope)
        );
        // A short final chunk sealed as non-last is also rejected.
        let mut blob = vec![VERSION];
        blob.extend_from_slice(&prefix);
        blob.extend_from_slice(&seal(0, false, b"short"));
        assert_eq!(decrypt(&key, AAD, &blob).err(), Some(Error::Decryption));
        // Index must start at 0.
        let mut blob = vec![VERSION];
        blob.extend_from_slice(&prefix);
        blob.extend_from_slice(&seal(1, true, b"x"));
        assert_eq!(decrypt(&key, AAD, &blob).err(), Some(Error::Decryption));
    }

    #[test]
    fn errors_are_sticky() {
        let (key, mut rng) = setup();
        let blob = encrypt(&key, AAD, &data(3 * CHUNK_LEN), &mut rng).unwrap();
        let mut bad = blob.clone();
        bad[HEADER_LEN + 5] ^= 1;
        let mut dec = BlobDecryptor::new(&key, AAD);
        assert_eq!(
            dec.update(&bad[..HEADER_LEN + CT_CHUNK_LEN + 1]).err(),
            Some(Error::Decryption)
        );
        assert_eq!(
            dec.update(&blob[HEADER_LEN + CT_CHUNK_LEN + 1..]).err(),
            Some(Error::Decryption)
        );
        assert_eq!(dec.finish().err(), Some(Error::Decryption));
    }

    #[test]
    fn nonce_layout() {
        let prefix: [u8; NONCE_PREFIX_LEN] = core::array::from_fn(|i| i as u8);
        let n = chunk_nonce(&prefix, 0x0102_0304, true).unwrap();
        assert_eq!(&n[..19], &prefix);
        assert_eq!(&n[19..23], &[1, 2, 3, 4]);
        assert_eq!(n[23], 1);
        assert_eq!(chunk_nonce(&prefix, 7, false).unwrap()[23], 0);
        assert!(chunk_nonce(&prefix, u64::from(u32::MAX), false).is_ok());
        assert_eq!(
            chunk_nonce(&prefix, MAX_CHUNKS, false),
            Err(Error::TooLarge)
        );
    }
}
