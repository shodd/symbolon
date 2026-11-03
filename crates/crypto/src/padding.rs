//! Record padding (PROTOCOL.md §8.1): append `0x80`, then `0x00` bytes up to
//! the next multiple of 256 bytes, or of 4096 bytes once the padded length
//! would exceed 4 KiB.
//!
//! Padding always adds at least the `0x80` byte. The block size depends on
//! the minimum padded length `n + 1`: up to 4096 it rounds to 256, above it
//! to 4096. So the buckets are 256, 512, …, 4096, 8192, 12288, … (a 4096-byte
//! input pads to 8192). See the PR's spec questions.
//!
//! [`unpad`] is strict: it only accepts output that [`pad`] produces.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::Error;

const SMALL_BLOCK: usize = 256;
const LARGE_BLOCK: usize = 4096;

/// The padded length for `n` bytes of content, or `None` on overflow.
pub fn padded_len(n: usize) -> Option<usize> {
    let min = n.checked_add(1)?;
    let block = if min <= LARGE_BLOCK {
        SMALL_BLOCK
    } else {
        LARGE_BLOCK
    };
    min.checked_next_multiple_of(block)
}

/// Pads `data` into a new zeroizing buffer of exactly the padded length.
pub fn pad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let len = padded_len(data.len()).ok_or(Error::TooLarge)?;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(data);
    out.push(0x80);
    out.resize(len, 0);
    Ok(out)
}

/// Strips the padding and returns the content. Rejects missing markers,
/// non-zero filler and lengths that aren't what [`pad`] would produce.
pub fn unpad(padded: &[u8]) -> Result<&[u8], Error> {
    let marker = padded
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::InvalidPadding)?;
    if padded[marker] != 0x80 || padded_len(marker) != Some(padded.len()) {
        return Err(Error::InvalidPadding);
    }
    Ok(&padded[..marker])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_sizes() {
        let cases = [
            (0, 256),
            (1, 256),
            (255, 256),
            (256, 512),
            (511, 512),
            (3839, 3840),
            (3840, 4096),
            (4095, 4096),
            (4096, 8192),
            (8191, 8192),
            (8192, 12288),
            (1_048_575, 1_048_576),
        ];
        for (n, expected) in cases {
            assert_eq!(padded_len(n), Some(expected), "n = {n}");
            let p = pad(&vec![0xab; n]).unwrap();
            assert_eq!(p.len(), expected);
            assert_eq!(p.capacity(), expected);
            assert_eq!(p[n], 0x80);
            assert!(p[n + 1..].iter().all(|&b| b == 0));
        }
        assert_eq!(padded_len(usize::MAX), None);
        assert_eq!(padded_len(usize::MAX - 1), None);
    }

    #[test]
    fn round_trip_every_small_length() {
        for n in 0..9000 {
            let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let p = pad(&data).unwrap();
            assert_eq!(unpad(&p).unwrap(), &data[..], "n = {n}");
        }
        // Content ending in 0x80 or 0x00 is fine.
        for data in [&[0x80][..], &[0x00], &[0x80, 0x00], &[0x00, 0x80]] {
            assert_eq!(unpad(&pad(data).unwrap()).unwrap(), data);
        }
    }

    #[test]
    fn rejects_bad_padding() {
        let good = pad(b"hello").unwrap();
        assert_eq!(unpad(&[]), Err(Error::InvalidPadding));
        assert_eq!(unpad(&[0; 256]), Err(Error::InvalidPadding)); // no marker
        let mut bad = good.to_vec();
        bad[5] = 0x81; // wrong marker
        assert_eq!(unpad(&bad), Err(Error::InvalidPadding));
        let mut bad = good.to_vec();
        bad[200] = 1; // non-zero filler
        assert_eq!(unpad(&bad), Err(Error::InvalidPadding));
        assert_eq!(unpad(&good[..255]), Err(Error::InvalidPadding)); // truncated
        let mut bad = good.to_vec();
        bad.push(0); // too long
        assert_eq!(unpad(&bad), Err(Error::InvalidPadding));
        let mut bad = good.to_vec();
        bad.resize(512, 0); // valid marker, wrong bucket
        assert_eq!(unpad(&bad), Err(Error::InvalidPadding));
        // 4096 bytes of content must use the 8192 bucket, not 4352.
        let mut bad = vec![0xab; 4096];
        bad.push(0x80);
        bad.resize(4352, 0);
        assert_eq!(unpad(&bad), Err(Error::InvalidPadding));
        assert_eq!(unpad(&[0x80]), Err(Error::InvalidPadding));
    }
}
