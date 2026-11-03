//! Sign-up proof-of-work (PROTOCOL.md §4.1): find an 8-byte `pow_nonce` with
//!
//! ```text
//! leading_zero_bits(SHA-256("symbolon/v1/pow" || challenge || pow_nonce)) >= difficulty
//! ```
//!
//! The solver tries nonces as big-endian counters from a start value. A
//! server can ask for an arbitrarily hard puzzle, so clients should cap the
//! difficulty they accept and run [`solve_range`] in slices (WASM is single
//! threaded).

use sha2::{Digest, Sha256};
use symbolon_protocol::domain;

use crate::Error;

pub const NONCE_LEN: usize = 8;
/// SHA-256 has 256 bits; anything above can never be met.
pub const MAX_DIFFICULTY: u32 = 256;

fn prefix(challenge: &[u8]) -> Sha256 {
    let mut h = Sha256::new();
    h.update(domain::POW.as_bytes());
    h.update(challenge);
    h
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut n = 0;
    for &b in hash {
        if b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// Checks a solution. Difficulties above 256 never verify.
pub fn verify(challenge: &[u8], nonce: &[u8; NONCE_LEN], difficulty: u32) -> bool {
    let mut h = prefix(challenge);
    h.update(nonce);
    difficulty <= MAX_DIFFICULTY && leading_zero_bits(&h.finalize()) >= difficulty
}

/// Tries `attempts` nonces starting at `start` (as a big-endian `u64`).
/// Returns `Ok(None)` if none of them works.
pub fn solve_range(
    challenge: &[u8],
    difficulty: u32,
    start: u64,
    attempts: u64,
) -> Result<Option<[u8; NONCE_LEN]>, Error> {
    if difficulty > MAX_DIFFICULTY {
        return Err(Error::InvalidPowDifficulty);
    }
    let base = prefix(challenge);
    let mut counter = start;
    for _ in 0..attempts {
        let nonce = counter.to_be_bytes();
        let mut h = base.clone();
        h.update(nonce);
        if leading_zero_bits(&h.finalize()) >= difficulty {
            return Ok(Some(nonce));
        }
        counter = match counter.checked_add(1) {
            Some(c) => c,
            None => break,
        };
    }
    Ok(None)
}

/// Searches the whole nonce space from 0. At the default difficulty (22)
/// this takes about 4 million hashes on average.
pub fn solve(challenge: &[u8], difficulty: u32) -> Result<[u8; NONCE_LEN], Error> {
    solve_range(challenge, difficulty, 0, u64::MAX)?.ok_or(Error::PowNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros() {
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x01]), 7);
        assert_eq!(leading_zero_bits(&[0x00, 0x80]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x3f]), 18);
        assert_eq!(leading_zero_bits(&[0; 32]), 256);
    }

    #[test]
    fn solve_and_verify() {
        let challenge = [0x11u8; 32];
        for difficulty in [0, 1, 8, 12, 16] {
            let nonce = solve(&challenge, difficulty).unwrap();
            assert!(verify(&challenge, &nonce, difficulty));
            // The first solution is the smallest counter that works.
            let n = u64::from_be_bytes(nonce);
            if n > 0 {
                assert_eq!(solve_range(&challenge, difficulty, 0, n).unwrap(), None);
            }
        }
        assert_eq!(solve(&challenge, 0).unwrap(), [0; 8]);
    }

    #[test]
    fn rejects_wrong_inputs() {
        // Fixed inputs, so these outcomes are deterministic. A random change
        // keeps 16 zero bits with probability 2^-16.
        let challenge = [0x22u8; 32];
        let nonce = solve(&challenge, 16).unwrap();
        assert!(verify(&challenge, &nonce, 16));
        let strength = (16..=256)
            .take_while(|&d| verify(&challenge, &nonce, d))
            .last()
            .unwrap();
        assert!(!verify(&challenge, &nonce, strength + 1));
        let mut other = challenge;
        other[0] ^= 1;
        assert!(!verify(&other, &nonce, 16));
        assert!(!verify(&challenge[..31], &nonce, 16));
        let mut bad = nonce;
        bad[7] ^= 1;
        assert!(!verify(&challenge, &bad, 16));
        assert!(!verify(&challenge, &nonce, 257));
        assert_eq!(solve(&challenge, 257), Err(Error::InvalidPowDifficulty));
        assert_eq!(
            solve_range(&challenge, 257, 0, 1),
            Err(Error::InvalidPowDifficulty)
        );
        // The counter doesn't wrap around.
        assert_eq!(solve_range(&challenge, 64, u64::MAX - 2, 10).unwrap(), None);
    }

    #[test]
    fn domain_prefix_is_used() {
        // The hash input is exactly POW || challenge || nonce.
        let challenge = b"abc";
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut data = b"symbolon/v1/pow".to_vec();
        data.extend_from_slice(challenge);
        data.extend_from_slice(&nonce);
        let zeros = leading_zero_bits(&Sha256::digest(&data));
        assert!(verify(challenge, &nonce, zeros));
        assert!(!verify(challenge, &nonce, zeros + 1));
    }
}
