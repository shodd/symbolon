# Test vectors

Test vectors for PROTOCOL.md §14. Every implementation MUST pass them. All
binary values are lowercase hex. Each file has a `description` and its
`vectors`. Some files also have an `invalid` list: inputs that must be
rejected, with the expected error class.

| File | Spec | Contents |
|---|---|---|
| `secret-key.json` | §3.1 | `encode`: bytes → `S1-…` text, covering every check-only symbol (`*~$=U`). `parse`: lenient inputs → bytes, or `format` / `checksum` errors |
| `kdf.json` | §1, §3.2 | password → NFKC bytes → `s_pw` → `master` → `auth_seed`, `auth_pk`, `kek`. Two vectors use the real default Argon2id parameters (m = 65536, t = 3, p = 4); one uses the floor (p = 1) |
| `aead-box.json` | §2 | key, nonce, AAD, plaintext → ct ‖ tag and `cbor(AeadBox)`. `invalid`: wrong version or alg, bad sizes, non-canonical CBOR, tampered tag, truncated ct, wrong AAD |
| `padding.json` | §8.1 | content lengths across both block sizes, including the 4096 boundary |
| `blob.json` | §9 | empty file, short file, exactly one full chunk, three chunks, with per-chunk nonces and hashes. `invalid`: truncation, appended data, wrong version, missing last-chunk flag |
| `pow.json` | §4.1 | the smallest counter nonce for several difficulties, plus the same nonce one bit too hard (`valid: false`) |
| `fingerprint.json` | §3.3 | key seeds → `sig_pk`, `enc_pk` → 20-byte fingerprint and display form |
| `signatures.json` | §1 | Ed25519 (RFC 8032) and ECDSA P-256 / SHA-256 (RFC 6979 nonces, DER, SEC1 compressed keys) |
| `hpke-box.json` | §1, §2 | `HpkeBox` to an X-Wing key. HPKE is randomized, so check these by opening, not by re-sealing |

Large inputs aren't stored. Their plaintext is byte `i` = `i mod 251`, and the
files give its length and the SHA-256 of the output.

## Conventions the spec leaves open

These are the readings the vectors encode. They are listed as spec questions
in the PR that added them, and they change if PROTOCOL.md decides otherwise.

- **Fingerprint display**: the 160-bit fingerprint is shown as 32 Crockford
  base32 symbols (the §3.1 alphabet, upper case) in 8 groups of **4**,
  separated by spaces. §3.3 says "8 groups of 5", which would need 200 bits.
- **Padding**: the block size is picked from the minimum padded length
  (`content + 1`). Up to 4096 bytes it's 256, above that 4096. So 4095 bytes
  of content pad to 4096, and 4096 bytes pad to 8192.
- **Blob chunking**: a non-empty file never ends with an empty chunk. A file of
  exactly 65536 bytes is one full last chunk.
- **HpkeBox**: X-Wing is KEM ID `0x647a` (draft-ietf-hpke-pq), and the HPKE
  AAD is empty.

## Checking and regenerating

`crates/crypto/src/test_vectors.rs` checks every file through the public API.
It also regenerates the files from fixed seeds and fails if they differ from
what's committed, so any byte-level drift breaks CI. To rewrite them after an
intended change:

```sh
cargo test -p symbolon-crypto -- --ignored regenerate_test_vectors
```

`independent_check.py` recomputes everything except HPKE and X-Wing key
derivation with libsodium, argon2-cffi, pyca/cryptography and hashlib. It
shares no code with the Rust implementation.

```sh
uv run docs/test-vectors/independent_check.py
```
