# symbolon-crypto

Symbolon's cryptographic constructions, exactly as `docs/PROTOCOL.md` specifies
them. The crate composes audited RustCrypto, dalek and `hpke` primitives and
implements none of its own.

| Module | Spec |
|---|---|
| `secret_key` | §3.1 Secret Key and its `S1-…` text form |
| `kdf` | §1 Argon2id parameter floor, §3.2 derivation |
| `aead_box` | §2 `AeadBox` |
| `hpke_box` | §1, §2 `HpkeBox` |
| `sign` | §1 Ed25519, ECDSA P-256 (`DeviceSigner` trait) |
| `fingerprint` | §3.3 identity fingerprint |
| `pow` | §4.1 sign-up proof-of-work |
| `padding` | §8.1 record padding |
| `blob` | §9 attachment STREAM |

AAD and HPKE `info` values are built by the caller with
`symbolon_protocol::cbor` and the strings in `symbolon_protocol::domain`.

## Randomness

Every function that needs randomness takes an explicit `CryptoRng`. Production
code passes `symbolon_crypto::os_rng()`, which is `getrandom`'s OS CSPRNG and
panics if the OS can't provide randomness. Tests pass a seeded RNG.

## WebAssembly

The crate builds for `wasm32-unknown-unknown`:

```sh
cargo build -p symbolon-crypto -p symbolon-protocol --target wasm32-unknown-unknown
```

(Use a rustup toolchain that has the wasm32 target installed. Homebrew's
cargo doesn't ship it.)

`wasm32-unknown-unknown` has no OS, so `getrandom` needs a backend. Both of
our WASM hosts, the browser extension and Cloudflare Workers, are JavaScript
environments with `crypto.getRandomValues`. `Cargo.toml` therefore turns on
getrandom's `wasm_js` feature for `cfg(all(target_family = "wasm", target_os =
"unknown"))` only. Nothing else is needed: no `RUSTFLAGS`, no `--cfg`.

This pulls in `wasm-bindgen` and `js-sys` on that target. A future non-JS WASM
host (WASI, a plain wasm runtime) would have to drop the feature and pick
another getrandom backend. getrandom's docs advise libraries against enabling
`wasm_js`; we do it anyway because every WASM consumer of this crate runs on
a JS host and must not end up without a CSPRNG.

## Test vectors

`src/test_vectors.rs` checks the committed files in `docs/test-vectors/` and
regenerates them from fixed seeds. See `docs/test-vectors/README.md`.
