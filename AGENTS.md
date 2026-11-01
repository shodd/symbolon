# Working on Symbolon

Symbolon is an end-to-end encrypted password and secrets manager. A bug here can leak someone's entire digital life, so correctness beats speed.

## Sources of truth

- `docs/ARCHITECTURE.md`: what we build and why.
- `docs/PROTOCOL.md`: the normative wire format and crypto constructions. Code MUST match it byte for byte.
- If your task requires a protocol or crypto change, change `PROTOCOL.md` in the same PR and say so at the top of the PR description. Never let code and spec drift apart silently.
- If the spec is ambiguous or looks wrong, stop and report it. Don't guess.

## Layout

The crates are in `crates/`, and their package names carry the `symbolon-` prefix. See ARCHITECTURE §4.

## Crypto rules

- Never implement primitives yourself. Use maintained, audited crates (RustCrypto, dalek). Every new crypto dependency needs a one-line justification in the PR.
- Secrets live in `zeroize`/`secrecy` types, and so do their intermediate buffers. Don't derive `Debug` or `Display` on anything holding key material.
- Compare MACs, tags and secrets in constant time (`subtle`).
- Randomness comes from the OS CSPRNG only (`getrandom` / `rand_core::OsRng`). Tests that need determinism take an explicit RNG parameter.
- Every AEAD, signature and KDF call uses the domain-separation constants in `symbolon-protocol` (`protocol::domain`). Never inline the strings.
- No `unsafe`. The workspace denies it. If it's truly unavoidable, add a narrow `#[allow]` with a comment and flag it in the PR.
- Crypto code needs negative tests: wrong key, tampered ciphertext, wrong AAD or context, truncated input, wrong version tag. Where `PROTOCOL.md` §14 applies, add or update the test vectors in `docs/test-vectors/`.

## Code rules

- Rust 2024 edition, using the toolchain pinned in `rust-toolchain.toml`.
- `symbolon-protocol`, `symbolon-core` and the crypto code must also build for `wasm32-unknown-unknown`. They must not use threads, filesystem access or the system clock directly.
- Async traits in `server-core` don't require `Send`, because the Cloudflare adapter runs on single-threaded WASM.
- Keep dependencies minimal and justify each new one.
- Write comments that are short and useful to the next contributor.

## Before you push

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Branches, commits, PRs

- One branch and one PR per task: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`.
- Small, focused PRs. Commit messages in the imperative mood ("Add AeadBox envelope").
- The PR description covers what changed, why, how it was tested, and anything you were unsure about.
- If the PR touches crypto, key handling or `PROTOCOL.md`, put **`[crypto]`** or **`[protocol]`** in the title. Those PRs need the project owner's approval before merging.
