<img src="assets/icon.svg" width="64" height="64" alt="">

# Symbolon

A free and open-source, end-to-end encrypted manager for passwords, passkeys, cards, bank accounts, documents, notes and files. It has apps for desktop and mobile, extensions for most browsers, live sync, sharing, and a server you can host yourself.

In ancient Greece a *symbolon* was a token broken in two, and matching the halves proved who you were. In Symbolon the two halves are your password and your Secret Key.

**Status:** design phase. Nothing is usable yet.

- [Architecture](docs/ARCHITECTURE.md): goals, threat model, keys, flows, sharing, server and clients
- [Protocol](docs/PROTOCOL.md): wire format, crypto constructions, endpoints

## Development

Required: Rust (the version is pinned in `rust-toolchain.toml`, and rustup installs it automatically).

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

Node (for the extension and Wrangler) and Flutter will be needed once those parts of the roadmap start. Their versions will be pinned in this repo at that point.

## License

- Server crates (`crates/server-*`): [AGPL-3.0-or-later](LICENSES/AGPL-3.0-or-later.txt)
- Everything else: [MPL-2.0](LICENSES/MPL-2.0.txt)
