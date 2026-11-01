//! Client core, shared by the Flutter app, the browser extension (WASM),
//! the native autofill providers (UniFFI) and the CLI.
//!
//! Planned modules (roadmap step 1, see `docs/ARCHITECTURE.md` §14):
//! - `crypto`: key derivation, envelopes, signatures, HPKE grants, blob streams
//! - `model`: item types and their CBOR encoding
//! - `sync`: change feed, write queue, three-way merge, checkpoint checks
//! - `store`: local encrypted SQLite copy
//! - `import` / `export`

pub use symbolon_protocol as protocol;
