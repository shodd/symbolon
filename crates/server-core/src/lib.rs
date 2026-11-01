//! Server logic: auth, sync, permissions and quotas, with no I/O.
//!
//! Deployments plug in through traits (`docs/ARCHITECTURE.md` §11.1):
//! - `Store`: transactional storage, serialized per vault and per account
//! - `BlobStore`: encrypted attachment blobs
//! - `Notifier`: tells an account's connected devices that a vault changed
//! - `RateLimiter`, `Clock`, `Rng`
//!
//! Async traits here must not require `Send`, because the Cloudflare adapter
//! runs on single-threaded WASM.

pub use symbolon_protocol as protocol;
