//! Wire types and constants shared by every client and server.
//!
//! The normative description is `docs/PROTOCOL.md`. Anything defined here must
//! match it exactly.

pub mod b64;
pub mod error;
pub mod ids;
pub mod wire;

pub use wire::Role;

/// Protocol version served under `/v1`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Domain-separation strings (PROTOCOL.md §0). Frozen at 1.0.
pub mod domain {
    pub const AUTH_KEY: &str = "symbolon/v1/auth-key";
    pub const KEK: &str = "symbolon/v1/kek";
    pub const ACCOUNT_KEY: &str = "symbolon/v1/account-key";
    pub const IDENTITY_KEYS: &str = "symbolon/v1/identity-keys";
    pub const IDENTITY_BUNDLE: &str = "symbolon/v1/identity-bundle";
    pub const FINGERPRINT: &str = "symbolon/v1/fingerprint";
    pub const POW: &str = "symbolon/v1/pow";
    pub const SIGNUP: &str = "symbolon/v1/signup";
    pub const LOGIN_DEVICE: &str = "symbolon/v1/login/device";
    pub const LOGIN_ACCOUNT: &str = "symbolon/v1/login/account";
    pub const CREDENTIALS: &str = "symbolon/v1/credentials";
    pub const PAIRING: &str = "symbolon/v1/pairing";
    pub const PAIRING_OFFER: &str = "symbolon/v1/pairing/offer";
    pub const PAIRING_HELLO: &str = "symbolon/v1/pairing/hello";
    pub const GRANT: &str = "symbolon/v1/grant";
    pub const VAULT_LOG: &str = "symbolon/v1/vault-log";
    pub const INVITE_MAC: &str = "symbolon/v1/invite-mac";
    pub const INVITE_ACCEPT: &str = "symbolon/v1/invite-accept";
    pub const RECORD: &str = "symbolon/v1/record";
    pub const STATE: &str = "symbolon/v1/state";
    pub const CHECKPOINT: &str = "symbolon/v1/checkpoint";
    pub const BLOB: &str = "symbolon/v1/blob";
}

/// Per-vault sequence number, assigned by the server on every accepted write.
pub type Seq = u64;
/// Per-item revision; a write sets `revision = base_revision + 1`.
pub type Revision = u64;
/// Vault key generation; starts at 1 and increases on every rotation.
pub type Epoch = u32;
