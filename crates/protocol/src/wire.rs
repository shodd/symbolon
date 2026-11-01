//! JSON request and response bodies (PROTOCOL.md §0.1, §4–§9, §11).
//!
//! Conventions:
//! - Binary values are [`B64`]; IDs are the typed UUIDs from [`crate::ids`].
//! - Times are Unix seconds ([`UnixSeconds`]).
//! - Unknown JSON fields are ignored on input (forward compatibility), so no
//!   type here uses `deny_unknown_fields`.
//! - Envelopes, signatures and keys are opaque bytes at this layer. Their
//!   structure is a later task.
//! - Endpoints with no body, or whose response the spec leaves open, are
//!   modelled with [`Empty`] (`{}`).
//! - Query strings and raw bodies (blob upload and download) are not JSON;
//!   the query structs below only name the parameters.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::b64::B64;
use crate::error::ErrorCode;
use crate::ids::{BlobId, ChallengeId, DeviceId, InviteId, ItemId, PairingId, UserId, VaultId};
use crate::{Epoch, Revision, Seq};

/// Time as Unix seconds (PROTOCOL.md §0).
pub type UnixSeconds = u64;

/// An empty JSON object, for bodies that carry no data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Vault membership roles, ordered from least to most privileged (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    View,
    Edit,
    Manage,
    Owner,
}

/// Session level (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLevel {
    /// Device-key login, 1 h.
    Device,
    /// Account-level login, 10 min; needed for step-up endpoints (§4.4).
    StepUp,
}

/// Opaque bearer token. `Debug` is redacted so it can't end up in logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessToken(pub String);

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken(<redacted>)")
    }
}

/// Password-stretching algorithm (§1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlg {
    Argon2id,
}

/// KDF parameters and salt (§3.2, §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kdf {
    pub alg: KdfAlg,
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
    pub salt: B64,
}

/// A signed identity bundle: `bundle` is `cbor(...)`, `bundle_sig` its Ed25519 signature (§3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBundle {
    pub bundle: B64,
    pub bundle_sig: B64,
}

// ---------------------------------------------------------------------------
// §0.1 Server info
// ---------------------------------------------------------------------------

/// `GET /v1/server` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Supported protocol versions.
    pub protocol: Vec<u32>,
    /// Canonical origin, lowercase, no trailing slash.
    pub origin: String,
    pub limits: Limits,
    pub pow: PowParams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_record_bytes: u64,
    pub max_file_bytes: u64,
    pub quota_bytes: u64,
    pub history_revisions: u32,
    pub tombstone_retention_days: u32,
}

/// Proof-of-work parameters advertised in server info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowParams {
    /// e.g. `sha256-lzb`.
    pub alg: String,
    pub difficulty: u32,
}

// ---------------------------------------------------------------------------
// §4 Accounts and sessions
// ---------------------------------------------------------------------------

/// `POST /v1/signup/begin` request. The spec defines no fields.
pub type SignupBeginRequest = Empty;

/// Proof-of-work challenge issued at sign-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge: B64,
    pub difficulty: u32,
}

/// `POST /v1/signup/begin` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupBeginResponse {
    pub user_id: UserId,
    pub signup_token: String,
    pub pow: PowChallenge,
    pub expires_at: UnixSeconds,
}

/// Device description sent at registration (§4.1, §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistration {
    pub name: String,
    /// e.g. `macos`.
    pub platform: String,
    /// ECDSA P-256 public key, SEC1 compressed.
    pub pk: B64,
    /// e.g. `hardware`.
    pub key_storage: String,
}

/// `POST /v1/signup/finish` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupFinishRequest {
    pub signup_token: String,
    pub pow_nonce: B64,
    pub kdf: Kdf,
    pub auth_pk: B64,
    pub wrapped_ak: B64,
    pub wrapped_ik: B64,
    pub bundle: B64,
    pub bundle_sig: B64,
    pub device: DeviceRegistration,
    pub auth_sig: B64,
}

/// `POST /v1/signup/finish` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupFinishResponse {
    pub device_id: DeviceId,
}

/// `GET /v1/accounts/{user_id}/prelogin` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginResponse {
    pub kdf: Kdf,
}

/// `POST /v1/auth/challenge` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallengeRequest {
    pub user_id: UserId,
}

/// `POST /v1/auth/challenge` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthChallengeResponse {
    pub challenge_id: ChallengeId,
    /// 32 bytes.
    pub challenge: B64,
    pub expires_at: UnixSeconds,
}

/// `POST /v1/auth/device` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthDeviceRequest {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub challenge_id: ChallengeId,
    pub sig: B64,
}

/// `POST /v1/auth/account` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthAccountRequest {
    pub user_id: UserId,
    pub challenge_id: ChallengeId,
    pub sig: B64,
}

/// Response of both login endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    pub access_token: AccessToken,
    pub level: SessionLevel,
    pub expires_at: UnixSeconds,
}

/// `GET /v1/account/keys` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountKeysResponse {
    pub kdf: Kdf,
    pub wrapped_ak: B64,
    pub wrapped_ik: B64,
    pub bundle: B64,
    pub bundle_sig: B64,
}

/// `GET /v1/users/{user_id}/identity` response.
pub type IdentityResponse = SignedBundle;

/// `PUT /v1/account/credentials` request (step-up).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialsChangeRequest {
    pub kdf: Kdf,
    pub auth_pk: B64,
    pub wrapped_ak: B64,
    pub auth_sig: B64,
}

/// `PUT /v1/account/credentials` response.
pub type CredentialsChangeResponse = Empty;

/// `DELETE /v1/account` response.
pub type DeleteAccountResponse = Empty;

// ---------------------------------------------------------------------------
// §5 Devices and pairing
// ---------------------------------------------------------------------------

/// `POST /v1/devices` request (step-up).
pub type CreateDeviceRequest = DeviceRegistration;

/// `POST /v1/devices` response.
pub type CreateDeviceResponse = SignupFinishResponse;

/// One entry of `GET /v1/devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: DeviceId,
    pub name: String,
    pub platform: String,
    pub key_storage: String,
    pub created_at: UnixSeconds,
    /// `None` until the device has authenticated once.
    #[serde(default)]
    pub last_seen_at: Option<UnixSeconds>,
}

/// `GET /v1/devices` response.
pub type ListDevicesResponse = Vec<DeviceInfo>;

/// `PATCH /v1/devices/{id}` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenameDeviceRequest {
    pub name: String,
}

/// `PATCH /v1/devices/{id}` response.
pub type RenameDeviceResponse = Empty;

/// `DELETE /v1/devices/{id}` response.
pub type RevokeDeviceResponse = Empty;

/// `POST /v1/pairing` request.
pub type CreatePairingRequest = Empty;

/// `POST /v1/pairing` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePairingResponse {
    pub pairing_id: PairingId,
}

/// Which side of a pairing sent a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PairingSide {
    New,
    Existing,
}

/// A pairing message: the body of `POST /v1/pairing/{id}/messages` and an
/// element of the `GET` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingMessage {
    pub from: PairingSide,
    /// Sender's X25519 public key.
    pub pk: B64,
    /// `AeadBox` under the pairing key.
    #[serde(rename = "box")]
    pub box_: B64,
}

/// `POST /v1/pairing/{id}/messages` response.
pub type PostPairingMessageResponse = Empty;

/// `GET /v1/pairing/{id}/messages` response, oldest first.
pub type GetPairingMessagesResponse = Vec<PairingMessage>;

// ---------------------------------------------------------------------------
// §6 Vaults
// ---------------------------------------------------------------------------

/// One signed membership-log entry (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// `cbor(E)`.
    pub entry: B64,
    pub sig: B64,
}

/// A vault key grant addressed to a member, as posted by a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberGrant {
    pub user_id: UserId,
    pub epoch: Epoch,
    /// `HpkeBox` to the member's `enc_pk`.
    pub grant: B64,
}

/// A grant as returned to its recipient by `GET /v1/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochGrant {
    pub epoch: Epoch,
    pub grant: B64,
}

/// `POST /v1/vaults` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    pub vault_id: VaultId,
    /// Exactly one `create` entry.
    pub log: Vec<LogEntry>,
    pub grants: Vec<MemberGrant>,
}

/// `POST /v1/vaults` response.
pub type CreateVaultResponse = Empty;

/// One entry of `GET /v1/vaults`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSummary {
    pub vault_id: VaultId,
    pub role: Role,
    pub seq: Seq,
    pub epoch: Epoch,
    pub grants: Vec<EpochGrant>,
}

/// `GET /v1/vaults` response.
pub type ListVaultsResponse = Vec<VaultSummary>;

/// Query of `GET /v1/vaults/{vid}/log`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogQuery {
    #[serde(default)]
    pub since: u64,
}

/// `GET /v1/vaults/{vid}/log` response, in index order.
pub type GetLogResponse = Vec<LogEntry>;

/// `POST /v1/vaults/{vid}/log` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendLogRequest {
    pub entries: Vec<LogEntry>,
    #[serde(default)]
    pub grants: Vec<MemberGrant>,
}

/// `POST /v1/vaults/{vid}/log` response.
pub type AppendLogResponse = Empty;

// ---------------------------------------------------------------------------
// §7 Invites
// ---------------------------------------------------------------------------

/// `POST /v1/vaults/{vid}/invites` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    pub invite_id: InviteId,
    pub role: Role,
    pub expires_at: UnixSeconds,
    pub max_uses: u32,
}

/// `POST /v1/vaults/{vid}/invites` response.
pub type CreateInviteResponse = Empty;

/// `POST /v1/invites/{invite_id}/accept` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptInviteRequest {
    pub bundle: B64,
    pub bundle_sig: B64,
    pub mac: B64,
}

/// `POST /v1/invites/{invite_id}/accept` response.
pub type AcceptInviteResponse = Empty;

/// One entry of `GET /v1/vaults/{vid}/invites`: an acceptance awaiting an `add` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAcceptance {
    pub invite_id: InviteId,
    /// The invitee, as authenticated by the server.
    pub user_id: UserId,
    /// Role the invite grants.
    pub role: Role,
    pub bundle: B64,
    pub bundle_sig: B64,
    pub mac: B64,
}

/// `GET /v1/vaults/{vid}/invites` response.
pub type ListInvitesResponse = Vec<PendingAcceptance>;

// ---------------------------------------------------------------------------
// §8 Records and sync
// ---------------------------------------------------------------------------

/// `PUT /v1/vaults/{vid}/items/{item_id}` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutItemRequest {
    pub base_revision: Revision,
    pub revision: Revision,
    pub key_epoch: Epoch,
    /// `AeadBox` over the padded item (§8.1).
    pub ciphertext: B64,
    #[serde(default)]
    pub blob_refs: Vec<BlobId>,
}

/// `PUT /v1/vaults/{vid}/items/{item_id}` response (200).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutItemResponse {
    pub seq: Seq,
}

/// A stored record as returned by sync and conflicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub item_id: ItemId,
    pub revision: Revision,
    pub key_epoch: Epoch,
    pub seq: Seq,
    pub ciphertext: B64,
}

/// Body of `409 conflict` on a write: the error body plus the current record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictBody {
    pub error: ErrorCode,
    pub message: String,
    pub record: Record,
}

/// One put inside a batch: a [`PutItemRequest`] plus its item ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPut {
    pub item_id: ItemId,
    #[serde(flatten)]
    pub put: PutItemRequest,
}

/// `POST /v1/vaults/{vid}/batch` request. All-or-nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRequest {
    pub puts: Vec<BatchPut>,
}

/// `POST /v1/vaults/{vid}/batch` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchResponse {
    /// Vault head after the batch.
    pub seq: Seq,
}

/// Query of `GET /v1/vaults/{vid}/changes`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesQuery {
    #[serde(default)]
    pub since: Seq,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Signed vault state attached to sync responses (§8.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub seq: Seq,
    pub state_hash: B64,
    pub signer: UserId,
    pub sig: B64,
}

/// `GET /v1/vaults/{vid}/changes` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesResponse {
    pub records: Vec<Record>,
    pub next_since: Seq,
    pub has_more: bool,
    pub head_seq: Seq,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Checkpoint>,
}

/// `GET /v1/vaults/{vid}/items/{item_id}/history` response, newest first.
pub type HistoryResponse = Vec<Record>;

/// `POST /v1/vaults/{vid}/checkpoints` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostCheckpointRequest {
    pub seq: Seq,
    pub state_hash: B64,
    pub sig: B64,
}

/// `POST /v1/vaults/{vid}/checkpoints` response.
pub type PostCheckpointResponse = Empty;

// ---------------------------------------------------------------------------
// §9 Attachments
// ---------------------------------------------------------------------------

/// `POST /v1/vaults/{vid}/blobs` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveBlobRequest {
    /// Ciphertext size in bytes.
    pub size: u64,
}

/// `POST /v1/vaults/{vid}/blobs` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveBlobResponse {
    pub blob_id: BlobId,
    pub expires_at: UnixSeconds,
}

/// `PUT /v1/vaults/{vid}/blobs/{blob_id}` response. The request body is raw bytes.
pub type UploadBlobResponse = Empty;

// ---------------------------------------------------------------------------
// §11 WebSocket
// ---------------------------------------------------------------------------

/// WebSocket close codes.
pub mod close_code {
    /// Unauthorized or revoked.
    pub const UNAUTHORIZED: u16 = 4001;
    /// Unsupported protocol version.
    pub const UNSUPPORTED_VERSION: u16 = 4002;
    /// Replaced by a newer connection from the same device.
    pub const REPLACED: u16 = 4003;
}

/// A vault and its head sequence number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSeq {
    pub vault_id: VaultId,
    pub seq: Seq,
}

/// Messages sent by the client. The first must be `auth`, within 10 s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Auth { token: AccessToken },
    Ping,
    Pong,
}

/// Messages sent by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Ready {
        vaults: Vec<VaultSeq>,
    },
    VaultChanged {
        vault_id: VaultId,
        seq: Seq,
    },
    /// Devices, vault list or grants changed.
    AccountChanged,
    /// A pairing message is waiting.
    Pairing {
        pairing_id: PairingId,
    },
    Ping,
    Pong,
}

#[cfg(test)]
mod tests {
    use core::fmt::Debug;

    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};

    use super::*;

    const U: &str = "3f2b8c1e-9d4a-4e7b-8a61-0c5d2f9e7b34";
    const V: &str = "7a1d0c52-6e33-4b0a-9f1e-2d8c4b6a1e90";

    fn id<T: core::str::FromStr>(s: &str) -> T
    where
        T::Err: Debug,
    {
        s.parse().unwrap()
    }

    fn b(bytes: &[u8]) -> B64 {
        B64::from(bytes)
    }

    /// Serializes to exactly `expected`, parses back to an equal value, and
    /// still parses when an unknown field is added at the top level.
    fn check<T>(value: &T, expected: Value)
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(json, expected);
        let text = serde_json::to_string(value).unwrap();
        assert_eq!(&serde_json::from_str::<T>(&text).unwrap(), value);
        if let Value::Object(mut map) = json {
            map.insert("future_field".into(), json!({"x": [1]}));
            let parsed: T = serde_json::from_value(Value::Object(map)).unwrap();
            assert_eq!(&parsed, value, "unknown field must be ignored");
        }
    }

    fn kdf() -> Kdf {
        Kdf {
            alg: KdfAlg::Argon2id,
            m: 65536,
            t: 3,
            p: 4,
            salt: b(&[1, 2, 3]),
        }
    }

    fn kdf_json() -> Value {
        json!({"alg": "argon2id", "m": 65536, "t": 3, "p": 4, "salt": "AQID"})
    }

    fn record() -> Record {
        Record {
            item_id: id(V),
            revision: 2,
            key_epoch: 1,
            seq: 9,
            ciphertext: b(&[0xfb, 0xff]),
        }
    }

    fn record_json() -> Value {
        json!({"item_id": V, "revision": 2, "key_epoch": 1, "seq": 9, "ciphertext": "-_8"})
    }

    // --- spec examples ---------------------------------------------------

    #[test]
    fn spec_server_info_example_parses() {
        // PROTOCOL.md §0.1, verbatim.
        let text = r#"{
          "protocol": [1],
          "origin": "https://sync.example.com",
          "limits": {
            "max_record_bytes": 1048576,
            "max_file_bytes": 26214400,
            "quota_bytes": 262144000,
            "history_revisions": 10,
            "tombstone_retention_days": 90
          },
          "pow": { "alg": "sha256-lzb", "difficulty": 22 }
        }"#;
        let info: ServerInfo = serde_json::from_str(text).unwrap();
        assert_eq!(info.protocol, [1]);
        assert_eq!(info.origin, "https://sync.example.com");
        assert_eq!(info.limits.max_record_bytes, 1_048_576);
        assert_eq!(info.limits.max_file_bytes, 26_214_400);
        assert_eq!(info.limits.quota_bytes, 262_144_000);
        assert_eq!(info.limits.history_revisions, 10);
        assert_eq!(info.limits.tombstone_retention_days, 90);
        assert_eq!(
            info.pow,
            PowParams {
                alg: "sha256-lzb".into(),
                difficulty: 22
            }
        );
        assert_eq!(
            serde_json::to_value(&info).unwrap(),
            serde_json::from_str::<Value>(text).unwrap()
        );
    }

    #[test]
    fn spec_signup_finish_example_parses() {
        // PROTOCOL.md §4.1, verbatim. The literal text `b64` happens to be a
        // valid unpadded base64url string (two bytes), and `…` is an opaque token.
        let text = r#"{
          "signup_token": "…", "pow_nonce": "b64",
          "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 4, "salt": "b64" },
          "auth_pk": "b64",
          "wrapped_ak": "b64", "wrapped_ik": "b64",
          "bundle": "b64", "bundle_sig": "b64",
          "device": { "name": "Felix's MacBook", "platform": "macos", "pk": "b64", "key_storage": "hardware" },
          "auth_sig": "b64"
        }"#;
        let req: SignupFinishRequest = serde_json::from_str(text).unwrap();
        assert_eq!(req.signup_token, "…");
        assert_eq!(req.kdf.m, 65536);
        assert_eq!(req.kdf.t, 3);
        assert_eq!(req.kdf.p, 4);
        assert_eq!(req.kdf.alg, KdfAlg::Argon2id);
        assert_eq!(req.device.name, "Felix's MacBook");
        assert_eq!(req.device.platform, "macos");
        assert_eq!(req.device.key_storage, "hardware");
        assert_eq!(req.auth_sig.len(), 2);
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            serde_json::from_str::<Value>(text).unwrap()
        );
    }

    #[test]
    fn spec_changes_response_shape_parses() {
        // PROTOCOL.md §8.3 field set, with and without a checkpoint.
        let text = json!({
            "records": [record_json()],
            "next_since": 123, "has_more": false, "head_seq": 123,
            "checkpoint": {"seq": 123, "state_hash": "AQID", "signer": U, "sig": "AQID"}
        });
        let parsed: ChangesResponse = serde_json::from_value(text).unwrap();
        assert_eq!(parsed.records, [record()]);
        assert_eq!(parsed.checkpoint.unwrap().seq, 123);
        let no_cp = json!({"records": [], "next_since": 0, "has_more": false, "head_seq": 0});
        assert!(
            serde_json::from_value::<ChangesResponse>(no_cp)
                .unwrap()
                .checkpoint
                .is_none()
        );
    }

    #[test]
    fn spec_websocket_examples_parse() {
        // PROTOCOL.md §11 table.
        let auth: ClientMessage = serde_json::from_str(r#"{"type":"auth","token":"…"}"#).unwrap();
        assert_eq!(
            auth,
            ClientMessage::Auth {
                token: AccessToken("…".into())
            }
        );
        let ready: ServerMessage =
            serde_json::from_value(json!({"type": "ready", "vaults": [{"vault_id": V, "seq": 5}]}))
                .unwrap();
        assert_eq!(
            ready,
            ServerMessage::Ready {
                vaults: vec![VaultSeq {
                    vault_id: id(V),
                    seq: 5
                }]
            }
        );
        let changed: ServerMessage =
            serde_json::from_value(json!({"type": "vault_changed", "vault_id": V, "seq": 6}))
                .unwrap();
        assert_eq!(
            changed,
            ServerMessage::VaultChanged {
                vault_id: id(V),
                seq: 6
            }
        );
        let acc: ServerMessage = serde_json::from_str(r#"{"type":"account_changed"}"#).unwrap();
        assert_eq!(acc, ServerMessage::AccountChanged);
        let pairing: ServerMessage =
            serde_json::from_value(json!({"type": "pairing", "pairing_id": U})).unwrap();
        assert_eq!(pairing, ServerMessage::Pairing { pairing_id: id(U) });
        for text in [r#"{"type":"ping"}"#, r#"{"type":"pong"}"#] {
            assert!(serde_json::from_str::<ClientMessage>(text).is_ok());
            assert!(serde_json::from_str::<ServerMessage>(text).is_ok());
        }
    }

    // --- round trips -----------------------------------------------------

    #[test]
    fn shared_types() {
        check(&Empty {}, json!({}));
        for (role, name) in [
            (Role::View, "view"),
            (Role::Edit, "edit"),
            (Role::Manage, "manage"),
            (Role::Owner, "owner"),
        ] {
            assert_eq!(serde_json::to_value(role).unwrap(), json!(name));
            assert_eq!(serde_json::from_value::<Role>(json!(name)).unwrap(), role);
        }
        assert!(serde_json::from_value::<Role>(json!("Owner")).is_err());
        assert!(serde_json::from_value::<Role>(json!("admin")).is_err());
        assert_eq!(
            serde_json::to_value(SessionLevel::Device).unwrap(),
            json!("device")
        );
        assert_eq!(
            serde_json::to_value(SessionLevel::StepUp).unwrap(),
            json!("step_up")
        );
        assert!(serde_json::from_value::<SessionLevel>(json!("stepup")).is_err());
        assert_eq!(
            serde_json::to_value(KdfAlg::Argon2id).unwrap(),
            json!("argon2id")
        );
        assert!(serde_json::from_value::<KdfAlg>(json!("scrypt")).is_err());
        check(&kdf(), kdf_json());
        check(
            &SignedBundle {
                bundle: b(&[1, 2, 3]),
                bundle_sig: b(&[4]),
            },
            json!({"bundle": "AQID", "bundle_sig": "BA"}),
        );
        assert_eq!(
            serde_json::to_value(AccessToken("t".into())).unwrap(),
            json!("t")
        );
    }

    #[test]
    fn roles_are_ordered_by_privilege() {
        assert!(Role::View < Role::Edit);
        assert!(Role::Edit < Role::Manage);
        assert!(Role::Manage < Role::Owner);
        assert_eq!(crate::Role::Owner, Role::Owner);
    }

    #[test]
    fn access_token_debug_is_redacted() {
        let resp = SessionResponse {
            access_token: AccessToken("super-secret".into()),
            level: SessionLevel::Device,
            expires_at: 1,
        };
        assert!(!format!("{resp:?}").contains("super-secret"));
        assert!(
            !format!(
                "{:?}",
                ClientMessage::Auth {
                    token: AccessToken("super-secret".into())
                }
            )
            .contains("super-secret")
        );
    }

    #[test]
    fn server_info_types() {
        check(
            &ServerInfo {
                protocol: vec![1],
                origin: "https://sync.example.com".into(),
                limits: Limits {
                    max_record_bytes: 1,
                    max_file_bytes: 2,
                    quota_bytes: 3,
                    history_revisions: 4,
                    tombstone_retention_days: 5,
                },
                pow: PowParams {
                    alg: "sha256-lzb".into(),
                    difficulty: 22,
                },
            },
            json!({
                "protocol": [1], "origin": "https://sync.example.com",
                "limits": {"max_record_bytes": 1, "max_file_bytes": 2, "quota_bytes": 3,
                           "history_revisions": 4, "tombstone_retention_days": 5},
                "pow": {"alg": "sha256-lzb", "difficulty": 22}
            }),
        );
    }

    #[test]
    fn signup_types() {
        check(&SignupBeginRequest::default(), json!({}));
        check(
            &SignupBeginResponse {
                user_id: id(U),
                signup_token: "tok".into(),
                pow: PowChallenge {
                    challenge: b(&[1, 2, 3]),
                    difficulty: 22,
                },
                expires_at: 1700000600,
            },
            json!({"user_id": U, "signup_token": "tok",
                   "pow": {"challenge": "AQID", "difficulty": 22}, "expires_at": 1700000600}),
        );
        let device = DeviceRegistration {
            name: "Laptop".into(),
            platform: "macos".into(),
            pk: b(&[2; 33]),
            key_storage: "hardware".into(),
        };
        check(
            &device,
            json!({"name": "Laptop", "platform": "macos", "pk": B64::encode(&[2; 33]),
                   "key_storage": "hardware"}),
        );
        check(
            &SignupFinishRequest {
                signup_token: "tok".into(),
                pow_nonce: b(&[0; 8]),
                kdf: kdf(),
                auth_pk: b(&[1]),
                wrapped_ak: b(&[2]),
                wrapped_ik: b(&[3]),
                bundle: b(&[4]),
                bundle_sig: b(&[5]),
                device,
                auth_sig: b(&[6]),
            },
            json!({
                "signup_token": "tok", "pow_nonce": "AAAAAAAAAAA", "kdf": kdf_json(),
                "auth_pk": "AQ", "wrapped_ak": "Ag", "wrapped_ik": "Aw",
                "bundle": "BA", "bundle_sig": "BQ",
                "device": {"name": "Laptop", "platform": "macos",
                           "pk": B64::encode(&[2; 33]), "key_storage": "hardware"},
                "auth_sig": "Bg"
            }),
        );
        check(
            &SignupFinishResponse { device_id: id(U) },
            json!({"device_id": U}),
        );
    }

    #[test]
    fn login_types() {
        check(&PreloginResponse { kdf: kdf() }, json!({"kdf": kdf_json()}));
        check(
            &AuthChallengeRequest { user_id: id(U) },
            json!({"user_id": U}),
        );
        check(
            &AuthChallengeResponse {
                challenge_id: id(V),
                challenge: b(&[7; 32]),
                expires_at: 60,
            },
            json!({"challenge_id": V, "challenge": B64::encode(&[7; 32]), "expires_at": 60}),
        );
        check(
            &AuthDeviceRequest {
                user_id: id(U),
                device_id: id(V),
                challenge_id: id(U),
                sig: b(&[1]),
            },
            json!({"user_id": U, "device_id": V, "challenge_id": U, "sig": "AQ"}),
        );
        check(
            &AuthAccountRequest {
                user_id: id(U),
                challenge_id: id(V),
                sig: b(&[1]),
            },
            json!({"user_id": U, "challenge_id": V, "sig": "AQ"}),
        );
        check(
            &SessionResponse {
                access_token: AccessToken("abc".into()),
                level: SessionLevel::StepUp,
                expires_at: 600,
            },
            json!({"access_token": "abc", "level": "step_up", "expires_at": 600}),
        );
    }

    #[test]
    fn account_types() {
        check(
            &AccountKeysResponse {
                kdf: kdf(),
                wrapped_ak: b(&[1]),
                wrapped_ik: b(&[2]),
                bundle: b(&[3]),
                bundle_sig: b(&[4]),
            },
            json!({"kdf": kdf_json(), "wrapped_ak": "AQ", "wrapped_ik": "Ag",
                   "bundle": "Aw", "bundle_sig": "BA"}),
        );
        let ident: IdentityResponse = SignedBundle {
            bundle: b(&[1]),
            bundle_sig: b(&[2]),
        };
        check(&ident, json!({"bundle": "AQ", "bundle_sig": "Ag"}));
        check(
            &CredentialsChangeRequest {
                kdf: kdf(),
                auth_pk: b(&[1]),
                wrapped_ak: b(&[2]),
                auth_sig: b(&[3]),
            },
            json!({"kdf": kdf_json(), "auth_pk": "AQ", "wrapped_ak": "Ag", "auth_sig": "Aw"}),
        );
        check(&CredentialsChangeResponse::default(), json!({}));
        check(&DeleteAccountResponse::default(), json!({}));
    }

    #[test]
    fn device_types() {
        let reg = CreateDeviceRequest {
            name: "Phone".into(),
            platform: "ios".into(),
            pk: b(&[1]),
            key_storage: "hardware".into(),
        };
        check(
            &reg,
            json!({"name": "Phone", "platform": "ios", "pk": "AQ", "key_storage": "hardware"}),
        );
        let created: CreateDeviceResponse = SignupFinishResponse { device_id: id(V) };
        check(&created, json!({"device_id": V}));
        let seen = DeviceInfo {
            device_id: id(U),
            name: "Phone".into(),
            platform: "ios".into(),
            key_storage: "hardware".into(),
            created_at: 10,
            last_seen_at: Some(20),
        };
        check(
            &seen,
            json!({"device_id": U, "name": "Phone", "platform": "ios", "key_storage": "hardware",
                   "created_at": 10, "last_seen_at": 20}),
        );
        let never = DeviceInfo {
            last_seen_at: None,
            ..seen.clone()
        };
        check(
            &never,
            json!({"device_id": U, "name": "Phone", "platform": "ios", "key_storage": "hardware",
                   "created_at": 10, "last_seen_at": null}),
        );
        // A missing last_seen_at is also accepted.
        let missing = json!({"device_id": U, "name": "Phone", "platform": "ios",
                             "key_storage": "hardware", "created_at": 10});
        assert_eq!(
            serde_json::from_value::<DeviceInfo>(missing).unwrap(),
            never
        );
        let list: ListDevicesResponse = vec![seen];
        assert!(serde_json::to_value(&list).unwrap().is_array());
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(
            serde_json::from_str::<ListDevicesResponse>(&json).unwrap(),
            list
        );
        check(
            &RenameDeviceRequest { name: "New".into() },
            json!({"name": "New"}),
        );
        check(&RenameDeviceResponse::default(), json!({}));
        check(&RevokeDeviceResponse::default(), json!({}));
    }

    #[test]
    fn pairing_types() {
        check(&CreatePairingRequest::default(), json!({}));
        check(
            &CreatePairingResponse { pairing_id: id(U) },
            json!({"pairing_id": U}),
        );
        let msg = PairingMessage {
            from: PairingSide::Existing,
            pk: b(&[1]),
            box_: b(&[2, 3]),
        };
        check(&msg, json!({"from": "existing", "pk": "AQ", "box": "AgM"}));
        let msg_new = PairingMessage {
            from: PairingSide::New,
            ..msg.clone()
        };
        check(&msg_new, json!({"from": "new", "pk": "AQ", "box": "AgM"}));
        assert!(serde_json::from_value::<PairingSide>(json!("other")).is_err());
        check(&PostPairingMessageResponse::default(), json!({}));
        let list: GetPairingMessagesResponse = vec![msg, msg_new];
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(
            serde_json::from_str::<GetPairingMessagesResponse>(&json).unwrap(),
            list
        );
    }

    #[test]
    fn vault_types() {
        let entry = LogEntry {
            entry: b(&[1]),
            sig: b(&[2]),
        };
        check(&entry, json!({"entry": "AQ", "sig": "Ag"}));
        let grant = MemberGrant {
            user_id: id(U),
            epoch: 1,
            grant: b(&[3]),
        };
        check(&grant, json!({"user_id": U, "epoch": 1, "grant": "Aw"}));
        check(
            &EpochGrant {
                epoch: 2,
                grant: b(&[3]),
            },
            json!({"epoch": 2, "grant": "Aw"}),
        );
        check(
            &CreateVaultRequest {
                vault_id: id(V),
                log: vec![entry.clone()],
                grants: vec![grant.clone()],
            },
            json!({"vault_id": V, "log": [{"entry": "AQ", "sig": "Ag"}],
                   "grants": [{"user_id": U, "epoch": 1, "grant": "Aw"}]}),
        );
        check(&CreateVaultResponse::default(), json!({}));
        let summary = VaultSummary {
            vault_id: id(V),
            role: Role::Manage,
            seq: 7,
            epoch: 2,
            grants: vec![EpochGrant {
                epoch: 1,
                grant: b(&[3]),
            }],
        };
        check(
            &summary,
            json!({"vault_id": V, "role": "manage", "seq": 7, "epoch": 2,
                   "grants": [{"epoch": 1, "grant": "Aw"}]}),
        );
        let list: ListVaultsResponse = vec![summary];
        let json = serde_json::to_string(&list).unwrap();
        assert!(json.starts_with('['));
        assert_eq!(
            serde_json::from_str::<ListVaultsResponse>(&json).unwrap(),
            list
        );
        check(&LogQuery { since: 3 }, json!({"since": 3}));
        assert_eq!(serde_json::from_str::<LogQuery>("{}").unwrap().since, 0);
        let entries: GetLogResponse = vec![entry.clone()];
        let json = serde_json::to_string(&entries).unwrap();
        assert_eq!(
            serde_json::from_str::<GetLogResponse>(&json).unwrap(),
            entries
        );
        let append = AppendLogRequest {
            entries: vec![entry],
            grants: vec![grant],
        };
        check(
            &append,
            json!({"entries": [{"entry": "AQ", "sig": "Ag"}],
                   "grants": [{"user_id": U, "epoch": 1, "grant": "Aw"}]}),
        );
        let no_grants: AppendLogRequest = serde_json::from_value(json!({"entries": []})).unwrap();
        assert!(no_grants.grants.is_empty());
        check(&AppendLogResponse::default(), json!({}));
    }

    #[test]
    fn invite_types() {
        check(
            &CreateInviteRequest {
                invite_id: id(U),
                role: Role::Edit,
                expires_at: 99,
                max_uses: 1,
            },
            json!({"invite_id": U, "role": "edit", "expires_at": 99, "max_uses": 1}),
        );
        check(&CreateInviteResponse::default(), json!({}));
        check(
            &AcceptInviteRequest {
                bundle: b(&[1]),
                bundle_sig: b(&[2]),
                mac: b(&[3]),
            },
            json!({"bundle": "AQ", "bundle_sig": "Ag", "mac": "Aw"}),
        );
        check(&AcceptInviteResponse::default(), json!({}));
        let pending = PendingAcceptance {
            invite_id: id(U),
            user_id: id(V),
            role: Role::View,
            bundle: b(&[1]),
            bundle_sig: b(&[2]),
            mac: b(&[3]),
        };
        check(
            &pending,
            json!({"invite_id": U, "user_id": V, "role": "view",
                   "bundle": "AQ", "bundle_sig": "Ag", "mac": "Aw"}),
        );
        let list: ListInvitesResponse = vec![pending];
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(
            serde_json::from_str::<ListInvitesResponse>(&json).unwrap(),
            list
        );
    }

    fn put() -> PutItemRequest {
        PutItemRequest {
            base_revision: 1,
            revision: 2,
            key_epoch: 3,
            ciphertext: b(&[9]),
            blob_refs: vec![id(U)],
        }
    }

    fn put_json() -> Value {
        json!({"base_revision": 1, "revision": 2, "key_epoch": 3, "ciphertext": "CQ",
               "blob_refs": [U]})
    }

    #[test]
    fn record_types() {
        check(&put(), put_json());
        let no_refs: PutItemRequest = serde_json::from_value(
            json!({"base_revision": 0, "revision": 1, "key_epoch": 1, "ciphertext": ""}),
        )
        .unwrap();
        assert!(no_refs.blob_refs.is_empty());
        check(&PutItemResponse { seq: 5 }, json!({"seq": 5}));
        check(&record(), record_json());
        check(
            &ConflictBody {
                error: ErrorCode::Conflict,
                message: "stale".into(),
                record: record(),
            },
            json!({"error": "conflict", "message": "stale", "record": record_json()}),
        );
        let batch_put = BatchPut {
            item_id: id(V),
            put: put(),
        };
        let mut expected = put_json();
        expected["item_id"] = json!(V);
        check(&batch_put, expected.clone());
        check(
            &BatchRequest {
                puts: vec![batch_put],
            },
            json!({"puts": [expected]}),
        );
        check(&BatchResponse { seq: 12 }, json!({"seq": 12}));
    }

    #[test]
    fn sync_types() {
        check(
            &ChangesQuery {
                since: 4,
                limit: Some(100),
            },
            json!({"since": 4, "limit": 100}),
        );
        let q: ChangesQuery = serde_json::from_str("{}").unwrap();
        assert_eq!((q.since, q.limit), (0, None));
        let cp = Checkpoint {
            seq: 8,
            state_hash: b(&[1]),
            signer: id(U),
            sig: b(&[2]),
        };
        check(
            &cp,
            json!({"seq": 8, "state_hash": "AQ", "signer": U, "sig": "Ag"}),
        );
        check(
            &ChangesResponse {
                records: vec![record()],
                next_since: 9,
                has_more: true,
                head_seq: 20,
                checkpoint: Some(cp),
            },
            json!({"records": [record_json()], "next_since": 9, "has_more": true, "head_seq": 20,
                   "checkpoint": {"seq": 8, "state_hash": "AQ", "signer": U, "sig": "Ag"}}),
        );
        check(
            &ChangesResponse {
                records: vec![],
                next_since: 0,
                has_more: false,
                head_seq: 0,
                checkpoint: None,
            },
            json!({"records": [], "next_since": 0, "has_more": false, "head_seq": 0}),
        );
        let history: HistoryResponse = vec![record()];
        let json = serde_json::to_string(&history).unwrap();
        assert_eq!(
            serde_json::from_str::<HistoryResponse>(&json).unwrap(),
            history
        );
        check(
            &PostCheckpointRequest {
                seq: 3,
                state_hash: b(&[1]),
                sig: b(&[2]),
            },
            json!({"seq": 3, "state_hash": "AQ", "sig": "Ag"}),
        );
        check(&PostCheckpointResponse::default(), json!({}));
    }

    #[test]
    fn blob_types() {
        check(&ReserveBlobRequest { size: 4096 }, json!({"size": 4096}));
        check(
            &ReserveBlobResponse {
                blob_id: id(U),
                expires_at: 3600,
            },
            json!({"blob_id": U, "expires_at": 3600}),
        );
        check(&UploadBlobResponse::default(), json!({}));
    }

    #[test]
    fn websocket_messages() {
        let auth = ClientMessage::Auth {
            token: AccessToken("tok".into()),
        };
        assert_eq!(
            serde_json::to_value(&auth).unwrap(),
            json!({"type": "auth", "token": "tok"})
        );
        assert_eq!(
            serde_json::to_value(ClientMessage::Ping).unwrap(),
            json!({"type": "ping"})
        );
        assert_eq!(
            serde_json::to_value(ClientMessage::Pong).unwrap(),
            json!({"type": "pong"})
        );
        for m in [auth, ClientMessage::Ping, ClientMessage::Pong] {
            let text = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<ClientMessage>(&text).unwrap(), m);
        }
        let cases = [
            (
                ServerMessage::Ready {
                    vaults: vec![VaultSeq {
                        vault_id: id(V),
                        seq: 1,
                    }],
                },
                json!({"type": "ready", "vaults": [{"vault_id": V, "seq": 1}]}),
            ),
            (
                ServerMessage::VaultChanged {
                    vault_id: id(V),
                    seq: 2,
                },
                json!({"type": "vault_changed", "vault_id": V, "seq": 2}),
            ),
            (
                ServerMessage::AccountChanged,
                json!({"type": "account_changed"}),
            ),
            (
                ServerMessage::Pairing { pairing_id: id(U) },
                json!({"type": "pairing", "pairing_id": U}),
            ),
            (ServerMessage::Ping, json!({"type": "ping"})),
            (ServerMessage::Pong, json!({"type": "pong"})),
        ];
        for (msg, expected) in cases {
            assert_eq!(serde_json::to_value(&msg).unwrap(), expected);
            let mut with_extra = expected.clone();
            with_extra["future"] = json!(true);
            assert_eq!(
                serde_json::from_value::<ServerMessage>(with_extra).unwrap(),
                msg
            );
            assert_eq!(
                serde_json::from_value::<ServerMessage>(expected).unwrap(),
                msg
            );
        }
        // Direction is enforced by the types.
        assert!(serde_json::from_str::<ServerMessage>(r#"{"type":"auth","token":"x"}"#).is_err());
        assert!(serde_json::from_str::<ClientMessage>(r#"{"type":"ready","vaults":[]}"#).is_err());
        assert!(serde_json::from_str::<ClientMessage>(r#"{"type":"nope"}"#).is_err());
        assert!(serde_json::from_str::<ClientMessage>(r#"{"token":"x"}"#).is_err());
    }

    #[test]
    fn close_codes_match_spec() {
        assert_eq!(close_code::UNAUTHORIZED, 4001);
        assert_eq!(close_code::UNSUPPORTED_VERSION, 4002);
        assert_eq!(close_code::REPLACED, 4003);
    }

    #[test]
    fn rejects_malformed_fields() {
        // Padded base64 and non-canonical IDs inside a struct are rejected.
        assert!(
            serde_json::from_value::<Record>(json!({
                "item_id": V, "revision": 1, "key_epoch": 1, "seq": 1, "ciphertext": "Zg=="
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<Record>(json!({
            "item_id": V.to_uppercase(), "revision": 1, "key_epoch": 1, "seq": 1, "ciphertext": "Zg"
        }))
        .is_err());
        // Missing required field.
        assert!(serde_json::from_value::<PutItemResponse>(json!({})).is_err());
        // Negative and fractional numbers.
        assert!(serde_json::from_value::<PutItemResponse>(json!({"seq": -1})).is_err());
        assert!(serde_json::from_value::<PutItemResponse>(json!({"seq": 1.5})).is_err());
    }
}
