# Protocol

Status: **draft v0.** Breaking changes are allowed until 1.0. Background and reasoning are in [ARCHITECTURE.md](ARCHITECTURE.md).

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 0. Conventions

| Topic | Rule |
|---|---|
| Transport | HTTPS, JSON bodies (`application/json`), UTF-8. Base path `/v1`. |
| Binary in JSON | base64url, no padding (written `b64`). |
| Signed or bound data | Deterministic CBOR (RFC 8949 §4.2.1), written `cbor(...)`. Signatures and AEAD associated data are always computed over these bytes, never over JSON. |
| IDs | UUIDv4. Lowercase canonical string in JSON, 16-byte bstr in CBOR. |
| `origin` | The server's canonical origin, e.g. `https://sync.example.com`: lowercase, no trailing slash. It is included in every login signature so signatures can't be replayed against another server. |
| Domain separation | Every signature, KDF info string and AAD starts with a string `symbolon/v1/<purpose>`. These strings are frozen at 1.0. |
| Time | Unix seconds (integer). |
| Auth | `Authorization: Bearer <access_token>` unless an endpoint is marked *public*. *step-up* marks endpoints that need an account-level session (§4.4). |

### 0.1 Server info (public)

`GET /v1/server`

```json
{
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
}
```

## 1. Primitives

| Use | Algorithm |
|---|---|
| Password stretching | Argon2id v1.3 (RFC 9106), 32-byte output |
| KDF | HKDF-SHA-256 (RFC 5869) |
| AEAD | XChaCha20-Poly1305: 24-byte random nonce, 16-byte tag |
| Auth and identity signatures | Ed25519 (RFC 8032, pure) |
| Device signatures | ECDSA P-256 with SHA-256, DER-encoded signature; public key as SEC1 compressed point (33 bytes) |
| Public-key encryption | HPKE (RFC 9180) base mode. KEM: X-Wing (X25519 + ML-KEM-768). KDF: HKDF-SHA256. AEAD: ChaCha20-Poly1305. Suite tag `1`. |
| Key agreement for pairing | X25519 |
| Hash | SHA-256 |
| Randomness | the OS CSPRNG only |

**Argon2id parameters.**

- Default: `m = 65536` KiB, `t = 3`, `p = 4`.
- Clients MUST refuse parameters below `m = 65536, t = 3, p = 1`, so a malicious server can't downgrade the KDF.
- Clients SHOULD remember the parameters last seen for an account and refuse to go lower.

## 2. Envelopes

Envelopes are CBOR arrays. In JSON they travel as `b64(cbor(envelope))`.

```
AeadBox = [ 1,            ; version
            1,            ; alg: 1 = XChaCha20-Poly1305
            nonce: bstr,  ; 24 bytes, random
            ct: bstr ]    ; ciphertext || tag

HpkeBox = [ 1,            ; version
            1,            ; suite (see §1)
            enc: bstr,    ; HPKE encapsulated key
            ct: bstr ]
```

Associated data (`aad`) and the HPKE `info` value are never stored in the envelope. The receiver rebuilds them from context, so an envelope moved to a different context fails to decrypt.

## 3. Account keys

### 3.1 Secret Key

- 16 random bytes.
- **Text form:** `S1-` followed by the 128-bit value in Crockford base32 (26 symbols, with 2 leading zero bits of padding), plus 1 Crockford check symbol (value mod 37).
- Displayed in groups: `S1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX`.
- Parsing ignores case, spaces and hyphens, and maps `I`/`L` → `1` and `O` → `0`.

### 3.2 Derivation

```
salt      = 16 random bytes, per account; renewed on every credential change
pw        = UTF-8( NFKC(password) )                 ; no trimming
s_pw      = Argon2id(pw, salt, m, t, p, 32)
master    = HKDF-Extract(salt = salt, ikm = s_pw || secret_key)
auth_seed = HKDF-Expand(master, "symbolon/v1/auth-key", 32)   ; Ed25519 seed → auth_sk, auth_pk
kek       = HKDF-Expand(master, "symbolon/v1/kek", 32)
```

### 3.3 Wrapped keys

```
account_key   = 32 random bytes
wrapped_ak    = AeadBox(kek, plaintext = account_key,
                        aad = cbor(["symbolon/v1/account-key", user_id, salt]))

identity keys:  enc = X-Wing keypair, sig = Ed25519 keypair
wrapped_ik    = AeadBox(account_key, plaintext = cbor({"enc": enc_sk, "sig": sig_sk}),
                        aad = cbor(["symbolon/v1/identity-keys", user_id, ik_version]))

bundle        = cbor({"user_id", "ik_version", "enc_pk", "sig_pk"})
bundle_sig    = Ed25519(sig_sk, cbor(["symbolon/v1/identity-bundle", bundle]))
fingerprint   = SHA-256(cbor(["symbolon/v1/fingerprint", sig_pk, enc_pk]))[0..20]
                displayed as 8 groups of 5 base32 symbols
```

Local unlock copies (biometrics, passkey PRF) are a client concern and are not part of the wire protocol.

## 4. Accounts and sessions

### 4.1 Sign-up

**`POST /v1/signup/begin`** *(public, rate-limited)* → `{ user_id, signup_token, pow: { challenge, difficulty }, expires_at }`

- The user ID is reserved for 10 minutes.
- Proof-of-work: find an 8-byte `pow_nonce` such that `SHA-256("symbolon/v1/pow" || challenge || pow_nonce)` has at least `difficulty` leading zero bits.

**`POST /v1/signup/finish`** *(public)*

```json
{
  "signup_token": "…", "pow_nonce": "b64",
  "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 4, "salt": "b64" },
  "auth_pk": "b64",
  "wrapped_ak": "b64", "wrapped_ik": "b64",
  "bundle": "b64", "bundle_sig": "b64",
  "device": { "name": "Felix's MacBook", "platform": "macos", "pk": "b64", "key_storage": "hardware" },
  "auth_sig": "b64"
}
```

- `auth_sig = Ed25519(auth_sk, cbor(["symbolon/v1/signup", origin, user_id, auth_pk, device.pk, SHA-256(bundle)]))`
- Response: `{ device_id }`. The client then logs in (§4.3) and creates its personal vault (§6.1).
- A client that finds no personal vault at startup MUST create one, which covers a crash between these two steps.

### 4.2 Pre-login *(public)*

`GET /v1/accounts/{user_id}/prelogin` → `{ kdf }`

For unknown user IDs the server MUST return plausible fake parameters derived deterministically from `HMAC(server_secret, user_id)`.

### 4.3 Login

1. **`POST /v1/auth/challenge`** `{ user_id }` → `{ challenge_id, challenge (32 bytes b64), expires_at }`. The challenge is single-use and valid for 60 s.
2. Then one of:

| Endpoint | Signature | Session |
|---|---|---|
| `POST /v1/auth/device` `{ user_id, device_id, challenge_id, sig }` | `ECDSA(device_sk, cbor(["symbolon/v1/login/device", origin, user_id, device_id, challenge]))` | `device`, 1 h |
| `POST /v1/auth/account` `{ user_id, challenge_id, sig }` | `Ed25519(auth_sk, cbor(["symbolon/v1/login/account", origin, user_id, challenge]))` | `step_up`, 10 min |

Response: `{ access_token, level, expires_at }`.

- Tokens are opaque and are renewed with a new challenge.
- Revoking a device or changing credentials MUST invalidate the affected sessions immediately, including open WebSockets.

### 4.4 Step-up endpoints

The following require a `step_up` session:

- registering or revoking devices
- changing credentials
- deleting the account
- (later) recovery and emergency settings

### 4.5 Account data

- `GET /v1/account/keys` → `{ kdf, wrapped_ak, wrapped_ik, bundle, bundle_sig }`
- `GET /v1/users/{user_id}/identity` → `{ bundle, bundle_sig }`. Clients MUST verify `bundle_sig`. They MUST NOT trust the result for sharing unless it was authenticated by an invite (§7) or a fingerprint check.

### 4.6 Credential change *(step-up)*

`PUT /v1/account/credentials` `{ kdf, auth_pk, wrapped_ak, auth_sig }`

- `auth_sig = Ed25519(new auth_sk, cbor(["symbolon/v1/credentials", origin, user_id, auth_pk, SHA-256(wrapped_ak)]))`
- The server replaces all four fields atomically and ends all other `step_up` sessions.
- The same endpoint covers password changes and Secret Key changes.

### 4.7 Account deletion *(step-up)*

`DELETE /v1/account`

- Fails with `owned_shared_vaults` while the user is the only owner of a vault that has other members.
- Otherwise the server deletes the account, its devices, its personal vaults and its memberships.

## 5. Devices and pairing

### 5.1 Devices

| Endpoint | |
|---|---|
| `POST /v1/devices` *(step-up)* `{ name, platform, pk, key_storage }` | → `{ device_id }` |
| `GET /v1/devices` | list: `device_id`, `name`, `platform`, `key_storage`, `created_at`, `last_seen_at` |
| `PATCH /v1/devices/{id}` `{ name }` | rename |
| `DELETE /v1/devices/{id}` *(step-up)* | revoke: ends sessions, closes WebSockets |

### 5.2 Pairing

A pairing session is single-use, expires after 5 minutes, and holds at most 4 messages of up to 4 KiB each.

**QR payload:**

```
symbolon-pair:1?s=<origin>&p=<pairing_id>&k=<b64 x25519 pk>&x=<b64 32-byte pairing secret ps>&r=<new|existing>
```

**Shared key:**

```
key = HKDF(salt = ps, ikm = X25519(own_sk, peer_pk),
           info = cbor(["symbolon/v1/pairing", pairing_id, pk_new, pk_existing]))
```

**Mode A: the new device shows the QR code.**

1. New device: `POST /v1/pairing` *(public, rate-limited)* → `{ pairing_id }`. It shows the QR code with `r=new`.
2. Existing device (signed in) scans it and posts `POST /v1/pairing/{id}/messages`:
   `{ from: "existing", pk: pk_existing, box: AeadBox(key, cbor({origin, user_id, secret_key, label}), aad = cbor(["symbolon/v1/pairing/offer", pairing_id])) }`
3. New device: `GET /v1/pairing/{id}/messages` (or via WebSocket), then decrypts. A successful decryption proves the sender knew `ps`.

**Mode B: the existing device shows the QR code.**

1. Existing device: `POST /v1/pairing` (authenticated). It shows the QR code with `r=existing`.
2. New device posts `{ from: "new", pk: pk_new, box: AeadBox(key, cbor({device_name, platform}), aad = cbor(["symbolon/v1/pairing/hello", pairing_id])) }`.
3. Existing device decrypts it, asks the user "Add <device_name>?", and then posts the offer exactly as in mode A, step 2.

**Then, in both modes:** the new device fetches the pre-login data, asks for the password, logs in with `/v1/auth/account`, and registers itself with `POST /v1/devices`. The server notifies the account's other devices (`account_changed`).

## 6. Vaults

### 6.1 Keys and grants

- `vault_key[epoch]` = 32 random bytes. `epoch` starts at 1.
- Each member's grant:
  `HpkeBox(member.enc_pk, plaintext = vault_key, info = cbor(["symbolon/v1/grant", vault_id, epoch, member_user_id]))`.
- Members keep their grants for all epochs, so records from older epochs stay readable.

**`POST /v1/vaults`** `{ vault_id, log: [entry0], grants: [own grant] }` creates a vault.

- `vault_id` is generated by the client.
- `entry0` is a `create` entry.
- The vault's name, color and icon are stored in an ordinary record with the nil item ID (`00000000-…`) and type `vault_meta`.

**`GET /v1/vaults`** → `[{ vault_id, role, seq, epoch, grants: [{ epoch, grant }] }]`

### 6.2 Membership log

Each entry is `{ entry: b64(cbor(E)), sig: b64 }` with:

```
E = { "vault_id", "index",      ; 0, 1, 2, …
      "prev",                   ; SHA-256 of previous entry bytes; 32 zero bytes for index 0
      "action",                 ; create | add | remove | set_role | rotate | leave
      "actor",                  ; user_id
      "subject", "subject_fp",  ; user_id + identity fingerprint (not used for rotate)
      "role",                   ; view | edit | manage | owner
      "epoch",                  ; current epoch after this entry
      "at" }
sig = Ed25519(actor.sig_sk, cbor(["symbolon/v1/vault-log", entry_bytes]))
```

**Roles:**

| Role | Can |
|---|---|
| `view` | read |
| `edit` | `view` + write records, upload blobs |
| `manage` | `edit` + add, remove and re-role non-owners; rotate |
| `owner` | everything, including managing owners and deleting the vault |

**Rules.** Both the server and the clients enforce these:

- `create` appears only at index 0, with actor = subject and role `owner`.
- `add`, `remove` and `set_role` require `manage`. Any change that touches an owner requires `owner`.
- `leave` requires actor = subject.
- At least one owner must remain.
- `rotate` increments `epoch` and MUST arrive together with new grants for every remaining member.
- A `remove` or `leave` MUST be followed by a `rotate` in the same request.

**Endpoints:**

- `GET /v1/vaults/{vid}/log?since=<index>`
- `POST /v1/vaults/{vid}/log` `{ entries: [...], grants: [...] }`: atomic, appended in order.

Clients MUST verify the whole chain (hashes, signatures and roles) before decrypting with a grant or encrypting to a member. The signing keys come from verified identity bundles whose fingerprints match `subject_fp` in the `add` entries, starting from the creator.

After a `rotate`, the rotating client SHOULD re-encrypt all records under the new epoch in the background. The server rejects writes that use an older epoch.

## 7. Invites

```
invite_secret = 32 random bytes
k_inv         = HKDF(salt = "", ikm = invite_secret, info = "symbolon/v1/invite-mac")
```

1. Inviter (`manage`+): `POST /v1/vaults/{vid}/invites` `{ invite_id, role, expires_at, max_uses }`
2. Link: `<origin>/invite#<invite_id>.<b64 invite_secret>.<b64 inviter_fingerprint>`. The server only ever sees the path.
3. Invitee: `POST /v1/invites/{invite_id}/accept` `{ bundle, bundle_sig, mac }`
   - `mac = HMAC-SHA256(k_inv, cbor(["symbolon/v1/invite-accept", origin, invite_id, invitee_user_id, SHA-256(bundle)]))`
4. Any `manage`+ device of the vault:
   - lists pending acceptances with `GET /v1/vaults/{vid}/invites`;
   - verifies the `mac` and `bundle_sig`;
   - posts an `add` entry with `subject_fp` and a grant (§6.2).
5. Invitee: verifies that the log chain contains the inviter's fingerprint from the link.

## 8. Records and sync

### 8.1 Record encryption

```
plaintext  = pad( cbor(item) )                       ; §10
ciphertext = AeadBox(vault_key[key_epoch], plaintext,
                     aad = cbor(["symbolon/v1/record", vault_id, item_id, revision, key_epoch]))
```

- `item_id` is a client-generated UUIDv4.
- **Padding:** append `0x80` followed by `0x00` bytes up to the next multiple of 256 bytes. Above 4 KiB, pad to the next multiple of 4 KiB instead.
- **Deletion** is a normal write whose item is a tombstone `{"v":1, "deleted": true}`.

### 8.2 Write

**`PUT /v1/vaults/{vid}/items/{item_id}`** `{ base_revision, revision, key_epoch, ciphertext, blob_refs: [blob_id] }`

The server MUST check:

- the writer's role is `edit` or higher;
- `base_revision` equals the current revision (0 for a new item);
- `revision == base_revision + 1`;
- `key_epoch` is the current epoch;
- the size is within `max_record_bytes`;
- every `blob_refs` entry is a finalized blob of this vault.

Responses:

- `200 { seq }`
- `409 conflict { record }` with the current record

**`POST /v1/vaults/{vid}/batch`** `{ puts: [...] }`: all-or-nothing. Used for imports and re-encryption.

### 8.3 Read

**`GET /v1/vaults/{vid}/changes?since=<seq>&limit=<n>`**

```json
{ "records": [{ "item_id", "revision", "key_epoch", "seq", "ciphertext" }],
  "next_since": 123, "has_more": false, "head_seq": 123,
  "checkpoint": { "seq", "state_hash", "signer", "sig" } }
```

- Returns the latest version of each item changed after `since`, ordered by `seq`.
- If `since` is older than the tombstone retention window, the server returns `410 resync_required` and the client fetches with `since=0`.

**`GET /v1/vaults/{vid}/items/{item_id}/history`** returns the last `history_revisions` revisions.

### 8.4 Merging (client behavior)

- Three-way merge per field, using the last synced plaintext as the base.
- If both sides changed the same field, the remote value wins and the local value is kept: secrets go into the item's password history, other fields into a conflict copy.
- Unknown fields MUST be preserved unchanged.

### 8.5 Checkpoints *(SHOULD in v0, MUST in 1.0)*

```
state_hash = SHA-256(cbor(["symbolon/v1/state", vault_id, seq,
               sorted by item_id: [[item_id, revision, key_epoch, SHA-256(ciphertext)], …]]))
sig        = Ed25519(signer.sig_sk, cbor(["symbolon/v1/checkpoint", vault_id, seq, state_hash]))
```

- After a write, a client posts `POST /v1/vaults/{vid}/checkpoints` `{ seq, state_hash, sig }`. The server keeps the last 16.
- A client at `head_seq` that receives a checkpoint for that exact seq MUST verify it. The signer must hold `edit` or higher in the verified log.
- Clients MUST reject any response whose `head_seq` is lower than the highest seq they have already seen for that vault.

## 9. Attachments

1. **Reserve:** `POST /v1/vaults/{vid}/blobs` `{ size }` → `{ blob_id, expires_at }`
   - `size` is the ciphertext size.
   - Errors: `413 file_too_large`, `403 quota_exceeded`.
   - A reservation is valid for 1 h.
2. **Encrypt** with `blob_id` bound into the AAD:

   ```
   file_key  = 32 random bytes
   header    = 0x01 || nonce_prefix (19 random bytes)
   chunk_i   = plaintext[i*65536 .. (i+1)*65536]         ; last chunk may be shorter
   nonce_i   = nonce_prefix || u32be(i) || (0x01 if last else 0x00)
   ct_i      = XChaCha20-Poly1305(file_key, nonce_i, chunk_i,
                                  aad = cbor(["symbolon/v1/blob", vault_id, blob_id]))
   blob      = header || ct_0 || ct_1 || …
   ```

   An empty file is one empty last chunk.
3. **Upload:** `PUT /v1/vaults/{vid}/blobs/{blob_id}` with the raw body. `Content-Length` MUST equal the reserved size. The upload finalizes the blob.
4. **Reference:** write the item with `blob_refs` containing the blob and the attachment entry (§10) containing `file_key`.
5. **Download:** `GET /v1/vaults/{vid}/blobs/{blob_id}` (`view`+).

**Retention and quota:**

- Blobs not referenced by any retained revision are deleted after 24 h.
- Quota counts all retained blobs plus record bytes. Shared vaults count against the owner, or against the org pool.

## 10. Item plaintext

CBOR map with string keys:

```
{ "v": 1,
  "type": "login" | "card" | "bank" | "identity" | "document" | "note" | "ssh_key" | "vault_meta",
  "title": str,
  "fields": { …per type… },
  "custom": [{ "label", "kind": "text"|"secret"|"url"|"date"|"totp", "value" }],
  "attachments": [{ "blob_id", "key", "name", "mime", "size", "sha256" }],
  "tags": [str], "favorite": bool,
  "created": int, "updated": int }
```

| Type | `fields` |
|---|---|
| `login` | `username`, `password`, `urls: [{url, match: domain\|host\|prefix\|exact\|regex\|never}]`, `totp` (otpauth URI), `passkeys: [{credential_id, rp_id, rp_name, user_handle, user_name, alg, private_key (PKCS#8), counter, discoverable, created}]`, `password_history: [{password, changed}]` |
| `card` | `holder`, `number`, `exp_month`, `exp_year`, `cvc`, `pin`, `brand` |
| `bank` | `holder`, `iban`, `account_number`, `bic`, `routing_number`, `bank_name`, `pin` |
| `identity` | `title`, `first`, `middle`, `last`, `birth_date`, `email`, `phone`, `addresses: [...]` |
| `document` | `kind: passport\|id_card\|driver_license\|other`, `number`, `name`, `nationality`, `birth_date`, `issued`, `expires`, `authority` |
| `note` | `text` (Markdown) |
| `ssh_key` | `private_key` (OpenSSH), `public_key`, `comment` |
| `vault_meta` | `name`, `color`, `icon` |

## 11. WebSocket

`GET /v1/ws` (upgrade). The token is sent in the first message, never in the URL.

| Direction | Message |
|---|---|
| C → S (within 10 s) | `{"type":"auth","token":"…"}` |
| S → C | `{"type":"ready","vaults":[{"vault_id","seq"}]}` |
| S → C | `{"type":"vault_changed","vault_id","seq"}` |
| S → C | `{"type":"account_changed"}`: devices, vault list or grants changed |
| S → C | `{"type":"pairing","pairing_id"}`: a pairing message is waiting |
| C ↔ S | `{"type":"ping"}` / `{"type":"pong"}` |

Close codes: `4001` unauthorized or revoked, `4002` unsupported protocol version, `4003` replaced by a newer connection from the same device.

## 12. Errors

All errors use the format `{"error": "<code>", "message": "<human readable>"}`.

| HTTP | Codes |
|---|---|
| 400 | `bad_request`, `invalid_signature`, `invalid_pow`, `weak_kdf` |
| 401 | `unauthorized`, `session_expired` |
| 403 | `forbidden`, `step_up_required`, `quota_exceeded` |
| 404 | `not_found` |
| 409 | `conflict`, `stale_epoch`, `owned_shared_vaults` |
| 410 | `resync_required` |
| 413 | `record_too_large`, `file_too_large` |
| 429 | `rate_limited` (with `Retry-After`) |
| 426 | `unsupported_version` |

## 13. Not yet specified

- Organizations, families, groups and recovery: the wire format comes in a later revision (see ARCHITECTURE §9.4).
- One-time share links and emergency access.
- Short-code pairing (CPace).
- Identity key rotation.

## 14. Test vectors

Generated by `crates/core` and committed under `docs/test-vectors/` once the core crypto exists. Implementations MUST pass them.
