# Architecture

Status: **draft v0**. Nothing here is frozen until 1.0. Wire-level details live in [PROTOCOL.md](PROTOCOL.md).

## 1. Goals

- A free and open-source manager for passwords, passkeys, payment and bank cards, identities and passports, secure notes, SSH keys and files.
- **Zero-knowledge.** The server only ever stores ciphertext. All encryption and decryption happens on the user's devices.
- Native apps for Windows, macOS, Linux, iOS and Android, plus browser extensions for Chromium browsers, Firefox and Safari.
- Live sync between devices that also works offline.
- Sharing, families and organizations.
- Self-hostable on many kinds of infrastructure, with the hosted service running on Cloudflare.

### Non-goals

- **Password reset by the operator.** Without the password plus either a device or the Emergency Kit, data can't be recovered. Organizer or admin recovery (§9.4) is the one opt-in exception.
- **Protection against malware on an unlocked device.** If an attacker controls the device while the vault is unlocked, they can read what the user can read.
- **Hiding all metadata from the server.** The server sees item counts, ciphertext sizes, timing and vault membership (see §12).

## 2. Threat model

| Adversary | Must not be able to | Mitigation |
|---|---|---|
| Server operator / database leak | Read any item, brute-force passwords offline | Client-side encryption; 128-bit Secret Key mixed into key derivation; server stores no password-equivalent |
| Anyone intercepting traffic (including the TLS-terminating CDN) | Log in as the user, read data | Login is a signature over a fresh challenge, so there is nothing to replay; payloads are already encrypted |
| Malicious or compromised server | Swap, replay or roll back records unnoticed; add itself to a shared vault | AEAD with associated data binds every record to its IDs and revision; signed checkpoints; signed membership log; invite secrets the server never sees |
| Thief with a locked device | Unlock the vault | Argon2id-stretched password; device-bound keys in Secure Enclave, Keystore or TPM; password required after reboot and every N days |
| Removed member of a shared vault | Read future changes | Server access revoked immediately, then the vault key is rotated |
| Malicious web page | Trick autofill into leaking credentials | Fill only on user gesture; check origin of the top frame and of the iframe; exact eTLD+1 match by default; harden against clickjacking |
| Supply chain | Ship a backdoored build | Reproducible builds, signed releases, protected store accounts, external audit before 1.0 |

## 3. System overview

```
┌──────────── clients ────────────┐         ┌──────────── server ────────────┐
│ Flutter app (desktop + mobile)  │         │ server-core (Rust, no I/O)     │
│ Browser extension (TS + WASM)   │◄──────► │   auth · sync · permissions ·  │
│ OS autofill / passkey providers │ HTTPS + │   quotas                       │
│ CLI                             │ WS      │ adapters:                      │
│        all built on             │         │   Cloudflare (DO + R2)         │
│      crates/core (Rust)         │         │   standalone (SQLite/Postgres, │
└─────────────────────────────────┘         │   disk/S3)                     │
                                            └────────────────────────────────┘
```

The server is deliberately dumb. It stores encrypted blobs, checks signatures, and enforces write permissions, quotas and rate limits. Everything that requires understanding data happens on the client.

## 4. Repository layout

```
crates/
  core/               client logic: crypto, data model, sync engine, local store, import/export
  protocol/           wire types shared by clients and servers (versioned)
  server-core/        server logic behind storage/blob/notifier traits, no I/O
  server-cloudflare/  adapter: Workers + Durable Objects + R2
  server-standalone/  adapter: single binary (axum), SQLite or Postgres, disk or S3
  conformance/        black-box protocol test suite, run against any server
  cli/                command-line client, also used to test the protocol
apps/                 (later)
  flutter/            desktop + mobile UI on top of core (flutter_rust_bridge)
  extension/          browser extension: TypeScript UI + core compiled to WASM
  ios-autofill/       Swift credential provider extension (core via UniFFI)
  android-autofill/   Kotlin autofill + Credential Manager provider (core via UniFFI)
design/
  tokens.json         colors, type, spacing, icons; generated into Dart and CSS
docs/
```

## 5. Keys

```
password ──Argon2id(salt)──┐
                           ├─HKDF─► master secret ─┬─► auth keypair (Ed25519)   server stores public key only
Secret Key (128 bit) ──────┘                       └─► KEK (key-encryption key)
                                                         │ wraps (AEAD)
                                                         ▼
                                  Account Key (random 256 bit; survives password changes)
                                         │ wraps (AEAD)
                                         ▼
                                  identity keys
                                    encryption: X-Wing (X25519 + ML-KEM-768)
                                    signing:    Ed25519
                                         │ vault keys are wrapped to the identity encryption key (HPKE)
                                         ▼
                                  Vault Key (per vault, versioned by epoch)
                                         │ encrypts (AEAD)
                                         ▼
                                  items ── contain per-file attachment keys

device key (P-256 ECDSA, inside Secure Enclave / StrongBox / Keystore / TPM where available)
  used for everyday login; never leaves the hardware
```

| Secret | On the server | On the device |
|---|---|---|
| Password | never | never stored |
| Secret Key | **never** | OS keychain; Emergency Kit |
| User ID, salt, KDF parameters | yes | yes |
| Auth public key, device public keys, identity public keys | yes | – |
| Account Key | wrapped by the KEK | wrapped by the KEK, plus local copies wrapped by biometrics and passkeys |
| Identity private keys | wrapped by the Account Key | same, decrypted only while unlocked |
| Vault keys | one HPKE grant per member | decrypted only while unlocked |
| Items, attachments | ciphertext | ciphertext on disk; plaintext only in memory while unlocked |

Design rules:

- The Secret Key is **only** an input to key derivation. Nothing is ever encrypted with it directly.
- **Every vault is shared.** A personal vault is simply a vault with one member. Personal, family and organization vaults all use the same code path.
- Every envelope carries an algorithm or version tag, so crypto can be upgraded later.
- Symmetric crypto is 256-bit, which is already post-quantum safe. Key wrapping uses a hybrid post-quantum KEM because wrapped keys sit on the server for years and could be harvested now and decrypted later. Signatures stay Ed25519 for now; forging one requires a quantum computer at the time of the attack, and the tagged formats leave room to add ML-DSA later.

## 6. Accounts and devices

There is no email address and no 2FA. The Secret Key works as the possession factor: logging in from a new device requires both the password and the Secret Key.

### 6.1 Create account

The app asks only for a password, with a strength meter and an enforced minimum.

1. The client requests a sign-up challenge. The server returns a fresh **user ID** (random UUID) and a proof-of-work puzzle.
2. The client generates the Secret Key, salt, Account Key, identity keys and device key, and derives the auth keypair and KEK.
3. The client solves the puzzle and uploads public keys, wrapped keys and KDF parameters. It then logs in and creates its personal vault.
4. User ID and Secret Key are stored in the OS keychain.
5. **Emergency Kit.** A PDF containing the server URL, user ID, Secret Key, a QR code of all three, and a blank line for the password. The app keeps nudging until the user confirms it's saved, and it can regenerate the kit from any unlocked device.

The password still has to be strong. A stolen laptop already contains the Secret Key, so on that machine the password is the only protection.

### 6.2 Unlock

| Method | How it works |
|---|---|
| Password | Re-derive the KEK and unwrap the Account Key |
| Biometrics | The OS keystore releases a local copy of the Account Key, wrapped by a biometry-gated key (Secure Enclave, Android Keystore, Windows Hello). On Linux there is no good standard, so it falls back to the password, or TPM2 + PIN. |
| Passkey | The WebAuthn PRF output unwraps another local copy. Works with security keys and in the standalone extension. |

The password is required after a reboot, after N days (configurable, default 14), and after failed biometric attempts. Locking wipes all decrypted material from memory (`zeroize`).

### 6.3 Login (getting a session)

- **Everyday:** the device signs a server challenge with its hardware device key. This works while the vault is **locked**, so background sync never needs the password.
- **New device / step-up:** sign the challenge with the auth key derived from password + Secret Key. Sensitive actions require a step-up session: changing the password or Secret Key, revoking devices, deleting the account, and changing recovery settings.

### 6.4 Add a device

**QR code (default).**

1. One device shows a QR code containing the server URL, a pairing ID, an ephemeral public key and a 256-bit pairing secret. The server never sees the secret.
2. The other device scans it. The two run an end-to-end encrypted exchange relayed by the server, authenticated by the pairing secret.
3. The existing device sends `{user ID, Secret Key}`.
4. The new device asks for the password, logs in with the auth key and registers its device key.
5. All other devices show "New device added".

Either side can show the code, so it works whichever device has the camera.

**Emergency Kit.** Scan the kit's QR code or type in the user ID and Secret Key, then enter the password. This is the path when every device is lost.

**Short typed code** for two devices without cameras: planned via a PAKE (CPace); not in v1.

### 6.5 Password or Secret Key change

Re-derive, re-wrap the Account Key, and atomically replace salt, KDF parameters and auth public key. No item is re-encrypted. Changing the Secret Key works the same way and produces a new Emergency Kit.

### 6.6 Lost device

- Revoke it from any device with a step-up session. The server deletes the device key and closes its connections immediately.
- Optional "rotate everything": new password, new Secret Key, new Account Key, new identity keys and new vault keys, with all items re-encrypted. Vaults are small, so this is cheap.

## 7. Data model

Item plaintext is versioned, typed and fully encrypted. That includes the type, title, URLs, tags and folders. Search and URL matching run on a local in-memory index while unlocked.

| Type | Main fields |
|---|---|
| Login | username, password, URLs (with match rules), TOTP, passkeys, password history |
| Passkey | stored inside a login: credential ID, RP ID, user handle, private key, counter |
| Payment card | cardholder, number, expiry, CVC, PIN, brand |
| Bank account | holder, IBAN/account number, BIC/routing, bank, PIN |
| Identity | names, addresses, phone, email, date of birth |
| Passport / ID | document type, number, nationality, issue/expiry, issuing authority |
| Secure note | markdown text |
| SSH key | private key, public key, comment |
| (all) | custom fields, attachments, tags, favorite, created/updated timestamps |

Per-item history keeps the last N revisions, which gives undo and protects against bad merges.

Import from Bitwarden, 1Password, KeePass(XC), Proton Pass and browser CSV, plus FIDO Credential Exchange (CXF/CXP). Export to an open, documented format.

## 8. Sync

- **One record per item:** `{vault_id, item_id, revision, key_epoch, ciphertext}`. The server stamps every accepted write with a per-vault, monotonically increasing `seq`.
- **Pull:** `changes(vault, since_seq)` returns changed records and deletion markers.
- **Push:** `put(item, base_revision)`. If the server's current revision differs, it returns a conflict with the current record. The client decrypts both versions, merges field by field and retries. The server never merges, because it can't read the data.
- **Live updates:** one WebSocket per client delivers `changed {vault, seq}` notifications. Everything also works over plain HTTPS, which mobile background tasks, extensions and retries depend on.
- **Offline-first:** every client keeps a local SQLite copy of the ciphertext plus a queue of pending writes.
- **Integrity:**
  - AEAD associated data binds each ciphertext to `(vault_id, item_id, revision, key_epoch)`, so the server can't swap records around.
  - Deletions are encrypted tombstones, so they can't be forged.
  - Writers sign checkpoints `{vault, seq, state_hash}` with their identity key.
  - Clients refuse to accept a `seq` lower than the highest they have seen.

Limit: a malicious server can still withhold updates. Clients can detect that it's happening, but they can't prevent it.

## 9. Sharing, families, organizations

### 9.1 Vault membership

- Each member holds a **grant**: the vault key HPKE-wrapped to that member's identity encryption key (or later to a group key).
- Reading is enforced by cryptography: no grant, no key.
- Writing is enforced by the server, which checks membership and role (`view`, `edit`, `manage`, `owner`).
- Every vault has a **signed membership log**. Each entry (create, add, remove, change role, rotate key) is signed by an actor who held the required role at that point, and records each subject's identity key fingerprint. Clients verify the whole chain before trusting a grant or encrypting to a member, so the server can't silently add a member.

### 9.2 Invites (key authenticity)

A server that hands out public keys could substitute its own. Invites prevent that:

1. Alice creates an invite. The link carries `#<invite secret>.<Alice's key fingerprint>`. Browsers never send the part after `#` to the server, and Alice shares the link over any channel she likes (chat, QR, in person).
2. Bob opens it and his app posts his identity public keys together with a MAC computed with the invite secret.
3. Any of Alice's admin devices verifies the MAC, appends a signed `add` entry and uploads Bob's grant. If none is online, this happens the next time one is unlocked.
4. Bob's app checks that the log is signed by the fingerprint from the link.

Key fingerprints stay visible on every member for manual verification.

### 9.3 Removal

1. Server access ends immediately.
2. An admin's client rotates the vault key (new epoch), re-encrypts the items and issues new grants to the remaining members.
3. Attachments are not re-encrypted, because their content didn't change and the server already denies the removed member access.
4. Anything the removed member already saw may have been copied. No system can prevent that.

### 9.4 Families and organizations

| | Family | Organization |
|---|---|---|
| Roles | organizer, member | owner, admin, member |
| Default vaults | "Family" (shared) + each member's private vault | none; created by admins |
| Groups | – | groups with their own HPKE keypair; vault grants can target a group |
| Recovery | opt-in organizer recovery | admin recovery, set by policy |
| Policies | – | minimum password strength, allowed unlock methods, sharing outside the org |
| Audit log | – | metadata only: who did what, when, on which vault/item ID |
| Quota | pooled | pooled |

**Recovery.** When enabled, the member's Account Key is also HPKE-wrapped to the org's recovery key. The recovery private key is held like a vault, wrapped to the organizers or admins. To recover, a member on a new device creates temporary credentials. An organizer approves out of band ("is this really Bob?") and re-wraps Bob's Account Key to his new device, and Bob then sets a new password and gets a new Secret Key. This is opt-in and clearly explained, because it technically lets organizers access that member's data.

SSO is deferred because it conflicts with zero-knowledge; it would need device-trust or key-connector designs.

### 9.5 Later

- Sharing a single item: copied into a shared vault behind the scenes.
- One-time share links: encrypted snapshot, key after the `#`, expiry and view limit.
- Emergency access: a trusted contact receives a wrapped Account Key copy, and the server releases it only after a waiting period the owner didn't cancel.
- New-device sign-in with a passkey: a server-stored, PRF-wrapped Account Key plus a WebAuthn assertion. It skips the Secret Key, which is a deliberate trade-off.

## 10. Attachments

- Each file has a random key, stored **inside the item** that references it, so it syncs with the item automatically.
- Files are encrypted in 64 KiB chunks (STREAM construction), so they can be streamed and can't be silently truncated or reordered.
- Upload: the client asks for an upload slot with the size, the server checks and reserves quota, the client streams the ciphertext, and only then writes the item that references the blob. Blobs nobody references are deleted after 24 h.
- **Quotas (defaults, configurable per deployment):**
  - 250 MB per user and 25 MB per file.
  - Shared vaults count against the vault's owner or org.
  - Families and orgs get 250 MB per seat, pooled.

## 11. Server

### 11.1 server-core and its adapters

`server-core` contains every protocol rule and talks to the outside world only through traits:

| Trait | Purpose |
|---|---|
| `Store` | transactional storage, serialized per vault and per account |
| `BlobStore` | encrypted attachment blobs |
| `Notifier` | tell an account's connected devices that a vault changed |
| `RateLimiter`, `Clock`, `Rng` | everything else that touches the environment |

| Adapter | Store | Blobs | Notifier | Good for |
|---|---|---|---|---|
| Cloudflare | SQLite-backed Durable Objects: one per account, one per vault | R2 | Durable Object WebSockets with hibernation | the hosted service; no ops |
| Standalone, simple | SQLite file | local disk or S3-compatible | in-process | homelab, Raspberry Pi, Docker one-liner |
| Standalone, scalable | Postgres (row lock per vault) | S3-compatible | Postgres `LISTEN/NOTIFY` | companies; multiple instances behind a load balancer |

- **Same behavior everywhere.** The `conformance` crate is a black-box test suite that speaks the protocol to any URL. Every adapter must pass it.
- **Fallback.** If workers-rs lacks a Durable Object API we need, a thin TypeScript Worker calls `server-core` compiled to WASM.

### 11.2 Cloudflare request path

```
Worker (routing, rate limit, proof-of-work)
  → AccountDO(user_id)   checks the session and device (so revocation is instant),
                         holds account keys, devices, WebSockets
  → VaultDO(vault_id)    records, seq, membership log, grants, blob index;
                         after a write it notifies the AccountDO of every member
R2                       {vault_id}/{blob_id}
```

No D1 and no KV. Without email there is no global lookup: user and vault IDs map straight to their Durable Objects.

### 11.3 Abuse prevention

- Proof-of-work on sign-up.
- Per-IP and per-account rate limits.
- Quotas.
- Unauthenticated endpoints (pre-login, pairing) return identical responses for unknown IDs.

## 12. What the server can see

- Number of vaults, items and revisions.
- Ciphertext sizes. Clients pad item ciphertexts to size buckets.
- Timing of reads and writes, and IP addresses.
- Who shares a vault with whom, and their roles.
- Device names and platforms (user-chosen and optional).

## 13. Clients

### 13.1 UI strategy

- **Behavior lives in `core`:** search ranking, URL matching, password generator, validation, item types, merge rules. Every client behaves the same because it runs the same code.
- **Look comes from `design/tokens.json`**, generated into Dart and CSS.

| Client | UI | Core binding |
|---|---|---|
| Desktop (Windows, macOS, Linux) + mobile (iOS, Android) | Flutter, one codebase | flutter_rust_bridge |
| Browser extension: popup + in-page fill menu | TypeScript (in-page menu inside a closed shadow root or isolated iframe) | WASM |
| iOS/macOS credential provider, Android autofill + Credential Manager, Windows passkey plugin | native Swift / Kotlin / C++ (separate OS processes with tight memory limits) | UniFFI |
| CLI | – | direct |

Flutter calls into Rust cost microseconds, and the heavy work (Argon2, crypto, search) runs in Rust on background threads, so performance is not a concern.

### 13.2 Browser extension

- One Manifest V3 codebase for Chromium (Chrome, Edge, Brave, Opera, Vivaldi), Firefox (manifest differences only) and Safari (packaged inside the macOS/iOS app).
- **Paired mode:** the extension talks to the desktop app over native messaging. The app holds the unlocked vault, syncs, and handles biometrics.
- **Standalone mode:** the WASM core syncs when the extension opens or on an alarm. This covers ChromeOS, locked-down work machines, and machines without the desktop app.
- Passkeys: the extension intercepts `navigator.credentials` calls.
- Autofill rules:
  - Fill only on an explicit user action, never automatically on page load.
  - Check the origin of both the top frame and the iframe.
  - Match the exact eTLD+1 by default.
  - Never fill into invisible or covered fields.

### 13.3 Local hygiene

- Secrets live in `secrecy`/`zeroize` types.
- The clipboard is cleared after 30 s and marked as sensitive where the OS supports it.
- The vault locks on idle, sleep and screen lock.
- Screenshots are blocked on mobile.

## 14. Roadmap

1. `core` + `cli`: crypto, data model, local store, sync engine; test vectors.
2. `server-core` + `server-standalone` (SQLite) + `conformance`.
3. `server-cloudflare`.
4. Flutter desktop.
5. Browser extension.
6. Flutter mobile.
7. OS autofill and passkey providers.
8. Families and organizations; then one-time share links and emergency access.
9. External audit; then 1.0, which freezes the protocol and domain-separation strings.

## 15. Name and license

- **Symbolon.** In ancient Greece a *symbolon* was a token broken in two; matching the halves proved identity. Here the two halves are the password and the Secret Key.
- **License.** Server crates (`server-*`) are AGPL-3.0-or-later, so hosted modifications stay open. Everything else (core, protocol, apps, extension, CLI) is MPL-2.0. That keeps copyleft on each file while allowing distribution through the Apple App Store, which conflicts with GPL terms.

## 16. Open questions

- Default Argon2id parameters on low-end Android and inside the extension's WASM memory limits; benchmark in step 1.
- Recovery and policy details for organizations; specified in PROTOCOL.md in a later revision.
