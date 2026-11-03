//! Test vectors (PROTOCOL.md §14) in `docs/test-vectors/`.
//!
//! - `committed_vectors_verify` checks every committed file through the
//!   public API (decrypt, parse, verify), the way another implementation would.
//! - `committed_vectors_match_generator` regenerates the files from fixed
//!   seeds and requires them to be unchanged, so any byte-level drift in the
//!   code fails CI.
//! - `regenerate_test_vectors` (ignored) rewrites the files:
//!   `cargo test -p symbolon-crypto -- --ignored regenerate_test_vectors`.

use std::fs;
use std::path::PathBuf;

use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use symbolon_protocol::cbor::Value;
use symbolon_protocol::domain;

use crate::blob::{self, BlobEncryptor, CT_CHUNK_LEN, HEADER_LEN};
use crate::kdf::{expand_master, extract_master, normalize_password, stretch_password};
use crate::*;

/// Files whose committed content must equal the generator output. The
/// HPKE file is only verified: its bytes depend on how the `hpke` crate
/// consumes the RNG, which isn't part of the spec.
const GENERATED: [&str; 8] = [
    "secret-key.json",
    "kdf.json",
    "aead-box.json",
    "padding.json",
    "blob.json",
    "pow.json",
    "fingerprint.json",
    "signatures.json",
];
const HPKE: &str = "hpke-box.json";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/test-vectors")
}

fn rng_for(name: &str) -> ChaCha20Rng {
    let seed: [u8; 32] = Sha256::digest(format!("symbolon test vectors: {name}")).into();
    ChaCha20Rng::from_seed(seed)
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn unh(v: &Json) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn arr<const N: usize>(v: &Json) -> [u8; N] {
    unh(v)
        .try_into()
        .expect("hex value has the expected length")
}

fn sha(b: &[u8]) -> String {
    h(&Sha256::digest(b))
}

fn random<const N: usize>(rng: &mut ChaCha20Rng) -> [u8; N] {
    let mut b = [0u8; N];
    rng.fill_bytes(&mut b);
    b
}

/// Plaintext used for large inputs: byte `i` is `i mod 251`.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn uuid(rng: &mut ChaCha20Rng) -> [u8; 16] {
    let mut id = random::<16>(rng);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

fn file(description: &str, vectors: Json) -> Json {
    json!({ "description": description, "vectors": vectors })
}

// ---------------------------------------------------------------------------
// Generators

fn gen_secret_key() -> Json {
    let mut rng = rng_for("secret-key");
    let mut keys = vec![[0u8; 16], [0xff; 16]];
    keys.extend((0..4).map(|_| random::<16>(&mut rng)));
    // Make sure every check-only symbol appears.
    for c in *b"*~$=U" {
        loop {
            let k = random::<16>(&mut rng);
            if SecretKey::from_bytes(&k).to_text().ends_with(c as char) {
                keys.push(k);
                break;
            }
        }
    }
    let encode: Vec<Json> = keys
        .iter()
        .map(|k| json!({ "bytes": h(k), "text": *SecretKey::from_bytes(k).to_text() }))
        .collect();

    let k = keys[2];
    let text = SecretKey::from_bytes(&k).to_text().to_string();
    let compact = text.replace('-', "");
    let mut bad_check = text.clone().into_bytes();
    let last = bad_check.len() - 1;
    bad_check[last] = if bad_check[last] == b'0' { b'1' } else { b'0' };
    let bad_check = String::from_utf8(bad_check).unwrap();
    let ok = |input: String| json!({ "input": input, "bytes": h(&k) });
    let err = |input: String, e: &str| json!({ "input": input, "error": e });
    let parse = vec![
        ok(text.clone()),
        ok(text.to_lowercase()),
        ok(compact.clone()),
        ok(text.replace('-', " ")),
        ok(format!(" {} \n", text.replace('-', " - "))),
        ok(text.replace('1', "l").replace('0', "o")),
        ok(text.replace('1', "I").replace('0', "O")),
        err(bad_check, "checksum"),
        err(compact[2..].to_string(), "format"),
        err(format!("S2{}", &compact[2..]), "format"),
        err(compact[..compact.len() - 1].to_string(), "format"),
        err(format!("{compact}0"), "format"),
        err(format!("S1U{}", &compact[3..]), "format"),
        err(format!("S18{}", &compact[3..]), "format"),
    ];
    file(
        "PROTOCOL.md §3.1 Secret Key text form. `encode`: bytes → text. `parse`: lenient \
         input → bytes, or an error class (`format` or `checksum`).",
        json!({ "encode": encode, "parse": parse }),
    )
}

fn kdf_vector(password: &str, sk: [u8; 16], salt: [u8; 16], params: KdfParams) -> Json {
    let secret_key = SecretKey::from_bytes(&sk);
    let salt = Salt::from_bytes(&salt);
    let s_pw = stretch_password(password, &salt, &params).unwrap();
    let master = extract_master(&s_pw, &secret_key, &salt);
    let secrets = expand_master(&master);
    json!({
        "password": password,
        "password_nfkc": h(normalize_password(password).as_bytes()),
        "secret_key": h(&sk),
        "salt": h(salt.as_bytes()),
        "m": params.m, "t": params.t, "p": params.p,
        "s_pw": h(&*s_pw),
        "master": h(&*master),
        "auth_seed": h(&*secrets.auth_key().to_seed()),
        "auth_pk": h(secrets.auth_key().public_key().as_bytes()),
        "kek": h(secrets.kek().as_bytes()),
    })
}

fn gen_kdf() -> Json {
    let mut rng = rng_for("kdf");
    let mut v = Vec::new();
    for (pw, params) in [
        ("correct horse battery staple", KdfParams::DEFAULT),
        // Full-width P, "fi" ligature, A + combining ring, trailing space.
        ("\u{ff30}\u{fb01}A\u{030a} ", KdfParams::DEFAULT),
        ("", KdfParams::MINIMUM),
    ] {
        v.push(kdf_vector(pw, random(&mut rng), random(&mut rng), params));
    }
    file(
        "PROTOCOL.md §3.2 key derivation with intermediates. `password_nfkc` is \
         UTF-8(NFKC(password)); `auth_pk` is the Ed25519 public key of `auth_seed`.",
        Json::Array(v),
    )
}

fn gen_aead_box() -> Json {
    let mut rng = rng_for("aead-box");
    let user_id = uuid(&mut rng);
    let salt = random::<16>(&mut rng);
    let account_aad = Value::Array(vec![
        Value::text(domain::ACCOUNT_KEY),
        Value::bytes(user_id),
        Value::bytes(salt),
    ])
    .encode()
    .unwrap();
    let account_key = random::<32>(&mut rng);
    let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (vec![], vec![]),
        (b"hello".to_vec(), b"aad".to_vec()),
        (account_key.to_vec(), account_aad),
        (pattern(300), vec![]),
    ];
    let v: Vec<Json> = cases
        .into_iter()
        .map(|(pt, aad)| {
            let key = SymmetricKey::from_bytes(&random(&mut rng));
            let nonce = random::<24>(&mut rng);
            let b = AeadBox::seal_with_nonce(&key, &nonce, &pt, &aad).unwrap();
            json!({
                "key": h(key.as_bytes()),
                "nonce": h(&nonce),
                "aad": h(&aad),
                "plaintext": h(&pt),
                "ciphertext": h(b.ciphertext()),
                "envelope": h(&b.to_bytes()),
            })
        })
        .collect();
    let invalid = aead_box_invalid(&v[1]);
    let mut j = file(
        "PROTOCOL.md §2 AeadBox. `ciphertext` is ct || tag; `envelope` is cbor(AeadBox). \
         The third vector uses a wrapped_ak-style AAD cbor([\"symbolon/v1/account-key\", \
         user_id, salt]). `invalid` envelopes must be rejected with the given error class: \
         `malformed` (not a canonical AeadBox), `version`, `algorithm` or `decryption`.",
        Json::Array(v),
    );
    j["invalid"] = invalid;
    j
}

/// Envelopes derived from a valid vector that must be rejected.
fn aead_box_invalid(good: &Json) -> Json {
    let nonce = unh(&good["nonce"]);
    let ct = unh(&good["ciphertext"]);
    let env = |version: u64, alg: u64, nonce: &[u8], ct: &[u8]| {
        Value::Array(vec![
            Value::Unsigned(version),
            Value::Unsigned(alg),
            Value::bytes(nonce),
            Value::bytes(ct),
        ])
        .encode()
        .unwrap()
    };
    let canonical = unh(&good["envelope"]);
    let mut non_canonical = vec![0x84, 0x18, 0x01];
    non_canonical.extend_from_slice(&canonical[2..]);
    let mut trailing = canonical.clone();
    trailing.push(0x00);
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&canonical[1..]);
    indefinite.push(0xff);
    let mut bad_tag = ct.clone();
    *bad_tag.last_mut().unwrap() ^= 0x01;
    let mut wrong_aad = unh(&good["aad"]);
    wrong_aad.push(0x00);
    let case = |why: &str, envelope: Vec<u8>, aad: &[u8], error: &str| json!({ "why": why, "envelope": h(&envelope), "aad": h(aad), "error": error });
    let aad = unh(&good["aad"]);
    Json::Array(vec![
        case("version 2", env(2, 1, &nonce, &ct), &aad, "version"),
        case("alg 2", env(1, 2, &nonce, &ct), &aad, "algorithm"),
        case(
            "23-byte nonce",
            env(1, 1, &nonce[..23], &ct),
            &aad,
            "malformed",
        ),
        case(
            "ct shorter than a tag",
            env(1, 1, &nonce, &ct[..15]),
            &aad,
            "malformed",
        ),
        case("version in a 2-byte head", non_canonical, &aad, "malformed"),
        case("indefinite-length array", indefinite, &aad, "malformed"),
        case("trailing byte", trailing, &aad, "malformed"),
        case(
            "tag bit flipped",
            env(1, 1, &nonce, &bad_tag),
            &aad,
            "decryption",
        ),
        case(
            "ct truncated by one byte",
            env(1, 1, &nonce, &ct[..ct.len() - 1]),
            &aad,
            "decryption",
        ),
        case(
            "AAD with an extra byte",
            canonical,
            &wrong_aad,
            "decryption",
        ),
    ])
}

fn error_class(e: Error) -> &'static str {
    match e {
        Error::MalformedEnvelope => "malformed",
        Error::UnsupportedVersion => "version",
        Error::UnsupportedAlgorithm => "algorithm",
        Error::Decryption => "decryption",
        Error::BlobTruncated => "truncated",
        other => panic!("unexpected error {other:?}"),
    }
}

fn gen_padding() -> Json {
    let v: Vec<Json> = [0usize, 1, 5, 255, 256, 4095, 4096, 8192]
        .into_iter()
        .map(|n| {
            let content = pattern(n);
            let padded = padding::pad(&content).unwrap();
            let mut j = json!({
                "content_len": n,
                "padded_len": padded.len(),
                "padded_sha256": sha(&padded),
            });
            if padded.len() <= 512 {
                j["padded"] = json!(h(&padded));
            }
            j
        })
        .collect();
    file(
        "PROTOCOL.md §8.1 record padding. Content byte i is (i mod 251). `padded` is \
         included for short outputs.",
        Json::Array(v),
    )
}

fn gen_blob() -> Json {
    let mut rng = rng_for("blob");
    let vault_id = uuid(&mut rng);
    let blob_id = uuid(&mut rng);
    let aad = Value::Array(vec![
        Value::text(domain::BLOB),
        Value::bytes(vault_id),
        Value::bytes(blob_id),
    ])
    .encode()
    .unwrap();
    let v: Vec<Json> = [0usize, 5, blob::CHUNK_LEN, 2 * blob::CHUNK_LEN + 100]
        .into_iter()
        .map(|n| {
            let key = SymmetricKey::from_bytes(&random(&mut rng));
            let prefix = random::<19>(&mut rng);
            let pt = pattern(n);
            let mut enc = BlobEncryptor::with_nonce_prefix(&key, &aad, prefix);
            let mut out = enc.update(&pt).unwrap();
            out.extend_from_slice(&enc.finish().unwrap());
            let chunks: Vec<Json> = out[HEADER_LEN..]
                .chunks(CT_CHUNK_LEN)
                .enumerate()
                .map(|(i, c)| {
                    let last = (i + 1) * CT_CHUNK_LEN >= out.len() - HEADER_LEN;
                    let mut nonce = prefix.to_vec();
                    nonce.extend_from_slice(&(i as u32).to_be_bytes());
                    nonce.push(u8::from(last));
                    json!({ "index": i, "last": last, "nonce": h(&nonce), "len": c.len(), "sha256": sha(c) })
                })
                .collect();
            let mut j = json!({
                "file_key": h(key.as_bytes()),
                "aad": h(&aad),
                "nonce_prefix": h(&prefix),
                "plaintext_len": n,
                "blob_len": out.len(),
                "blob_sha256": sha(&out),
                "chunks": chunks,
            });
            if out.len() <= 512 {
                j["blob"] = json!(h(&out));
            }
            j
        })
        .collect();
    let invalid = blob_invalid(&v[1]);
    let mut j = file(
        "PROTOCOL.md §9 attachment STREAM. Plaintext byte i is (i mod 251). The AAD is \
         cbor([\"symbolon/v1/blob\", vault_id, blob_id]). Vectors: empty file, short file, \
         exactly one chunk, three chunks. `invalid` blobs (derived from the 5-byte vector's \
         key, AAD and nonce prefix) must be rejected with the given error class: `truncated`, \
         `version` or `decryption`.",
        Json::Array(v),
    );
    j["invalid"] = invalid;
    j
}

/// Blobs derived from a valid short vector that must be rejected.
fn blob_invalid(good: &Json) -> Json {
    let blob = unh(&good["blob"]);
    let key = SymmetricKey::from_bytes(&arr(&good["file_key"]));
    let aad = unh(&good["aad"]);
    let prefix: [u8; 19] = arr(&good["nonce_prefix"]);
    // The same 5 bytes sealed with the last-chunk flag cleared.
    let mut nonce = prefix.to_vec();
    nonce.extend_from_slice(&[0, 0, 0, 0, 0]);
    let not_last =
        crate::aead_box::xchacha_seal(&key, &nonce.try_into().unwrap(), &pattern(5), &aad).unwrap();
    let with = |tail: &[u8]| [&blob[..], tail].concat();
    let mut version = blob.clone();
    version[0] = 0x02;
    let case =
        |why: &str, b: Vec<u8>, error: &str| json!({ "why": why, "blob": h(&b), "error": error });
    Json::Array(vec![
        case("empty input", vec![], "truncated"),
        case("header only", blob[..HEADER_LEN].to_vec(), "truncated"),
        case(
            "chunk shorter than a tag",
            blob[..HEADER_LEN + 15].to_vec(),
            "truncated",
        ),
        case(
            "last byte missing",
            blob[..blob.len() - 1].to_vec(),
            "decryption",
        ),
        case("one byte appended", with(&[0]), "decryption"),
        case("empty chunk appended", with(&[0; 16]), "decryption"),
        case("version byte 2", version, "version"),
        case(
            "only chunk not flagged last",
            [&blob[..HEADER_LEN], &not_last[..]].concat(),
            "decryption",
        ),
    ])
}

fn gen_pow() -> Json {
    let mut rng = rng_for("pow");
    let challenge = random::<32>(&mut rng);
    let mut v = Vec::new();
    for difficulty in [0u32, 1, 8, 16, 20] {
        let nonce = pow::solve(&challenge, difficulty).unwrap();
        let mut input = domain::POW.as_bytes().to_vec();
        input.extend_from_slice(&challenge);
        input.extend_from_slice(&nonce);
        v.push(json!({
            "challenge": h(&challenge), "difficulty": difficulty, "nonce": h(&nonce),
            "hash": sha(&input), "valid": true,
        }));
        // The same nonce one bit harder than it actually is.
        let strength = (difficulty..=256)
            .take_while(|&d| pow::verify(&challenge, &nonce, d))
            .last()
            .unwrap();
        v.push(json!({
            "challenge": h(&challenge), "difficulty": strength + 1, "nonce": h(&nonce),
            "hash": sha(&input), "valid": false,
        }));
    }
    file(
        "PROTOCOL.md §4.1 proof-of-work. `hash` = SHA-256(\"symbolon/v1/pow\" || challenge || \
         nonce). Valid nonces are the smallest big-endian counter that meets the difficulty.",
        Json::Array(v),
    )
}

fn gen_fingerprint() -> Json {
    let mut rng = rng_for("fingerprint");
    let v: Vec<Json> = (0..2)
        .map(|_| {
            let sig_seed = random::<32>(&mut rng);
            let enc_seed = random::<32>(&mut rng);
            let sig_pk = Ed25519SigningKey::from_seed(&sig_seed).public_key();
            let enc_pk = XWingSecretKey::from_bytes(&enc_seed).public_key();
            let fp = Fingerprint::compute(&sig_pk, &enc_pk);
            json!({
                "sig_seed": h(&sig_seed),
                "enc_seed": h(&enc_seed),
                "sig_pk": h(sig_pk.as_bytes()),
                "enc_pk": h(&enc_pk.to_bytes()),
                "fingerprint": h(fp.as_bytes()),
                "display": fp.to_display(),
            })
        })
        .collect();
    file(
        "PROTOCOL.md §3.3 fingerprint = SHA-256(cbor([\"symbolon/v1/fingerprint\", sig_pk, \
         enc_pk]))[0..20]. `display` uses 8 groups of 4 Crockford symbols (see the README).",
        Json::Array(v),
    )
}

fn gen_signatures() -> Json {
    let mut rng = rng_for("signatures");
    let messages: [&[u8]; 2] = [b"", b"symbolon"];
    let ed: Vec<Json> = messages
        .iter()
        .map(|m| {
            let seed = random::<32>(&mut rng);
            let key = Ed25519SigningKey::from_seed(&seed);
            json!({
                "seed": h(&seed), "public_key": h(key.public_key().as_bytes()),
                "message": h(m), "signature": h(&key.sign(m).to_bytes()),
            })
        })
        .collect();
    let challenge_msg = Value::Array(vec![
        Value::text(domain::LOGIN_DEVICE),
        Value::text("https://sync.example.com"),
        Value::bytes(uuid(&mut rng)),
        Value::bytes(uuid(&mut rng)),
        Value::bytes(random::<32>(&mut rng)),
    ])
    .encode()
    .unwrap();
    let p256: Vec<Json> = [&b"symbolon"[..], &challenge_msg]
        .iter()
        .map(|m| {
            let key = SoftwareDeviceKey::generate(&mut rng);
            let sig = key.sign(m).unwrap();
            json!({
                "private_key": h(&*key.to_bytes()), "public_key": h(&key.public_key().to_bytes()),
                "message": h(m), "signature": h(sig.as_der()),
            })
        })
        .collect();
    file(
        "PROTOCOL.md §1 signatures. Ed25519 (RFC 8032). ECDSA P-256 / SHA-256 with RFC 6979 \
         deterministic nonces, DER signatures, SEC1 compressed public keys; the second P-256 \
         message has the shape of a device login message (§4.3).",
        json!({ "ed25519": ed, "p256": p256 }),
    )
}

fn gen_hpke_box() -> Json {
    let mut rng = rng_for("hpke-box");
    let vault_id = uuid(&mut rng);
    let member = uuid(&mut rng);
    let grant_info = Value::Array(vec![
        Value::text(domain::GRANT),
        Value::bytes(vault_id),
        Value::Unsigned(1),
        Value::bytes(member),
    ])
    .encode()
    .unwrap();
    let cases: [(Vec<u8>, Vec<u8>); 2] = [
        (random::<32>(&mut rng).to_vec(), grant_info),
        (b"hello".to_vec(), vec![]),
    ];
    let v: Vec<Json> = cases
        .into_iter()
        .map(|(pt, info)| {
            let seed = random::<32>(&mut rng);
            let sk = XWingSecretKey::from_bytes(&seed);
            let b = HpkeBox::seal(&sk.public_key(), &info, &pt, &mut rng).unwrap();
            json!({
                "secret_key": h(&seed),
                "public_key": h(&sk.public_key().to_bytes()),
                "info": h(&info),
                "plaintext": h(&pt),
                "envelope": h(&b.to_bytes()),
            })
        })
        .collect();
    file(
        "PROTOCOL.md §1, §2 HpkeBox: HPKE base mode, X-Wing (KEM 0x647a) / HKDF-SHA256 / \
         ChaCha20-Poly1305, empty AAD. HPKE is randomized, so check these by opening. The \
         first vector uses a grant-style info cbor([\"symbolon/v1/grant\", vault_id, 1, user_id]).",
        Json::Array(v),
    )
}

fn generate(name: &str) -> Json {
    match name {
        "secret-key.json" => gen_secret_key(),
        "kdf.json" => gen_kdf(),
        "aead-box.json" => gen_aead_box(),
        "padding.json" => gen_padding(),
        "blob.json" => gen_blob(),
        "pow.json" => gen_pow(),
        "fingerprint.json" => gen_fingerprint(),
        "signatures.json" => gen_signatures(),
        HPKE => gen_hpke_box(),
        _ => unreachable!(),
    }
}

fn render(j: &Json) -> String {
    serde_json::to_string_pretty(j).unwrap() + "\n"
}

fn load(name: &str) -> Json {
    let text = fs::read_to_string(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn vectors(j: &Json) -> &Vec<Json> {
    j["vectors"].as_array().unwrap()
}

#[test]
#[ignore = "rewrites docs/test-vectors; run explicitly"]
fn regenerate_test_vectors() {
    fs::create_dir_all(dir()).unwrap();
    for name in GENERATED.iter().chain([&HPKE]) {
        fs::write(dir().join(name), render(&generate(name))).unwrap();
    }
}

#[test]
fn committed_vectors_match_generator() {
    for name in GENERATED {
        // Git may check the files out with CRLF line endings (Windows CI).
        let committed = fs::read_to_string(dir().join(name))
            .unwrap()
            .replace("\r\n", "\n");
        assert!(
            committed == render(&generate(name)),
            "{name} differs from the generator; if the change is intended, regenerate"
        );
    }
}

// ---------------------------------------------------------------------------
// Verification of committed files through the public API

#[test]
fn verify_secret_key() {
    let j = load("secret-key.json");
    for v in j["vectors"]["encode"].as_array().unwrap() {
        let key = SecretKey::from_bytes(&arr(&v["bytes"]));
        assert_eq!(&*key.to_text(), v["text"].as_str().unwrap());
        assert!(SecretKey::parse(v["text"].as_str().unwrap()).unwrap() == key);
    }
    for v in j["vectors"]["parse"].as_array().unwrap() {
        let r = SecretKey::parse(v["input"].as_str().unwrap());
        match v["error"].as_str() {
            None => assert_eq!(r.unwrap().as_bytes(), &arr::<16>(&v["bytes"])),
            Some("checksum") => assert_eq!(r.err(), Some(Error::SecretKeyChecksum)),
            Some("format") => assert_eq!(r.err(), Some(Error::SecretKeyFormat)),
            Some(e) => panic!("unknown error class {e}"),
        }
    }
}

#[test]
fn verify_kdf() {
    for v in vectors(&load("kdf.json")) {
        let params = KdfParams {
            m: v["m"].as_u64().unwrap() as u32,
            t: v["t"].as_u64().unwrap() as u32,
            p: v["p"].as_u64().unwrap() as u32,
        };
        let pw = v["password"].as_str().unwrap();
        assert_eq!(
            normalize_password(pw).as_bytes(),
            &unh(&v["password_nfkc"])[..]
        );
        let secrets = derive_account_secrets(
            pw,
            &SecretKey::from_bytes(&arr(&v["secret_key"])),
            &Salt::from_bytes(&arr(&v["salt"])),
            &params,
        )
        .unwrap();
        assert_eq!(&*secrets.auth_key().to_seed(), &arr::<32>(&v["auth_seed"]));
        assert_eq!(
            secrets.auth_key().public_key().as_bytes(),
            &arr::<32>(&v["auth_pk"])
        );
        assert_eq!(secrets.kek().as_bytes(), &arr::<32>(&v["kek"]));
        // The intermediates chain together.
        let master = expand_master(&arr(&v["master"]));
        assert!(master.kek() == secrets.kek());
    }
}

#[test]
fn verify_aead_box() {
    for v in vectors(&load("aead-box.json")) {
        let key = SymmetricKey::from_bytes(&arr(&v["key"]));
        let b = AeadBox::from_bytes(&unh(&v["envelope"])).unwrap();
        assert_eq!(b.nonce(), &arr::<24>(&v["nonce"]));
        assert_eq!(b.ciphertext(), &unh(&v["ciphertext"])[..]);
        assert_eq!(
            &*b.open(&key, &unh(&v["aad"])).unwrap(),
            &unh(&v["plaintext"])[..]
        );
        // Negative: the AAD is bound.
        let mut aad = unh(&v["aad"]);
        aad.push(0);
        assert_eq!(b.open(&key, &aad).err(), Some(Error::Decryption));
    }
    let j = load("aead-box.json");
    let key = SymmetricKey::from_bytes(&arr(&vectors(&j)[1]["key"]));
    for v in j["invalid"].as_array().unwrap() {
        let r =
            AeadBox::from_bytes(&unh(&v["envelope"])).and_then(|b| b.open(&key, &unh(&v["aad"])));
        assert_eq!(
            r.map(|_| ()).map_err(error_class),
            Err(v["error"].as_str().unwrap()),
            "{}",
            v["why"]
        );
    }
}

#[test]
fn verify_padding() {
    for v in vectors(&load("padding.json")) {
        let content = pattern(v["content_len"].as_u64().unwrap() as usize);
        let padded = padding::pad(&content).unwrap();
        assert_eq!(padded.len() as u64, v["padded_len"].as_u64().unwrap());
        assert_eq!(sha(&padded), v["padded_sha256"].as_str().unwrap());
        if let Some(p) = v.get("padded") {
            assert_eq!(&padded[..], &unh(p)[..]);
        }
        assert_eq!(padding::unpad(&padded).unwrap(), &content[..]);
    }
}

#[test]
fn verify_blob() {
    for v in vectors(&load("blob.json")) {
        let key = SymmetricKey::from_bytes(&arr(&v["file_key"]));
        let aad = unh(&v["aad"]);
        let pt = pattern(v["plaintext_len"].as_u64().unwrap() as usize);
        let mut enc = BlobEncryptor::with_nonce_prefix(&key, &aad, arr(&v["nonce_prefix"]));
        let mut out = enc.update(&pt).unwrap();
        out.extend_from_slice(&enc.finish().unwrap());
        assert_eq!(out.len() as u64, v["blob_len"].as_u64().unwrap());
        assert_eq!(
            Some(out.len() as u64),
            blob::ciphertext_len(pt.len() as u64)
        );
        assert_eq!(sha(&out), v["blob_sha256"].as_str().unwrap());
        if let Some(b) = v.get("blob") {
            assert_eq!(out, unh(b));
        }
        let chunks = v["chunks"].as_array().unwrap();
        for (c, cv) in out[HEADER_LEN..].chunks(CT_CHUNK_LEN).zip(chunks) {
            assert_eq!(sha(c), cv["sha256"].as_str().unwrap());
        }
        assert_eq!(&*blob::decrypt(&key, &aad, &out).unwrap(), &pt[..]);
        assert!(blob::decrypt(&key, &aad, &out[..out.len() - 1]).is_err());
    }
    let j = load("blob.json");
    let good = &vectors(&j)[1];
    let key = SymmetricKey::from_bytes(&arr(&good["file_key"]));
    let aad = unh(&good["aad"]);
    for v in j["invalid"].as_array().unwrap() {
        let r = blob::decrypt(&key, &aad, &unh(&v["blob"]));
        assert_eq!(
            r.map(|_| ()).map_err(error_class),
            Err(v["error"].as_str().unwrap()),
            "{}",
            v["why"]
        );
    }
}

#[test]
fn verify_pow() {
    for v in vectors(&load("pow.json")) {
        let challenge = unh(&v["challenge"]);
        let nonce = arr::<8>(&v["nonce"]);
        let difficulty = v["difficulty"].as_u64().unwrap() as u32;
        assert_eq!(
            pow::verify(&challenge, &nonce, difficulty),
            v["valid"].as_bool().unwrap()
        );
        let mut input = domain::POW.as_bytes().to_vec();
        input.extend_from_slice(&challenge);
        input.extend_from_slice(&nonce);
        assert_eq!(sha(&input), v["hash"].as_str().unwrap());
    }
}

#[test]
fn verify_fingerprint() {
    for v in vectors(&load("fingerprint.json")) {
        let sig_pk = Ed25519PublicKey::from_bytes(&unh(&v["sig_pk"])).unwrap();
        let enc_pk = XWingPublicKey::from_bytes(&unh(&v["enc_pk"])).unwrap();
        assert_eq!(
            Ed25519SigningKey::from_seed(&arr(&v["sig_seed"])).public_key(),
            sig_pk
        );
        assert_eq!(
            XWingSecretKey::from_bytes(&arr(&v["enc_seed"])).public_key(),
            enc_pk
        );
        let fp = Fingerprint::compute(&sig_pk, &enc_pk);
        assert_eq!(fp.as_bytes(), &arr::<20>(&v["fingerprint"]));
        assert_eq!(fp.to_display(), v["display"].as_str().unwrap());
    }
}

#[test]
fn verify_signatures() {
    let j = load("signatures.json");
    for v in j["vectors"]["ed25519"].as_array().unwrap() {
        let key = Ed25519SigningKey::from_seed(&arr(&v["seed"]));
        let pk = Ed25519PublicKey::from_bytes(&unh(&v["public_key"])).unwrap();
        assert_eq!(key.public_key(), pk);
        let msg = unh(&v["message"]);
        let sig = Ed25519Signature::from_bytes(&unh(&v["signature"])).unwrap();
        assert_eq!(key.sign(&msg), sig);
        pk.verify(&msg, &sig).unwrap();
    }
    for v in j["vectors"]["p256"].as_array().unwrap() {
        let key = SoftwareDeviceKey::from_bytes(&arr(&v["private_key"])).unwrap();
        let pk = DevicePublicKey::from_bytes(&unh(&v["public_key"])).unwrap();
        assert_eq!(key.public_key(), pk);
        let msg = unh(&v["message"]);
        let sig = DeviceSignature::from_der(&unh(&v["signature"])).unwrap();
        assert_eq!(key.sign(&msg).unwrap(), sig);
        pk.verify(&msg, &sig).unwrap();
    }
}

#[test]
fn verify_hpke_box() {
    for v in vectors(&load(HPKE)) {
        let sk = XWingSecretKey::from_bytes(&arr(&v["secret_key"]));
        assert_eq!(sk.public_key().to_bytes(), unh(&v["public_key"]));
        let b = HpkeBox::from_bytes(&unh(&v["envelope"])).unwrap();
        let info = unh(&v["info"]);
        assert_eq!(&*b.open(&sk, &info).unwrap(), &unh(&v["plaintext"])[..]);
        assert_eq!(b.open(&sk, b"other info").err(), Some(Error::Decryption));
    }
}
