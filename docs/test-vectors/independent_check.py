# /// script
# requires-python = ">=3.11"
# dependencies = ["pynacl>=1.5", "argon2-cffi>=23.1", "cryptography>=43"]
# ///
"""Recomputes the test vectors with libraries that share no code with the
Rust implementation: libsodium (PyNaCl), argon2-cffi, pyca/cryptography and
hashlib. CBOR and the encodings are written out by hand from PROTOCOL.md.

    uv run docs/test-vectors/independent_check.py

Not covered: X-Wing / HPKE (no independent Python implementation), so
`hpke-box.json` and the X-Wing `enc_pk` in `fingerprint.json` are taken as given.
"""

import hashlib
import hmac
import json
import sys
import unicodedata
from pathlib import Path

import argon2.low_level as argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nacl import bindings as sodium
from nacl.signing import SigningKey, VerifyKey

DIR = Path(__file__).resolve().parent
CHECK = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"
checked = 0


def load(name):
    return json.loads((DIR / name).read_text())


def b(x):
    return bytes.fromhex(x)


def ok(cond, what):
    global checked
    if not cond:
        sys.exit(f"FAIL: {what}")
    checked += 1


# Minimal deterministic CBOR for the shapes the vectors use.
def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")


def cbor(v):
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        e = v.encode()
        return head(3, len(e)) + e
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    raise TypeError(v)


def pattern(n):
    return bytes(i % 251 for i in range(n))


def secret_key():
    j = load("secret-key.json")["vectors"]
    for v in j["encode"]:
        n = int(v["bytes"], 16)
        data = "".join(CHECK[(n >> (5 * (25 - i))) & 31] for i in range(26)) + CHECK[n % 37]
        text = "S1-" + "-".join(data[i : i + 5] for i in range(0, 27, 5))
        ok(text == v["text"], f"secret key text {v['bytes']}")
    for v in j["parse"]:
        s = "".join(c for c in v["input"].upper() if c not in "- \t\r\n")
        s = s.replace("I", "1").replace("L", "1").replace("O", "0")
        result = "format"
        if len(s) == 29 and s[:2] == "S1" and all(c in CHECK[:32] for c in s[2:28]) and s[28] in CHECK:
            n = 0
            for c in s[2:28]:
                n = n * 32 + CHECK.index(c)
            if n < 1 << 128:
                result = n.to_bytes(16, "big").hex() if CHECK[n % 37] == s[28] else "checksum"
        ok(result == v.get("bytes", v.get("error")), f"secret key parse {v['input']!r}")


def hkdf_expand(prk, info, n=32):
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:n]


def kdf():
    for v in load("kdf.json")["vectors"]:
        pw = unicodedata.normalize("NFKC", v["password"]).encode()
        ok(pw == b(v["password_nfkc"]), "NFKC")
        s_pw = argon2.hash_secret_raw(pw, b(v["salt"]), v["t"], v["m"], v["p"], 32, argon2.Type.ID, 0x13)
        ok(s_pw == b(v["s_pw"]), "argon2id")
        master = hmac.new(b(v["salt"]), s_pw + b(v["secret_key"]), hashlib.sha256).digest()
        ok(master == b(v["master"]), "HKDF-Extract")
        seed = hkdf_expand(master, b"symbolon/v1/auth-key")
        ok(seed == b(v["auth_seed"]), "auth seed")
        ok(bytes(SigningKey(seed).verify_key) == b(v["auth_pk"]), "auth pk")
        ok(hkdf_expand(master, b"symbolon/v1/kek") == b(v["kek"]), "kek")


def xchacha_open(key, nonce, ct, aad):
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)


def aead_box():
    j = load("aead-box.json")
    for v in j["vectors"]:
        key, nonce, aad, pt = b(v["key"]), b(v["nonce"]), b(v["aad"]), b(v["plaintext"])
        ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, nonce, key)
        ok(ct == b(v["ciphertext"]), "AeadBox ciphertext")
        ok(cbor([1, 1, nonce, ct]) == b(v["envelope"]), "AeadBox envelope")
    good = j["vectors"][1]
    for v in j["invalid"]:
        env = b(v["envelope"])
        n, ct = env[5:29], env[29:]
        # A well-formed envelope is exactly cbor([1, 1, nonce(24), ct(>= 16)]).
        for size in (1, 2, 3, 5, 9):
            if cbor([1, 1, n, ct[size:]]) == env:
                ct = ct[size:]
                break
        else:
            ct = None
        if ct is None or len(ct) < 16:
            ok(v["error"] in ("malformed", "version", "algorithm"), f"AeadBox invalid: {v['why']}")
            continue
        try:
            xchacha_open(b(good["key"]), n, ct, b(v["aad"]))
            opened = True
        except Exception:
            opened = False
        ok(not opened and v["error"] == "decryption", f"AeadBox invalid: {v['why']}")


def padding():
    for v in load("padding.json")["vectors"]:
        n = v["content_len"]
        block = 256 if n + 1 <= 4096 else 4096
        size = -(-(n + 1) // block) * block
        padded = pattern(n) + b"\x80" + b"\0" * (size - n - 1)
        ok(len(padded) == v["padded_len"], f"padded length {n}")
        ok(hashlib.sha256(padded).hexdigest() == v["padded_sha256"], f"padding {n}")


def blob_encrypt(key, aad, prefix, pt):
    chunks = [pt[i : i + 65536] for i in range(0, len(pt), 65536)] or [b""]
    out = [b"\x01" + prefix]
    for i, c in enumerate(chunks):
        nonce = prefix + i.to_bytes(4, "big") + bytes([i == len(chunks) - 1])
        out.append(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(c, aad, nonce, key))
    return out


def blob():
    j = load("blob.json")
    for v in j["vectors"]:
        key, aad, prefix = b(v["file_key"]), b(v["aad"]), b(v["nonce_prefix"])
        ok(aad == cbor(["symbolon/v1/blob", aad[-33:-17], aad[-16:]]), "blob AAD shape")
        parts = blob_encrypt(key, aad, prefix, pattern(v["plaintext_len"]))
        whole = b"".join(parts)
        ok(len(whole) == v["blob_len"], "blob length")
        ok(hashlib.sha256(whole).hexdigest() == v["blob_sha256"], "blob")
        for c, cv in zip(parts[1:], v["chunks"], strict=True):
            ok(hashlib.sha256(c).hexdigest() == cv["sha256"], f"blob chunk {cv['index']}")
    good = j["vectors"][1]
    key, aad = b(good["file_key"]), b(good["aad"])
    for v in j["invalid"]:
        data = b(v["blob"])
        if len(data) < 21 + 15 or data[0] != 1:
            ok(v["error"] in ("truncated", "version"), f"blob invalid: {v['why']}")
            continue
        # Short blobs have one chunk; it must open as the last chunk 0.
        try:
            xchacha_open(key, data[1:20] + b"\0\0\0\0\x01", data[20:], aad)
            opened = True
        except Exception:
            opened = False
        ok(not opened and v["error"] == "decryption", f"blob invalid: {v['why']}")


def leading_zero_bits(h):
    n = int.from_bytes(h, "big")
    return 256 - n.bit_length()


def pow_():
    for v in load("pow.json")["vectors"]:
        ch, nonce, d = b(v["challenge"]), b(v["nonce"]), v["difficulty"]
        hsh = hashlib.sha256(b"symbolon/v1/pow" + ch + nonce).digest()
        ok(hsh.hex() == v["hash"], "pow hash")
        ok((leading_zero_bits(hsh) >= d) == v["valid"], "pow validity")
        if v["valid"]:
            pre = hashlib.sha256(b"symbolon/v1/pow" + ch)
            first = next(i for i in range(1 << 32) if leading_zero_bits(_h(pre, i)) >= d)
            ok(first == int.from_bytes(nonce, "big"), "pow nonce is the smallest counter")


def _h(pre, i):
    h = pre.copy()
    h.update(i.to_bytes(8, "big"))
    return h.digest()


def fingerprint():
    for v in load("fingerprint.json")["vectors"]:
        sig_pk = bytes(SigningKey(b(v["sig_seed"])).verify_key)
        ok(sig_pk == b(v["sig_pk"]), "fingerprint sig_pk")
        fp = hashlib.sha256(cbor(["symbolon/v1/fingerprint", sig_pk, b(v["enc_pk"])])).digest()[:20]
        ok(fp.hex() == v["fingerprint"], "fingerprint")
        n = int.from_bytes(fp, "big")
        sym = "".join(CHECK[(n >> (5 * (31 - i))) & 31] for i in range(32))
        ok(" ".join(sym[i : i + 4] for i in range(0, 32, 4)) == v["display"], "fingerprint display")


def signatures():
    j = load("signatures.json")["vectors"]
    for v in j["ed25519"]:
        sk = SigningKey(b(v["seed"]))
        ok(bytes(sk.verify_key) == b(v["public_key"]), "ed25519 pk")
        sig = sk.sign(b(v["message"])).signature
        ok(sig == b(v["signature"]), "ed25519 signature")
        VerifyKey(b(v["public_key"])).verify(b(v["message"]), sig)
    for v in j["p256"]:
        sk = ec.derive_private_key(int(v["private_key"], 16), ec.SECP256R1())
        pk = sk.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        ok(pk == b(v["public_key"]), "p256 compressed pk")
        msg, sig = b(v["message"]), b(v["signature"])
        sk.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        det = sk.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        ok(det == sig, "p256 RFC 6979 signature")


for f in (secret_key, kdf, aead_box, padding, blob, pow_, fingerprint, signatures):
    f()
    print(f"ok  {f.__name__.strip('_')}")
print(f"all {checked} checks passed")
