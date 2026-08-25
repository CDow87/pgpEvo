from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidSignature

from pgp_evolution.age_like.keys import AgeIdentity

_CHUNK_SIZE = 65536
_CHUNK_WITH_TAG = _CHUNK_SIZE + 16
_HKDF_INFO_WRAP = b"age-encryption.org/v1/X25519"
_HKDF_INFO_PAYLOAD = b"payload"
_HKDF_INFO_HEADER = b"header"


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def _pad_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decrypt(data: bytes, identity: AgeIdentity) -> bytes:
    # Split header from body at the "---" line
    header_end = data.find(b"\n--- ")
    if header_end < 0:
        raise ValueError("No age header terminator found")

    header_bytes = data[:header_end]
    rest = data[header_end + 1 :]
    mac_line, body = rest.split(b"\n", 1)
    mac_b64 = mac_line[4:].decode().strip()  # strip "--- "

    header_str = header_bytes.decode()
    lines = header_str.splitlines()
    if lines[0] != "age-encryption.org/v1":
        raise ValueError("Not an age v1 file")

    # Find the stanza for this identity
    id_priv = identity.raw
    id_pub_bytes = identity.recipient.pub_bytes

    file_key: bytes | None = None
    i = 1
    while i < len(lines):
        line = lines[i]
        if not line.startswith("-> X25519 "):
            i += 1
            continue
        eph_pub_b64 = line[len("-> X25519 "):]
        eph_pub_bytes = base64.b64decode(_pad_b64(eph_pub_b64))
        encrypted_file_key_b64 = lines[i + 1] if i + 1 < len(lines) else ""
        encrypted_file_key = base64.b64decode(_pad_b64(encrypted_file_key_b64))

        ephemeral_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        shared_secret = id_priv.exchange(ephemeral_pub)
        salt = eph_pub_bytes + id_pub_bytes
        enc_key = _hkdf(shared_secret, salt, _HKDF_INFO_WRAP)

        try:
            file_key = ChaCha20Poly1305(enc_key).decrypt(b"\x00" * 12, encrypted_file_key, None)
            break
        except Exception:
            i += 2
            continue

    if file_key is None:
        raise ValueError("No matching recipient stanza found for this identity")

    # Verify header MAC
    mac_key = _hkdf(file_key, b"", _HKDF_INFO_HEADER)
    h = HMAC(mac_key, hashes.SHA256())
    h.update(header_bytes)
    try:
        h.verify(base64.b64decode(_pad_b64(mac_b64)))
    except InvalidSignature:
        raise ValueError("Header MAC verification failed -- file may be tampered")

    # Decrypt body
    payload_nonce = body[:16]
    encrypted_body = body[16:]
    body_key = _hkdf(file_key, payload_nonce, _HKDF_INFO_PAYLOAD)

    plaintext_parts = []
    idx = 0
    offset = 0
    while offset < len(encrypted_body):
        chunk = encrypted_body[offset : offset + _CHUNK_WITH_TAG]
        is_last = (offset + _CHUNK_WITH_TAG) >= len(encrypted_body)
        nonce = idx.to_bytes(11, "big") + bytes([1 if is_last else 0])
        plaintext_parts.append(ChaCha20Poly1305(body_key).decrypt(nonce, chunk, None))
        offset += _CHUNK_WITH_TAG
        idx += 1

    return b"".join(plaintext_parts)
