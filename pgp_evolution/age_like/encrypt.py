"""
age file format v1 encryption.

Header format (text):
    age-encryption.org/v1
    -> X25519 <base64(ephemeral_pub)>
    <base64(encrypted_file_key)>
    --- <base64(header_mac)>

Body: ChaCha20-Poly1305 encrypted payload split into 64 KiB chunks.
Each chunk has a 16-byte Poly1305 tag. The last chunk is distinguished by a
different nonce (final byte set to 1 instead of 0).

File key derivation:
    shared_secret = X25519(ephemeral_priv, recipient_pub)
    salt = ephemeral_pub || recipient_pub
    enc_key = HKDF-SHA256(shared_secret, salt, "age-encryption.org/v1/X25519")
    encrypted_file_key = ChaCha20-Poly1305(enc_key, nonce=0, file_key)

Body key derivation:
    body_key = HKDF-SHA256(file_key, nonce=random 16 bytes, "payload")
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC

from pgp_evolution.age_like.keys import AgeRecipient

_CHUNK_SIZE = 65536  # 64 KiB
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


def encrypt(plaintext: bytes, recipients: list[AgeRecipient]) -> bytes:
    file_key = os.urandom(16)

    stanzas: list[str] = []
    for recipient in recipients:
        ephemeral_priv = X25519PrivateKey.generate()
        ephemeral_pub = ephemeral_priv.public_key()
        eph_pub_bytes = ephemeral_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        rec_pub_bytes = recipient.pub_bytes

        shared_secret = ephemeral_priv.exchange(recipient.raw)
        salt = eph_pub_bytes + rec_pub_bytes
        enc_key = _hkdf(shared_secret, salt, _HKDF_INFO_WRAP)

        wrap_nonce = b"\x00" * 12
        encrypted_file_key = ChaCha20Poly1305(enc_key).encrypt(wrap_nonce, file_key, None)

        stanzas.append(
            f"-> X25519 {base64.b64encode(eph_pub_bytes).decode().rstrip('=')}\n"
            f"{base64.b64encode(encrypted_file_key).decode().rstrip('=')}"
        )

    header = "age-encryption.org/v1\n" + "\n".join(stanzas)

    # Header MAC authenticates the full header so recipients detect tampering
    mac_key = _hkdf(file_key, b"", _HKDF_INFO_HEADER)
    h = HMAC(mac_key, hashes.SHA256())
    h.update(header.encode())
    mac = base64.b64encode(h.finalize()).decode().rstrip("=")

    full_header = (header + f"\n--- {mac}\n").encode()

    # Encrypt body in chunks
    payload_nonce = os.urandom(16)
    body_key = _hkdf(file_key, payload_nonce, _HKDF_INFO_PAYLOAD)

    chunks = [plaintext[i : i + _CHUNK_SIZE] for i in range(0, len(plaintext), _CHUNK_SIZE)]
    if not chunks:
        chunks = [b""]

    encrypted_chunks = []
    for idx, chunk in enumerate(chunks):
        is_last = idx == len(chunks) - 1
        nonce = idx.to_bytes(11, "big") + bytes([1 if is_last else 0])
        encrypted_chunks.append(ChaCha20Poly1305(body_key).encrypt(nonce, chunk, None))

    return full_header + payload_nonce + b"".join(encrypted_chunks)
