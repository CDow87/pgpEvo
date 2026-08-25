"""
Hybrid post-quantum encryption extending the age file format.

Stanza type: "-> X25519+MLKEM768 <base64(eph_x25519_pub)> <base64(mlkem_ct)>"
  followed by <base64(encrypted_file_key)>

Combined shared secret:
    ss_classical = X25519(ephemeral_priv, recipient_x25519_pub)
    ss_pq = ML-KEM-768 Encaps(recipient_mlkem_pub) -> (ciphertext, shared_secret)
    combined = HKDF-SHA256(ss_classical || ss_pq,
                           salt = eph_x25519_pub || recipient_x25519_pub || mlkem_ciphertext,
                           info = "pq-age/v1/X25519+MLKEM768")

The classical and PQ secrets are concatenated as HKDF input keying material so
that both must be broken for the combined secret to be recovered.

Body encryption is identical to the age-like layer: ChaCha20-Poly1305 + chunking.
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC

from pgp_evolution.pq_hybrid.keys import PQRecipient, _KEM_ALG, _require_oqs

_CHUNK_SIZE = 65536
_HKDF_INFO_WRAP = b"pq-age/v1/X25519+MLKEM768"
_HKDF_INFO_PAYLOAD = b"payload"
_HKDF_INFO_HEADER = b"header"


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def encrypt(plaintext: bytes, recipients: list[PQRecipient]) -> bytes:
    _require_oqs()
    import oqs

    file_key = os.urandom(16)
    stanzas: list[str] = []

    for recipient in recipients:
        # Classical half
        eph_x25519_priv = X25519PrivateKey.generate()
        eph_x25519_pub_bytes = eph_x25519_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        ss_classical = eph_x25519_priv.exchange(
            __import__("cryptography.hazmat.primitives.asymmetric.x25519",
                       fromlist=["X25519PublicKey"]).X25519PublicKey.from_public_bytes(
                recipient.x25519_pub
            )
        )

        # PQ half
        with oqs.KeyEncapsulation(_KEM_ALG) as kem:
            mlkem_ciphertext, ss_pq = kem.encap_secret(recipient.mlkem_pub)

        salt = eph_x25519_pub_bytes + recipient.x25519_pub + mlkem_ciphertext
        enc_key = _hkdf(ss_classical + ss_pq, salt, _HKDF_INFO_WRAP)

        wrap_nonce = b"\x00" * 12
        encrypted_file_key = ChaCha20Poly1305(enc_key).encrypt(wrap_nonce, file_key, None)

        eph_b64 = base64.b64encode(eph_x25519_pub_bytes).decode().rstrip("=")
        ct_b64 = base64.b64encode(mlkem_ciphertext).decode().rstrip("=")
        ek_b64 = base64.b64encode(encrypted_file_key).decode().rstrip("=")
        stanzas.append(f"-> X25519+MLKEM768 {eph_b64} {ct_b64}\n{ek_b64}")

    header = "pq-age-encryption/v1\n" + "\n".join(stanzas)

    mac_key = _hkdf(file_key, b"", _HKDF_INFO_HEADER)
    h = HMAC(mac_key, hashes.SHA256())
    h.update(header.encode())
    mac = base64.b64encode(h.finalize()).decode().rstrip("=")

    full_header = (header + f"\n--- {mac}\n").encode()

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
