"""
OpenPGP v6 key pair per RFC 9580.

Changes from v4:
- Version byte is 6 in all packets
- Fingerprint is SHA3-256 of the key packet body (32 bytes, not 20)
- Key IDs are the first 8 bytes of the fingerprint (not the last 8)
- Ed448 and X448 are available alongside Ed25519/X25519
- We use Ed25519 + X25519 here for implementation simplicity
"""
from __future__ import annotations

import hashlib
import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


class V6PublicKey:
    def __init__(
        self,
        sign_pub: Ed25519PublicKey,
        enc_pub: X25519PublicKey,
        created_at: int | None = None,
    ) -> None:
        self.sign_pub = sign_pub
        self.enc_pub = enc_pub
        self.created_at = created_at or int(time.time())

    @property
    def sign_pub_bytes(self) -> bytes:
        return self.sign_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def enc_pub_bytes(self) -> bytes:
        return self.enc_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def fingerprint(self) -> bytes:
        # RFC 9580 section 5.5.4: SHA3-256 of (0x9B || 4-byte-len || packet-body)
        body = struct.pack(">BIB", 6, self.created_at, 22)  # algo 22 = EdDSA
        body += b"\x09\x2b\x06\x01\x04\x01\xda\x47\x0f\x01"  # Ed25519 OID
        body += b"\x40" + self.sign_pub_bytes
        prefix = b"\x9b" + struct.pack(">I", len(body))
        h = hashlib.sha3_256()
        h.update(prefix + body)
        return h.digest()

    def key_id(self) -> bytes:
        # v6: first 8 bytes of fingerprint (v4 used last 8)
        return self.fingerprint()[:8]


class V6PrivateKey:
    def __init__(
        self,
        sign_priv: Ed25519PrivateKey,
        enc_priv: X25519PrivateKey,
        public: V6PublicKey,
    ) -> None:
        self.sign_priv = sign_priv
        self.enc_priv = enc_priv
        self.public = public

    @classmethod
    def generate(cls) -> "V6PrivateKey":
        sign_priv = Ed25519PrivateKey.generate()
        enc_priv = X25519PrivateKey.generate()
        pub = V6PublicKey(sign_priv.public_key(), enc_priv.public_key())
        return cls(sign_priv, enc_priv, pub)

    def sign(self, data: bytes) -> bytes:
        return self.sign_priv.sign(data)
