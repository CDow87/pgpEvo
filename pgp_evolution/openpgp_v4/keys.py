"""
OpenPGP v4 key pair using Ed25519 (signing) and X25519 (encryption subkey).

The primary key signs and certifies. The encryption subkey is bound to it via
a self-signature. This matches the GPG --full-gen-key "ECC/EdDSA + ECC/ECDH"
choice, which is the default in GPG 2.3+.
"""
from __future__ import annotations

import hashlib
import os
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


class V4PublicKey:
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
        # v4 fingerprint: SHA-1 over the public key packet body.
        # Retained here for spec fidelity. The v6 layer replaces this with SHA3-256.
        body = struct.pack(">BIB", 4, self.created_at, 22)  # algo 22 = EdDSA
        body += b"\x09\x2b\x06\x01\x04\x01\xda\x47\x0f\x01"  # Ed25519 OID
        body += b"\x40" + self.sign_pub_bytes  # 0x40 prefix for EdDSA native point
        prefix = b"\x99" + struct.pack(">H", len(body))
        return hashlib.sha1(prefix + body).digest()

    def key_id(self) -> bytes:
        return self.fingerprint()[-8:]


class V4PrivateKey:
    def __init__(
        self,
        sign_priv: Ed25519PrivateKey,
        enc_priv: X25519PrivateKey,
        public: V4PublicKey,
    ) -> None:
        self.sign_priv = sign_priv
        self.enc_priv = enc_priv
        self.public = public

    @classmethod
    def generate(cls) -> "V4PrivateKey":
        sign_priv = Ed25519PrivateKey.generate()
        enc_priv = X25519PrivateKey.generate()
        pub = V4PublicKey(sign_priv.public_key(), enc_priv.public_key())
        return cls(sign_priv, enc_priv, pub)

    def sign(self, data: bytes) -> bytes:
        return self.sign_priv.sign(data)

    def verify(self, signature: bytes, data: bytes) -> None:
        self.public.sign_pub.verify(signature, data)
