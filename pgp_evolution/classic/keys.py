"""
RSA-2048 key generation and serialization for the classic PGP layer.

The original PGP used PKCS#1 v1.5 padding for RSA. We use OAEP here because
PKCS#1 v1.5 is vulnerable to adaptive chosen-ciphertext attacks (Bleichenbacher
1998). Even so, this layer exists to show the RSA paradigm, not as a
recommendation.

Key packet format follows RFC 4880 section 5.5, version 4.
"""
from __future__ import annotations

import struct
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives import serialization


class ClassicPublicKey:
    def __init__(self, key: RSAPublicKey, created_at: int | None = None) -> None:
        self._key = key
        self.created_at = created_at or int(time.time())

    @classmethod
    def generate(cls) -> tuple["ClassicPublicKey", "ClassicPrivateKey"]:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = cls(private.public_key())
        priv = ClassicPrivateKey(private, pub)
        return pub, priv

    @property
    def raw(self) -> RSAPublicKey:
        return self._key

    def to_pem(self) -> bytes:
        return self._key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @classmethod
    def from_pem(cls, pem: bytes) -> "ClassicPublicKey":
        key = serialization.load_pem_public_key(pem)
        assert isinstance(key, RSAPublicKey)
        return cls(key)

    def fingerprint(self) -> bytes:
        # v4 fingerprint: SHA-1 of the public key packet body.
        # SHA-1 is broken for general collision resistance but is retained here
        # to match the v4 spec. The v6 layer uses SHA3-256.
        import hashlib
        from pgp_evolution.classic.packet_body import public_key_body_v4
        body = public_key_body_v4(self)
        return hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()


class ClassicPrivateKey:
    def __init__(self, key: RSAPrivateKey, public: ClassicPublicKey) -> None:
        self._key = key
        self.public = public

    @property
    def raw(self) -> RSAPrivateKey:
        return self._key

    def to_pem(self, password: bytes | None = None) -> bytes:
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )

    @classmethod
    def from_pem(cls, pem: bytes, password: bytes | None = None) -> "ClassicPrivateKey":
        key = serialization.load_pem_private_key(pem, password=password)
        assert isinstance(key, RSAPrivateKey)
        pub = ClassicPublicKey(key.public_key())
        return cls(key, pub)
