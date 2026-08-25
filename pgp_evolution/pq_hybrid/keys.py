"""
Post-quantum hybrid key pair: X25519 (classical) + ML-KEM-768 (FIPS 203).

The hybrid design means an attacker must break BOTH algorithms to recover
the file key. If ML-KEM turns out to have a flaw, X25519 still provides
classical 128-bit security. If a quantum computer breaks X25519, ML-KEM-768
provides 192-bit post-quantum security.

This mirrors the X25519Kyber768 construction deployed by Cloudflare and Chrome
in TLS 1.3 (2023-2024).

ML-KEM operations:
    KeyGen() -> (pk, sk)
    Encaps(pk) -> (ciphertext, shared_secret)
    Decaps(sk, ciphertext) -> shared_secret
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

try:
    import oqs  # pyoqs
    _OQS_AVAILABLE = True
except ImportError:
    _OQS_AVAILABLE = False

_KEM_ALG = "Kyber768"  # ML-KEM-768 (FIPS 203)


def _require_oqs() -> None:
    if not _OQS_AVAILABLE:
        raise ImportError(
            "pyoqs is required for the pq_hybrid layer. "
            "Install it with: pip install pyoqs\n"
            "liboqs must also be installed on your system."
        )


@dataclass
class PQRecipient:
    x25519_pub: bytes       # 32 bytes
    mlkem_pub: bytes        # 1184 bytes for ML-KEM-768

    def to_bytes(self) -> bytes:
        return self.x25519_pub + self.mlkem_pub

    @classmethod
    def from_bytes(cls, data: bytes) -> "PQRecipient":
        return cls(x25519_pub=data[:32], mlkem_pub=data[32:])


@dataclass
class PQIdentity:
    x25519_priv: X25519PrivateKey
    mlkem_secret: bytes     # ML-KEM secret key (2400 bytes for ML-KEM-768)

    @property
    def recipient(self) -> PQRecipient:
        x25519_pub = self.x25519_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        _require_oqs()
        import oqs
        with oqs.KeyEncapsulation(_KEM_ALG) as kem:
            mlkem_pub = kem.export_secret_key()  # not right -- see generate()
        # The public key is stored separately; see generate()
        raise NotImplementedError("Use PQIdentity.generate() which stores both keys")

    @classmethod
    def generate(cls) -> tuple["PQIdentity", "PQRecipient"]:
        _require_oqs()
        import oqs

        x25519_priv = X25519PrivateKey.generate()
        x25519_pub_bytes = x25519_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

        with oqs.KeyEncapsulation(_KEM_ALG) as kem:
            mlkem_pub_bytes = kem.generate_keypair()
            mlkem_secret_bytes = kem.export_secret_key()

        identity = cls(x25519_priv=x25519_priv, mlkem_secret=mlkem_secret_bytes)
        recipient = PQRecipient(x25519_pub=x25519_pub_bytes, mlkem_pub=mlkem_pub_bytes)
        return identity, recipient
