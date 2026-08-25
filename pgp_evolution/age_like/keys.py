"""
age identity (private key) and recipient (public key).

age uses Bech32 encoding for keys:
  - Identity: "AGE-SECRET-KEY-1" prefix
  - Recipient: "age1" prefix

We use raw bytes internally and provide Bech32 encode/decode for
interoperability with the reference age tool.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from pgp_evolution.age_like.bech32 import bech32_encode, bech32_decode


class AgeRecipient:
    def __init__(self, pub: X25519PublicKey) -> None:
        self._pub = pub

    @property
    def raw(self) -> X25519PublicKey:
        return self._pub

    @property
    def pub_bytes(self) -> bytes:
        return self._pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def to_string(self) -> str:
        return bech32_encode("age", self.pub_bytes)

    @classmethod
    def from_string(cls, s: str) -> "AgeRecipient":
        hrp, data = bech32_decode(s)
        if hrp != "age":
            raise ValueError(f"Expected hrp 'age', got '{hrp}'")
        pub = X25519PublicKey.from_public_bytes(data)
        return cls(pub)


class AgeIdentity:
    def __init__(self, priv: X25519PrivateKey) -> None:
        self._priv = priv

    @property
    def raw(self) -> X25519PrivateKey:
        return self._priv

    @property
    def recipient(self) -> AgeRecipient:
        return AgeRecipient(self._priv.public_key())

    def to_string(self) -> str:
        raw = self._priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return bech32_encode("AGE-SECRET-KEY-", raw).upper()

    @classmethod
    def from_string(cls, s: str) -> "AgeIdentity":
        hrp, data = bech32_decode(s.lower())
        if hrp != "age-secret-key-":
            raise ValueError(f"Expected age identity string, got hrp '{hrp}'")
        priv = X25519PrivateKey.from_private_bytes(data)
        return cls(priv)

    @classmethod
    def generate(cls) -> "AgeIdentity":
        return cls(X25519PrivateKey.generate())
