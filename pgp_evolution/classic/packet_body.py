"""
Helpers for serializing RSA key material into OpenPGP v4 packet bodies.
MPI (Multi-Precision Integer) encoding is defined in RFC 4880 section 3.2.
"""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pgp_evolution.classic.keys import ClassicPublicKey


def encode_mpi(n: int) -> bytes:
    bit_length = n.bit_length()
    byte_length = (bit_length + 7) // 8
    return struct.pack(">H", bit_length) + n.to_bytes(byte_length, "big")


def public_key_body_v4(key: "ClassicPublicKey") -> bytes:
    pub_numbers = key.raw.public_key().public_numbers() if hasattr(key.raw, "private_numbers") else key.raw.public_numbers()  # type: ignore[union-attr]
    body = struct.pack(">BIB", 4, key.created_at, 1)  # version=4, created, algo=RSA
    body += encode_mpi(pub_numbers.n)
    body += encode_mpi(pub_numbers.e)
    return body
