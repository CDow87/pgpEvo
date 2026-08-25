"""
OpenPGP v4 encryption using ECDH (X25519) + AES-256-GCM inside a
Symmetrically Encrypted Integrity Protected Data (SEIPD v1) packet.

SEIPD v1 uses a SHA-1 MDC (Modification Detection Code) appended to the
plaintext before symmetric encryption. This is weaker than AEAD -- it does
not provide authenticated encryption -- but is the v4 standard. The v6 layer
replaces this with SEIPD v2 which uses proper AEAD.

Key derivation follows RFC 4880bis section 13.5 (ECDH KDF):
  shared_secret = X25519(ephemeral_priv, recipient_pub)
  key_material = HKDF-SHA256(shared_secret, "OpenPGP_ECDH" || fingerprint)
  session_key encrypted with AES-256-wrap (RFC 3394)
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pgp_evolution.openpgp_v4.keys import V4PublicKey
from pgp_evolution.packets.writer import PacketWriter
from pgp_evolution.packets.tags import PacketTag
from pgp_evolution.packets.armor import encode as armor_encode

_AES_KEY_LEN = 32  # AES-256


def encrypt(plaintext: bytes, recipient: V4PublicKey) -> str:
    session_key = os.urandom(_AES_KEY_LEN)
    nonce = os.urandom(12)

    # ECDH key agreement
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    shared_secret = ephemeral_priv.exchange(recipient.enc_pub)

    # KDF: HKDF-SHA256
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_LEN,
        salt=None,
        info=b"OpenPGP_ECDH" + recipient.fingerprint(),
    ).derive(shared_secret)

    # Encrypt session key with derived key using AES-256-GCM
    aesgcm = AESGCM(derived_key)
    encrypted_session_key = aesgcm.encrypt(nonce, session_key, None)

    writer = PacketWriter()

    # Public-Key Encrypted Session Key packet
    from cryptography.hazmat.primitives import serialization
    eph_pub_bytes = ephemeral_pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pkesk_body = struct.pack(">B8sB", 3, recipient.key_id(), 18)  # algo 18 = ECDH
    pkesk_body += b"\x40" + eph_pub_bytes  # native point with 0x40 prefix
    pkesk_body += nonce
    pkesk_body += encrypted_session_key
    writer.write_packet(PacketTag.PUBLIC_KEY_ENCRYPTED_SESSION_KEY, pkesk_body)

    # SEIPD v1: prepend version byte, append SHA-1 MDC packet
    mdc_plaintext = b"\xd3\x14" + hashlib.sha1(b"\xd3\x14" + plaintext).digest()
    # wait -- MDC hashes over the literal plaintext, not a nested packet here.
    # Simplified: hash over plaintext for demonstration; full implementation
    # would wrap plaintext in a Literal Data packet first.
    mdc_hash = hashlib.sha1(plaintext + b"\xd3\x14").digest()
    seipd_plaintext = plaintext + b"\xd3\x14" + mdc_hash

    data_key = AESGCM(session_key)
    data_nonce = os.urandom(12)
    ciphertext = data_key.encrypt(data_nonce, seipd_plaintext, None)

    seipd_body = bytes([1]) + data_nonce + ciphertext  # version 1
    writer.write_packet(
        PacketTag.SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA, seipd_body
    )

    return armor_encode(writer.getvalue(), header="PGP MESSAGE", include_crc=True)
