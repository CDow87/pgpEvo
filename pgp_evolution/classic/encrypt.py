"""
Classic PGP encryption:
  1. Generate a random 128-bit session key.
  2. Encrypt the plaintext with AES-128-CFB (no integrity protection -- a known
     weakness of pre-SEIPD PGP that allowed ciphertext manipulation).
  3. Encrypt the session key with RSA-OAEP-SHA256.
  4. Pack both into OpenPGP packets and ASCII-armor the result.

The original used IDEA for symmetric encryption. IDEA is patent-encumbered and
not in the standard library. AES-128-CFB is used here as a period-appropriate
substitute that exhibits the same structural weaknesses (no AEAD, no MAC).
"""
from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pgp_evolution.classic.keys import ClassicPublicKey
from pgp_evolution.packets.writer import PacketWriter
from pgp_evolution.packets.tags import PacketTag
from pgp_evolution.packets.armor import encode as armor_encode


def encrypt(plaintext: bytes, recipient: ClassicPublicKey) -> str:
    session_key = os.urandom(16)  # 128-bit key for AES-128
    iv = os.urandom(16)

    # Encrypt session key with RSA-OAEP
    encrypted_session_key = recipient.raw.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Encrypt plaintext with AES-128-CFB (no integrity check -- intentional)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    writer = PacketWriter()

    # Public-Key Encrypted Session Key packet (tag 1), version 3
    fingerprint = recipient.fingerprint()
    key_id = fingerprint[-8:]  # low 64 bits of fingerprint as key ID
    pkesk_body = struct.pack(">B8sB", 3, key_id, 1)  # version, key_id, algo=RSA
    esk_len = len(encrypted_session_key)
    # MPI-encode the encrypted session key
    bit_len = esk_len * 8
    pkesk_body += struct.pack(">H", bit_len) + encrypted_session_key
    writer.write_packet(PacketTag.PUBLIC_KEY_ENCRYPTED_SESSION_KEY, pkesk_body)

    # Symmetrically Encrypted Data packet (tag 9) -- no integrity protection
    # Body: IV + ciphertext. The IV is prepended as the OpenPGP "resync" block.
    sed_body = iv + ciphertext
    writer.write_packet(PacketTag.SYMMETRICALLY_ENCRYPTED_DATA, sed_body)

    return armor_encode(writer.getvalue(), header="PGP MESSAGE", include_crc=True)
