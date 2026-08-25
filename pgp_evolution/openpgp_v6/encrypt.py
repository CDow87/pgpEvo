"""
OpenPGP v6 encryption per RFC 9580.

Uses SEIPD v2 (Symmetrically Encrypted Integrity Protected Data, version 2),
which mandates AEAD with chunk-based processing. Each chunk is independently
authenticated, allowing streaming decryption and early abort on corruption.

Chunk size: 2^22 bytes (4 MiB) by default, encoded as chunk_size_octet = 22.
AEAD mode: AES-256-OCB (algo ID 2 in RFC 9580 table 22).

The associated data for each chunk is:
  packet_header || aead_algo || chunk_size_octet || big_endian_chunk_index
"""
from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # OCB not in stdlib; GCM used
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pgp_evolution.openpgp_v6.keys import V6PublicKey
from pgp_evolution.packets.writer import PacketWriter
from pgp_evolution.packets.tags import PacketTag
from pgp_evolution.packets.armor import encode as armor_encode

_AES_KEY_LEN = 32
_CHUNK_SIZE_OCTET = 22  # 2^22 = 4 MiB chunks

# Note: Python's cryptography library does not expose AES-OCB directly.
# We use AES-256-GCM here as a structural equivalent. A production
# implementation would use AES-256-OCB via cffi bindings to OpenSSL EVP_OCB.


def encrypt(plaintext: bytes, recipient: V6PublicKey) -> str:
    session_key = os.urandom(_AES_KEY_LEN)

    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    shared_secret = ephemeral_priv.exchange(recipient.enc_pub)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_LEN,
        salt=None,
        info=b"OpenPGPv6_ECDH" + recipient.fingerprint(),
    ).derive(shared_secret)

    eph_pub_bytes = ephemeral_pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    # Encrypt session key
    wrap_nonce = os.urandom(12)
    encrypted_session_key = AESGCM(derived_key).encrypt(wrap_nonce, session_key, None)

    writer = PacketWriter()

    # PKESK v6 packet
    pkesk_body = struct.pack(">BB8sB", 6, 6, recipient.key_id(), 18)  # v6, v6-key, algo=ECDH
    pkesk_body += b"\x40" + eph_pub_bytes
    pkesk_body += wrap_nonce + encrypted_session_key
    writer.write_packet(PacketTag.PUBLIC_KEY_ENCRYPTED_SESSION_KEY, pkesk_body)

    # SEIPD v2 with chunk-based AEAD (GCM standing in for OCB)
    chunk_size = 1 << _CHUNK_SIZE_OCTET
    chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
    if not chunks:
        chunks = [b""]

    seipd_body = bytes([2, 9, 2, _CHUNK_SIZE_OCTET])  # version=2, sym=AES256, aead=GCM, chunk

    ad_prefix = bytes([0xC0 | int(PacketTag.SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA),
                       2, 9, 2, _CHUNK_SIZE_OCTET])

    base_iv = os.urandom(12)
    seipd_body += base_iv

    for idx, chunk in enumerate(chunks):
        chunk_iv = (int.from_bytes(base_iv, "big") ^ idx).to_bytes(12, "big")
        ad = ad_prefix + struct.pack(">Q", idx)
        seipd_body += AESGCM(session_key).encrypt(chunk_iv, chunk, ad)

    # Final authentication tag over empty plaintext with chunk_count as index
    final_iv = (int.from_bytes(base_iv, "big") ^ len(chunks)).to_bytes(12, "big")
    final_ad = ad_prefix + struct.pack(">Q", len(chunks))
    seipd_body += AESGCM(session_key).encrypt(final_iv, b"", final_ad)

    writer.write_packet(
        PacketTag.SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA, seipd_body
    )

    # RFC 9580: no CRC24 checksum in v6 armor
    return armor_encode(writer.getvalue(), header="PGP MESSAGE", include_crc=False)
