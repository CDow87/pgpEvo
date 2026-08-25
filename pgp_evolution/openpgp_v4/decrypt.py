from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pgp_evolution.openpgp_v4.keys import V4PrivateKey
from pgp_evolution.packets.reader import PacketReader
from pgp_evolution.packets.tags import PacketTag
from pgp_evolution.packets.armor import decode as armor_decode

_AES_KEY_LEN = 32


def decrypt(armored: str, key: V4PrivateKey) -> bytes:
    _, raw = armor_decode(armored)
    reader = PacketReader(raw)
    packets = reader.read_all()

    pkesk = next(p for p in packets if p.tag == PacketTag.PUBLIC_KEY_ENCRYPTED_SESSION_KEY)
    seipd = next(
        p
        for p in packets
        if p.tag == PacketTag.SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA
    )

    # Parse PKESK: version(1) + key_id(8) + algo(1) + 0x40_prefix(1) + eph_pub(32) + nonce(12) + enc_sk
    offset = 10  # skip version + key_id + algo
    assert pkesk.body[offset] == 0x40, "Expected native point prefix 0x40"
    eph_pub_bytes = pkesk.body[offset + 1 : offset + 33]
    nonce = pkesk.body[offset + 33 : offset + 45]
    encrypted_session_key = pkesk.body[offset + 45 :]

    ephemeral_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared_secret = key.enc_priv.exchange(ephemeral_pub)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_LEN,
        salt=None,
        info=b"OpenPGP_ECDH" + key.public.fingerprint(),
    ).derive(shared_secret)

    session_key = AESGCM(derived_key).decrypt(nonce, encrypted_session_key, None)

    # Parse SEIPD v1: version(1) + data_nonce(12) + ciphertext
    data_nonce = seipd.body[1:13]
    ciphertext = seipd.body[13:]
    seipd_plaintext = AESGCM(session_key).decrypt(data_nonce, ciphertext, None)

    # Strip trailing MDC: last 22 bytes are 0xd3 0x14 + SHA-1 digest
    return seipd_plaintext[:-22]
