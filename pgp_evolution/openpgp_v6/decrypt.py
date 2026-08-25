from __future__ import annotations

import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pgp_evolution.openpgp_v6.keys import V6PrivateKey
from pgp_evolution.packets.reader import PacketReader
from pgp_evolution.packets.tags import PacketTag
from pgp_evolution.packets.armor import decode as armor_decode

_AES_KEY_LEN = 32
_GCM_TAG_LEN = 16


def decrypt(armored: str, key: V6PrivateKey) -> bytes:
    _, raw = armor_decode(armored)
    reader = PacketReader(raw)
    packets = reader.read_all()

    pkesk = next(p for p in packets if p.tag == PacketTag.PUBLIC_KEY_ENCRYPTED_SESSION_KEY)
    seipd = next(
        p for p in packets
        if p.tag == PacketTag.SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA
    )

    # PKESK v6: version(1) + key_version(1) + key_id(8) + algo(1) + 0x40(1) + eph_pub(32) + nonce(12) + enc_sk
    offset = 11  # skip version + key_version + key_id + algo
    assert pkesk.body[offset] == 0x40
    eph_pub_bytes = pkesk.body[offset + 1 : offset + 33]
    wrap_nonce = pkesk.body[offset + 33 : offset + 45]
    encrypted_session_key = pkesk.body[offset + 45 :]

    ephemeral_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared_secret = key.enc_priv.exchange(ephemeral_pub)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_LEN,
        salt=None,
        info=b"OpenPGPv6_ECDH" + key.public.fingerprint(),
    ).derive(shared_secret)

    session_key = AESGCM(derived_key).decrypt(wrap_nonce, encrypted_session_key, None)

    # SEIPD v2: version(1) + sym_algo(1) + aead_algo(1) + chunk_size(1) + base_iv(12) + chunks
    chunk_size_octet = seipd.body[3]
    chunk_size = 1 << chunk_size_octet
    base_iv = seipd.body[4:16]
    encrypted_body = seipd.body[16:]

    ad_prefix = bytes([
        0xC0 | int(PacketTag.SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA),
        2, 9, 2, chunk_size_octet
    ])

    chunk_ct_size = chunk_size + _GCM_TAG_LEN
    plaintext_parts = []
    idx = 0
    offset = 0

    while offset < len(encrypted_body):
        remaining = len(encrypted_body) - offset
        if remaining <= _GCM_TAG_LEN:
            # Final auth tag chunk
            chunk_iv = (int.from_bytes(base_iv, "big") ^ idx).to_bytes(12, "big")
            final_ad = ad_prefix + struct.pack(">Q", idx)
            AESGCM(session_key).decrypt(chunk_iv, encrypted_body[offset:], final_ad)
            break
        ct_len = min(chunk_ct_size, remaining)
        chunk_iv = (int.from_bytes(base_iv, "big") ^ idx).to_bytes(12, "big")
        ad = ad_prefix + struct.pack(">Q", idx)
        plaintext_parts.append(
            AESGCM(session_key).decrypt(chunk_iv, encrypted_body[offset : offset + ct_len], ad)
        )
        offset += ct_len
        idx += 1

    return b"".join(plaintext_parts)
