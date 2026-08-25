from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pgp_evolution.classic.keys import ClassicPrivateKey
from pgp_evolution.packets.reader import PacketReader
from pgp_evolution.packets.tags import PacketTag
from pgp_evolution.packets.armor import decode as armor_decode


def decrypt(armored: str, key: ClassicPrivateKey) -> bytes:
    _, raw = armor_decode(armored)
    reader = PacketReader(raw)
    packets = reader.read_all()

    pkesk = next(p for p in packets if p.tag == PacketTag.PUBLIC_KEY_ENCRYPTED_SESSION_KEY)
    sed = next(p for p in packets if p.tag == PacketTag.SYMMETRICALLY_ENCRYPTED_DATA)

    # Parse PKESK body: 1 byte version, 8 bytes key_id, 1 byte algo, MPI
    mpi_bit_len = int.from_bytes(pkesk.body[10:12], "big")
    mpi_byte_len = (mpi_bit_len + 7) // 8
    encrypted_session_key = pkesk.body[12 : 12 + mpi_byte_len]

    session_key = key.raw.decrypt(
        encrypted_session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    iv = sed.body[:16]
    ciphertext = sed.body[16:]

    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
