import pytest
from pgp_evolution.openpgp_v6.keys import V6PrivateKey
from pgp_evolution.openpgp_v6 import encrypt, decrypt


def test_roundtrip():
    priv = V6PrivateKey.generate()
    plaintext = b"OpenPGP v6 RFC 9580 round trip"
    armored = encrypt(plaintext, priv.public)
    assert decrypt(armored, priv) == plaintext


def test_large_payload():
    priv = V6PrivateKey.generate()
    plaintext = b"x" * (1024 * 1024)  # 1 MiB
    assert decrypt(encrypt(plaintext, priv.public), priv) == plaintext


def test_fingerprint_is_sha3_256():
    priv = V6PrivateKey.generate()
    assert len(priv.public.fingerprint()) == 32  # SHA3-256 = 32 bytes


def test_key_id_is_first_8_bytes_of_fingerprint():
    priv = V6PrivateKey.generate()
    assert priv.public.key_id() == priv.public.fingerprint()[:8]


def test_no_crc_in_armor():
    priv = V6PrivateKey.generate()
    armored = encrypt(b"test", priv.public)
    # RFC 9580: no CRC24 checksum line
    assert "\n=" not in armored


def test_wrong_key_fails():
    priv1 = V6PrivateKey.generate()
    priv2 = V6PrivateKey.generate()
    armored = encrypt(b"secret", priv1.public)
    with pytest.raises(Exception):
        decrypt(armored, priv2)
