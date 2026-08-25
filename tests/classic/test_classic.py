import pytest
from pgp_evolution.classic.keys import ClassicPublicKey
from pgp_evolution.classic import encrypt, decrypt


def test_roundtrip():
    pub, priv = ClassicPublicKey.generate()
    plaintext = b"Hello from 1991"
    armored = encrypt(plaintext, pub)
    assert decrypt(armored, priv) == plaintext


def test_armor_header():
    pub, _ = ClassicPublicKey.generate()
    armored = encrypt(b"test", pub)
    assert armored.startswith("-----BEGIN PGP MESSAGE-----")
    assert "-----END PGP MESSAGE-----" in armored


def test_fingerprint_length():
    pub, _ = ClassicPublicKey.generate()
    assert len(pub.fingerprint()) == 20  # SHA-1 = 20 bytes


def test_wrong_key_fails():
    pub1, _ = ClassicPublicKey.generate()
    _, priv2 = ClassicPublicKey.generate()
    armored = encrypt(b"secret", pub1)
    with pytest.raises(Exception):
        decrypt(armored, priv2)
