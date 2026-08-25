import pytest
from pgp_evolution.openpgp_v4.keys import V4PrivateKey
from pgp_evolution.openpgp_v4 import encrypt, decrypt


def test_roundtrip():
    priv = V4PrivateKey.generate()
    plaintext = b"OpenPGP v4 round trip"
    armored = encrypt(plaintext, priv.public)
    assert decrypt(armored, priv) == plaintext


def test_fingerprint_length():
    priv = V4PrivateKey.generate()
    assert len(priv.public.fingerprint()) == 20


def test_key_id_is_last_8_bytes_of_fingerprint():
    priv = V4PrivateKey.generate()
    assert priv.public.key_id() == priv.public.fingerprint()[-8:]


def test_wrong_key_fails():
    priv1 = V4PrivateKey.generate()
    priv2 = V4PrivateKey.generate()
    armored = encrypt(b"secret", priv1.public)
    with pytest.raises(Exception):
        decrypt(armored, priv2)


def test_sign_verify():
    priv = V4PrivateKey.generate()
    message = b"sign me"
    sig = priv.sign(message)
    priv.verify(sig, message)  # should not raise
