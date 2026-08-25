import pytest
from pgp_evolution.age_like.keys import AgeIdentity, AgeRecipient
from pgp_evolution.age_like import encrypt, decrypt
from pgp_evolution.age_like.bech32 import bech32_encode, bech32_decode


def test_roundtrip():
    identity = AgeIdentity.generate()
    plaintext = b"age-compatible encryption"
    encrypted = encrypt(plaintext, [identity.recipient])
    assert decrypt(encrypted, identity) == plaintext


def test_multi_recipient():
    id1 = AgeIdentity.generate()
    id2 = AgeIdentity.generate()
    plaintext = b"multiple recipients"
    encrypted = encrypt(plaintext, [id1.recipient, id2.recipient])
    assert decrypt(encrypted, id1) == plaintext
    assert decrypt(encrypted, id2) == plaintext


def test_large_payload_chunking():
    identity = AgeIdentity.generate()
    # 3 full 64 KiB chunks + partial
    plaintext = b"a" * (65536 * 3 + 100)
    assert decrypt(encrypt(plaintext, [identity.recipient]), identity) == plaintext


def test_bech32_roundtrip():
    identity = AgeIdentity.generate()
    s = identity.to_string()
    assert s.startswith("AGE-SECRET-KEY-1")
    recovered = AgeIdentity.from_string(s)
    assert identity.recipient.pub_bytes == recovered.recipient.pub_bytes


def test_recipient_string_roundtrip():
    identity = AgeIdentity.generate()
    rec_str = identity.recipient.to_string()
    assert rec_str.startswith("age1")
    rec = AgeRecipient.from_string(rec_str)
    assert rec.pub_bytes == identity.recipient.pub_bytes


def test_wrong_identity_fails():
    id1 = AgeIdentity.generate()
    id2 = AgeIdentity.generate()
    encrypted = encrypt(b"secret", [id1.recipient])
    with pytest.raises(ValueError, match="No matching recipient"):
        decrypt(encrypted, id2)


def test_tampered_header_fails():
    identity = AgeIdentity.generate()
    encrypted = encrypt(b"secret", [identity.recipient])
    tampered = encrypted.replace(b"age-encryption.org/v1", b"age-encryption.org/v2")
    with pytest.raises(Exception):
        decrypt(tampered, identity)
