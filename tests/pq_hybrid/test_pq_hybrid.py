import pytest

try:
    import oqs
    _OQS_AVAILABLE = True
except ImportError:
    _OQS_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _OQS_AVAILABLE,
    reason="pyoqs / liboqs not installed -- skipping post-quantum tests"
)

from pgp_evolution.pq_hybrid.keys import PQIdentity
from pgp_evolution.pq_hybrid import encrypt, decrypt


def test_roundtrip():
    identity, recipient = PQIdentity.generate()
    plaintext = b"post-quantum hybrid round trip"
    encrypted = encrypt(plaintext, [recipient])
    assert decrypt(encrypted, identity) == plaintext


def test_large_payload():
    identity, recipient = PQIdentity.generate()
    plaintext = b"q" * (65536 * 2 + 500)
    assert decrypt(encrypt(plaintext, [recipient]), identity) == plaintext


def test_wrong_identity_fails():
    identity1, recipient1 = PQIdentity.generate()
    identity2, _ = PQIdentity.generate()
    encrypted = encrypt(b"secret", [recipient1])
    with pytest.raises(ValueError, match="No matching recipient"):
        decrypt(encrypted, identity2)


def test_header_format():
    identity, recipient = PQIdentity.generate()
    encrypted = encrypt(b"test", [recipient])
    header_part = encrypted[:encrypted.find(b"\n--- ")].decode()
    assert "-> X25519+MLKEM768" in header_part
    assert header_part.startswith("pq-age-encryption/v1")
