# age_like: a faithful implementation of the age file format v1.
# X25519 key agreement + ChaCha20-Poly1305 + HKDF-SHA256.
# Spec: https://age-encryption.org/v1
from pgp_evolution.age_like.keys import AgeIdentity, AgeRecipient
from pgp_evolution.age_like.encrypt import encrypt
from pgp_evolution.age_like.decrypt import decrypt

__all__ = ["AgeIdentity", "AgeRecipient", "encrypt", "decrypt"]
