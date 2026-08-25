# classic: RSA-2048 + SHA-1 + AES-128-CFB, demonstrating the 1991-era PGP design.
# This layer intentionally uses the original algorithm choices to show their
# weaknesses. Do not use this for anything real.
from pgp_evolution.classic.keys import ClassicPublicKey, ClassicPrivateKey
from pgp_evolution.classic.encrypt import encrypt
from pgp_evolution.classic.decrypt import decrypt

__all__ = ["ClassicPublicKey", "ClassicPrivateKey", "encrypt", "decrypt"]
