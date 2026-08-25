"""CLI for the OpenPGP v6 layer (RFC 9580, Ed25519 + X25519 + AES-256-GCM/OCB)."""
from __future__ import annotations

import argparse
import json
import sys
from base64 import b64encode, b64decode

from pgp_evolution.openpgp_v6.keys import V6PrivateKey, V6PublicKey
from pgp_evolution.openpgp_v6 import encrypt, decrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenPGP v6 (RFC 9580, SEIPD v2 AEAD)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen")

    enc = sub.add_parser("encrypt")
    enc.add_argument("--key-json", required=True)
    enc.add_argument("--in", dest="infile", required=True)
    enc.add_argument("--out", required=True)

    dec = sub.add_parser("decrypt")
    dec.add_argument("--key-json", required=True)
    dec.add_argument("--in", dest="infile", required=True)

    args = parser.parse_args()

    if args.cmd == "keygen":
        priv = V6PrivateKey.generate()
        data = {
            "sign_priv": b64encode(priv.sign_priv.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()
            )).decode(),
            "enc_priv": b64encode(priv.enc_priv.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()
            )).decode(),
            "sign_pub": b64encode(priv.public.sign_pub_bytes).decode(),
            "enc_pub": b64encode(priv.public.enc_pub_bytes).decode(),
            "created_at": priv.public.created_at,
        }
        print(json.dumps(data, indent=2))

    elif args.cmd == "encrypt":
        data = json.loads(open(args.key_json).read())
        pub = V6PublicKey(
            sign_pub=Ed25519PublicKey.from_public_bytes(b64decode(data["sign_pub"])),
            enc_pub=X25519PublicKey.from_public_bytes(b64decode(data["enc_pub"])),
            created_at=data["created_at"],
        )
        plaintext = open(args.infile, "rb").read()
        open(args.out, "w").write(encrypt(plaintext, pub))
        print(f"Encrypted to {args.out}")

    elif args.cmd == "decrypt":
        data = json.loads(open(args.key_json).read())
        priv = V6PrivateKey(
            sign_priv=Ed25519PrivateKey.from_private_bytes(b64decode(data["sign_priv"])),
            enc_priv=X25519PrivateKey.from_private_bytes(b64decode(data["enc_priv"])),
            public=V6PublicKey(
                sign_pub=Ed25519PublicKey.from_public_bytes(b64decode(data["sign_pub"])),
                enc_pub=X25519PublicKey.from_public_bytes(b64decode(data["enc_pub"])),
                created_at=data["created_at"],
            ),
        )
        sys.stdout.buffer.write(decrypt(open(args.infile).read(), priv))
