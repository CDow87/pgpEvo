"""CLI for the OpenPGP v4 layer (Ed25519 + X25519 + AES-256-GCM)."""
from __future__ import annotations

import argparse
import json
import sys
from base64 import b64encode, b64decode

from pgp_evolution.openpgp_v4.keys import V4PrivateKey
from pgp_evolution.openpgp_v4 import encrypt, decrypt
from cryptography.hazmat.primitives import serialization


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenPGP v4 (Ed25519 + X25519 + AES-256-GCM)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen")

    enc = sub.add_parser("encrypt")
    enc.add_argument("--key-json", required=True, help="Recipient public key JSON")
    enc.add_argument("--in", dest="infile", required=True)
    enc.add_argument("--out", required=True)

    dec = sub.add_parser("decrypt")
    dec.add_argument("--key-json", required=True, help="Private key JSON")
    dec.add_argument("--in", dest="infile", required=True)

    args = parser.parse_args()

    if args.cmd == "keygen":
        priv = V4PrivateKey.generate()
        raw_enc = priv.enc_priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        raw_sign = priv.sign_priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        data = {
            "sign_priv": b64encode(raw_sign).decode(),
            "enc_priv": b64encode(raw_enc).decode(),
            "sign_pub": b64encode(priv.public.sign_pub_bytes).decode(),
            "enc_pub": b64encode(priv.public.enc_pub_bytes).decode(),
            "created_at": priv.public.created_at,
        }
        print(json.dumps(data, indent=2))

    elif args.cmd == "encrypt":
        from pgp_evolution.openpgp_v4.keys import V4PublicKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        data = json.loads(open(args.key_json).read())
        pub = V4PublicKey(
            sign_pub=Ed25519PublicKey.from_public_bytes(b64decode(data["sign_pub"])),
            enc_pub=X25519PublicKey.from_public_bytes(b64decode(data["enc_pub"])),
            created_at=data["created_at"],
        )
        plaintext = open(args.infile, "rb").read()
        armored = encrypt(plaintext, pub)
        open(args.out, "w").write(armored)
        print(f"Encrypted to {args.out}")

    elif args.cmd == "decrypt":
        from pgp_evolution.openpgp_v4.keys import V4PublicKey, V4PrivateKey
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

        data = json.loads(open(args.key_json).read())
        sign_priv = Ed25519PrivateKey.from_private_bytes(b64decode(data["sign_priv"]))
        enc_priv = X25519PrivateKey.from_private_bytes(b64decode(data["enc_priv"]))
        pub = V4PublicKey(
            sign_pub=Ed25519PublicKey.from_public_bytes(b64decode(data["sign_pub"])),
            enc_pub=X25519PublicKey.from_public_bytes(b64decode(data["enc_pub"])),
            created_at=data["created_at"],
        )
        priv = V4PrivateKey(sign_priv, enc_priv, pub)
        armored = open(args.infile).read()
        plaintext = decrypt(armored, priv)
        sys.stdout.buffer.write(plaintext)
