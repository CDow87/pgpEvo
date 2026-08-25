"""CLI for the post-quantum hybrid layer (X25519 + ML-KEM-768)."""
from __future__ import annotations

import argparse
import base64
import json
import sys

from cryptography.hazmat.primitives import serialization

from pgp_evolution.pq_hybrid.keys import PQIdentity, PQRecipient
from pgp_evolution.pq_hybrid import encrypt, decrypt


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Post-quantum hybrid encryption (X25519 + ML-KEM-768 + ChaCha20-Poly1305)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen")

    enc = sub.add_parser("encrypt")
    enc.add_argument("--key-json", required=True, help="Recipient public key JSON")
    enc.add_argument("--in", dest="infile", required=True)
    enc.add_argument("--out", required=True)

    dec = sub.add_parser("decrypt")
    dec.add_argument("--key-json", required=True, help="Identity (private key) JSON")
    dec.add_argument("--in", dest="infile", required=True)

    args = parser.parse_args()

    if args.cmd == "keygen":
        identity, recipient = PQIdentity.generate()
        priv_raw = identity.x25519_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        priv_data = {
            "x25519_priv": base64.b64encode(priv_raw).decode(),
            "mlkem_secret": base64.b64encode(identity.mlkem_secret).decode(),
        }
        pub_data = {
            "x25519_pub": base64.b64encode(recipient.x25519_pub).decode(),
            "mlkem_pub": base64.b64encode(recipient.mlkem_pub).decode(),
        }
        print("# Private key (keep secret):")
        print(json.dumps(priv_data, indent=2))
        print("# Public key (share with senders):")
        print(json.dumps(pub_data, indent=2))

    elif args.cmd == "encrypt":
        data = json.loads(open(args.key_json).read())
        recipient = PQRecipient(
            x25519_pub=base64.b64decode(data["x25519_pub"]),
            mlkem_pub=base64.b64decode(data["mlkem_pub"]),
        )
        plaintext = open(args.infile, "rb").read()
        open(args.out, "wb").write(encrypt(plaintext, [recipient]))
        print(f"Encrypted to {args.out}")

    elif args.cmd == "decrypt":
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        data = json.loads(open(args.key_json).read())
        identity = PQIdentity(
            x25519_priv=X25519PrivateKey.from_private_bytes(base64.b64decode(data["x25519_priv"])),
            mlkem_secret=base64.b64decode(data["mlkem_secret"]),
        )
        encrypted = open(args.infile, "rb").read()
        sys.stdout.buffer.write(decrypt(encrypted, identity))
