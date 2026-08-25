"""
CLI for the age-like layer. Designed to mirror the reference age tool's interface.

Usage:
    age-enc keygen
    age-enc encrypt -r age1... --in plaintext.txt --out msg.age
    age-enc decrypt -i identity.txt --in msg.age
"""
from __future__ import annotations

import argparse
import sys

from pgp_evolution.age_like.keys import AgeIdentity, AgeRecipient
from pgp_evolution.age_like import encrypt, decrypt


def main() -> None:
    parser = argparse.ArgumentParser(description="age-compatible encryption (X25519 + ChaCha20-Poly1305)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen")

    enc = sub.add_parser("encrypt")
    enc.add_argument("-r", "--recipient", required=True, help="Recipient public key (age1...)")
    enc.add_argument("--in", dest="infile", required=True)
    enc.add_argument("--out", required=True)

    dec = sub.add_parser("decrypt")
    dec.add_argument("-i", "--identity", required=True, help="Identity file (AGE-SECRET-KEY-1...)")
    dec.add_argument("--in", dest="infile", required=True)

    args = parser.parse_args()

    if args.cmd == "keygen":
        identity = AgeIdentity.generate()
        print(f"# created by pgp-evolution age-like layer")
        print(identity.to_string())
        print(f"# public key: {identity.recipient.to_string()}")

    elif args.cmd == "encrypt":
        recipient = AgeRecipient.from_string(args.recipient)
        plaintext = open(args.infile, "rb").read()
        encrypted = encrypt(plaintext, [recipient])
        open(args.out, "wb").write(encrypted)
        print(f"Encrypted to {args.out}")

    elif args.cmd == "decrypt":
        identity_str = open(args.identity).read().strip()
        for line in identity_str.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                identity = AgeIdentity.from_string(line)
                break
        else:
            print("No identity found in file", file=sys.stderr)
            sys.exit(1)
        encrypted = open(args.infile, "rb").read()
        sys.stdout.buffer.write(decrypt(encrypted, identity))
