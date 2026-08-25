"""
CLI for the classic PGP layer.

Usage:
    pgp-classic keygen --out keyname
    pgp-classic encrypt --pub keyname.pub.pem --in plaintext.txt --out msg.asc
    pgp-classic decrypt --priv keyname.priv.pem --in msg.asc
"""
from __future__ import annotations

import argparse
import sys

from pgp_evolution.classic.keys import ClassicPublicKey, ClassicPrivateKey
from pgp_evolution.classic import encrypt, decrypt


def main() -> None:
    parser = argparse.ArgumentParser(description="Classic PGP (RSA-2048 + AES-128-CFB)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    kg = sub.add_parser("keygen")
    kg.add_argument("--out", required=True, help="Base name for output key files")

    enc = sub.add_parser("encrypt")
    enc.add_argument("--pub", required=True)
    enc.add_argument("--in", dest="infile", required=True)
    enc.add_argument("--out", required=True)

    dec = sub.add_parser("decrypt")
    dec.add_argument("--priv", required=True)
    dec.add_argument("--in", dest="infile", required=True)

    args = parser.parse_args()

    if args.cmd == "keygen":
        pub, priv = ClassicPublicKey.generate()
        with open(f"{args.out}.pub.pem", "wb") as f:
            f.write(pub.to_pem())
        with open(f"{args.out}.priv.pem", "wb") as f:
            f.write(priv.to_pem())
        print(f"Keys written to {args.out}.pub.pem and {args.out}.priv.pem")

    elif args.cmd == "encrypt":
        pub = ClassicPublicKey.from_pem(open(args.pub, "rb").read())
        plaintext = open(args.infile, "rb").read()
        armored = encrypt(plaintext, pub)
        with open(args.out, "w") as f:
            f.write(armored)
        print(f"Encrypted to {args.out}")

    elif args.cmd == "decrypt":
        priv = ClassicPrivateKey.from_pem(open(args.priv, "rb").read())
        armored = open(args.infile).read()
        plaintext = decrypt(armored, priv)
        sys.stdout.buffer.write(plaintext)
