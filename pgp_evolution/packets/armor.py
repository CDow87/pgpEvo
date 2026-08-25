"""
ASCII armor encoding and decoding per RFC 4880 section 6 / RFC 9580 section 6.

Format:
    -----BEGIN PGP MESSAGE-----
    <base64 data>
    =<CRC24 checksum>
    -----END PGP MESSAGE-----

RFC 9580 makes the CRC24 checksum optional (and recommends omitting it).
We retain it for v4 compatibility and omit it in the v6 layer.
"""
from __future__ import annotations

import base64
import re
import struct

# CRC24 parameters from RFC 4880 section 6.1
_CRC24_INIT = 0xB704CE
_CRC24_POLY = 0x1864CFB


def crc24(data: bytes) -> int:
    crc = _CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= _CRC24_POLY
    return crc & 0xFFFFFF


def encode(data: bytes, header: str = "PGP MESSAGE", include_crc: bool = True) -> str:
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i : i + 76] for i in range(0, len(b64), 76)]
    parts = [f"-----BEGIN {header}-----", ""]
    parts.extend(lines)
    if include_crc:
        checksum = base64.b64encode(struct.pack(">I", crc24(data))[1:]).decode("ascii")
        parts.append(f"={checksum}")
    parts.append(f"-----END {header}-----")
    return "\n".join(parts)


def decode(armored: str) -> tuple[str, bytes]:
    """Returns (header_type, raw_bytes)."""
    lines = armored.strip().splitlines()

    begin = next((l for l in lines if l.startswith("-----BEGIN")), None)
    if begin is None:
        raise ValueError("No armor header found")
    header = re.search(r"BEGIN (.+)-----", begin)
    if header is None:
        raise ValueError("Malformed armor header")
    header_type = header.group(1)

    # Find the blank line separating headers from body
    try:
        blank = lines.index("", lines.index(begin))
    except ValueError:
        blank = lines.index(begin) + 1

    body_lines = []
    for line in lines[blank + 1 :]:
        if line.startswith("-----END") or line.startswith("="):
            break
        body_lines.append(line)

    raw = base64.b64decode("".join(body_lines))
    return header_type, raw
