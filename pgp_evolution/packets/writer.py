"""
OpenPGP packet writer. Always emits new-format packet headers (RFC 4880 s4.2.2).
This is required by RFC 9580 and is also valid for v4 implementations.
"""
from __future__ import annotations

import struct

from pgp_evolution.packets.tags import PacketTag


class PacketWriter:
    def __init__(self) -> None:
        self._parts: list[bytes] = []

    def write_packet(self, tag: PacketTag, body: bytes) -> None:
        header = bytes([0xC0 | int(tag)])
        header += _encode_new_format_length(len(body))
        self._parts.append(header + body)

    def getvalue(self) -> bytes:
        return b"".join(self._parts)


def _encode_new_format_length(n: int) -> bytes:
    if n < 192:
        return bytes([n])
    elif n < 8384:
        n -= 192
        return bytes([((n >> 8) + 192), (n & 0xFF)])
    else:
        return b"\xff" + struct.pack(">I", n)
