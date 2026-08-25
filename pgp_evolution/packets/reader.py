"""
OpenPGP packet reader supporting both old-format and new-format packet headers.

Old format (RFC 4880 section 4.2.1): bit 7 = 1, bit 6 = 0
New format (RFC 4880 section 4.2.2): bit 7 = 1, bit 6 = 1

RFC 9580 v6 uses new-format headers exclusively.
"""
from __future__ import annotations

import io
import struct
from dataclasses import dataclass

from pgp_evolution.packets.tags import PacketTag


@dataclass
class RawPacket:
    tag: PacketTag
    body: bytes


class PacketReader:
    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)

    def read_all(self) -> list[RawPacket]:
        packets: list[RawPacket] = []
        while True:
            pkt = self._read_one()
            if pkt is None:
                break
            packets.append(pkt)
        return packets

    def _read_one(self) -> RawPacket | None:
        header = self._buf.read(1)
        if not header:
            return None

        octet = header[0]
        if not (octet & 0x80):
            raise ValueError(f"Invalid packet header byte: 0x{octet:02x}")

        if octet & 0x40:
            # New format
            tag = PacketTag(octet & 0x3F)
            body = self._read_new_format_body()
        else:
            # Old format
            tag = PacketTag((octet & 0x3C) >> 2)
            length_type = octet & 0x03
            body = self._read_old_format_body(length_type)

        return RawPacket(tag=tag, body=body)

    def _read_new_format_body(self) -> bytes:
        first = self._buf.read(1)[0]
        if first < 192:
            length = first
        elif first < 224:
            second = self._buf.read(1)[0]
            length = ((first - 192) << 8) + second + 192
        elif first == 255:
            (length,) = struct.unpack(">I", self._buf.read(4))
        else:
            # Partial body length -- reassemble all chunks
            chunk_size = 1 << (first & 0x1F)
            parts = [self._buf.read(chunk_size)]
            while True:
                next_octet = self._buf.read(1)[0]
                if next_octet < 192:
                    parts.append(self._buf.read(next_octet))
                    break
                elif next_octet < 224:
                    second = self._buf.read(1)[0]
                    remaining = ((next_octet - 192) << 8) + second + 192
                    parts.append(self._buf.read(remaining))
                    break
                elif next_octet == 255:
                    (remaining,) = struct.unpack(">I", self._buf.read(4))
                    parts.append(self._buf.read(remaining))
                    break
                else:
                    chunk_size = 1 << (next_octet & 0x1F)
                    parts.append(self._buf.read(chunk_size))
            return b"".join(parts)
        return self._buf.read(length)

    def _read_old_format_body(self, length_type: int) -> bytes:
        if length_type == 0:
            (length,) = struct.unpack(">B", self._buf.read(1))
        elif length_type == 1:
            (length,) = struct.unpack(">H", self._buf.read(2))
        elif length_type == 2:
            (length,) = struct.unpack(">I", self._buf.read(4))
        else:
            # Indeterminate length: read until EOF
            return self._buf.read()
        return self._buf.read(length)
