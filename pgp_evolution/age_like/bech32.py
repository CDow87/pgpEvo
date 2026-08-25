"""
Bech32 encoding and decoding per BIP-0173.
Used for age identity and recipient string serialization.
"""
from __future__ import annotations

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= _GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _verify_checksum(hrp: str, data: list[int]) -> bool:
    return _polymod(_hrp_expand(hrp) + data) == 1


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = ((acc << frombits) | value) & 0xFFFFFF
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding in bech32 conversion")
    return ret


def bech32_encode(hrp: str, data: bytes) -> str:
    enc = _convertbits(data, 8, 5)
    checksum = _create_checksum(hrp, enc)
    return hrp + "1" + "".join(_CHARSET[d] for d in enc + checksum)


def bech32_decode(bech: str) -> tuple[str, bytes]:
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        raise ValueError("Invalid character in bech32 string")
    if bech.lower() != bech and bech.upper() != bech:
        raise ValueError("Mixed case in bech32 string")
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        raise ValueError("Invalid separator position in bech32 string")
    hrp = bech[:pos]
    data = []
    for c in bech[pos + 1 :]:
        d = _CHARSET.find(c)
        if d < 0:
            raise ValueError(f"Invalid character '{c}' in bech32 data")
        data.append(d)
    if not _verify_checksum(hrp, data):
        raise ValueError("Invalid bech32 checksum")
    decoded = _convertbits(bytes(data[:-6]), 5, 8, False)
    return hrp, bytes(decoded)
