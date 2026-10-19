# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Bounded mixed-stream framing and DHAV extraction, without any media decoder."""

import hashlib
import struct
from dataclasses import dataclass

from mibo_py._crypto import ofb
from mibo_py._validation import MAX_BODY, fail
from mibo_py.models import EncodedUnit


@dataclass(frozen=True, repr=False)
class Item:
    """A validated inner control response or complete DHAV record."""

    status: int = 0
    sequence: int = 0
    record: bytes = b""


def validate_record(record: bytes) -> None:
    """Check little-endian duplicate lengths, extension bounds and additive header checksum."""
    if not 32 <= len(record) <= MAX_BODY or record[:4] != b"DHAV" or record[-8:-4] != b"dhav":
        fail("dhav-frame")
    if struct.unpack_from("<I", record, 12)[0] != len(record) or int.from_bytes(
        record[-4:], "little"
    ) != len(record):
        fail("dhav-length")
    if 24 + record[22] > len(record) - 8 or sum(record[:23]) & 255 != record[23]:
        fail("dhav-header")


class Parser:
    """Reassemble fragments; no resynchronization or unbounded accumulation is allowed."""

    def __init__(self) -> None:
        """Create an empty stream parser."""
        self._buffer = bytearray()

    def append(self, data: bytes) -> None:
        """Bound the next append before accepting it."""
        if len(data) + len(self._buffer) > MAX_BODY + 16_384:
            fail("media-buffer")
        self._buffer.extend(data)

    def read(self, pending_keepalive: int | None = None) -> Item | None:
        """Read one six-byte $ envelope or strictly framed HTTP-like response."""
        if not self._buffer:
            return None
        if self._buffer[0] == 36:
            return self._read_record()
        return self._read_control(pending_keepalive)

    def _read_record(self) -> Item | None:
        if len(self._buffer) < 6:
            return None
        size = struct.unpack_from("!I", self._buffer, 2)[0]
        if not 32 <= size <= MAX_BODY:
            fail("media-record-size")
        if len(self._buffer) < 6 + size:
            return None
        record = bytes(self._buffer[6 : 6 + size])
        validate_record(record)
        self._consume(6 + size)
        return Item(record=record)

    def _read_control(self, pending_keepalive: int | None) -> Item | None:
        if len(self._buffer) < 5:
            return None
        if not self._buffer.startswith(b"HTTP/"):
            fail("media-prefix")
        marker = self._buffer.find(b"\r\n\r\n")
        if marker < 0:
            if len(self._buffer) > 16_384:
                fail("media-header-size")
            return None
        if marker > 16_384:
            fail("media-header-size")
        status, sequence, size = parse_header(bytes(self._buffer[:marker]), pending_keepalive)
        if len(self._buffer) < marker + 4 + size:
            return None
        self._consume(marker + 4 + size)
        return Item(status, sequence)

    def _consume(self, size: int) -> None:
        self._buffer[:size] = b"\0" * size
        del self._buffer[:size]

    def clear(self) -> None:
        """Erase the owned mutable reassembly buffer."""
        self._consume(len(self._buffer))


def parse_header(raw: bytes, pending_keepalive: int | None) -> tuple[int, int, int]:
    """Require CSeq and Private-Length; only a pending keepalive may omit its zero length."""
    if any((value < 32 and value not in (9, 10, 13)) or value > 126 for value in raw):
        fail("media-header-character")
    lines = raw.split(b"\r\n")
    first = lines[0].split(b" ", 2)
    if len(first) < 2 or first[0] not in (b"HTTP/1.0", b"HTTP/1.1"):
        fail("media-status")
    if len(first[1]) != 3 or not first[1].isdigit() or not 100 <= int(first[1]) <= 599:
        fail("media-status")
    status = int(first[1])
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not name or name[:1] in (b" ", b"\t") or name.lower() in headers:
            fail("media-header")
        headers[name.lower()] = value.strip()
    if b"content-length" in headers or b"transfer-encoding" in headers:
        fail("media-ambiguous-length")
    sequence = headers.get(b"cseq", b"")
    if not sequence.isdigit() or len(sequence) > 10 or not 1 <= int(sequence) <= 2_147_483_647:
        fail("media-cseq")
    length = headers.get(b"private-length")
    if (
        length is None
        and status == 200
        and int(sequence) == pending_keepalive
        and pending_keepalive not in (1, 3)
    ):
        length = b"0"
    if length is None or not length.isdigit() or len(length) > 5 or not 0 <= int(length) <= 65_536:
        fail("media-private-length")
    return status, int(sequence), int(length)


def crc16(raw: bytes) -> int:
    """Reduce the protocol's SHA-256 digest to its weak 16-bit wire verifier."""
    value = 0
    for octet in raw:
        value ^= octet
        for _ in range(8):
            value = (value >> 1) ^ (0xA001 if value & 1 else 0)
    return value


def extensions(record: bytes) -> tuple[int, int, int]:
    """Walk known extension tags; never search for B5 inside arbitrary payload bytes."""
    end, protection, audio = 24 + record[22], -1, -1
    cursor = 24
    while cursor < end:
        tag = record[cursor]
        if tag == 0xB5 and cursor + 1 < end:
            size = record[cursor + 1]
        else:
            size = {0x88: 8, 0x80: 4, 0x81: 4, 0x83: 4, 0x96: 4}.get(tag, 0)
        if not 1 <= size <= end - cursor:
            fail("dhav-extension")
        if tag == 0xB5:
            if protection >= 0:
                fail("dhav-protection-duplicate")
            protection = cursor
        if tag == 0x83:
            if audio >= 0:
                fail("dhav-audio-config-duplicate")
            audio = cursor
        cursor += size
    return end, protection, audio


def adts(unit: bytes) -> None:
    """Accept one AAC-LC, MPEG-4, 16 kHz mono, CRC-free ADTS frame."""
    if not 7 <= len(unit) <= 8191:
        fail("audio-adts")
    if unit[:2] != b"\xff\xf1" or unit[2] >> 6 != 1 or (unit[2] >> 2) & 15 != 8:
        fail("audio-adts")
    if unit[2] & 1 or unit[3] >> 6 != 1 or unit[6] & 3:
        fail("audio-adts")
    if ((unit[3] & 3) << 11 | unit[4] << 3 | unit[5] >> 5) != len(unit):
        fail("audio-adts-length")


def extract(record: bytes, key: bytes) -> EncodedUnit | None:
    """Extract H.264/AAC bytes; accept only the observed protection and codec variants."""
    validate_record(record)
    variant = record[4]
    if variant == 0xF1:
        return None
    if variant not in (0xFC, 0xFD, 0xF0) or len(key) != 32:
        fail("media-variant")
    end, protection, audio = extensions(record)
    if variant == 0xF0 and (audio < 0 or record[audio + 1 : audio + 4] != b"\x01\x1a\x04"):
        fail("audio-configuration")
    unit = record[end:-8]
    if variant == 0xFC:
        if protection >= 0:
            fail("clear-video-protection")
    else:
        unit = decrypt_unit(record, unit, protection, key)
    if variant == 0xF0:
        adts(unit)
    elif not unit.startswith((b"\x00\x00\x01", b"\x00\x00\x00\x01")):
        fail("video-annex-b")
    return EncodedUnit(
        "aac" if variant == 0xF0 else "h264", unit, int.from_bytes(record[20:22], "little"), variant
    )


def decrypt_unit(record: bytes, unit: bytes, offset: int, key: bytes) -> bytes:
    """Check B5 bounds and short verifier before decrypting its exact protected span."""
    if offset < 0 or record[offset + 1 : offset + 3] != b"\x2c\x01":
        fail("media-protection")
    prefix = int.from_bytes(record[offset + 3 : offset + 6], "little")
    size = int.from_bytes(record[offset + 6 : offset + 9], "little")
    if not 1 <= size <= len(unit) - prefix:
        fail("media-protected-span")
    seed = record[offset + 9 : offset + 25]
    digest = hashlib.sha256(b"\x01:" + seed + b":" + key).digest()
    if crc16(digest) != int.from_bytes(record[offset + 25 : offset + 27], "little"):
        fail("media-key-verifier")
    clear = ofb(unit[prefix : prefix + size], key, record[offset + 27 : offset + 43])
    return unit[:prefix] + clear + unit[prefix + size :]
