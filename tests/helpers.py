# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Synthetic protocol peers and media; no vendor account, camera, or network access."""

import hashlib
import struct
from collections import deque
from typing import Self

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from mibo_py import Application, VideoParameters
from mibo_py._crypto import b64, md5_hex, ofb
from mibo_py._media import crc16
from mibo_py._signaling import Bootstrap
from mibo_py._transport import packet
from mibo_py._validation import Object

APPLICATION = Application(
    "synthetic-app", "synthetic-secret", '{"terminalId":"test","ttid":"test"}'
)
PARAMETERS = VideoParameters("project", "app", bytes(16), bytes(32), bytes(16))
KEY = bytes(range(32))
ANNEX_B = b"\x00\x00\x00\x01\x65synthetic"
ADTS = bytes.fromhex("fff16040011ffc00")


def wrap(clear: str) -> str:
    padder = PKCS7(128).padder()
    padded = padder.update(clear.encode()) + padder.finalize()
    cipher = Cipher(
        algorithms.AES(md5_hex(b"SYNTHETICDAHUAKEY").encode()), modes.CBC(bytes(16))
    ).encryptor()
    return b64(cipher.update(padded) + cipher.finalize())


def basic() -> Object:
    return {
        "deviceId": "synthetic",
        "p2pConfig": {
            "account": wrap("admin"),
            "password": wrap("secret"),
            "ak": "synthetic-ak",
            "p2pToken": "synthetic-p2p",
        },
        "channelList": [
            {
                "channelId": "1",
                "mediaConfig": '{"streamClarity":[{"name":"HD","streamChannel":0,"imageSize":-1}]}',
            }
        ],
    }


def configuration() -> Object:
    return {
        "serverConfig": {
            "services": [{"type": "p2p-v2", "port": 8800, "host": "p2p.easy4ipcloud.com"}]
        }
    }


def bootstrap() -> Bootstrap:
    return Bootstrap.read("synthetic", basic(), configuration(), PARAMETERS, 1)


def record(
    payload: bytes = ANNEX_B,
    *,
    variant: int = 0xFC,
    protection: bool = False,
    timestamp: int = 17,
    key: bytes = KEY,
) -> bytes:
    extension = b"\x83\x01\x1a\x04" if variant == 0xF0 else b""
    if protection:
        seed, iv = bytes(range(16)), bytes(reversed(range(16)))
        verifier = crc16(hashlib.sha256(b"\x01:" + seed + b":" + key).digest())
        extension += b"\xb5\x2c\x01" + bytes(3) + len(payload).to_bytes(3, "little")
        extension += seed + verifier.to_bytes(2, "little") + iv + b"\0"
        payload = ofb(payload, key, iv)
    size = 32 + len(extension) + len(payload)
    header = bytearray(24)
    header[:4], header[4] = b"DHAV", variant
    struct.pack_into("<I", header, 12, size)
    struct.pack_into("<H", header, 20, timestamp)
    header[22] = len(extension)
    header[23] = sum(header[:23]) & 255
    return bytes(header) + extension + payload + b"dhav" + struct.pack("<I", size)


def envelope(value: bytes) -> bytes:
    return b"$\0" + struct.pack("!I", len(value)) + value


class PeerSocket:
    """A deterministic UDP peer emulating PTCP control, CONN, PLAY and media."""

    def __init__(self, key: bytes = KEY) -> None:
        self.key = key
        self.incoming: deque[bytes] = deque()
        self.sent: list[bytes] = []
        self.closed = False
        self.channel = 0
        self.receive_next = 20

    def send(self, wire: bytes) -> int:
        self.sent.append(wire)
        sequence = int.from_bytes(wire[4:8], "big")
        payload = wire[24:]
        if wire[13] == 2:
            self.incoming.append(packet(0, 4, 2, 0, b"\x00\x03\x01\x00"))
        elif payload and payload[0] == 0x11:
            self.channel = int.from_bytes(payload[4:8], "big")
            self.incoming.append(
                packet(4, 24, 0, 0, b"\x12\0\0\0" + payload[4:8] + bytes(4) + b"CONN")
            )
        elif payload and payload[0] == 0x10:
            acknowledgement = sequence + len(payload)
            self.incoming.append(packet(self.receive_next, acknowledgement, 0, 0, b""))
            request = payload[12:]
            if request.startswith(b"PLAY ") and b"method=0 " in request:
                data = (
                    b"HTTP/1.1 200 OK\r\nCseq: 1\r\nPrivate-Length: 0\r\n\r\n"
                    + envelope(record(protection=True, variant=0xFD, key=self.key))
                    + envelope(record(ADTS, variant=0xF0, protection=True, key=self.key))
                )
                for offset in range(0, len(data), 53):
                    chunk = data[offset : offset + 53]
                    wrapped = struct.pack("!BBHII", 0x10, 0, len(chunk), self.channel, 0) + chunk
                    self.incoming.append(packet(self.receive_next, acknowledgement, 0, 0, wrapped))
                    self.receive_next += len(wrapped)
        return len(wire)

    def recv(self, _limit: int) -> bytes:
        if not self.incoming:
            raise TimeoutError
        return self.incoming.popleft()

    def close(self) -> None:
        self.closed = True

    def settimeout(self, _value: float) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
