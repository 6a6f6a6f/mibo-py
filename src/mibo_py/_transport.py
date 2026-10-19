# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""PTCP byte-offset state machine, bounded retransmission and proxy media flow."""

import secrets
import socket
import struct
import time
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass

from mibo_py._media import Parser
from mibo_py._requests import request
from mibo_py._signaling import Bootstrap
from mibo_py._validation import MiboError, fail


@dataclass(repr=False)
class Outgoing:
    """One bounded wrapped request fragment retained until acknowledgement."""

    sequence: int
    data: bytes
    attempts: int = 0
    last_sent: float = 0


def packet(sequence: int, acknowledgement: int, flags: int, echo: int, payload: bytes) -> bytes:
    """Write PTCP's 24-byte big-endian header; clock is modulo unsigned 32 bits."""
    if not 0 <= sequence < 1 << 32 or not 0 <= acknowledgement < 1 << 32:
        fail("ptcp-offset-overflow")
    return (
        struct.pack(
            "!4sIIBBHII",
            b"PTCP",
            sequence,
            acknowledgement,
            0,
            flags,
            65535,
            int(time.monotonic() * 1000) & 0xFFFFFFFF,
            echo,
        )
        + payload
    )


def read_packet(raw: bytes) -> tuple[int, int, int, int, bytes] | None:
    """Parse structure only; byte windows and channel identity are checked separately."""
    if not 24 <= len(raw) < 4096 or raw[:4] != b"PTCP" or raw[12] != 0:
        return None
    return (
        int.from_bytes(raw[4:8], "big"),
        int.from_bytes(raw[8:12], "big"),
        raw[13],
        int.from_bytes(raw[16:20], "big"),
        raw[24:],
    )


class Transport:
    """One connected, confirmed camera peer with one matching proxy channel."""

    def __init__(self, sock: socket.socket, source: Bootstrap, salt: str, subtype: int) -> None:
        """Take socket ownership; open the proxy before sending any PLAY request."""
        self.sock, self.source, self.salt, self.subtype = sock, source, salt, subtype
        self.channel = secrets.randbelow((1 << 31) - 1) + 1
        self.send_next, self.receive_next, self.echo = 24, 20, 0
        self.closed = False
        self._received: dict[int, bytes] = {}
        self._outgoing: list[Outgoing] = []
        self._pending: set[int] = {1}
        self._completed: deque[int] = deque(maxlen=64)
        self._parser = Parser()
        self._next_sequence = 2
        self._handshake()

    def _send(self, sequence: int, acknowledgement: int, payload: bytes, flags: int = 0) -> None:
        self.sock.send(packet(sequence, acknowledgement, flags, self.echo, payload))

    def _receive(self) -> tuple[int, int, int, int, bytes] | None:
        try:
            raw = self.sock.recv(4096)
        except TimeoutError:
            return None
        if len(raw) == 4096:
            fail("ptcp-datagram-size")
        return read_packet(raw)

    def _handshake(self) -> None:
        control = b"\x00\x03\x01\x00"
        matched = False
        for _ in range(2):
            self._send(0, 0, control, 2)
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                incoming = self._receive()
                if incoming is None:
                    continue
                sequence, acknowledgement, flags, self.echo, payload = incoming
                if (sequence, acknowledgement, flags, payload) == (0, 4, 2, control):
                    self._send(4, 4, b"")
                    matched = True
                    break
            if matched:
                break
        if not matched:
            fail("ptcp-control-timeout")
        self._open_proxy()

    def _open_proxy(self) -> None:
        opened = bytearray(20)
        opened[0] = 0x11
        struct.pack_into("!I", opened, 4, self.channel)
        struct.pack_into("!H", opened, 14, 8086)
        opened[16:20] = b"\x7f\x00\x00\x01"
        self._send(4, 4, bytes(opened))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            incoming = self._receive()
            if incoming is None:
                continue
            sequence, acknowledgement, flags, self.echo, payload = incoming
            if acknowledgement > 24:
                fail("ptcp-proxy-ack")
            if (
                sequence == 4
                and flags == 0
                and len(payload) == 16
                and payload[0] == 0x12
                and int.from_bytes(payload[4:8], "big") == self.channel
                and payload[12:] == b"CONN"
            ):
                self._ack()
                return
        fail("ptcp-proxy-timeout")

    def _ack(self) -> None:
        self._send(self.send_next, self.receive_next, b"")

    def _queue(self, wire: bytes) -> None:
        if not 1 <= len(wire) <= 8192 or len(self._outgoing) > 8:
            fail("ptcp-outgoing-limit")
        for offset in range(0, len(wire), 1280):
            chunk = wire[offset : offset + 1280]
            wrapped = struct.pack("!BBHII", 0x10, 0, len(chunk), self.channel, 0) + chunk
            self._outgoing.append(Outgoing(self.send_next, wrapped))
            self.send_next += len(wrapped)
            if self.send_next >= 1 << 32:
                fail("ptcp-offset-overflow")

    def _flush(self) -> None:
        now = time.monotonic()
        for outgoing in self._outgoing:
            if outgoing.attempts and now - outgoing.last_sent < 0.4:
                continue
            if outgoing.attempts >= 4:
                fail("ptcp-send-timeout")
            self._send(outgoing.sequence, self.receive_next, outgoing.data)
            outgoing.last_sent = now
            outgoing.attempts += 1

    def _accept(self, incoming: tuple[int, int, int, int, bytes]) -> None:
        sequence, acknowledgement, flags, self.echo, payload = incoming
        if flags != 0:
            return
        if acknowledgement > self.send_next:
            fail("ptcp-ack-window")
        self._outgoing = [
            item for item in self._outgoing if item.sequence + len(item.data) > acknowledgement
        ]
        if sequence < self.receive_next:
            if sequence + len(payload) > self.receive_next:
                fail("ptcp-overlap")
            self._ack()
            return
        self._reorder(sequence, payload)
        self._ack()

    def _reorder(self, sequence: int, payload: bytes) -> None:
        if sequence - self.receive_next > 65535 or len(self._received) >= 64:
            fail("ptcp-receive-window")
        if payload:
            for previous, data in self._received.items():
                if previous == sequence and data == payload:
                    break
                if max(previous, sequence) < min(previous + len(data), sequence + len(payload)):
                    fail("ptcp-conflicting-retransmission")
            self._received[sequence] = payload
        while self.receive_next in self._received:
            ordered = self._received.pop(self.receive_next)
            self.receive_next += len(ordered)
            self._unwrap(ordered)

    def _unwrap(self, ordered: bytes) -> None:
        if (
            len(ordered) >= 12
            and ordered[0] == 0x10
            and int.from_bytes(ordered[4:8], "big") == self.channel
            and len(ordered) == 12 + int.from_bytes(ordered[2:4], "big")
        ):
            self._parser.append(ordered[12:])
        elif (
            len(ordered) == 16
            and ordered[0] == 0x12
            and int.from_bytes(ordered[4:8], "big") == self.channel
            and ordered[12:] == b"DISC"
        ):
            fail("ptcp-peer-closed")
        elif len(ordered) != 12 or ordered[0] != 0x13:
            fail("ptcp-proxy-frame")

    def records(self) -> Iterator[bytes]:
        """Yield validated DHAV records after PLAY succeeds, maintaining method-2 keepalives."""
        self._queue(request(self.source, self.salt, self.subtype, 0, 1))
        opened = False
        started = last_media = time.monotonic()
        keepalive = started + 20
        while not self.closed:
            now = time.monotonic()
            self._check_timeout(
                opened=opened, since_start=now - started, since_media=now - last_media
            )
            if opened and now >= keepalive:
                self._keepalive()
                keepalive = now + 20
            self._flush()
            incoming = self._receive()
            if incoming is not None:
                self._accept(incoming)
            pending = (
                next(iter(self._pending))
                if len(self._pending) == 1 and 1 not in self._pending
                else None
            )
            while (item := self._parser.read(pending)) is not None:
                if item.record:
                    if not opened:
                        fail("media-before-play")
                    last_media = time.monotonic()
                    yield item.record
                else:
                    if item.status != 200 or item.sequence not in self._pending | set(
                        self._completed
                    ):
                        fail("media-control-rejected")
                    self._pending.discard(item.sequence)
                    if item.sequence not in self._completed:
                        self._completed.append(item.sequence)
                    if item.sequence == 1:
                        opened = True

    @staticmethod
    def _check_timeout(*, opened: bool, since_start: float, since_media: float) -> None:
        if (not opened and since_start > 14) or (opened and since_media > 10):
            fail("media-timeout")

    def _keepalive(self) -> None:
        if self._pending:
            fail("media-keepalive-timeout")
        sequence = self._next_sequence
        self._next_sequence += 1
        if self._next_sequence == 3:
            self._next_sequence += 1
        self._pending.add(sequence)
        self._queue(request(self.source, self.salt, self.subtype, 2, sequence))

    def close(self) -> None:
        """Attempt method-3/DISC, then always close locally; remote receipt is unconfirmed."""
        if self.closed:
            return
        self.closed = True
        try:
            self._queue(request(self.source, self.salt, self.subtype, 3, 3))
            for item in self._outgoing:
                if not item.attempts:
                    self._send(item.sequence, self.receive_next, item.data)
            disc = struct.pack("!BBHII", 0x12, 0, 0, self.channel, 0) + b"DISC"
            self._send(self.send_next, self.receive_next, disc)
        except (OSError, MiboError):
            pass
        finally:
            self.sock.close()
            self._received.clear()
            self._outgoing.clear()
            self._parser.clear()
            self.source.password = self.source.token = ""
            self.salt = ""
