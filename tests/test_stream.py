# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Synthetic camera transport tests, including fragmented compressed media delivery."""

import struct
from typing import TYPE_CHECKING, cast

import pytest

from mibo_py import MiboError, RawStream
from mibo_py._requests import request
from mibo_py._transport import Transport
from tests.helpers import ADTS, ANNEX_B, KEY, PeerSocket, bootstrap, record

if TYPE_CHECKING:
    import socket


def transport() -> tuple[Transport, PeerSocket]:
    sock = PeerSocket()
    return Transport(cast("socket.socket", sock), bootstrap(), "salt", 0), sock


def test_fragmented_encoded_stream_and_explicit_close() -> None:
    wire, sock = transport()
    with RawStream(wire, KEY) as stream:
        iterator = iter(stream)
        video, audio = next(iterator), next(iterator)
        assert video.codec == "h264"
        assert video.data == ANNEX_B
        assert audio.codec == "aac"
        assert audio.data == ADTS
    assert sock.closed
    assert stream.closed
    assert not any(stream._key)
    assert any(b"method=3 " in message for message in sock.sent)
    assert sock.sent[-1].endswith(b"DISC")
    stream.close()


def test_raw_dhav_and_single_consumer() -> None:
    wire, sock = transport()
    with RawStream(wire, KEY) as stream:
        iterator = stream.records()
        assert next(iterator) == record(protection=True, variant=0xFD)
        with pytest.raises(MiboError, match="single-consumer"):
            next(stream.records())
    assert sock.closed


def test_ptcp_reorder_duplicate_conflict_and_ack_bounds() -> None:
    wire, sock = transport()
    first = struct.pack("!BBHII", 0x10, 0, 3, wire.channel, 0) + b"HTT"
    second = struct.pack("!BBHII", 0x10, 0, 2, wire.channel, 0) + b"P/"
    wire._accept((20 + len(first), 24, 0, 0, second))
    wire._accept((20 + len(first), 24, 0, 0, second))
    assert wire.receive_next == 20
    with pytest.raises(MiboError, match="conflicting"):
        wire._accept((20 + len(first), 24, 0, 0, second[:-1] + b"x"))
    wire._accept((20, 24, 0, 0, first))
    assert wire.receive_next == 20 + len(first) + len(second)
    wire._accept((20, 24, 0, 0, first))
    with pytest.raises(MiboError, match="ack-window"):
        wire._accept((wire.receive_next, wire.send_next + 1, 0, 0, b""))
    wire.close()
    assert sock.closed


def test_ptcp_rejects_overlap_and_foreign_channel() -> None:
    wire, _sock = transport()
    with pytest.raises(MiboError, match="overlap"):
        wire._accept((19, 24, 0, 0, b"too long"))
    foreign = struct.pack("!BBHII", 0x10, 0, 1, wire.channel + 1, 0) + b"x"
    with pytest.raises(MiboError, match="proxy-frame"):
        wire._accept((20, 24, 0, 0, foreign))
    wire.close()


def test_keepalive_does_not_reuse_close_cseq() -> None:
    wire, sock = transport()
    wire._pending.clear()
    wire._keepalive()
    assert wire._pending == {2}
    wire._pending.clear()
    wire._keepalive()
    assert wire._pending == {4}
    with pytest.raises(MiboError, match="keepalive-timeout"):
        wire._keepalive()
    wire.close()
    assert sock.closed


def test_transport_retry_is_bounded() -> None:
    wire, _sock = transport()
    wire._queue(b"synthetic")
    for _ in range(4):
        wire._outgoing[0].last_sent = 0
        wire._flush()
    wire._outgoing[0].last_sent = 0
    with pytest.raises(MiboError, match="send-timeout"):
        wire._flush()
    wire.close()


def test_play_shape_preserves_vendor_wire_fields() -> None:
    source = bootstrap()
    wire = request(source, "salt", 1, 0, 1)
    header, body = wire.split(b"\r\n\r\n", 1)
    assert b"subtype=1&encrypt=3&audioType=1&trackID=31&method=0" in header
    assert b"Accpet-Sdp: Private" in header
    assert f"Private-Length: {len(body)}".encode() in header
    assert b"LightweightDigest=" in header
    assert b"trackID=31" not in request(source, "salt", 1, 2, 2)


def test_close_never_leaks_socket_error(monkeypatch: pytest.MonkeyPatch) -> None:
    wire, sock = transport()

    def failed_send(_self: PeerSocket, _wire: bytes) -> int:
        message = "private-peer-address"
        raise OSError(message)

    monkeypatch.setattr(PeerSocket, "send", failed_send)
    stream = RawStream(wire, KEY)
    stream.close()
    assert stream.closed
    assert sock.closed
    assert not any(stream._key)
