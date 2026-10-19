# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Complete synthetic signaling exchanges with explicit destination and peer policies."""

import re
import socket
from collections import deque
from typing import Self, cast

import pytest

from mibo_py import MiboError, RawStream
from mibo_py._crypto import b64, ofb
from mibo_py._signaling import Bootstrap, exchange, open_peer, probe, resolve, stun, xml_value
from mibo_py._validation import Object, encode_json
from tests.helpers import PARAMETERS, PeerSocket, basic, bootstrap, configuration

IDENTITY = bytes(range(8))


class SignalingSocket:
    def __init__(self, *, lan: bool = False) -> None:
        self.incoming: deque[bytes] = deque()
        self.destinations: list[tuple[str, int]] = []
        self.closed = False
        self.lan = lan
        self.current = ("8.8.8.8", 8800)

    def connect(self, destination: tuple[str, int]) -> None:
        self.current = destination
        self.destinations.append(destination)

    def getsockname(self) -> tuple[str, int]:
        return "192.168.1.4", 40000

    def getpeername(self) -> tuple[str, int]:
        return self.current

    def send(self, raw: bytes) -> int:
        if raw.startswith((b"NFPOST ", b"NFGET ")):
            self._nf(raw)
        else:
            clear = bytes(value ^ 255 for value in raw)
            if clear[:2] == b"\0\x01":
                self.incoming.append(stun(0x101, clear[8:20], IDENTITY, self.current, address=True))
        return len(raw)

    def _nf(self, raw: bytes) -> None:
        match = re.search(rb"\r\nCSeq: ([0-9]+)\r\n", raw)
        assert match is not None
        if raw.startswith(b"NFGET /online/"):
            body = b"<body><US>9.9.9.9:8803</US></body>"
        elif raw.startswith(b"NFGET /info/"):
            encrypted = ofb(
                encode_json({"randsalt": "synthetic-salt"}), PARAMETERS.info_key, PARAMETERS.info_iv
            )
            body = f"<body><Info>{b64(encrypted)}</Info></body>".encode()
        else:
            body = (
                "<body><PubAddr>9.9.9.9:50000</PubAddr><Identify>"
                + " ".join(f"{value:x}" for value in IDENTITY)
                + "</Identify><LocalAddr>192.168.1.2:50000</LocalAddr>"
                "<IpEncrpt>false</IpEncrpt></body>"
            ).encode()
        self.incoming.append(
            b"HTTP/1.1 200 OK\r\nCSeq: "
            + match[1]
            + f"\r\nContent-Length: {len(body)}\r\n\r\n".encode()
            + body
        )

    def recv(self, _limit: int) -> bytes:
        if not self.incoming:
            raise TimeoutError
        return self.incoming.popleft()

    def settimeout(self, _value: float) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@pytest.mark.parametrize("allow_lan", [False, True])
@pytest.mark.parametrize("alternate", [False, True])
def test_complete_signaling_does_not_follow_off_pool_info(
    monkeypatch: pytest.MonkeyPatch, *, allow_lan: bool, alternate: bool
) -> None:
    sockets: list[SignalingSocket] = []

    def factory(_family: int, _kind: int) -> SignalingSocket:
        result = SignalingSocket()
        sockets.append(result)
        return result

    monkeypatch.setattr(socket, "socket", factory)

    def dns(destination: str) -> tuple[str, ...]:
        if destination.startswith("alternate"):
            message = "synthetic DNS failure"
            raise OSError(message)
        return ("8.8.8.8",)

    monkeypatch.setattr("mibo_py._signaling.resolve", dns)
    source = bootstrap()
    if alternate:
        source.alternate = "alternate.easy4ipcloud.com"
    own, salt = open_peer(source, ("192.168.1.2",) if allow_lan else ())
    assert salt == "synthetic-salt"
    assert own is cast("socket.socket", sockets[1])
    assert sockets[0].closed
    assert ("9.9.9.9", 8803) not in sockets[0].destinations
    assert sockets[0].destinations[-1] == ("8.8.8.8", 8803)
    assert sockets[1].destinations[-1] == (
        ("192.168.1.2", 50000) if allow_lan else ("9.9.9.9", 50000)
    )
    own.close()
    assert sockets[1].closed


def test_candidate_probe_answers_peer_transaction() -> None:
    sock = SignalingSocket()
    transaction = bytes(range(12))
    sock.incoming.extend(
        [
            b"malformed",
            stun(1, transaction, IDENTITY, sock.current, address=True),
            stun(0x101, transaction, IDENTITY, sock.current, address=False),
        ]
    )
    assert probe(cast("socket.socket", sock), bytes(8), IDENTITY)


def test_signaling_limits_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = SignalingSocket()
    sock.incoming.extend([b"malformed"] * 64)
    with pytest.raises(MiboError, match="signaling-timeout"):
        exchange(cast("socket.socket", sock), b"ignored", 7)
    with pytest.raises(MiboError, match="request-size"):
        exchange(cast("socket.socket", sock), bytes(8193), 7)
    sock.incoming.extend([b"malformed"] * 32)
    assert not probe(cast("socket.socket", sock), bytes(8), IDENTITY)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args: [(2, 2, 17, "", ("8.8.8.8", 8800))])
    assert resolve("synthetic.easy4ipcloud.com") == ("8.8.8.8",)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args: [(2, 2, 17, "", ("127.0.0.1", 8800))])
    with pytest.raises(MiboError, match="signaling-dns"):
        resolve("synthetic.easy4ipcloud.com")


@pytest.mark.parametrize(
    "patch", [{"deviceId": "foreign"}, {"p2pConfig": {}}, {"deviceId": "path/injection"}]
)
def test_bootstrap_rejects_foreign_or_incomplete_values(patch: Object) -> None:
    with pytest.raises(MiboError):
        Bootstrap.read("synthetic", basic() | patch, configuration(), PARAMETERS, 1)


def test_raw_stream_open_owns_and_closes_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = PeerSocket()
    monkeypatch.setattr(
        "mibo_py.stream.open_peer", lambda _source, _allowed: (sock, "synthetic-salt")
    )
    with RawStream.open("synthetic", 0, basic(), configuration(), PARAMETERS, 1) as stream:
        assert not stream.closed
    assert sock.closed
    assert not any(stream._key)
    with pytest.raises(MiboError):
        stream.__enter__()
    with pytest.raises(MiboError, match="lan-allowlist"):
        RawStream.open("synthetic", 0, basic(), configuration(), PARAMETERS, 1, ("8.8.8.8",))


def test_xml_utf16_without_bom_is_rejected() -> None:
    source = '<!DOCTYPE x [<!ENTITY e "expanded">]><body><Info>&e;</Info></body>'
    with pytest.raises(MiboError):
        xml_value(source.encode("utf-16-le"), "Info")


def test_open_failure_closes_socket_and_sanitizes_error(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = PeerSocket()
    monkeypatch.setattr("mibo_py.stream.open_peer", lambda _source, _allowed: (sock, "salt"))

    def failed_send(_self: PeerSocket, _wire: bytes) -> int:
        message = "private-peer-address"
        raise OSError(message)

    monkeypatch.setattr(PeerSocket, "send", failed_send)
    with pytest.raises(MiboError, match="camera-transport") as error:
        RawStream.open("synthetic", 0, basic(), configuration(), PARAMETERS, 1)
    assert error.value.__suppress_context__
    assert sock.closed
