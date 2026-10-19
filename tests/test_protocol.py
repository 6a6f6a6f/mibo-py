# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Golden protocol vectors and hostile-input rejection."""

import gzip
import hashlib
import json
import struct
from pathlib import Path

import pytest

from mibo_py import MiboError
from mibo_py._crypto import media_key, ofb, sign, unbase64, unwrap
from mibo_py._http import inflate
from mibo_py._media import Parser, adts, extract, parse_header, validate_record
from mibo_py._signaling import (
    endpoint,
    info_address,
    local_candidates,
    public,
    read_stun,
    response,
    stun,
    xml_value,
)
from mibo_py._transport import packet, read_packet
from mibo_py._validation import (
    MAX_BODY,
    flag,
    host,
    identifier,
    integer,
    obj,
    parse_json,
    rows,
    text,
)
from tests.helpers import ADTS, ANNEX_B, KEY, PARAMETERS, envelope, record, wrap


def test_account_golden_vectors() -> None:
    fixture = parse_json(
        Path(__file__).with_name("fixtures").joinpath("account-signing.json").read_bytes()
    )
    for value in rows(fixture["vectors"]):
        vector = obj(value)
        headers = {key: text(val, 65_536) for key, val in obj(vector["signedFields"]).items()}
        headers["Content-Type"] = text(vector["contentType"])
        if vector["session"] is not None:
            session = vector["session"]
            assert isinstance(session, str)
            headers["x-pcs-session-id"] = session
        signature = sign(
            text(vector["path"]),
            text(vector["bodyUtf8"]).encode(),
            headers,
            text(vector["syntheticCredentialText"]),
            password=vector["role"] == "fresh_password",
        )
        assert signature == vector["signatureBase64"]
        assert headers["Content-MD5"] == vector["contentMd5Base64"]


def test_crypto_vectors() -> None:
    assert unwrap(wrap("synthetic-password"), "synthetic", bytes(16)) == "synthetic-password"
    expected = hashlib.pbkdf2_hmac(
        "sha256",
        hashlib.md5(b"admin:Login to device:secret", usedforsecurity=False)
        .hexdigest()
        .upper()
        .encode(),
        b"device",
        20_000,
        32,
    )
    assert media_key("admin", "device", "secret") == expected
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    # NIST SP 800-38A AES-256 OFB first block.
    clear = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    assert ofb(clear, key, bytes.fromhex("000102030405060708090a0b0c0d0e0f")) == bytes.fromhex(
        "dc7e84bfda79164b7ecd8486985d3860"
    )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"[]",
        b"\xff",
        b"{",
        b'{"a":' + b"[" * 25 + b"]" * 25 + b"}",
    ],
)
def test_reject_bad_json(raw: bytes) -> None:
    with pytest.raises(MiboError):
        parse_json(raw)


def test_json_depth_ignores_escaped_string() -> None:
    source = {"a": '\\"' + "[" * 100}
    assert parse_json(json.dumps(source)) == source
    with pytest.raises(MiboError, match="json-size"):
        parse_json(b" " * (MAX_BODY + 1))


@pytest.mark.parametrize(
    "value",
    [
        "https://evil.invalid/",
        "http://app-br.easy4ipcloud.com/",
        "https://app-br.easy4ipcloud.com@evil.invalid/",
        "https://app-br.easy4ipcloud.com/x",
        "https://app-br.easy4ipcloud.com/?q=1",
        "https://app-br.easy4ipcloud.com/#x",
        "https://app-br.easy4ipcloud.com:444/",
    ],
)
def test_reject_unapproved_account_origin(value: str) -> None:
    with pytest.raises(MiboError):
        host(value)


@pytest.mark.parametrize("value", ["a/b", "a\r\nb", "a?x=y", "", "é", "a" * 257])
def test_device_path_rejection(value: str) -> None:
    with pytest.raises(MiboError):
        identifier(value)


def test_scalar_schema_rejection() -> None:
    invalid: tuple[object, ...] = (None, [], {}, True, 1.0, "1")
    for value in invalid:
        with pytest.raises(MiboError):
            integer(value)
    for value in (1, "false", None):
        with pytest.raises(MiboError):
            flag(value)
    with pytest.raises(MiboError):
        rows([0] * 129)
    with pytest.raises(MiboError):
        obj({1: "foreign"})
    with pytest.raises(MiboError):
        text("secret\0suffix")


def test_gzip_limits() -> None:
    assert inflate(gzip.compress(b"{}")) == b"{}"
    for raw in (
        b"invalid",
        gzip.compress(b"{}")[:-1],
        gzip.compress(b"x" * (MAX_BODY + 1)),
        gzip.compress(b"{}") * 2,
    ):
        with pytest.raises(MiboError):
            inflate(raw)


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "192.168.1.2",
        "100.64.0.1",
        "198.18.0.1",
        "192.0.2.1",
        "224.0.0.1",
        "0.0.0.0",  # noqa: S104 -- Rejected address fixture; no socket is bound.
        "255.255.255.255",
    ],
)
def test_nonpublic_destinations(value: str) -> None:
    assert not public(value)


def test_info_destination_policy() -> None:
    pool = ("8.8.8.8", "1.1.1.1")
    assert info_address("1.1.1.1:8803", pool) == ("1.1.1.1", 8803)
    assert info_address("9.9.9.9:8803", pool) == ("8.8.8.8", 8803)
    for value in ("127.0.0.1:8803", "8.8.8.8:80", "8.8.8.08:8803", "host:8803", "8.8.8.8:0"):
        with pytest.raises(MiboError):
            info_address(value, pool)
    assert endpoint("192.168.1.2:8800") == ("192.168.1.2", 8800)


def test_nf_response_binding() -> None:
    raw = b"HTTP/1.1 200 OK\r\nCSeq: 7\r\nContent-Length: 4\r\n\r\nbody"
    assert response(raw, 7) == (200, b"body")
    assert response(raw, 8) is None
    for invalid in (
        raw + b"x",
        raw.replace(b"CSeq: 7", b"CSeq: 7\r\ncseq: 7"),
        raw.replace(b"Content-Length: 4", b"Content-Length: 3"),
        raw.replace(b"200", b"999"),
        raw.replace(b"CSeq", b" CSeq"),
    ):
        assert response(invalid, 7) is None


def test_xml_declarations_and_duplicates() -> None:
    assert xml_value(b"<body><Info>synthetic</Info></body>", "Info") == "synthetic"
    assert xml_value(b"<body/>", "LocalAddr", optional=True) == ""
    for raw in (
        b'<!DOCTYPE x [<!ENTITY x "expand">]><body><Info>&x;</Info></body>',
        b"<body><Info>a</Info><Info>b</Info></body>",
        b"<body><Info><nested/></Info></body>",
        "<body/>".encode("utf-16"),
        b"<",
    ):
        with pytest.raises(MiboError):
            xml_value(raw, "Info")


def test_lan_requires_caller_and_server_agreement() -> None:
    raw = (
        b"<body><LocalAddr>192.168.1.2,192.168.1.3:8800</LocalAddr>"
        b"<IpEncrpt>false</IpEncrpt></body>"
    )
    assert local_candidates(raw, (), "192.168.1.4") == ()
    assert local_candidates(raw, ("192.168.1.2",), "192.168.1.4") == (("192.168.1.2", 8800),)
    assert local_candidates(raw, ("192.168.1.2",), "192.168.1.2") == ()
    assert local_candidates(raw.replace(b"false", b"true"), ("192.168.1.2",), "192.168.1.4") == ()


def test_stun_identity_and_shape() -> None:
    transaction, identity = bytes(range(12)), bytes(range(8))
    for kind in (1, 0x101):
        for address in (False, True):
            raw = stun(kind, transaction, identity, ("192.168.1.2", 8800), address=address)
            assert read_stun(raw, identity) == (kind, transaction, address)
            assert read_stun(raw, bytes(8)) is None
            assert read_stun(raw[:-1], identity) is None
            bad = bytearray(raw)
            bad[4] ^= 1
            assert read_stun(bytes(bad), identity) is None


def test_ptcp_envelope() -> None:
    wire = packet(24, 20, 0, 7, b"payload")
    parsed = read_packet(wire)
    assert parsed is not None
    assert parsed[:3] == (24, 20, 0)
    assert parsed[4] == b"payload"
    for raw in (wire[:23], b"OTHER" + wire[5:], wire[:12] + b"\x01" + wire[13:], bytes(4096)):
        assert read_packet(raw) is None
    with pytest.raises(MiboError):
        packet(1 << 32, 0, 0, 0, b"")


@pytest.mark.parametrize(
    ("variant", "protected", "payload"),
    [(0xFC, False, ANNEX_B), (0xFD, True, ANNEX_B), (0xF0, True, ADTS)],
)
def test_media_round_trip(*, variant: int, protected: bool, payload: bytes) -> None:
    unit = extract(record(payload, variant=variant, protection=protected), KEY)
    assert unit is not None
    assert unit.data == payload
    assert unit.source_counter_ms == 17
    assert unit.codec == ("aac" if variant == 0xF0 else "h264")


def test_reject_wrong_media_key_and_truncated_record() -> None:
    value = record(variant=0xFD, protection=True)
    with pytest.raises(MiboError, match="media-key-verifier"):
        extract(value, bytes(32))
    for raw in (value[:-1], value[:4], value[:23] + bytes([value[23] ^ 1]) + value[24:]):
        with pytest.raises(MiboError):
            validate_record(raw)
    with pytest.raises(MiboError):
        extract(record(variant=0xFC, protection=True), KEY)
    assert extract(record(variant=0xF1), KEY) is None
    with pytest.raises(MiboError):
        extract(record(variant=0xEE), KEY)


def test_mixed_parser_every_fragment_boundary() -> None:
    wire = b"HTTP/1.1 200 OK\r\nCseq: 1\r\nPrivate-Length: 0\r\n\r\n" + envelope(record())
    for split in range(len(wire) + 1):
        parser = Parser()
        items = []
        for chunk in (wire[:split], wire[split:]):
            parser.append(chunk)
            while (item := parser.read()) is not None:
                items.append(item)
        assert len(items) == 2
        assert items[0].sequence == 1
        assert items[1].record == record()
        parser.clear()
        assert parser.read() is None


@pytest.mark.parametrize(
    "header",
    [
        b"HTTP/1.1 200 OK\r\nCseq: 1",
        b"HTTP/1.1 200 OK\r\nCseq: 1\r\nCseq: 1\r\nPrivate-Length: 0",
        b"HTTP/1.1 200 OK\r\nCseq: 2\r\nContent-Length: 0",
        b"HTTP/1.1 200 OK\r\nCseq: 2\r\nTransfer-Encoding: chunked",
        b"HTTP/1.1 200 OK\r\nCseq: -1\r\nPrivate-Length: 0",
        b"HTTP/1.1 200 OK\r\nCseq: 1\r\nPrivate-Length: 65537",
    ],
)
def test_reject_ambiguous_control_headers(header: bytes) -> None:
    with pytest.raises(MiboError):
        parse_header(header, None)


def test_keepalive_length_exception_is_bound() -> None:
    assert parse_header(b"HTTP/1.1 200 OK\r\nCseq: 2", 2) == (200, 2, 0)
    for pending in (None, 1, 3, 4):
        with pytest.raises(MiboError):
            parse_header(b"HTTP/1.1 200 OK\r\nCseq: 2", pending)


def test_media_and_codec_size_limits() -> None:
    parser = Parser()
    with pytest.raises(MiboError):
        parser.append(bytes(MAX_BODY + 16_385))
    parser.append(b"$\0" + struct.pack("!I", MAX_BODY + 1))
    with pytest.raises(MiboError):
        parser.read()
    for unit in (b"", ADTS[:-1], b"\0" * 8, ADTS[:4] + b"\0" + ADTS[5:]):
        with pytest.raises(MiboError):
            adts(unit)
    with pytest.raises(MiboError):
        unbase64("not base64")
    with pytest.raises(MiboError):
        unwrap("AAAA", "synthetic", bytes(16))
    assert "000000" not in repr(PARAMETERS)
