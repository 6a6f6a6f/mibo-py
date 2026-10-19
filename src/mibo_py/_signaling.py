# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Bounded vendor signaling and candidate identity/transaction confirmation."""

import hmac
import html
import ipaddress
import re
import secrets
import socket
import struct
import time
import xml.etree.ElementTree as ET
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime

from mibo_py._crypto import b64, md5_hex, ofb, sha1_b64, unbase64, unwrap
from mibo_py._validation import MiboError, Object, fail, identifier, obj, parse_json, rows, text
from mibo_py.models import VideoParameters

PRIVATE = tuple(
    ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


@dataclass(repr=False)
class Bootstrap:
    """Fresh camera-bound credentials; never serialize or log this object."""

    device: str
    user: str
    password: str
    access_key: str
    token: str
    service: str
    alternate: str | None
    parameters: VideoParameters
    user_id: int

    @classmethod
    def read(
        cls, device: str, basic: Object, config: Object, parameters: VideoParameters, user_id: int
    ) -> "Bootstrap":
        """Validate the device binding, credential envelopes, and vendor service hosts."""
        identifier(device)
        if basic.get("deviceId") != device:
            fail("bootstrap-device-binding")
        p2p = obj(basic.get("p2pConfig"))
        user = unwrap(text(p2p.get("account"), 16_384), device, parameters.credential_iv)
        password = unwrap(text(p2p.get("password"), 16_384), device, parameters.credential_iv)
        if re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", user) is None:
            fail("bootstrap-user")
        access = text(p2p.get("ak"), 4096)
        if re.fullmatch(r"[A-Za-z0-9+/_=-]+", access) is None:
            fail("bootstrap-access-key")
        services: dict[str, str] = {}
        for value in rows(obj(config.get("serverConfig")).get("services"), 64):
            row = obj(value)
            kind = row.get("type")
            if kind not in ("p2p-v2", "p2p"):
                continue
            if (
                not isinstance(kind, str)
                or kind in services
                or row.get("port") not in (8800, "8800")
            ):
                fail("bootstrap-service")
            destination = text(row.get("host"), 253)
            if (
                re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.easy4ipcloud\.com", destination)
                is None
            ):
                fail("bootstrap-host")
            services[kind] = destination
        if "p2p-v2" not in services:
            fail("bootstrap-service-missing")
        return cls(
            device,
            user,
            password,
            access,
            text(p2p.get("p2pToken"), 8192),
            services["p2p-v2"],
            services.get("p2p"),
            parameters,
            user_id,
        )


def private(address: str) -> bool:
    """Recognize RFC1918 only, rather than every non-global address class."""
    parsed = ipaddress.IPv4Address(address)
    return any(parsed in network for network in PRIVATE)


def endpoint(value: str) -> tuple[str, int]:
    """Parse canonical IPv4 and a bounded decimal port."""
    try:
        address, port_text = value.rsplit(":", 1)
        parsed = ipaddress.IPv4Address(address)
        if str(parsed) != address or not port_text.isascii() or not port_text.isdecimal():
            fail("endpoint-format")
        port = int(port_text)
        if not 1 <= port <= 65535:
            fail("endpoint-port")
    except ValueError:
        fail("endpoint-format")
    else:
        return address, port


def public(address: str) -> bool:
    """Reject private, reserved, documentation, shared, and multicast candidates."""
    parsed = ipaddress.IPv4Address(address)
    return parsed.is_global and not parsed.is_multicast and not parsed.is_reserved


def resolve(destination: str) -> tuple[str, ...]:
    """Resolve one authenticated vendor host and retain public IPv4 answers only."""
    answers = socket.getaddrinfo(destination, 8800, socket.AF_INET, socket.SOCK_DGRAM)
    result = tuple(
        dict.fromkeys(str(answer[4][0]) for answer in answers if public(str(answer[4][0])))
    )
    if not 1 <= len(result) <= 64:
        fail("signaling-dns")
    return result


def xml_value(raw: bytes, name: str, *, optional: bool = False) -> str:
    """Reject DTD/entity declarations before parsing bounded strict UTF-8 XML."""
    if not 0 < len(raw) <= 16_384:
        fail("xml-size")
    try:
        source = raw.decode("utf-8")
        if "<!" in source or "\0" in source:
            fail("xml-declaration")
        # DTDs are rejected above, including UTF-16 input through strict UTF-8.
        document = ET.fromstring(source)  # noqa: S314
        values = list(document.iter(name))
        if optional and (not values or (len(values) == 1 and not values[0].text)):
            return ""
        if len(values) != 1 or list(values[0]):
            fail("xml-field")
        return text(values[0].text, 8192)
    except (ET.ParseError, UnicodeError):
        fail("xml-invalid")


def response(raw: bytes, expected: int) -> tuple[int, bytes] | None:
    """Require one CSeq and exact Content-Length in one complete UDP datagram."""
    header, separator, body = raw.partition(b"\r\n\r\n")
    if (
        not separator
        or not 12 <= len(header) <= 8192
        or len(raw) >= 16_384
        or any((value < 32 and value not in (9, 10, 13)) or value > 126 for value in header)
    ):
        return None
    lines = header.split(b"\r\n")
    match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", lines[0])
    if match is None:
        return None
    fields: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not name or name[:1] in (b" ", b"\t") or name.lower() in fields:
            return None
        fields[name.lower()] = value.strip()
    sequence, length = fields.get(b"cseq", b""), fields.get(b"content-length", b"")
    if not sequence.isdigit() or len(sequence) > 10 or not length.isdigit() or len(length) > 5:
        return None
    if int(sequence) != expected or int(length) != len(body):
        return None
    return int(match[1]), body


def header(source: Bootstrap) -> str:
    """Build WSSE using the observed service token, not account HTTP signing."""
    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    nonce = str(secrets.randbelow(1 << 32) - (1 << 31))
    digest = sha1_b64((nonce + created + source.token).encode())
    user = (
        f"LeChange\\v2\\{source.parameters.project_id}\\phone\\{source.parameters.app_id}"
        f"\\{source.user_id}\\{source.access_key}"
    )
    return (
        'Authorization: WSSE profile="UsernameToken"\r\n'
        f'X-WSSE: UsernameToken Username="{user}", PasswordDigest="{digest}", '
        f'Nonce="{nonce}", Created="{created}"\r\n'
    )


def exchange(sock: socket.socket, request: bytes, sequence: int) -> bytes:
    """Allow six seconds and at most 64 datagrams for one NF operation."""
    if len(request) > 8192:
        fail("signaling-request-size")
    sock.send(request)
    deadline = time.monotonic() + 6
    count = 0
    while time.monotonic() < deadline and count < 64:
        try:
            raw = sock.recv(16_384)
        except TimeoutError:
            continue
        count += 1
        parsed = response(raw, sequence)
        if parsed is None or parsed[0] < 200:
            continue
        if parsed[0] != 200:
            fail("signaling-rejected")
        return parsed[1]
    return fail("signaling-timeout")


def get(sock: socket.socket, source: Bootstrap, path: str) -> bytes:
    """Send one bounded NFGET over the connected service socket."""
    sequence = secrets.randbelow((1 << 31) - 1) + 1
    wire = (
        f"NFGET {path} HTTP/1.1\r\nX-Version: 6.7.46\r\n"
        f"X-ToUType: Client/Imou_Android\r\nCSeq: {sequence}\r\n{header(source)}\r\n"
    )
    return exchange(sock, wire.encode(), sequence)


def register(sock: socket.socket, source: Bootstrap, salt: str) -> tuple[bytes, bytes]:
    """Register initially, then with fresh server salt on a new source port."""
    local_ip, local_port = sock.getsockname()
    if not private(local_ip):
        fail("local-topology")
    local = ".".join(str(255 - part) for part in ipaddress.IPv4Address(local_ip).packed)
    local += f":{local_port}"
    identity = secrets.token_bytes(8)
    nonce, created = str(secrets.randbelow(1 << 32) - (1 << 31)), str(int(time.time()))
    key = md5_hex(f"{source.user}:Login to {salt}:{source.password}".encode()).upper().encode()
    fields = {
        "CreateDate": created,
        "DevAuth": b64(hmac.digest(key, (nonce + created + local).encode(), "sha256")),
        "Identify": " ".join(f"{value:x}" for value in identity),
        "IpEncrpt": "true",
        "IpType": "2",
        "LocalAddr": local,
        "NatValueT": "0",
        "Nonce": nonce,
        "Pid": "0",
        "UserName": source.user,
        "version": "6.7.46",
    }
    if salt:
        fields["RandSalt"] = salt
    body = (
        "<body>"
        + "".join(
            f"<{name}>{html.escape(value)}</{name}>" for name, value in sorted(fields.items())
        )
        + "</body>"
    )
    sequence = secrets.randbelow((1 << 31) - 1) + 1
    wire = (
        f"NFPOST /device/{source.device}/p2p-channel HTTP/1.1\r\nX-Version: 6.7.46\r\n"
        f"x-pcs-request-id: {secrets.token_hex(16)}\r\nX-ToUType: Client/Imou_Android\r\n"
        f"CSeq: {sequence}\r\n{header(source)}Content-Type: \r\n"
        f"Content-Length: {len(body.encode())}\r\n\r\n{body}"
    )
    return identity, exchange(sock, wire.encode(), sequence)


def stun(
    kind: int, transaction: bytes, identity: bytes, remote: tuple[str, int], *, address: bool
) -> bytes:
    """Write 20-byte STUN header, 12-byte identity and optional 12-byte address, then invert."""
    if kind not in (1, 0x101) or len(transaction) != 12 or len(identity) != 8:
        fail("stun-parameters")
    packet = struct.pack("!HHI", kind, 24 if address else 12, 0x2112A442) + transaction
    packet += struct.pack("!HH", 0x802A if kind == 1 else 0x8029, 8) + identity
    if address:
        packet += (
            struct.pack("!HHBBH", 4, 8, 0, 1, remote[1]) + ipaddress.IPv4Address(remote[0]).packed
        )
    return bytes(value ^ 255 for value in packet)


def read_stun(raw: bytes, peer: bytes) -> tuple[int, bytes, bool] | None:
    """Validate shape and discovered identity before any transaction can complete."""
    if len(raw) not in (32, 44):
        return None
    packet = bytes(value ^ 255 for value in raw)
    kind, size, cookie = struct.unpack_from("!HHI", packet)
    if kind not in (1, 0x101) or size != len(packet) - 20 or cookie != 0x2112A442:
        return None
    if (
        struct.unpack_from("!HH", packet, 20) != (0x802A if kind == 1 else 0x8029, 8)
        or packet[24:32] != peer
    ):
        return None
    if len(packet) == 44 and struct.unpack_from("!HHBB", packet, 32) != (4, 8, 0, 1):
        return None
    return kind, packet[8:20], len(packet) == 44


def probe(sock: socket.socket, own: bytes, peer: bytes, budget: float = 5) -> bool:
    """Confirm a connected endpoint against fresh local or answered peer transactions."""
    remote = sock.getpeername()
    transaction, peer_transaction = secrets.token_bytes(12), b""
    sock.send(stun(1, transaction, own, remote, address=True))
    deadline, count = time.monotonic() + budget, 0
    while time.monotonic() < deadline and count < 32:
        try:
            raw = sock.recv(16_384)
        except TimeoutError:
            continue
        count += 1
        parsed = read_stun(raw, peer)
        if parsed is None:
            continue
        kind, incoming, has_address = parsed
        if kind == 0x101 and has_address and incoming == transaction:
            for _ in range(5):
                sock.send(stun(0x101, transaction, own, remote, address=False))
            return True
        if kind == 0x101 and not has_address and peer_transaction and incoming == peer_transaction:
            return True
        if kind == 1 and has_address:
            peer_transaction = incoming
            sock.send(stun(0x101, incoming, own, remote, address=True))
    return False


def local_candidates(
    raw: bytes, allowed: tuple[str, ...], local: str
) -> tuple[tuple[str, int], ...]:
    """Use at most two advertised LAN peers explicitly allowlisted by the caller.

    The SDK never infers LAN authorization from a server response or scans a
    subnet. The caller supplies camera host addresses, never network ranges.
    """
    encryption = xml_value(raw, "IpEncrpt", optional=True)
    value = xml_value(raw, "LocalAddr", optional=True)
    if encryption not in ("", "false") or not value or len(value) > 256:
        return ()
    address_text, _, port = value.rpartition(":")
    parts = address_text.split(",")
    if (
        not port.isascii()
        or not port.isdecimal()
        or len(parts) > 8
        or not 1024 <= int(port) <= 65535
    ):
        return ()
    result: list[tuple[str, int]] = []
    for part in parts:
        address = endpoint(f"{part}:{port}")
        if private(part) and part in allowed and part != local and address not in result:
            result.append(address)
    return tuple(result[:2])


def info_address(advertised: str, pool: tuple[str, ...]) -> tuple[str, int]:
    """Use an approved shard or the already contacted registration host on port 8803."""
    address, port = endpoint(advertised)
    if port != 8803 or not public(address):
        fail("info-destination")
    return (address if address in pool else pool[0]), port


def open_peer(source: Bootstrap, allowed_lan_hosts: tuple[str, ...]) -> tuple[socket.socket, str]:
    """Run initial registration, bound Info, salted registration, and candidate probe."""
    addresses = resolve(source.service)
    pool = addresses
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as initial:
        initial.settimeout(0.1)
        initial.connect((addresses[0], 8800))
        register(initial, source, "")
        online = get(initial, source, f"/online/p2psrv/{source.device}")
        advertised = xml_value(online, "US")
        address, port = endpoint(advertised)
        if port == 8803 and public(address) and address not in addresses and source.alternate:
            with suppress(OSError, MiboError):
                pool += resolve(source.alternate)
        initial.connect(info_address(advertised, pool))
        raw = get(initial, source, f"/info/device/{source.device}")
        encrypted = unbase64(xml_value(raw, "Info"))
        clear = ofb(encrypted, source.parameters.info_key, source.parameters.info_iv)
        salt = text(parse_json(clear, 8192).get("randsalt"), 256)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.1)
        sock.connect((addresses[0], 8800))
        own, registered = register(sock, source, salt)
        peer_text = xml_value(registered, "Identify")
        if re.fullmatch(r"(?:[0-9a-fA-F]{1,2} ){7}[0-9a-fA-F]{1,2}", peer_text) is None:
            fail("peer-identity")
        peer = bytes(int(part, 16) for part in peer_text.split(" "))
        public_peer = endpoint(xml_value(registered, "PubAddr"))
        if not public(public_peer[0]):
            fail("candidate-address")
        for candidate in local_candidates(registered, allowed_lan_hosts, sock.getsockname()[0]):
            sock.connect(candidate)
            if probe(sock, own, peer, 2):
                return sock, salt
        sock.connect(public_peer)
        if probe(sock, own, peer):
            return sock, salt
        fail("candidate-timeout")
    except BaseException:
        sock.close()
        raise
