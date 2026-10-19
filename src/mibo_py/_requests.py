# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Observed camera PLAY, keepalive and close requests inside the PTCP proxy."""

import hashlib
import secrets
import time
from datetime import UTC, datetime

from mibo_py._crypto import b64, md5_hex, sha1_b64
from mibo_py._signaling import Bootstrap
from mibo_py._validation import fail

SDP = (
    "v=0\r\no=- {origin} {origin} IN IP4 127.0.0.1\r\n"
    "s=Media Server\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\na=control:*\r\n"
    "a=packetization-supported:DH\r\na=rtppayload-supported:DH\r\na=range:npt=now-\r\n"
    "m=video 0 RTP/AVP 0\r\na=control:trackID=0\r\na=framerate:0\r\n"
    "a=rtpmap:0 disable/90000\r\na=fmtp\r\na=sendonly\r\n"
    "m=audio 0 RTP/AVP 0\r\na=control:trackID=1\r\na=rtpmap:0 disable/8000\r\na=sendonly\r\n"
    "m=audio 0 RTP/AVP 0\r\na=control:trackID=2\r\na=rtpmap:0 disable/8000\r\na=sendonly\r\n"
    "m=application 0 RTP/AVP 100\r\na=control:trackID=3\r\n"
    "a=rtpmap:100 stream-assist-frame/90000\r\na=sendonly\r\n"
    "m=application 0 RTP/AVP 107\r\na=control:trackID=4\r\n"
    "a=rtpmap:107 vnd.onvif.metadata/90000\r\na=sendonly\r\n"
    "m=audio 0 RTP/AVP 8\r\na=control:trackID=5\r\na=rtpmap:8 PCMA/16000\r\na=sendonly\r\n"
)


def request(source: Bootstrap, salt: str, subtype: int, method: int, sequence: int) -> bytes:
    """Preserve the observed Accpet-Sdp spelling and method-specific query layout."""
    if subtype not in (0, 1) or method not in (0, 2, 3):
        fail("media-request")
    path = f"/live/visualtalk.xav?channel=1&subtype={subtype}&encrypt=3&audioType=1"
    if method == 0:
        path += "&trackID=31"
    path += f"&method={method}"
    headers = {
        "Accpet-Sdp": "Private",
        "Connect-Type": "P2P",
        "Connection": "keep-alive",
        "Cseq": str(sequence),
        "Host": "127.0.0.1:8086",
        "User-Agent": "Http Stream Client/1.0",
        "x-pcs-request-id": secrets.token_hex(8),
    }
    body = ""
    if method == 0:
        nonce = secrets.token_hex(16)
        created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        material = md5_hex(f"{source.user}:Login to {salt}:{source.password}".encode()).upper()
        light = (
            hashlib.sha256(f"{source.user}:Login to {source.device}:{source.password}".encode())
            .hexdigest()
            .upper()
        )
        digest = sha1_b64((nonce + created + material).encode())
        lightweight = b64(hashlib.sha256((nonce + created + light).encode()).digest())
        body = SDP.format(origin=int(time.time()))
        headers.update(
            {
                "Authorization": 'WSSE profile="UsernameToken"',
                "Private-Length": str(len(body.encode())),
                "Private-Type": "application/sdp",
                "Speed": "1.000000",
                "WSSE": (
                    f'UsernameToken Username="{source.user}", PasswordDigest="{digest}", '
                    f'LightweightDigest="{lightweight}", Nonce="{nonce}", Created="{created}"'
                ),
            }
        )
    return (
        f"PLAY {path} HTTP/1.1\r\n"
        + "".join(f"{name}: {value}\r\n" for name, value in sorted(headers.items()))
        + "\r\n"
        + body
    ).encode()
