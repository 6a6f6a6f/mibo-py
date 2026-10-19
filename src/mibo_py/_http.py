# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Bounded HTTPS account calls with no redirects, proxies, retries, or persistence."""

import gzip
import http.client
import secrets
import ssl
import time
import zlib
from datetime import UTC, datetime

from mibo_py._crypto import b64, sign
from mibo_py._validation import MAX_BODY, Object, encode_json, fail, host, integer, obj, parse_json


class AccountHTTP:
    """Send canonical signed requests only to the observed account origins."""

    def __init__(self, ua_json: str) -> None:
        """Retain only the caller-owned terminal UA, encoded for the wire."""
        self.ua = b64(ua_json.encode())

    # Wire signing fields and revision are intentionally explicit at each call site.
    def post(  # noqa: PLR0913
        self,
        destination: str,
        operation: str,
        data: Object,
        principal: str,
        credential: str,
        *,
        session: str | None = None,
        password: bool = False,
        revision: str = "191204",
        legacy: bool = False,
    ) -> Object:
        """Sign uncompressed bytes, gzip the body, and sanitize all remote failures."""
        destination = host(destination)
        path = "/pcs/v1/" + operation
        body = encode_json({"data": data})
        if len(body) > MAX_BODY:
            fail("request-size")
        headers = {
            "Content-Type": "application/json" if legacy else "application/json; charset=utf-8",
            "x-pcs-apiver": revision,
            "x-pcs-client-ua": self.ua,
            "x-pcs-date": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "x-pcs-nonce": secrets.token_hex(24),
            "x-pcs-username": principal,
        }
        if session is not None:
            headers["x-pcs-session-id"] = session
        headers["x-pcs-signature"] = sign(path, body, headers, credential, password=password)
        headers.update(
            {"Content-Encoding": "gzip", "Accept-Encoding": "gzip", "Connection": "close"}
        )
        raw = self._request(destination, path, gzip.compress(body, mtime=0), headers)
        result = parse_json(raw)
        code = integer(result.get("code"), -2_147_483_648, 2_147_483_647)
        if code == 12002:
            fail("session-rejected")
        if code != 10000:
            fail("api-rejected")
        return obj(result.get("data", {}))

    @staticmethod
    def _request(destination: str, path: str, body: bytes, headers: dict[str, str]) -> bytes:
        connection = http.client.HTTPSConnection(
            destination, timeout=5, context=ssl.create_default_context()
        )
        try:
            connection.request("POST", path, body, headers)
            response = connection.getresponse()
            if response.status != 200:
                fail("http-status")
            encoding = response.getheader("Content-Encoding", "").lower()
            if encoding not in {"", "gzip"}:
                fail("http-encoding")
            raw = bytearray()
            deadline = time.monotonic() + 20
            while True:
                if time.monotonic() >= deadline:
                    fail("http-deadline")
                chunk = response.read1(min(65_536, MAX_BODY + 1 - len(raw)))
                raw.extend(chunk)
                if len(raw) > MAX_BODY:
                    fail("http-size")
                if not chunk:
                    break
            return inflate(bytes(raw)) if encoding else bytes(raw)
        except (OSError, http.client.HTTPException, ValueError):
            fail("http-transport")
        finally:
            connection.close()


def inflate(raw: bytes) -> bytes:
    """Reject gzip bombs, trailing members, truncation, and unsupported encodings."""
    try:
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        clear = inflater.decompress(raw, MAX_BODY + 1)
        if (
            len(clear) > MAX_BODY
            or inflater.unconsumed_tail
            or inflater.unused_data
            or not inflater.eof
        ):
            fail("http-gzip")
    except zlib.error:
        fail("http-gzip")
    else:
        return clear
