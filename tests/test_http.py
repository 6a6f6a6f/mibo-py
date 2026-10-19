# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Synthetic HTTPS boundary checks with no real service connection."""

import gzip
import http.client
from collections import deque
from typing import NoReturn, cast

import pytest

from mibo_py import MiboError
from mibo_py._http import AccountHTTP
from mibo_py._validation import MAX_BODY, Object, encode_json


class Response:
    def __init__(self, status: int, data: bytes, encoding: str) -> None:
        self.status, self.data, self.encoding = status, data, encoding

    def getheader(self, _name: str, _default: str = "") -> str:
        return self.encoding

    def read1(self, limit: int) -> bytes:
        chunk, self.data = self.data[:limit], self.data[limit:]
        return chunk


class Connection:
    responses: deque[Response]
    requests: list[tuple[str, bytes, dict[str, str]]]
    closed: list[bool]

    def __init__(self, _host: str, **_options: object) -> None:
        self.closed.append(False)

    def request(self, _method: str, path: str, body: bytes, headers: dict[str, str]) -> None:
        self.requests.append((path, body, headers))

    def getresponse(self) -> http.client.HTTPResponse:
        return cast("http.client.HTTPResponse", self.responses.popleft())

    def close(self) -> None:
        self.closed[-1] = True


def setup(
    monkeypatch: pytest.MonkeyPatch, value: Object, *, status: int = 200, encoding: str = "gzip"
) -> AccountHTTP:
    raw = encode_json(value)
    Connection.responses = deque(
        [Response(status, gzip.compress(raw) if encoding == "gzip" else raw, encoding)]
    )
    Connection.requests = []
    Connection.closed = []
    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    return AccountHTTP('{"terminalId":"synthetic","ttid":"synthetic"}')


def test_signed_post_uses_exact_uncompressed_body(monkeypatch: pytest.MonkeyPatch) -> None:
    http = setup(monkeypatch, {"code": 10000, "data": {"synthetic": True}})
    assert http.post(
        "app-br.easy4ipcloud.com",
        "user.account.Login",
        {},
        "principal",
        "token",
        session="synthetic",
    ) == {"synthetic": True}
    path, body, headers = Connection.requests[0]
    assert path == "/pcs/v1/user.account.Login"
    assert gzip.decompress(body) == b'{"data":{}}'
    assert headers["x-pcs-session-id"] == "synthetic"
    assert headers["x-pcs-signature"]
    assert Connection.closed == [True]


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 500])
def test_no_redirect_or_http_error_is_followed(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    http = setup(monkeypatch, {}, status=status)
    with pytest.raises(MiboError, match="http-status"):
        http.post("app-br.easy4ipcloud.com", "user.account.Login", {}, "principal", "token")
    assert len(Connection.requests) == 1
    assert Connection.closed == [True]


@pytest.mark.parametrize("code", [12002, 0, 400, -1])
def test_api_error_never_exposes_remote_message(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    http = setup(monkeypatch, {"code": code, "message": "PRIVATE-RESPONSE"})
    with pytest.raises(MiboError) as error:
        http.post("app-br.easy4ipcloud.com", "user.account.Login", {}, "principal", "token")
    assert "PRIVATE" not in str(error.value)
    assert error.value.__suppress_context__


def test_reject_unknown_encoding_and_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    http = setup(monkeypatch, {}, encoding="br")
    with pytest.raises(MiboError, match="http-encoding"):
        http.post("app-br.easy4ipcloud.com", "user.account.Login", {}, "principal", "token")
    http = setup(monkeypatch, {}, encoding="")
    Connection.responses = deque([Response(200, b"x" * (MAX_BODY + 1), "")])
    with pytest.raises(MiboError, match="http-size"):
        http.post("app-br.easy4ipcloud.com", "user.account.Login", {}, "principal", "token")


def test_network_errors_are_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    http = setup(monkeypatch, {})

    def rejected(_self: Connection) -> NoReturn:
        message = "PRIVATE-URL-OR-SECRET"
        raise OSError(message)

    monkeypatch.setattr(Connection, "getresponse", rejected)
    with pytest.raises(MiboError, match="http-transport") as error:
        http.post("app-br.easy4ipcloud.com", "user.account.Login", {}, "principal", "token")
    assert error.value.__suppress_context__
    assert Connection.closed == [True]
