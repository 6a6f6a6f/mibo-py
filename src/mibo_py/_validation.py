# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Bounded wire values and sanitized errors shared by protocol boundaries."""

import json
import re
from typing import NoReturn, cast

MAX_BODY = 1_048_576
ASCII_CONTROL = 32
ASCII_DELETE = 127
MAX_JSON_DEPTH = 24
HOSTS = frozenset({"app-br.easy4ipcloud.com", "app-sp2.easy4ipcloud.com"})
type Object = dict[str, object]


class MiboError(Exception):
    """A fixed operation code, with no remote text, credentials, or peer addresses."""


def fail(code: str) -> NoReturn:
    """Reject a protocol operation using a local, fixed error code."""
    raise MiboError(code) from None


def text(value: object, limit: int = 512) -> str:
    """Require nonempty bounded text without controls or header delimiters."""
    if not isinstance(value, str) or not 0 < len(value) <= limit:
        fail("invalid-text")
    if any(ord(char) < ASCII_CONTROL or ord(char) == ASCII_DELETE for char in value):
        fail("invalid-text")
    return value


def identifier(value: object, limit: int = 256) -> str:
    """Allow only path-safe ASCII identifiers."""
    result = text(value, limit)
    if re.fullmatch(r"[A-Za-z0-9_-]+", result) is None:
        fail("invalid-identifier")
    return result


def obj(value: object) -> Object:
    """Require a JSON object; parsing has already checked key types."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        fail("invalid-object")
    return cast("Object", value)


def rows(value: object, maximum: int = 128) -> list[object]:
    """Require a bounded JSON array."""
    if not isinstance(value, list) or len(value) > maximum:
        fail("invalid-array")
    return cast("list[object]", value)


def integer(value: object, minimum: int = 0, maximum: int = (1 << 63) - 1) -> int:
    """Reject booleans, floats and integers outside the wire field's range."""
    if type(value) is not int or not minimum <= value <= maximum:
        fail("invalid-integer")
    return value


def flag(value: object) -> bool:
    """Require an actual boolean, never truthiness of an untrusted value."""
    if not isinstance(value, bool):
        fail("invalid-boolean")
    return value


def host(value: object) -> str:
    """Accept only observed account origins, without userinfo or extra URL parts."""
    result = text(value)
    for allowed in HOSTS:
        if result in {
            allowed,
            f"https://{allowed}",
            f"https://{allowed}/",
            f"https://{allowed}:443",
            f"https://{allowed}:443/",
        }:
            return allowed
    fail("account-routing")


def _pairs(pairs: list[tuple[str, object]]) -> Object:
    result: Object = {}
    for key, value in pairs:
        if key in result:
            fail("json-duplicate-key")
        result[key] = value
    return result


def _constant(_value: str) -> NoReturn:
    fail("json-nonfinite")


def parse_json(raw: bytes | str, maximum: int = MAX_BODY) -> Object:
    """Bound bytes and nesting before JSON decoding; reject duplicate keys and NaN."""
    if len(raw) > maximum:
        fail("json-size")
    try:
        source = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        _check_depth(source)
        value: object = json.loads(source, object_pairs_hook=_pairs, parse_constant=_constant)
        return obj(value)
    except (ValueError, UnicodeError, RecursionError):
        fail("json-invalid")


def encode_json(value: Object) -> bytes:
    """Serialize the exact UTF-8 request bytes used by account signing."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def _check_depth(source: str) -> None:
    depth, quoted, escaped = 0, False, False
    for char in source:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                fail("json-depth")
        elif char in "]}":
            depth -= 1
