# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Observed legacy wire cryptography; none of these formats is a new security design."""

import base64
import binascii
import hashlib
import hmac

from cryptography.hazmat.decrepit.ciphers.modes import OFB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from mibo_py._validation import fail, text


def md5_hex(value: bytes) -> str:
    """Reproduce the service's legacy digest, never password storage."""
    return hashlib.md5(value, usedforsecurity=False).hexdigest()


def b64(value: bytes) -> str:
    """Encode a bounded protocol value as ASCII base64."""
    return base64.b64encode(value).decode("ascii")


def unbase64(value: str, maximum: int = 8192) -> bytes:
    """Decode strict base64 with both encoded and decoded bounds."""
    if len(value) > maximum * 2:
        fail("base64-size")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        fail("base64-invalid")
    if not 0 < len(result) <= maximum:
        fail("base64-size")
    return result


def sha1_b64(value: bytes) -> str:
    """Reproduce the observed WSSE SHA-1 format required by the peer."""
    return b64(hashlib.sha1(value, usedforsecurity=False).digest())


def sign(
    path: str, body: bytes, headers: dict[str, str], credential: str, *, password: bool
) -> str:
    """Sign canonical headers in wire order, including the trailing LF."""
    names = ["x-pcs-apiver", "x-pcs-client-ua", "x-pcs-date", "x-pcs-nonce"]
    if "x-pcs-session-id" in headers:
        names.append("x-pcs-session-id")
    names.append("x-pcs-username")
    for value in [path, credential, *[v for k, v in headers.items() if k != "x-pcs-session-id"]]:
        text(value, 65_536)
    if headers.get("x-pcs-session-id"):
        text(headers["x-pcs-session-id"], 512)
    if not path.startswith("/pcs/v1/"):
        fail("signing-path")
    digest = b64(hashlib.md5(body, usedforsecurity=False).digest())
    headers["Content-MD5"] = digest
    canonical = (
        "\n".join(
            [
                "POST",
                path,
                digest,
                headers["Content-Type"],
                *[f"{name}:{headers[name]}" for name in names],
            ]
        )
        + "\n"
    )
    key = md5_hex(credential.encode())
    if password:
        key = md5_hex(key.encode("ascii"))
    return b64(hmac.digest(key.encode("ascii"), canonical.encode(), "sha256"))


def ofb(value: bytes, key: bytes, iv: bytes) -> bytes:
    """Apply the protocol's AES-OFB, which does not authenticate ciphertext."""
    if len(key) != 32 or len(iv) != 16:
        fail("cipher-parameters")
    decryptor = Cipher(algorithms.AES(key), OFB(iv)).decryptor()
    return decryptor.update(value) + decryptor.finalize()


def unwrap(value: str, device: str, iv: bytes) -> str:
    """Unwrap CBC camera credentials bound to an authenticated device response."""
    encrypted = unbase64(value)
    if len(iv) != 16 or len(encrypted) % 16:
        fail("credential-envelope")
    key = md5_hex((device.upper() + "DAHUAKEY").encode()).encode("ascii")
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        clear = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return text((unpadder.update(clear) + unpadder.finalize()).decode("utf-8"), 4096)
    except (ValueError, UnicodeError):
        fail("credential-envelope")


def media_key(user: str, device: str, password: str) -> bytes:
    """Derive the observed PBKDF2-SHA256 key with 20,000 iterations."""
    material = md5_hex(f"{user}:Login to {device}:{password}".encode()).upper().encode("ascii")
    return hashlib.pbkdf2_hmac("sha256", material, device.encode(), 20_000, dklen=32)
