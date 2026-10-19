# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Explicitly owned, pull-based camera stream; no decoder, player, recorder, or relay."""

from collections.abc import Iterator
from contextlib import AbstractContextManager
from typing import Self

from mibo_py._crypto import media_key
from mibo_py._media import extract
from mibo_py._signaling import Bootstrap, endpoint, open_peer, private
from mibo_py._transport import Transport
from mibo_py._validation import Object, fail, integer
from mibo_py.models import EncodedUnit, VideoParameters


class RawStream(AbstractContextManager["RawStream"]):
    """One single-consumer camera stream; consume promptly and always use a with block."""

    def __init__(self, transport: Transport, key: bytes) -> None:
        """Take transport ownership and copy mutable media key material."""
        self._transport = transport
        self._key = bytearray(key)
        self._consumed = False

    @property
    def closed(self) -> bool:
        """Whether local camera resources have been released."""
        return self._transport.closed

    @classmethod
    # Bootstrap fields are explicit so the session binding remains reviewable.
    def open(  # noqa: PLR0913, PLR0917
        cls,
        device: str,
        subtype: int,
        basic: Object,
        config: Object,
        parameters: VideoParameters,
        user_id: int,
        allowed_lan_hosts: tuple[str, ...] = (),
    ) -> Self:
        """Open a freshly authorized bootstrap without automatic reconnection."""
        integer(subtype, 0, 1)
        integer(user_id, 1)
        if len(allowed_lan_hosts) > 8:
            fail("stream-selection")
        for address in allowed_lan_hosts:
            endpoint(address + ":1024")
            if not private(address):
                fail("lan-allowlist")
        source = Bootstrap.read(device, basic, config, parameters, user_id)
        try:
            sock, salt = open_peer(source, allowed_lan_hosts)
        except OSError:
            fail("signaling-transport")
        try:
            transport = Transport(sock, source, salt, subtype)
            return cls(transport, media_key(source.user, device, source.password))
        except OSError:
            sock.close()
            fail("camera-transport")
        except BaseException:
            sock.close()
            raise

    def records(self) -> Iterator[bytes]:
        """Yield original DHAV records, still containing vendor media encryption.

        Use either this method or iteration over compressed units once. Returned
        bytes belong to the caller; the SDK never saves or logs camera media.
        """
        if self.closed or self._consumed:
            fail("stream-single-consumer")
        self._consumed = True
        try:
            yield from self._transport.records()
        except OSError:
            fail("camera-transport")
        finally:
            self.close()

    def __iter__(self) -> Iterator[EncodedUnit]:
        """Yield decrypted H.264 Annex B and AAC ADTS units, with raw source counters."""
        try:
            for record in self.records():
                unit = extract(record, bytes(self._key))
                if unit is not None:
                    yield unit
        finally:
            self.close()

    def close(self) -> None:
        """Erase the owned mutable media key and close the camera transport."""
        try:
            self._transport.close()
        finally:
            self._key[:] = b"\0" * len(self._key)

    def __enter__(self) -> Self:
        """Enter the explicit stream lifetime scope."""
        if self.closed:
            fail("stream-closed")
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close even if the consumer stops before the iterator is exhausted."""
        self.close()
