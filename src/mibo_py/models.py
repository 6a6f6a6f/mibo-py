# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Small public values; secret-bearing objects deliberately disable generated repr."""

from dataclasses import dataclass, field
from typing import Literal

from mibo_py._validation import fail, identifier


@dataclass(frozen=True, repr=False)
class Application:
    """Caller-provisioned app identity and terminal UA; never bundled vendor secrets."""

    principal: str
    credential: str
    terminal_ua_json: str
    entry_host: str = "app-br.easy4ipcloud.com"


@dataclass(frozen=True, repr=False)
class VideoParameters:
    """Caller-provisioned vendor parameters needed for the observed media negotiation."""

    project_id: str
    app_id: str
    credential_iv: bytes
    info_key: bytes
    info_iv: bytes

    def __post_init__(self) -> None:
        """Reject invalid lengths and header injection before network operations."""
        identifier(self.project_id, 128)
        identifier(self.app_id, 128)
        if (len(self.credential_iv), len(self.info_key), len(self.info_iv)) != (16, 32, 16):
            fail("video-parameters")


@dataclass(frozen=True, repr=False)
class Family:
    """One inventory family, bound to the account session that returned it."""

    id: str
    name: str
    _generation: object = field(repr=False)


@dataclass(frozen=True, repr=False)
class Device:
    """A server-returned device selection; its ID alone does not authorize media."""

    id: str
    name: str
    model: str
    product_id: str
    _generation: object = field(repr=False)


@dataclass(frozen=True, repr=False)
class Profile:
    """An explicitly selected video subtype from current device details."""

    name: str
    subtype: int
    channel_id: str


@dataclass(frozen=True, repr=False)
class Camera:
    """Fresh details and supported profiles for one session-bound device."""

    device: Device
    firmware: str
    profiles: tuple[Profile, ...]
    _generation: object = field(repr=False)


@dataclass(frozen=True, repr=False)
class EncodedUnit:
    """Owned compressed bytes, not pixels or PCM; timestamp is a wrapping wire counter.

    ``data`` is H.264 Annex B or AAC ADTS. ``source_counter_ms`` is the raw
    unsigned 16-bit DHAV counter, not a wall clock or presentation timestamp.
    The consumer owns scheduling, rollover handling, decoding, and retention.
    """

    codec: Literal["h264", "aac"]
    data: bytes
    source_counter_ms: int
    record_type: int
