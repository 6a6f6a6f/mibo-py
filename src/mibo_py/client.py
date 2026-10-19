# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Explicit account authorization and inventory; no credential extraction or storage."""

from __future__ import annotations

import time
import uuid
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Self

from mibo_py._http import AccountHTTP
from mibo_py._validation import (
    MiboError,
    Object,
    fail,
    flag,
    host,
    identifier,
    integer,
    obj,
    parse_json,
    rows,
    text,
)
from mibo_py.models import Application, Camera, Device, Family, Profile, VideoParameters
from mibo_py.stream import RawStream

if TYPE_CHECKING:
    from types import TracebackType


class Client(AbstractContextManager["Client"]):
    """A synchronous, single-thread-owned client for caller-authorized accounts."""

    def __init__(self, application: Application) -> None:
        """Validate transient caller provisioning without sending network requests."""
        self._host = host(application.entry_host)
        self._principal = text(application.principal, 512)
        self._credential = text(application.credential, 4096)
        ua = parse_json(application.terminal_ua_json, 16_384)
        text(ua.get("terminalId"))
        text(ua.get("ttid"))
        self._http = AccountHTTP(application.terminal_ua_json)
        self._closed = False
        self._sessions: set[Session] = set()
        self._challenges: set[Challenge] = set()

    def authenticate(self, account: str, password: str) -> Session | Challenge:
        """Read both server gates, returning a session or an explicit email challenge."""
        self._check_open()
        account, password = text(account), text(password, 4096)
        managed, credited, two_factor, challenge_account = self._status(account)
        if managed and not credited:
            return self._challenge(account, password, challenge_account, "terminal-trust")
        if two_factor:
            return self._challenge(account, password, challenge_account, "two-factor")
        return self._login(account, password)

    def _check_open(self) -> None:
        if self._closed:
            fail("client-closed")
        self._sessions = {session for session in self._sessions if not session._closed}
        if len(self._sessions) + len(self._challenges) >= 8:
            fail("account-operation-limit")

    def _challenge(self, account: str, password: str, target: str, kind: str) -> Challenge:
        challenge = Challenge(self, account, password, target, kind)
        self._challenges.add(challenge)
        return challenge

    def _status(self, account: str) -> tuple[bool, bool, bool, str]:
        result = self._http.post(
            self._host,
            "user.account.GetTwoStepVerifyState",
            {"account": account},
            self._principal,
            self._credential,
        )
        managed = flag(result.get("terminalManageState"))
        credited = flag(result.get("GrantingCreditFlag"))
        state = result.get("state")
        if state not in ("on", "off"):
            fail("trust-state")
        target = (
            text(result.get("account")) if (managed and not credited) or state == "on" else account
        )
        if target.casefold() != account.casefold():
            fail("challenge-account-binding")
        return managed, credited, state == "on", target

    def _login(self, account: str, password: str) -> Session:
        token = self._http.post(
            self._host,
            "user.account.GetToken",
            {"gpsInfo": {"latitude": 0, "longitude": 0}},
            "account\\" + account,
            password,
            password=True,
        )
        destination = host(token.get("entryUrlV2"))
        principal = "uuid\\" + text(token.get("username"))
        credential = text(token.get("token"), 8192)
        session_id = text(token.get("sessionId"))
        login = self._http.post(
            destination,
            "user.account.Login",
            {"timezoneOffset": -time.timezone},
            principal,
            credential,
            session=session_id,
        )
        route = host(login["entryUrlV2"]) if "entryUrlV2" in login else destination
        session = Session(
            self._http, route, principal, credential, session_id, integer(login.get("userId"), 1)
        )
        self._sessions.add(session)
        return session

    def close(self) -> None:
        """Close local sessions and challenges; this does not revoke server tokens."""
        if self._closed:
            return
        self._closed = True
        for challenge in tuple(self._challenges):
            challenge.close()
        for session in self._sessions:
            session.close()
        self._sessions.clear()
        self._credential = ""

    def __enter__(self) -> Self:
        """Enter the explicit lifetime scope."""
        self._check_open()
        return self

    def __exit__(self, *_exc: object) -> None:
        """Release account and camera resources on every exit path."""
        self.close()


class Challenge(AbstractContextManager["Challenge"]):
    """A single-use server challenge; code delivery and submission are explicit."""

    def __init__(self, client: Client, account: str, password: str, target: str, kind: str) -> None:
        """Retain a password only until submission or explicit close."""
        self._client, self._account, self._password = client, account, password
        self._target, self.kind = target, kind
        self._closed = False
        self._requested = False

    def request_code(self) -> None:
        """Request one email; there is no automatic resend or retry."""
        self._check()
        if self._requested:
            fail("challenge-code-already-requested")
        self._requested = True
        self._client._http.post(
            self._client._host,
            "common.validcode.GetValidCode",
            {"account": self._target, "type": "email", "usage": self._usage()},
            self._client._principal,
            self._client._credential,
            revision="61452",
            legacy=True,
        )

    def _usage(self) -> str:
        return "GrantingCredit" if self.kind == "terminal-trust" else "CheckTwoStepVerify"

    def _check(self) -> None:
        if self._closed or self._client._closed:
            fail("challenge-closed")

    def submit(self, code: str) -> Session | Challenge:
        """Consume one code attempt; only explicit server acceptance permits login."""
        self._check()
        code = text(code, 128)
        if not code.isascii() or not code.isdecimal():
            fail("challenge-code-format")
        client, account, password = self._client, self._account, self._password
        self.close()
        if self.kind == "terminal-trust":
            client._http.post(
                client._host,
                "user.account.GrantingCredit",
                {
                    "account": account,
                    "grantCreditAccount": self._target,
                    "type": "email",
                    "uuid": str(uuid.uuid4()),
                    "validCode": code,
                },
                client._principal,
                client._credential,
                revision="82197",
                legacy=True,
            )
            _, credited, two_factor, target = client._status(account)
            if not credited:
                fail("terminal-trust-readback")
            if two_factor:
                return client._challenge(account, password, target, "two-factor")
        else:
            result = client._http.post(
                client._host,
                "common.validcode.CheckValidCode",
                {
                    "account": self._target,
                    "type": "email",
                    "usage": "CheckTwoStepVerify",
                    "validCode": code,
                },
                client._principal,
                client._credential,
                revision="3421",
                legacy=True,
            )
            if result.get("valid") is not True:
                fail("two-factor-rejected")
        return client._login(account, password)

    def close(self) -> None:
        """Drop owned references; immutable Python strings cannot be reliably erased."""
        self._closed = True
        self._password = ""
        self._client._challenges.discard(self)

    def __enter__(self) -> Self:
        """Enter the challenge's lifetime scope."""
        self._check()
        return self

    def __exit__(self, *_exc: object) -> None:
        """Release any retained password reference."""
        self.close()


class Session(AbstractContextManager["Session"]):
    """One accepted account generation; server rejection closes its local streams."""

    # One immutable server identity is bound from the accepted Login response.
    def __init__(  # noqa: PLR0913, PLR0917
        self,
        http: AccountHTTP,
        destination: str,
        principal: str,
        token: str,
        session_id: str,
        user_id: int,
    ) -> None:
        """Bind server-approved identity and route to a fresh in-process generation."""
        self._http, self._host, self._principal = http, destination, principal
        self._token, self._session_id, self._user_id = token, session_id, user_id
        self._generation = object()
        self._closed = False
        self._streams: set[RawStream] = set()

    def _check(self, generation: object | None = None) -> None:
        if self._closed:
            fail("session-closed")
        if generation is not None and generation is not self._generation:
            fail("session-selection-binding")

    def _post(
        self, operation: str, data: Object, *, revision: str = "191204", legacy: bool = False
    ) -> Object:
        self._check()
        try:
            return self._http.post(
                self._host,
                operation,
                data,
                self._principal,
                self._token,
                session=self._session_id,
                revision=revision,
                legacy=legacy,
            )
        except MiboError as error:
            if str(error) == "session-rejected":
                self.close()
            raise

    def families(self) -> tuple[Family, ...]:
        """Read the current account's families; no cached global inventory is used."""
        data = self._post("family.manager.UserFamilyGet", {"_nouse": 0})
        result = tuple(
            Family(text(obj(row).get("familyId")), text(obj(row).get("name")), self._generation)
            for row in rows(data.get("families"))
        )
        if len({family.id for family in result}) != len(result):
            fail("family-duplicates")
        return result

    def devices(self, family: Family) -> tuple[Device, ...]:
        """Read bounded pages, rejecting duplicate devices and stalled continuations."""
        self._check(family._generation)
        result: list[Device] = []
        continuation = ""
        seen: set[str] = set()
        for _ in range(32):
            data = self._post(
                "device.list.BasicList",
                {
                    "familyId": family.id,
                    "limit": 128,
                    "offset": len(result),
                    "roomId": "-1",
                    "transferStr": continuation,
                },
            )
            page = rows(data.get("deviceList"))
            for value in page:
                row = obj(value)
                product = row.get("productId")
                result.append(
                    Device(
                        identifier(row.get("deviceId")),
                        text(row.get("deviceName")),
                        text(row.get("deviceModel")),
                        "" if product in (None, "") else text(product),
                        self._generation,
                    )
                )
            if len({device.id for device in result}) != len(result):
                fail("device-duplicates")
            more = flag(data.get("hasNextPage"))
            transfer = data.get("transferStr")
            if not isinstance(transfer, str) or len(transfer) > 8192:
                fail("inventory-continuation")
            if not more:
                return tuple(result)
            if not page or not transfer or transfer in seen:
                fail("inventory-stalled")
            seen.add(transfer)
            continuation = transfer
        return fail("inventory-page-limit")

    def availability(self, devices: tuple[Device, ...]) -> dict[str, bool]:
        """Read online/offline snapshots for at most 128 current-session devices."""
        if not 1 <= len(devices) <= 128:
            fail("status-selection")
        for device in devices:
            self._check(device._generation)
        ids = {device.id for device in devices}
        if len(ids) != len(devices):
            fail("status-selection")
        result: dict[str, bool] = {}
        for offset in range(0, len(devices), 64):
            batch = {device.id for device in devices[offset : offset + 64]}
            data = self._post(
                "device.list.DeviceBasicStatusGetForOpenPlatform",
                {"deviceIds": sorted(batch)},
                revision="3421",
                legacy=True,
            )
            for value in rows(data.get("devices"), 64):
                row = obj(value)
                device_id = text(row.get("deviceId"))
                status = row.get("status")
                if (
                    device_id not in batch
                    or device_id in result
                    or status not in ("online", "offline")
                ):
                    fail("status-binding")
                result[device_id] = status == "online"
            if not batch <= result.keys():
                fail("status-partial")
        return result

    def camera(self, device: Device) -> Camera:
        """Bind details and observed video subtypes to one current-session camera."""
        self._check(device._generation)
        data = self._post("device.list.DeviceDetailsInfoGetByDeviceId", {"deviceId": device.id})
        details = rows(data.get("deviceList"), 1)
        if len(details) != 1:
            fail("camera-detail-count")
        detail = obj(details[0])
        if detail.get("deviceId") != device.id or detail.get("deviceModel") != device.model:
            fail("camera-detail-binding")
        basic = self._basic(device)
        channels = rows(basic.get("channelList"), 1)
        if len(channels) != 1:
            fail("camera-channel-count")
        channel = obj(channels[0])
        channel_id = text(channel.get("channelId"))
        media = parse_json(text(channel.get("mediaConfig"), 32_768), 32_768)
        profiles: list[Profile] = []
        for value in rows(media.get("streamClarity"), 8):
            row = obj(value)
            subtype = integer(row.get("streamChannel"), 0, 1)
            if integer(row.get("imageSize"), -1, -1) != -1 or any(
                p.subtype == subtype for p in profiles
            ):
                fail("camera-profile")
            profiles.append(Profile(text(row.get("name"), 128), subtype, channel_id))
        if not profiles:
            fail("camera-profile-missing")
        return Camera(device, text(detail.get("version")), tuple(profiles), self._generation)

    def _basic(self, device: Device) -> Object:
        result = self._post(
            "device.info.BasicInfoGet", {"deviceId": device.id, "productId": device.product_id}
        )
        if result.get("deviceId") != device.id:
            fail("bootstrap-device-binding")
        return result

    def open_stream(
        self,
        camera: Camera,
        profile: Profile,
        parameters: VideoParameters,
        *,
        allowed_lan_hosts: tuple[str, ...] = (),
    ) -> RawStream:
        """Open one explicit profile; return owned H.264/AAC units without decoding."""
        self._check(camera._generation)
        self._check(camera.device._generation)
        if not any(profile is item for item in camera.profiles):
            fail("profile-selection-binding")
        self._streams = {stream for stream in self._streams if not stream.closed}
        if len(self._streams) >= 4:
            fail("stream-limit")
        config = self._post("common.service.GlobalConfigGet", {})
        basic = self._basic(camera.device)
        stream = RawStream.open(
            camera.device.id,
            profile.subtype,
            basic,
            config,
            parameters,
            self._user_id,
            allowed_lan_hosts,
        )
        self._streams.add(stream)
        return stream

    def close(self) -> None:
        """Close all camera sockets and drop tokens; remote revocation is not implied."""
        if self._closed:
            return
        self._closed = True
        for stream in self._streams:
            stream.close()
        self._streams.clear()
        self._token = self._session_id = ""

    def __enter__(self) -> Self:
        """Enter the session scope."""
        self._check()
        return self

    def __exit__(
        self,
        _type: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        """Close account-owned camera resources."""
        self.close()
