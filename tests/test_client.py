# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Authentication gates, identity binding, pagination, and explicit lifetime checks."""

from collections.abc import Callable

import pytest

from mibo_py import Challenge, Client, MiboError, Profile, Session
from mibo_py._crypto import media_key
from mibo_py._http import AccountHTTP
from mibo_py._validation import Object
from tests.helpers import ANNEX_B, APPLICATION, PARAMETERS, PeerSocket, basic, configuration


def install(monkeypatch: pytest.MonkeyPatch, handler: Callable[[str, Object], Object]) -> list[str]:
    calls: list[str] = []

    def post(
        _http: AccountHTTP,
        _destination: str,
        operation: str,
        data: Object,
        _principal: str,
        _credential: str,
        **_options: object,
    ) -> Object:
        calls.append(operation)
        return handler(operation, data)

    monkeypatch.setattr(AccountHTTP, "post", post)
    return calls


def defaults(operation: str, _data: Object) -> Object:
    responses: dict[str, Object] = {
        "user.account.GetTwoStepVerifyState": {
            "terminalManageState": False,
            "GrantingCreditFlag": False,
            "state": "off",
        },
        "user.account.GetToken": {
            "token": "synthetic-token",
            "username": "synthetic-user",
            "sessionId": "synthetic-session",
            "entryUrlV2": "https://app-br.easy4ipcloud.com/",
        },
        "user.account.Login": {"userId": 1},
        "family.manager.UserFamilyGet": {
            "families": [{"familyId": "synthetic-family", "name": "Synthetic"}]
        },
        "device.list.BasicList": {
            "deviceList": [
                {"deviceId": "synthetic", "deviceName": "Synthetic", "deviceModel": "iM3B-C"}
            ],
            "hasNextPage": False,
            "transferStr": "",
        },
        "device.list.DeviceDetailsInfoGetByDeviceId": {
            "deviceList": [
                {
                    "deviceId": "synthetic",
                    "deviceModel": "iM3B-C",
                    "version": "2.800.00IB01X.0.R.240927",
                }
            ]
        },
        "device.info.BasicInfoGet": basic(),
        "common.service.GlobalConfigGet": configuration(),
    }
    return responses.get(operation, {})


def login(client: Client) -> Session:
    result = client.authenticate("synthetic@example.invalid", "synthetic-password")
    assert isinstance(result, Session)
    return result


def test_authentication_and_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install(monkeypatch, defaults)
    with Client(APPLICATION) as client, login(client) as session:
        family = session.families()[0]
        devices = session.devices(family)
        camera = session.camera(devices[0])
        assert camera.firmware == "2.800.00IB01X.0.R.240927"
        assert camera.profiles[0].subtype == 0
        assert len(devices) == 1
        assert "synthetic-token" not in repr(session)
    assert calls[:3] == [
        "user.account.GetTwoStepVerifyState",
        "user.account.GetToken",
        "user.account.Login",
    ]
    with pytest.raises(MiboError, match="session-closed"):
        session.families()
    with pytest.raises(MiboError, match="client-closed"):
        client.authenticate("account", "password")
    client.close()


def test_two_factor_requires_explicit_valid_true(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(operation: str, data: Object) -> Object:
        if operation == "user.account.GetTwoStepVerifyState":
            return {
                "terminalManageState": False,
                "GrantingCreditFlag": False,
                "state": "on",
                "account": "synthetic@example.invalid",
            }
        if operation == "common.validcode.CheckValidCode":
            return {"valid": False}
        return defaults(operation, data)

    calls = install(monkeypatch, handler)
    with Client(APPLICATION) as client:
        challenge = client.authenticate("synthetic@example.invalid", "password")
        assert isinstance(challenge, Challenge)
        assert calls == ["user.account.GetTwoStepVerifyState"]
        challenge.request_code()
        with pytest.raises(MiboError, match="already-requested"):
            challenge.request_code()
        with pytest.raises(MiboError, match="two-factor-rejected"):
            challenge.submit("123456")
        with pytest.raises(MiboError, match="challenge-closed"):
            challenge.submit("123456")
        assert "user.account.GetToken" not in calls
        assert not challenge._password


def test_terminal_trust_then_separate_two_factor(monkeypatch: pytest.MonkeyPatch) -> None:
    trusted = False

    def handler(operation: str, data: Object) -> Object:
        nonlocal trusted
        if operation == "user.account.GetTwoStepVerifyState":
            return {
                "terminalManageState": True,
                "GrantingCreditFlag": trusted,
                "state": "on",
                "account": "synthetic@example.invalid",
            }
        if operation == "user.account.GrantingCredit":
            trusted = True
        if operation == "common.validcode.CheckValidCode":
            return {"valid": True}
        return defaults(operation, data)

    install(monkeypatch, handler)
    with Client(APPLICATION) as client:
        first = client.authenticate("synthetic@example.invalid", "password")
        assert isinstance(first, Challenge)
        assert first.kind == "terminal-trust"
        second = first.submit("123456")
        assert isinstance(second, Challenge)
        assert second.kind == "two-factor"
        session = second.submit("123456")
        assert isinstance(session, Session)


@pytest.mark.parametrize(
    "patch",
    [
        {"terminalManageState": "false"},
        {"state": []},
        {"GrantingCreditFlag": None},
        {"state": "on", "account": "foreign@example.invalid"},
    ],
)
def test_authentication_rejects_missing_or_unbound_gates(
    monkeypatch: pytest.MonkeyPatch, patch: Object
) -> None:
    def handler(operation: str, data: Object) -> Object:
        return defaults(operation, data) | patch

    calls = install(monkeypatch, handler)
    with Client(APPLICATION) as client, pytest.raises(MiboError):
        client.authenticate("synthetic@example.invalid", "password")
    assert "user.account.GetToken" not in calls


def test_client_close_erases_pending_challenge_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    install(
        monkeypatch,
        lambda _op, _data: {
            "terminalManageState": True,
            "GrantingCreditFlag": False,
            "state": "off",
            "account": "account",
        },
    )
    client = Client(APPLICATION)
    challenge = client.authenticate("account", "password")
    assert isinstance(challenge, Challenge)
    client.close()
    assert not challenge._password
    with pytest.raises(MiboError):
        challenge.request_code()


def test_cross_session_selection_rejected_before_http(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install(monkeypatch, defaults)
    with Client(APPLICATION) as client:
        first, second = login(client), login(client)
        family = first.families()[0]
        devices = first.devices(family)
        camera = first.camera(devices[0])
        before = len(calls)
        with pytest.raises(MiboError, match="session-selection-binding"):
            second.devices(family)
        with pytest.raises(MiboError, match="session-selection-binding"):
            second.camera(devices[0])
        with pytest.raises(MiboError, match="session-selection-binding"):
            second.open_stream(camera, camera.profiles[0], PARAMETERS)
        assert len(calls) == before


def test_bounded_inventory_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    offsets: list[object] = []

    def handler(operation: str, data: Object) -> Object:
        if operation != "device.list.BasicList":
            return defaults(operation, data)
        offset = data["offset"]
        offsets.append(offset)
        return {
            "deviceList": [
                {
                    "deviceId": f"synthetic-{offset}",
                    "deviceName": "Synthetic",
                    "deviceModel": "iM3-C",
                    "productId": "",
                }
            ],
            "hasNextPage": offset == 0,
            "transferStr": "next",
        }

    install(monkeypatch, handler)
    with Client(APPLICATION) as client:
        session = login(client)
        assert len(session.devices(session.families()[0])) == 2
    assert offsets == [0, 1]


@pytest.mark.parametrize("foreign", [False, True])
def test_inventory_and_status_binding(monkeypatch: pytest.MonkeyPatch, *, foreign: bool) -> None:
    def handler(operation: str, data: Object) -> Object:
        if operation == "device.list.DeviceBasicStatusGetForOpenPlatform":
            return {
                "devices": [{"deviceId": "foreign" if foreign else "synthetic", "status": "online"}]
            }
        return defaults(operation, data)

    install(monkeypatch, handler)
    with Client(APPLICATION) as client:
        session = login(client)
        devices = session.devices(session.families()[0])
        if foreign:
            with pytest.raises(MiboError):
                session.availability(devices)
        else:
            assert session.availability(devices) == {"synthetic": True}
        with pytest.raises(MiboError):
            session.availability(devices + devices)


def test_session_rejection_invalidates_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(operation: str, data: Object) -> Object:
        if operation == "family.manager.UserFamilyGet":
            message = "session-rejected"
            raise MiboError(message)
        return defaults(operation, data)

    install(monkeypatch, handler)
    with Client(APPLICATION) as client:
        session = login(client)
        with pytest.raises(MiboError, match="session-rejected"):
            session.families()
        assert session._closed
        assert not session._token


def test_account_to_compressed_stream_and_stream_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = install(monkeypatch, defaults)
    sockets: list[PeerSocket] = []

    def open_peer(_source: object, _allowed: object) -> tuple[PeerSocket, str]:
        sock = PeerSocket(media_key("admin", "synthetic", "secret"))
        sockets.append(sock)
        return sock, "synthetic-salt"

    monkeypatch.setattr("mibo_py.stream.open_peer", open_peer)
    with Client(APPLICATION) as client:
        session = login(client)
        camera = session.camera(session.devices(session.families()[0])[0])
        profile = camera.profiles[0]
        with pytest.raises(MiboError, match="profile-selection-binding"):
            session.open_stream(
                camera, Profile(profile.name, profile.subtype, profile.channel_id), PARAMETERS
            )
        with session.open_stream(camera, profile, PARAMETERS) as stream:
            assert next(iter(stream)).data == ANNEX_B
        streams = [session.open_stream(camera, profile, PARAMETERS) for _ in range(4)]
        with pytest.raises(MiboError, match="stream-limit"):
            session.open_stream(camera, profile, PARAMETERS)
        assert calls.count("common.service.GlobalConfigGet") == 5
        session.close()
        assert all(item.closed for item in streams)
        assert all(sock.closed for sock in sockets)
