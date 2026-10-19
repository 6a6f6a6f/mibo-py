# Copyright (c) 2026 Jojo. SPDX-License-Identifier: MIT
"""Inspect compressed-unit counts using caller-provisioned private configuration."""

import getpass
import sys
from pathlib import Path

from mibo_py import Application, Challenge, Client, MiboError, Session, VideoParameters
from mibo_py._validation import fail, integer, obj, parse_json, rows, text


def authenticate(client: Client, account: str) -> Session:
    """Prompt for credentials and explicitly approve each email-code delivery."""
    result = client.authenticate(account, getpass.getpass("Account password: "))
    for _ in range(4):
        if isinstance(result, Session):
            return result
        with result as challenge:
            if input("Request a verification email? [y/N] ").strip().lower() != "y":
                fail("verification-not-requested")
            challenge.request_code()
            result = challenge.submit(getpass.getpass("Verification code: "))
    if isinstance(result, Challenge):
        result.close()
    return fail("verification-limit")


def inspect(path: Path) -> None:
    """Open only the explicitly selected camera and count units without saving bytes."""
    with path.open("rb") as source:
        config = parse_json(source.read(65_537), 65_536)
    app = obj(config.get("application"))
    video = obj(config.get("video"))
    application = Application(
        text(app.get("principal")),
        text(app.get("credential"), 4096),
        text(app.get("terminal_ua_json"), 16_384),
        text(app.get("entry_host")),
    )
    parameters = VideoParameters(
        text(video.get("project_id"), 128),
        text(video.get("app_id"), 128),
        bytes.fromhex(text(video.get("credential_iv_hex"), 32)),
        bytes.fromhex(text(video.get("info_key_hex"), 64)),
        bytes.fromhex(text(video.get("info_iv_hex"), 32)),
    )
    allowed = tuple(text(value, 15) for value in rows(config.get("allowed_lan_hosts", []), 8))
    limit = integer(config.get("unit_limit", 100), 1, 10_000)
    family_index = integer(config.get("family_index"), 0, 127)
    device_index = integer(config.get("device_index"), 0, 4095)
    profile_index = integer(config.get("profile_index"), 0, 7)
    with (
        Client(application) as client,
        authenticate(client, text(config.get("account"))) as session,
    ):
        family = session.families()[family_index]
        devices = session.devices(family)
        print(f"Inventory devices: {len(devices)}")  # noqa: T201 -- Explicit CLI output, no identifiers.
        camera = session.camera(devices[device_index])
        counts = {"h264": 0, "aac": 0}
        with session.open_stream(
            camera, camera.profiles[profile_index], parameters, allowed_lan_hosts=allowed
        ) as stream:
            for count, unit in enumerate(stream, 1):
                counts[unit.codec] += 1
                if count >= limit:
                    break
        print(f"Compressed units: h264={counts['h264']} aac={counts['aac']}")  # noqa: T201


CLI_ARGUMENT_COUNT = 2


def main() -> int:
    """Report only normalized local errors, never raw network or configuration values."""
    if len(sys.argv) != CLI_ARGUMENT_COUNT:
        print("Usage: uv run python examples/inspect_stream.py /private/path/config.local.json")  # noqa: T201
        return 2
    try:
        inspect(Path(sys.argv[1]))
    except MiboError as error:
        print(f"Operation failed: {error}", file=sys.stderr)  # noqa: T201
        return 1
    except (OSError, ValueError, IndexError, EOFError):
        print("Configuration or input failed.", file=sys.stderr)  # noqa: T201
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
