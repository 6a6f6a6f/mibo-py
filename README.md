<p align="center">
  <a href="https://jojo.dev.br/">
    <img src="docs/assets/jojos-shenanigans.svg" alt="Jojo's Shenanigans" width="128" height="128">
  </a>
</p>

<h1 align="center">mibo-py</h1>

<p align="center">
  An independent protocol proof of concept by
  <a href="https://jojo.dev.br/">Jojo's Shenanigans</a>.
</p>

An **unofficial, independent, experimental** Python proof of concept for doing
useful work with Mibo camera protocols from the client machine. It uses `uv`
and requires Python 3.12 or newer. No backend, vendor runtime, Android emulator,
native media decoder, or playback application is included. Account and signaling
operations still depend on the vendor cloud services.

> **No affiliation.** This project is not affiliated with, endorsed by, sponsored
> by, or supported by Intelbras, Mibo, Dahua, Imou, Lechange, their affiliates,
> OEM/white-label partners, or any camera or cloud-service manufacturer or operator.
> Product and company names identify observed interoperability only. All trademarks
> belong to their respective owners. This is not an official SDK.

## Scope

- Explicit account login, terminal-trust and email two-factor challenges.
- Account-scoped families, bounded paginated device inventory, online/offline status.
- Device details and explicit selection of advertised video quality profiles.
- Fresh camera bootstrap, UDP signaling, candidate confirmation, PTCP proxy transport.
- Raw DHAV records or decrypted compressed H.264 Annex B / AAC ADTS units.
- Application keepalive and best-effort remote close, with deterministic local cleanup.

There is no player, codec decoder, transcoding, recording feature, automatic
reconnect, PTZ, firmware update, camera binding, or persistent settings writer.
Read-only controls and stream profile selection are demonstrated. Unobserved
commands are not guessed. Failure requires an explicit new operation.

"Raw" has two precise meanings here: `stream.records()` yields validated DHAV
records **with the vendor media encryption still present**; iterating `stream`
yields **decrypted compressed** access units. Neither mode yields pixels or PCM.
The 16-bit `source_counter_ms` is the camera's wrapping source counter, not a
wall clock or ready-to-use presentation timestamp. Decode and synchronization
belong to the consumer.

## Compatibility and evidence

| Model | Firmware | Evidence from the reference research |
| --- | --- | --- |
| Intelbras iM3B-C | `2.800.00IB01X.0.R.240927` | Authorized independent reference client delivered video and audio; public candidate path observed. |
| Intelbras iM3-C | Not recorded in the public evidence | Owner identified the older camera model; authorized reference client delivered its video over a LAN candidate. |

These are **reference-client observations**, not live acceptance of this Python
port. The Python implementation is checked with synthetic offline tests. No live
camera test of this port has been performed. No claim is made for other firmware,
models, account regions, NAT topologies, service changes, or audio/video playback.
The iM3-C firmware must be recorded before making a firmware-specific claim.

The implementation accepts the observed wire formats rather than guessing
formats from a product name. An unlisted camera is not automatically compatible.
Unknown protection extensions, unsupported codec configurations and ambiguous
framing fail explicitly. Current account origins are limited to the two observed
Brazil service hosts. Public relay and IPv6 transports are not implemented.

## Install and develop

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --cov --cov-report=term-missing
uv run pip-audit --skip-editable
uv build
```

The lockfile pins transitive dependencies. Ruff enables `ALL`, with narrowly
explained exceptions in `pyproject.toml`; `mypy` uses strict mode and prohibits
explicit `Any`. CI runs checks on Python 3.12 and 3.13 across Linux, macOS and
Windows. CI never receives account credentials or contacts a camera.

## Provisioning is a prerequisite

The caller must supply authorized application credentials, a terminal UA, and
vendor video parameters. **This repository does not contain vendor secrets or
extract them from applications, devices, accounts, or another user's session.**
A normal account password alone is not enough for the demonstrated protocol.
You are responsible for obtaining permission to use the service and supplying
these parameters lawfully. There is no claim of a generally available public
vendor provisioning API.

Keep configuration outside the repository and outside logs. Do not paste live
values into issues or command-line arguments. `Application` and `VideoParameters`
disable field-based representations, but Python strings and immutable byte
objects cannot be reliably erased. Dropping references is not secure zeroization.

## Example

`examples/inspect_stream.py` reads a caller-selected, private JSON configuration
file and prompts for the account password and any verification code. It displays
only fixed progress labels and counts; it never prints device identifiers,
addresses, tokens, response bodies, or media. Choose a device and profile by
inventory index in the private configuration. It opens only the selected camera.

```sh
uv run python examples/inspect_stream.py /path/outside/repository/config.local.json
```

Configuration shape (all values below are synthetic placeholders):

```json
{
  "application": {
    "entry_host": "app-br.easy4ipcloud.com",
    "principal": "synthetic-principal",
    "credential": "synthetic-credential",
    "terminal_ua_json": "{\"terminalId\":\"synthetic-terminal\",\"ttid\":\"synthetic-type\"}"
  },
  "video": {
    "project_id": "synthetic-project",
    "app_id": "synthetic-app",
    "credential_iv_hex": "00000000000000000000000000000000",
    "info_key_hex": "0000000000000000000000000000000000000000000000000000000000000000",
    "info_iv_hex": "00000000000000000000000000000000"
  },
  "account": "synthetic@example.invalid",
  "family_index": 0,
  "device_index": 0,
  "profile_index": 0,
  "allowed_lan_hosts": [],
  "unit_limit": 100
}
```

These placeholders do not authorize any account. Reuse a stable caller-owned
terminal identity; the SDK does not invent a trusted terminal or bypass 2FA.
Code delivery is an explicit action and requires confirmation in this example.

For LAN candidates, set `allowed_lan_hosts` to the actual camera IPv4 addresses
you authorize. Empty means **public candidates only**. The library considers at
most two server-advertised candidates whose hosts are also explicitly allowed,
with unprivileged ports and RFC1918 addresses. It never scans a subnet. Do not
allowlist a router, DNS server, or unrelated host. Public candidate selection
still requires the discovered identity and a fresh matching probe transaction;
that binding is not cryptographic peer authentication.

Library lifetime:

```python
from mibo_py import Challenge, Client

# application and video_parameters come from your private provisioning.
with Client(application) as client:
    result = client.authenticate(account, password)
    # Handle Challenge.request_code()/submit() explicitly before continuing.
    if isinstance(result, Challenge):
        result.close()
        raise RuntimeError("Explicit verification required")
    with result as session:
        family = session.families()[0]
        device = session.devices(family)[device_index]
        camera = session.camera(device)
        with session.open_stream(
            camera,
            camera.profiles[profile_index],
            video_parameters,
            allowed_lan_hosts=allowed_lan_hosts,
        ) as stream:
            for unit in stream:
                consume_compressed_bytes(unit.codec, unit.data, unit.source_counter_ms)
```

This is a synchronous, single-thread-owned, pull-based POC. Consume promptly:
while your code is paused, it cannot service UDP acknowledgements or keepalives.
No background queue hides loss or reconnects. Use `with` even when breaking early.
At most four streams belong to one session. Closing a client or rejected session
closes its streams. Local close does not prove remote resource reclamation.

## Security and limitations

Only access accounts and cameras you own or are explicitly authorized to use.
The SDK preserves server authentication and authorization; local generation
checks prevent accidental stale/cross-session selection but are not a security
boundary against code running inside the same Python process.

Network responses and media are hostile inputs: HTTPS destinations are
allowlisted, redirects and ambient proxies are unused, gzip/JSON/UDP/XML/PTCP
buffers and deadlines are bounded, XML declarations are rejected, and the
advertised Info address cannot expand the authenticated DNS pools. MD5, SHA-1,
CBC and OFB reproduce legacy protocol formats; the short media verifier is not
a strong MAC, and OFB does not authenticate media. This project cannot repair
the vendor protocol's security properties.

DNS lookup uses the operating system resolver; its timeout is OS-controlled.
Credentials and decrypted bytes can remain in process memory. The caller is
responsible for secrets storage, output protection, resource budgets, and any
external decoder's security. Do not expose this client as an unauthenticated
network service. See [SECURITY.md](SECURITY.md) and [protocol notes](docs/protocol.md).

## Research

This proof of concept builds on the Mibo protocol research behind Noctua by
[Jojo's Shenanigans](https://jojo.dev.br/):

1. [From APK to first frame: inside Mibo's protocol](https://jojo.dev.br/blog/mibo-apk-to-first-frame/)
   ([Portuguese](https://jojo.dev.br/pt-br/blog/mibo-apk-to-first-frame/)).
2. [Inside Mibo, part 2: P2P tunnels, native decoders, and the birth of Noctua](https://jojo.dev.br/blog/mibo-p2p-native-noctua/)
   ([Portuguese](https://jojo.dev.br/pt-br/blog/mibo-p2p-native-noctua/)).

The articles describe the reference research and Noctua implementation. Their
live results do not establish live-camera acceptance of this Python port.

## License

MIT for this project's source. No proprietary code, vendor runtime, private
captures, live camera media, account credentials, or codec binaries are shipped.
The source license does not grant rights to use third-party services, brands,
or codec patents. No package is automatically published to PyPI.
