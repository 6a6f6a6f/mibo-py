# Repository guidance

This is an unofficial, independent protocol proof of concept. Read README.md,
SECURITY.md and docs/protocol.md before changing account or media boundaries.

Use uv, US English and Conventional Commits. Preserve Ruff ALL, strict mypy,
locked dependencies and the coverage gate. Run formatting verification, lint,
types, offline tests and git diff --check before committing. Test new behavior
with synthetic acceptance and rejection vectors; CI must never use vendor
credentials or cameras.

Treat every response, endpoint, datagram and media record as hostile. Preserve
server authentication, authorization and account/session/device binding. Never
bundle vendor secrets, private captures, camera media, or application-extraction
helpers. Do not put secrets, media, addresses or identifiers into errors/logs.

Keep the client synchronous and single-thread-owned. Preserve bounded buffers,
work, retries, candidates and explicit cleanup. No player, decoder, automatic
reconnect or persistent camera settings. Keep protocol notes aligned with code.
Distinguish reference-client observations, offline Python checks and live Python
acceptance. Do not generalize device/firmware support from offline tests.
