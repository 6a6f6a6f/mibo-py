# Contributing

Use Python 3.12+ and `uv`. Source, documentation, commits and pull requests use
US English. Use Conventional Commits and keep changes focused.

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest --cov --cov-report=term-missing
uv run pip-audit --skip-editable
uv build
git diff --check
```

Tests must be offline and synthetic, with no credentials, private account IDs,
private captures or real media. New protocol behavior needs both acceptance and
hostile-input rejection tests. Do not claim device compatibility from a build,
mock, inventory entry, product name, or another implementation's live result.
Record model, firmware, runtime, path and exact observed behavior separately.

Keep security controls intact: bound memory/work, enforce server authorization,
reject redirects/arbitrary destinations, and keep secrets/media out of exceptions.
Do not disable broad rule families or lower coverage to accommodate a change.
Document reverse-engineered fields, byte order, validation and ownership in code
and `docs/protocol.md`. No native decoders, player or camera-settings writer
belongs in this proof of concept without a separate scope decision.

A PR should explain what changed, why, validation, and risks. Explicitly describe
authentication, authorization, cryptography, network, secrets or data-protection
changes. Include only synthetic reproduction inputs in issues and PRs.
