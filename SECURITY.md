# Security policy

This is an experimental protocol proof of concept, not a supported security
product. No release currently carries a production-security guarantee.

Do not open public issues containing credentials, identifiers, camera addresses,
private captures, images, audio, application parameters, or account responses.
For a suspected vulnerability, use GitHub private vulnerability reporting when
available, or request a private contact channel without including sensitive data.
Never attach live material to demonstrate a parser bug: provide a synthetic
reproducer instead. Do not test accounts/cameras without the owner's permission.

## Lightweight threat model

| Threat | Boundary and control | Remaining limitation |
| --- | --- | --- |
| Spoofing | HTTPS validation, server auth gates, fresh bootstrap, connected UDP, probe transaction/identity binding | Vendor UDP identity is not cryptographic peer authentication. |
| Tampering | Canonical signatures, strict lengths/checksums/extensions, bound endpoints | OFB and the 16-bit verifier do not provide strong media integrity. |
| Repudiation | Explicit email, code submission, profile selection and close | This POC deliberately has no persistent audit log or recorder. |
| Information disclosure | No media/credential logging, normalized errors, no secret persistence, secret-bearing repr disabled | Python immutable values and caller-owned output can remain in memory. |
| Denial of service | Size, depth, page, stream, gap, retry and exchange limits | OS DNS deadlines and consumer execution time are outside library control. |
| Elevation of privilege | Separate trust/2FA gates, server-authorized inventory/bootstrap and local generation checks | Same-process Python code is fully trusted; generation tags are not authorization. |

The library does not expose an HTTP service or credentials to other users. A
consumer that adds a server must implement its own authentication, authorization,
tenant boundaries, rate limiting and output protection. Do not expose generic
internal protocol calls as unauthenticated endpoints.

## Dependency and publishing policy

The only runtime dependency is `cryptography` (Apache-2.0 OR BSD-3-Clause), used
for AES rather than a handwritten primitive. Its public source and maintenance
history are at https://github.com/pyca/cryptography. Transitive versions and hashes
are recorded in `uv.lock`; CI audits the installed lockfile environment with
`pip-audit` and fails on known vulnerabilities. Offline tests do not establish
absence of vulnerabilities. Review changes to dependencies and lockfiles.

Ruff `ALL`, strict typing, formatter verification, and offline tests run in CI.
Lint exceptions are narrow and explained in configuration or adjacent comments;
new blanket ignores, untyped boundary data and silently weakened checks are not
accepted. Raw wire offsets may remain numeric where the protocol layout explains
them. Public API input lists retain explicit fields rather than hiding them in
an untyped options dictionary.

No action publishes packages, stores vendor credentials, logs in to the cloud,
or opens a real camera in CI. Production distribution, service terms, trademark
rights and H.264/AAC patent obligations require their own review; the project's
MIT source license does not resolve them.
