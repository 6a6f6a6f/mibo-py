# Observed protocol and ownership

This describes an independent proof of concept, not a published vendor contract.
The reference playback cameras were iM3B-C. A separate iM3-C was identified in
authorized inventory; it must not inherit those playback results. The Python
[live test](live-test-2026-10-19.md) confirmed media for iM3B-C firmware
`2.800.00IB01X.0.R.240927`; iM3-C reported `2.800.00IB00N.0.R.220624` but was
offline. Model or inventory identification alone does not establish compatibility.

## Account layer

A caller provisions an application principal/credential, terminal UA, and video
parameters. `GetTwoStepVerifyState` must return actual booleans for
`terminalManageState`/`GrantingCreditFlag` and `on`/`off` for two-factor state.
Terminal trust is a separate gate. A challenge must bind back to the requested
account. Requesting email is explicit. Code submission consumes the challenge;
terminal-trust success is read back, and two-factor verification requires
`valid=true` before token exchange and login. Nothing is retried automatically.

Account POST signatures cover **uncompressed UTF-8 JSON**. Canonical lines are
method, `/pcs/v1/<operation>`, base64 MD5 body digest, content type, then
`x-pcs-apiver`, `x-pcs-client-ua`, `x-pcs-date`, `x-pcs-nonce`, optional
`x-pcs-session-id`, and `x-pcs-username`, each separated by LF, including a trailing
LF. HMAC-SHA256 uses the ASCII lowercase MD5 hex of the credential; the account
password variant applies one additional MD5-hex pass. Requests are then gzip
compressed. Revisions and content types differ for email/trust and device-status routes;
status uses revision 3421 with `application/json`. These fields are explicit in
the implementation and regression tests. Successful code-delivery and trust-grant
responses may omit their data object; authentication and inventory still require
their complete response schemas.

Only `app-br.easy4ipcloud.com` and `app-sp2.easy4ipcloud.com` HTTPS origins are
accepted, including an explicit default `:443` with an empty or root path. There
are no redirects, ambient proxies, or automatic HTTP retries.
Encoded and decoded bodies are each limited to one MiB. JSON nesting is bounded
to 24; duplicate keys, invalid UTF-8, nonfinite values and incorrect scalar types
are rejected. Service rejection `12002` invalidates that local account generation.
Other API failures do not become an unauthenticated retry or password fallback.

Families, devices and camera details carry an in-process generation. Profiles
must be the exact selection returned with those details. Server bootstrap is
fetched again for every open: local inventory is never an authorization grant.
Pagination is bounded to 32 pages of at most 128 devices, with duplicate-device,
empty-progress and repeated-continuation checks. Status is read-only and cannot
authorize a media open. This POC does not persist or restore account tokens.

## Signaling and destinations

Fresh `BasicInfoGet` must match the selected device. Credential envelopes are
AES-CBC/PKCS7 with the configured IV and ASCII lowercase MD5 hex of uppercase
device ID plus the observed `DAHUAKEY` suffix. Decrypted camera credentials are
never returned through the public inventory API.

Authenticated global configuration nominates one `p2p-v2` service at port 8800,
optionally one `p2p` alternate, under `easy4ipcloud.com`. Only public IPv4 DNS
answers are used. The connected UDP socket binds replies to the current peer.
Initial NFPOST registration is followed by online discovery and Info retrieval.
NF responses require one matching CSeq and one exact Content-Length; each
exchange has a six-second/64-datagram budget. XML is bounded and rejects DTD,
entity declarations and embedded NULs before parsing.

The advertised Info destination must be public and use port 8803. It may select
only the authenticated services' resolved pools. If a public shard falls outside
those pools, the already-used registration address is queried on 8803; the
unapproved address is never contacted. Info is AES-OFB encrypted under the
caller-provisioned key/IV and supplies fresh `randsalt` for the second registration.
This is an observed reference-client alternative, not a claim about vendor routing.

Public candidates must be public IPv4. LAN candidates require a separate
**caller-owned exact camera-host allowlist**, plus server advertisement and
RFC1918/unprivileged-port validation; at most two candidates are tried for two
seconds each. Empty allowlist disables LAN selection. The POC does not infer
subnet, gateway or DNS-server authorization and does not scan the LAN.

The candidate probe uses a complemented STUN-like message: 20-byte big-endian
header (type, length, `0x2112A442`, fresh 12-byte transaction), a 12-byte identity
attribute, and optionally a 12-byte IPv4 address attribute. Every wire byte is
XORed with `0xff`. Completion requires the discovered eight-byte peer identity
and a fresh local transaction or a peer transaction answered in that exchange.
Identity/transaction binding is not cryptographic peer authentication.

## PTCP and media

PTCP has a 24-byte big-endian header: marker at 0, send offset at 4, next receive
offset at 8, reserved zero at 12, flags at 13, window at 14, clock at 16, echo at
20. Offsets count **wrapped bytes**, not packets. The four-byte control exchange
must be acknowledged before a random proxy channel opens the camera's inner
loopback service (8086); loopback is payload to the confirmed camera, never a
host socket destination. A matching channel ID and `CONN` complete proxy open.

Requests split into at most 1280-byte chunks with a 12-byte channel wrapper.
Unacknowledged chunks have at most four attempts, 400 ms apart. Receive reordering
is bounded to 64 entries and a 65535-byte gap. Conflicting overlapping fragments,
foreign channels, excessive acknowledgements and offset overflow fail closed.

The inner stream interleaves HTTP-like responses and six-byte `$` envelopes
(channel byte plus a **big-endian u32** DHAV length). Control uses Private-Length;
Content-Length and Transfer-Encoding are rejected as ambiguous. Only the current
pending method-2 keepalive may receive an empty 200 response without an explicit
length. PLAY CSeq 1, close CSeq 3 and unsolicited replies retain strict framing.
Keepalive runs every 20 seconds while the caller actively consumes the stream.
First media must arrive within 14 seconds; subsequent inactivity is limited to
10 seconds. Returned units are pull-based and are not buffered in a background
thread; slow consumers can lose their connection.

DHAV uses a 24-byte header, bounded extensions, payload, and eight-byte trailer.
Its total length occurs at byte 12 and in the trailer in **little-endian** order.
The marker is `DHAV`; trailer is `dhav`. Header byte 22 is extension length;
byte 23 is the additive checksum of bytes 0-22 modulo 256, not authentication.
The raw 16-bit millisecond counter at bytes 20-21 wraps; the consumer handles
rollover, synchronization and presentation. Records are at most one MiB.

Accepted media categories are FC clear H.264, FD protected H.264 and F0 protected
AAC; F1 assist records are ignored by compressed-unit iteration. Extension tags
are walked by known size. B5 has size 44, version 1, a little-endian u24 clear
prefix and protected length, 16-byte seed, u16 verifier and 16-byte OFB IV.
The 32-byte media key is PBKDF2-SHA256, 20000 iterations, over ASCII uppercase
MD5 hex of `user:Login to <device>:password`, with the device ID as salt.
The verifier is CRC16 of SHA256(`01 : seed : key`) with literal colon separators.
It has only 16 bits and is not a strong MAC. AES-OFB applies only to the bounded
protected span. H.264 must have Annex B start framing. Audio requires the
observed 83 extension `[01 1a 04]` and one CRC-free MPEG-4 AAC-LC ADTS unit at
16 kHz mono, at most 8191 bytes. Unknown variants are rejected, not decoded.

## Lifetime and evidence

Client close closes all sessions/challenges. Session close or server rejection
closes its streams; each permits at most four active streams. A stream has one
consumer, for either original encrypted DHAV records or decrypted compressed
units. `with` guarantees local close when iteration ends early. Method-3 and
DISC are sent best-effort; server-side reclamation is not verified.

The SDK clears owned mutable media-key/reassembly buffers. It cannot securely
erase immutable Python strings/bytes or references retained by the caller.
Frames, response bodies, credentials, addresses and identifiers are never logged.
Errors contain fixed local codes and suppress underlying exception context.

Automated tests use synthetic credentials and media only. They prove offline
parser, state-machine and ownership behavior. The separately authorized
[live test](live-test-2026-10-19.md) confirmed iM3B-C DHAV and compressed H.264/AAC
on macOS ARM64. iM3-C streaming, other firmware, relay transport, codec decoders
and audible playback remain unverified. No account or camera access runs in CI.
