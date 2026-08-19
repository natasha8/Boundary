# ADR 0002: Use HTTPCore for controlled HTTP transport

- Status: Accepted and implemented (Milestone 2)
- Date: 2026-08-13
- Implementation: `src/boundary/transport.py`

## Context

BOUNDARY must send HTTP requests only after scope validation has accepted the
target origin and every resolved IP address. After that validation, the
transport must never perform an uncontrolled second DNS lookup: connecting by
hostname would reopen a DNS-rebinding TOCTOU window between check and connect.

The Scope Engine already provides:

- `parse_target_url` and immutable `TargetUrl` / `Origin` value objects;
- exact origin allowlisting;
- `AddressResolver` and `resolve_allowed_addresses`;
- `resolve_allowed_redirect` for destination origin checks.

The HTTP transport must own connection pinning, Host and TLS SNI semantics,
timeouts, response-size limits, redirect hop and loop control, and connection
reuse.

Candidates considered:

1. **HTTPX** — high-level client built on HTTPCore.
2. **HTTPCore directly** — low-level request sender with a public network-backend API.
3. **A hand-written HTTP/1.1 client** — sockets plus a custom parser.

## Decision

BOUNDARY uses **HTTPCore directly** for HTTP transport, through its public
custom network-backend API. The Controlled HTTP Transport is implemented; the
sections below describe the delivered behavior.

### Required flow

1. Parse `TargetUrl`.
2. Require an allowed `Origin`.
3. Resolve the hostname using an `AddressResolver`.
4. Validate every returned IP using `resolve_allowed_addresses()`.
5. Select an already validated destination IP (first address in resolver order).
6. Establish a TCP connection to that IP.
7. Preserve `TargetUrl.host` for HTTP Host semantics and TLS SNI / certificate
   hostname verification.
8. Send the HTTP request.
9. Handle redirects manually through `resolve_allowed_redirect()`.
10. Re-resolve and revalidate every accepted redirect destination before
    connecting.

### Pinned async network backend

Transport implements `PinnedAsyncNetworkBackend`, an `AsyncNetworkBackend`
wrapper that:

- accepts a prevalidated IP address at construction time;
- rejects non-IP constructor values via `ipaddress.ip_address()`;
- on `connect_tcp(host, port, ...)`, ignores `host` and dials the pinned IP;
- forwards `port`, `timeout`, `local_address`, and `socket_options` unchanged;
- performs no DNS resolution;
- refuses `connect_unix_socket` (UDS would bypass IP pinning);
- forwards `sleep` to the inner backend;
- propagates underlying networking exceptions unchanged.

Production code uses `httpcore.AnyIOBackend` as the inner backend. Pools are
constructed with `network_backend=` so pinning uses only public HTTPCore APIs:

- `httpcore.AsyncNetworkBackend`
- `httpcore.AsyncNetworkStream`
- `httpcore.AnyIOBackend`
- `httpcore.AsyncConnectionPool`

HTTPCore applies TLS SNI through `start_tls(..., server_hostname=...)`
independently of the `connect_tcp` host. Pinning the TCP dial therefore does
not weaken certificate hostname verification when the request origin host is
preserved.

### Request execution

`request_once` sends exactly one request over a pinned connection:

- it wraps `httpcore.AnyIOBackend` in a `PinnedAsyncNetworkBackend` and opens
  an isolated `httpcore.AsyncConnectionPool` per request, configured with
  `max_connections=1`, `max_keepalive_connections=0`, `http1=True`,
  `http2=False`, `retries=0`, and `uds=None`;
- the original hostname remains authoritative for HTTP Host semantics and TLS
  SNI: HTTPCore derives both from the request URL, and only the TCP dial uses
  the pinned IP;
- the response body is consumed incrementally from the streaming response under
  a mandatory maximum byte limit; exceeding it raises
  `TransportError(RESPONSE_TOO_LARGE)` and closes the stream without reading
  the remaining bytes;
- `RequestLimits` provides `max_body_bytes` plus `connect`, `read`, `write`,
  and `pool` timeout values, each validated as `None`, zero, or a positive
  finite float;
- timeout enforcement is delegated to HTTPCore through its timeout extension
  `{"timeout": {"connect": ..., "read": ..., "write": ..., "pool": ...}}`.
  BOUNDARY implements no timer of its own.

### Redirects

HTTPCore does not follow redirects, and no automatic redirect following from
HTTPX or any other client is used. `request_with_redirects` handles redirects
manually: 3xx responses are terminal at the HTTPCore layer, and every followed
redirect

- passes origin validation through `require_allowed_origin` on the destination
  produced by `resolve_allowed_redirect`;
- resolves DNS again for the destination host;
- validates every returned address through `resolve_allowed_addresses`;
- selects a newly validated pinned IP for the next hop.

Redirect handling is fail-closed:

- a hop limit (`max_redirects`) raises `TransportError(TOO_MANY_REDIRECTS)`;
- loop detection over normalized hop URLs raises
  `TransportError(REDIRECT_LOOP)`;
- duplicate `Location` headers are rejected with
  `TransportError(INVALID_REDIRECT)`;
- malformed `Location` values fail closed: non-ASCII bytes raise a decode
  error, and unsafe, credential-bearing, or out-of-allowlist values surface
  `UrlValidationError` / `ScopeValidationError` unchanged instead of being
  followed.

### Destination selection

When multiple addresses pass policy, transport selects the first address from
`resolve_allowed_addresses`. Happy Eyeballs and connect-time address fallback
are out of scope; they would constitute a retry framework.

### Connection reuse identity (design-only, deferred)

A single `AsyncConnectionPool` sharing one pinned backend would send every
origin to the same IP, so hostname-keyed reuse is unsafe. If persistent pooling
is ever introduced, reuse identity would have to include scheme, host, port,
and pinned IP — not hostname or IP alone.

**Persistent connection pooling and keep-alive reuse were never implemented
and remain deferred.** No reuse-key type is part of the runtime surface.
`request_once` remains isolated: one pool per request with
`max_keepalive_connections=0`, opened and closed around a single request.

Why the deferral: an HTTPCore pool binds to one network backend, while
BOUNDARY's backend is pinned to one validated IP. Safe persistent reuse
would require lifecycle management — per-identity pools, eviction, and
revalidation on pin change. That machinery is not justified until
Discovery/Crawler work demonstrates a concrete performance need.

### Delivered surface

The transport module contains only:

- `PinnedAsyncNetworkBackend`;
- `request_once` and `request_with_redirects`;
- `RequestLimits`, `TransportResponse`, `TransportError` /
  `TransportErrorCode`.

### Explicitly excluded

- HTTPX;
- generic repository patterns;
- service layers;
- retry frameworks (`retries=0` on HTTPCore connections);
- plugin architecture;
- database persistence;
- logging frameworks;
- distributed workers;
- HTTP/2 extras, proxies, and Unix domain sockets;
- Happy Eyeballs.

### Dependency

`httpcore[asyncio]` is the single runtime dependency (it pulls `anyio` for
`AnyIOBackend`).

## Why not HTTPX

HTTPX adds redirects, cookies, authentication helpers, content decoding, and
environment-based defaults. Those features conflict with BOUNDARY’s requirement
to revalidate every redirect hop and to keep request mutation explicit.

HTTPX also does not expose `network_backend` as a supported public constructor
parameter. Pinning would require reaching into private connection-pool state.
Unless that encapsulation is broken, HTTPX would re-resolve DNS at connect time
and reopen the rebinding window the Scope Engine closed.

## Why not a hand-written HTTP/1.1 parser

A custom parser would own chunked encoding, `Content-Length`, header folding,
connection lifecycle, TLS integration, and eventually HTTP/2. That is a large
security-sensitive protocol surface. The product principle of minimal
dependencies favors reusing a focused library that already implements request
sending, while BOUNDARY retains control of scope, pinning, redirects, and
limits.

## Consequences

Positive:

- DNS validation and TCP connect share one validated IP with no second lookup;
- Host header and TLS SNI remain tied to `TargetUrl.host`;
- redirects stay under explicit scope and address policy;
- HTTPCore’s public backend API avoids private HTTPX internals;
- the transport surface stays small and testable offline with a fake inner
  backend.

Negative:

- BOUNDARY owns redirect hop and loop control, response-size limits, and
  redirect revalidation;
- persistent connection reuse remains deferred, so every request still pays a
  full connect; a future reuse identity would have to include origin and
  pinned IP, not hostname alone;
- every request opens and closes its own connection, so repeated requests to
  one origin pay a full connect (and TLS handshake) each time;
- `httpcore[asyncio]` is a runtime dependency.
