# ADR 0002: Use HTTPCore for controlled HTTP transport

- Status: Accepted
- Date: 2026-08-13

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

BOUNDARY will use **HTTPCore directly** for HTTP transport, through its public
custom network-backend API.

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

Transport will implement a small `AsyncNetworkBackend` wrapper that:

- accepts a prevalidated IP address at construction time;
- rejects non-IP constructor values via `ipaddress.ip_address()`;
- on `connect_tcp(host, port, ...)`, ignores `host` and dials the pinned IP;
- forwards `port`, `timeout`, `local_address`, and `socket_options` unchanged;
- performs no DNS resolution;
- refuses `connect_unix_socket` (UDS would bypass IP pinning);
- forwards `sleep` to the inner backend;
- propagates underlying networking exceptions unchanged.

Production code will use `httpcore.AnyIOBackend` as the inner backend.
Connections and pools will be constructed with `network_backend=` so pinning
uses only public HTTPCore APIs:

- `httpcore.AsyncNetworkBackend`
- `httpcore.AsyncNetworkStream`
- `httpcore.AnyIOBackend`
- `httpcore.AsyncHTTPConnection` / `httpcore.AsyncConnectionPool`

HTTPCore applies TLS SNI through `start_tls(..., server_hostname=...)`
independently of the `connect_tcp` host. Pinning the TCP dial therefore does
not weaken certificate hostname verification when the request origin host is
preserved.

### Redirects

HTTPCore does not follow redirects. BOUNDARY will treat 3xx responses as
terminal at the HTTPCore layer, then apply scope checks, re-resolve, revalidate,
and reconnect under the same pinning rules. Automatic redirect following from
HTTPX or any other client is out of scope.

### Destination selection

When multiple addresses pass policy, transport selects the first address from
`resolve_allowed_addresses`. Happy Eyeballs and connect-time address fallback
are out of scope; they would constitute a retry framework.

### Connection reuse

A single `AsyncConnectionPool` sharing one pinned backend would send every
origin to the same IP. Reuse is allowed only when scheme, host, port, and pinned
IP all match. Initial delivery opens one connection and closes it; keep-alive
under that key is a later slice.

### Minimum concepts

The initial architecture contains only:

- a pinned async network backend;
- controlled request transport;
- request limits / configuration when timeouts and size limits require it;
- a BOUNDARY response representation only when consuming or closing the
  HTTPCore stream creates a concrete need.

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

Implementation will add `httpcore[asyncio]` (which pulls `anyio` for
`AnyIOBackend`). This decision does not install that dependency by itself.

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

- BOUNDARY must implement redirect loops, size limits, and Host construction;
- connection reuse must be keyed by origin and pinned IP, not by hostname alone;
- `httpcore[asyncio]` becomes a runtime dependency when implementation starts.
