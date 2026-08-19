# Controlled HTTP Transport Plan

- Status: Completed
- Branch: feat/http-transport
- Started: 2026-08-13
- Completed: 2026-08-13
- Implementation: `src/boundary/transport.py`

## Purpose

The HTTP transport sends scoped HTTP requests without performing an
uncontrolled second DNS lookup after address validation.

It sits on top of the completed Scope Engine and uses HTTPCore directly, as
decided in `docs/decisions/0002-controlled-http-transport.md`.

## Prerequisites

The Scope Engine already provides:

- strict HTTP/HTTPS target URL parsing;
- normalized `TargetUrl` and `Origin` value objects;
- exact origin allowlisting;
- `PUBLIC` and `LOCAL_LAB` address policies;
- `AddressResolver` and `resolve_allowed_addresses`;
- `resolve_allowed_redirect` for destination origin checks;
- `SystemAddressResolver` based on the running asyncio event loop;
- offline tests with zero public-Internet contact.

Transport remains responsible for:

- pinning connections to already validated IP addresses;
- preventing a second DNS lookup during connection establishment;
- preserving the original hostname for HTTP Host and TLS SNI;
- connection timeout;
- response size limits;
- redirect count and loop detection;
- connection reuse policy.

## Architecture

Grow a single module `src/boundary/transport.py` in the same style as
`src/boundary/scope.py`: functions and small cohesive types, no service layer.

Delivered concepts:

- `PinnedAsyncNetworkBackend`;
- `request_once` and `request_with_redirects`;
- `RequestLimits`;
- `TransportResponse`, `TransportError` and `TransportErrorCode`.

Required request flow:

1. Parse `TargetUrl`.
2. Require an allowed `Origin`.
3. Resolve the hostname using an `AddressResolver`.
4. Validate every returned IP using `resolve_allowed_addresses()`.
5. Select the first already validated destination IP.
6. Establish a TCP connection to that IP through the pinned backend.
7. Preserve `TargetUrl.host` for HTTP Host and TLS SNI / certificate hostname
   verification.
8. Send the HTTP request via HTTPCore.
9. Handle redirects manually through `resolve_allowed_redirect()`.
10. Re-resolve and revalidate every accepted redirect destination before
    connecting again.

HTTPCore is used through its public custom network-backend API:

- `httpcore.AsyncNetworkBackend`
- `httpcore.AsyncNetworkStream`
- `httpcore.AnyIOBackend` as the production inner backend
- `httpcore.AsyncConnectionPool` with `network_backend=`

`httpcore[asyncio]` is the single runtime dependency; no other dependency was
added.

## Non-goals for the milestone

Transport did not introduce:

- HTTPX;
- generic repository patterns;
- service layers;
- retry frameworks (`retries=0` on HTTPCore connections);
- plugin architecture;
- database persistence;
- logging frameworks;
- distributed workers;
- HTTP/2 extras, proxies, or Unix domain sockets;
- Happy Eyeballs or connect-time address fallback;
- CLI scan commands, passive rules, evidence, or reporting.

## Testing approach

- Add or update tests before implementing each slice.
- Slice A tests live in `tests/test_pinned_backend.py`.
- Later slices add focused transport tests under `tests/`.
- Inject a recording fake inner `AsyncNetworkBackend`; do not mock the pinning
  behavior under test.
- Autouse guards must keep `socket.getaddrinfo` and real sockets unused where
  the suite claims zero network I/O.
- Automated tests must never contact public Internet targets.
- Use deterministic local fixtures only.

## Delivery slices

### Slice A: Pinned TCP backend — completed

Slice A implements `PinnedAsyncNetworkBackend`, a subclass of
`httpcore.AsyncNetworkBackend` that dials a prevalidated IP and never resolves
DNS.

Behavior:

- store a prevalidated IP and an inner `AsyncNetworkBackend` at construction;
- reject non-IP constructor values with `ipaddress.ip_address()` so a hostname
  cannot be stored as the pin;
- on `connect_tcp(host, port, timeout=None, local_address=None,
  socket_options=None)`, call the inner backend with the pinned IP and the
  provided `port`, `timeout`, `local_address`, and `socket_options`;
- never pass the original hostname to the inner `connect_tcp()`;
- perform no DNS resolution inside the pinned backend;
- refuse `connect_unix_socket` because UDS would bypass IP pinning;
- forward `sleep` to the inner backend;
- propagate underlying networking exceptions unchanged;
- support both IPv4 and IPv6 literal pins.

#### Slice A non-goals

Slice A will not:

- send HTTP requests;
- perform TLS handshakes;
- construct Host headers or set SNI;
- follow redirects;
- define product timeout or response-size policy;
- implement connection pooling or reuse;
- install `httpcore` until implementation of this slice is approved;
- introduce a service class or repository.

#### Slice A acceptance criteria

- the original hostname is never used for `connect_tcp()` on the inner backend;
- the prevalidated IP is used instead;
- port is preserved;
- timeout, local-address, and socket-options arguments are forwarded;
- no DNS resolution occurs inside the pinned backend;
- underlying networking exceptions propagate;
- tests perform zero network I/O;
- the constructor rejects a non-IP address;
- `connect_unix_socket` is refused;
- IPv4 and IPv6 literal pins are both covered.

### Slice B: Controlled single HTTP request — completed

Slice B implements the first end-to-end scoped request using HTTPCore and the
pinned backend.

Behavior:

- run steps 1–8 of the required request flow;
- select the first address from `resolve_allowed_addresses`;
- construct HTTPCore with `http2=False`, `retries=0`, no `uds`, and no proxy;
- preserve `TargetUrl.host` for the Host header and TLS `server_hostname`;
- open one connection, send one request, then close;
- do not wrap HTTPCore’s response type unless tests demonstrate a concrete need.

#### Slice B non-goals

Slice B will not:

- follow redirects;
- enforce response-size limits beyond what is required to close the stream
  safely;
- reuse connections across requests;
- add Happy Eyeballs or connect fallback;
- add CLI or reporting integration.

#### Slice B acceptance criteria

- a scoped hostname target connects only through the pinned validated IP;
- Host and SNI use `TargetUrl.host`, not the pinned IP;
- disallowed origins and disallowed addresses fail before connect;
- HTTPCore connection retries remain disabled;
- tests cover success and rejection paths with zero public-Internet contact.

### Slice C: Timeouts and response-size limits — completed

Slice C adds explicit request limits.

Behavior:

- introduce a frozen `RequestLimits` value object with `max_body_bytes` plus
  connect, read, write and pool timeouts, each validated as `None`, zero, or a
  positive finite float;
- delegate timeout enforcement to HTTPCore through its timeout extension
  `{"timeout": {"connect": ..., "read": ..., "write": ..., "pool": ...}}`;
- consume the response body incrementally and enforce the mandatory
  `max_body_bytes` limit while reading, closing the stream on excess;
- introduce the frozen `TransportResponse` value object holding status, raw
  headers and the capped body.

#### Slice C non-goals

Slice C will not:

- add redirect following;
- add connection reuse;
- add concurrency or rate-limit workers;
- add a logging framework.

#### Slice C acceptance criteria

- connect, read, write and pool timeouts are applied through HTTPCore
  extensions;
- responses larger than the configured limit are rejected and the stream is
  closed;
- within-limit bodies are returned completely;
- tests cover timeout configuration mapping and size-limit boundary cases
  without public-Internet contact.

### Slice D: Manual redirect loop — completed

Slice D follows redirects under Scope Engine rules.

Behavior:

- treat HTTPCore 3xx responses as terminal at the library layer;
- when a redirect is accepted for following, call `resolve_allowed_redirect`;
- re-resolve and revalidate every accepted redirect destination before
  connecting;
- create a new pinned backend for the newly selected validated IP;
- enforce a hop limit and loop detection on normalized URLs;
- reject duplicate `Location` headers with
  `TransportErrorCode.INVALID_REDIRECT`;
- fail closed on malformed `Location` values rather than following them;
- preserve `UrlValidationError` and `ScopeValidationError` without swallowing
  them;
- never use HTTPCore or HTTPX automatic redirect following.

#### Slice D non-goals

Slice D will not:

- allow out-of-allowlist redirect destinations;
- skip address revalidation on redirect hops;
- introduce a redirect-specific exception enum without a concrete need shown by
  tests;
- add cookie jars or authentication helpers.

#### Slice D acceptance criteria

- in-allowlist redirects re-resolve, revalidate, and reconnect through a new
  pin;
- out-of-allowlist and unsafe `Location` values are rejected;
- hop-limit and loop cases fail closed;
- each accepted hop preserves Host/SNI from the hop’s `TargetUrl.host`;
- tests cover success, rejection, hop-limit, and loop cases offline.

### Slice E: Connection reuse identity and policy — deferred, not shipped

Slice E considered the identity under which a connection could ever be shared.
It did not deliver persistent pooling, and no reuse-key production surface was
retained.

Live behavior remains isolated:

- `request_once` uses one pool per request with
  `max_keepalive_connections=0` and `retries=0`.

If persistent pooling is ever introduced, a reuse identity would need to
include scheme, host, port, and pinned IP so that cross-origin and changed-pin
reuse stay excluded by construction.

#### Slice E non-goals

Slice E did not:

- implement persistent pooling, keep-alive lifecycle, or a pool cache;
- share one pinned backend across unrelated origins;
- add retry, backoff, or circuit-breaker frameworks;
- add proxies or HTTP/2 multiplexing policy;
- ship a `ConnectionReuseKey` / `connection_reuse_key` runtime surface.

#### Slice E acceptance criteria

- persistent pooling remains unimplemented;
- `request_once` stays isolated: one pool per request with
  `max_keepalive_connections=0` and `retries=0`;
- tests prove the isolated request path without public-Internet contact.

## Deferred: persistent connection pooling

Persistent connection pooling and keep-alive reuse are deferred, not
implemented.

An HTTPCore pool binds to one network backend, while BOUNDARY's backend is
pinned to one validated IP. Safe persistent reuse would require lifecycle
management keyed by origin and pinned IP. That machinery is not justified until
Discovery/Crawler work demonstrates a concrete performance need.

## Final security invariants

- no second DNS lookup happens between address validation and TCP connect: the
  pinned backend dials a prevalidated IP and never resolves;
- the pinned value must be an IP address; hostnames and malformed values are
  rejected at construction;
- Unix-domain sockets are refused, so pinning cannot be bypassed;
- the original hostname stays authoritative for HTTP Host semantics and TLS
  SNI / certificate hostname verification;
- every request carries a mandatory maximum body size, and the body is read
  incrementally so an oversized response is rejected before it is buffered;
- connect, read, write and pool timeouts are always applied through HTTPCore's
  timeout extension;
- redirects are never followed automatically; each hop revalidates origin,
  re-resolves DNS, validates every returned address, and pins a newly validated
  IP;
- hop limits, normalized-URL loop detection, duplicate `Location` headers and
  malformed `Location` values all fail closed;
- `UrlValidationError` and `ScopeValidationError` propagate unchanged;
- connection reuse is not implemented; each request uses an isolated pool;
- retries stay disabled (`retries=0`);
- tests run offline: autouse guards fail transport tests immediately on DNS
  resolution or real socket I/O.

## Test coverage

Offline transport tests, all passing:

- `tests/test_pinned_backend.py`: 17 tests;
- `tests/test_transport_request.py`: 38 tests;
- `tests/test_transport_redirects.py`: 26 tests.

Full suite: 235 tests passing, with no skipped tests.

## Definition of done for the milestone

Met:

- all slices A–E meet their acceptance criteria;
- relevant security boundaries have negative tests;
- `ruff format --check`, `ruff check`, `mypy` and `pytest` pass without skipped
  or weakened tests;
- documentation matches the implementation, including the deferred pooling
  decision;
- no secrets or sensitive evidence are exposed;
- automated tests never contact public Internet targets.
