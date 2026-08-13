# Controlled HTTP Transport Plan

- Status: Planned
- Branch: feat/http-transport
- Started: 2026-08-13

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

Initial concepts only:

- a pinned async network backend;
- controlled request transport;
- request limits / configuration when Slice C needs them;
- a BOUNDARY response representation only when size limits or redirect handling
  require consuming or closing the HTTPCore stream.

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
- `httpcore.AsyncHTTPConnection` / `httpcore.AsyncConnectionPool` with
  `network_backend=`

Implementation will add `httpcore[asyncio]` when Slice A coding begins. This
plan document does not install dependencies.

## Non-goals for the milestone

Transport will not introduce:

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

### Slice A: Pinned TCP backend

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

### Slice B: Controlled single HTTP request

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

### Slice C: Timeouts and response-size limits

Slice C adds explicit request limits.

Behavior:

- introduce a frozen `RequestLimits` value object with connect, read, and write
  timeouts plus a maximum response body size in bytes;
- map timeouts onto HTTPCore request extensions
  `{"timeout": {"connect": ..., "read": ..., "write": ...}}`;
- enforce the body-size limit while reading the response stream and close the
  stream on excess;
- introduce a small BOUNDARY response value object only if needed to hold
  capped bytes together with status and headers.

#### Slice C non-goals

Slice C will not:

- add redirect following;
- add connection reuse;
- add concurrency or rate-limit workers;
- add a logging framework.

#### Slice C acceptance criteria

- connect, read, and write timeouts are applied through HTTPCore extensions;
- responses larger than the configured limit are rejected and the stream is
  closed;
- within-limit bodies are returned completely;
- tests cover timeout configuration mapping and size-limit boundary cases
  without public-Internet contact.

### Slice D: Manual redirect loop

Slice D follows redirects under Scope Engine rules.

Behavior:

- treat HTTPCore 3xx responses as terminal at the library layer;
- when a redirect is accepted for following, call `resolve_allowed_redirect`;
- re-resolve and revalidate every accepted redirect destination before
  connecting;
- create a new pinned backend for the newly selected validated IP;
- enforce a hop limit and loop detection on normalized URLs;
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

### Slice E: Connection reuse policy

Slice E allows keep-alive only under a strict key.

Behavior:

- reuse a connection only when scheme, host, port, and pinned IP all match;
- refuse cross-origin reuse;
- refuse reuse when the pinned IP differs even if the hostname matches;
- keep `retries=0`;
- do not introduce a generic pool service beyond what HTTPCore already provides
  for a single keyed connection.

#### Slice E non-goals

Slice E will not:

- share one pinned backend across unrelated origins;
- add retry, backoff, or circuit-breaker frameworks;
- add proxies or HTTP/2 multiplexing policy.

#### Slice E acceptance criteria

- matching origin and pinned IP may reuse a keep-alive connection;
- a different origin or different pinned IP opens a new connection;
- tests prove reuse eligibility and refusal without public-Internet contact.

## Definition of done for the milestone

The milestone is complete when:

- all slices A–E meet their acceptance criteria;
- relevant security boundaries have negative tests;
- checks pass without skipped or weakened tests;
- documentation matches the implementation;
- no secrets or sensitive evidence are exposed;
- automated tests still never contact public Internet targets.
