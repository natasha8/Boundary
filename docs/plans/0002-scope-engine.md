# Scope Engine Plan

- Status: In progress
- Branch: feat/scope-engine
- Started: 2026-08-07

## Purpose

The Scope Engine decides whether a target may be processed by BOUNDARY.

It must reject malformed or ambiguous input before any DNS resolution or
network request occurs.

## Delivery slices

### Slice A: Target URL parsing — complete

- accept absolute HTTP and HTTPS URLs;
- reject unsupported schemes;
- reject embedded credentials;
- reject missing hosts;
- reject invalid or explicitly empty ports;
- reject ambiguous hosts (`INVALID_HOST`), including empty DNS labels and
  percent-encoded hostnames;
- reject unsafe raw characters;
- normalize scheme and host casing;
- normalize default ports;
- accept a single trailing DNS dot on hostnames;
- support localhost, IPv4 literals, bracketed IPv6 literals and ASCII
  Punycode hostnames;
- preserve raw paths and queries without percent-decoding or path-segment
  normalization;
- remove fragments because they are not sent in HTTP requests.

### Slice B: Origin allowlist — complete

- represent an immutable, hashable `Origin` value object (`scheme`, `host`,
  `port`);
- expose `TargetUrl.origin` returning that value object;
- allow only exact configured origins via `require_allowed_origin`;
- compare origins by scheme, normalized host and effective port only;
- treat default ports as already normalized (`https://example.com` and
  `https://example.com:443` are the same origin);
- keep non-default ports distinct;
- keep HTTP and HTTPS origins distinct;
- support IPv4 and bracketed IPv6 origins;
- reject every target when the allowlist is empty;
- raise `ScopeValidationError` with `ScopeErrorCode.ORIGIN_NOT_ALLOWED`
  for disallowed origins.

Exact matching only: no wildcard matching, no suffix matching, and no
implicit subdomain allowance. A host such as `api.example.com` is allowed
only when that exact origin is configured.

### Slice C: Address policy — complete

Slice C validates already-resolved IP addresses. It does not perform DNS
resolution and does not perform network requests.

- expose `AddressPolicy` as a `StrEnum` with `PUBLIC` and `LOCAL_LAB`;
- extend `ScopeErrorCode` with `INVALID_IP_ADDRESS` and
  `ADDRESS_NOT_ALLOWED`;
- expose `require_allowed_address(address, policy)` that returns `None` on
  success;
- under `PUBLIC`, allow only globally routable IPv4 and IPv6 addresses;
- under `PUBLIC`, reject loopback, private, link-local, unspecified,
  multicast, reserved/special-use, documentation ranges, and IPv4-mapped
  IPv6 addresses whose mapped IPv4 address is not allowed;
- under `LOCAL_LAB`, allow loopback, RFC1918 private IPv4, unique-local
  IPv6 and link-local addresses;
- under `LOCAL_LAB`, still reject invalid syntax, unspecified, multicast,
  documentation ranges and other non-routable special-use ranges not
  required for a local lab;
- raise `ScopeValidationError` with `INVALID_IP_ADDRESS` for malformed
  input and `ADDRESS_NOT_ALLOWED` for syntactically valid but disallowed
  addresses.

Implementation constraints for Slice C:

- use only the Python standard-library `ipaddress` module;
- parse with `ip_address()`;
- do not use regex;
- do not hard-code public allowlists;
- do not resolve hostnames;
- do not add a class or service.

### Slice D: Redirect validation — complete

Slice D resolves `Location` values against the current request URL and
enforces exact origin allowlisting. It does not perform DNS resolution,
does not validate resolved IPs after DNS, and does not implement redirect
limits or loop detection.

- expose `resolve_allowed_redirect(current, location, allowed_origins)` that
  returns a normalized `TargetUrl`;
- resolve root-relative, path-relative and query-only `Location` values
  against the current URL using RFC `urljoin()` semantics;
- accept absolute and scheme-relative redirects only when the normalized
  destination origin is present in the exact allowlist;
- treat explicit and implicit default ports as the same origin;
- preserve non-default ports;
- remove fragments from the returned normalized URL;
- reject absolute redirects to another host, unapproved subdomains, scheme
  changes and non-default ports unless that exact origin is allowlisted;
- reject embedded credentials and unsupported schemes in the redirect URL;
- reject raw backslashes, spaces, tabs, CR and LF in the original `Location`
  value before `urljoin()` can normalize or remove them;
- do not percent-decode the redirect path or query;
- do not normalize path segments beyond the RFC resolution performed by
  `urljoin()`;
- raise `UrlValidationError` with the appropriate `UrlErrorCode` for
  malformed or unsafe redirect URL input;
- raise `ScopeValidationError` with `ScopeErrorCode.ORIGIN_NOT_ALLOWED`
  for a valid redirect URL outside the origin allowlist;
- do not introduce a redirect-specific exception or error enum unless tests
  demonstrate a concrete need.

### Slice E: Controlled DNS resolution — in progress

Slice E resolves a hostname through an injected async resolver and validates
every returned address against the selected `AddressPolicy`. It does not
perform concrete socket DNS lookups, caching, retries, timeouts, or DNS
rebinding protection.

- expose `AddressResolver` as a minimal `typing.Protocol` with
  `async resolve(self, host: str, port: int) -> Collection[str]`;
- expose `async resolve_allowed_addresses(host, port, policy, resolver)` that
  returns a `tuple[str, ...]`;
- call `resolver.resolve(host, port)` exactly once;
- validate every returned address with `require_allowed_address()`;
- return normalized textual IP addresses using `ipaddress.ip_address()`
  canonical form;
- remove duplicate addresses while preserving first-seen order;
- allow results only when every returned address passes the selected policy;
- reject the entire result if any address is invalid or disallowed;
- reject an empty resolver result with `ScopeErrorCode.NO_RESOLVED_ADDRESSES`
  (`"no_resolved_addresses"`);
- preserve `INVALID_IP_ADDRESS` and `ADDRESS_NOT_ALLOWED` for resolver output
  that fails existing address validation;
- do not silently discard invalid or disallowed addresses;
- do not create a DNS service class;
- do not use `socket` directly in this slice;
- unit tests must inject a fake resolver and must not perform real DNS or
  HTTP.

## Slice A non-goals

Slice A will not:

- resolve domain names;
- classify IP addresses;
- apply an origin allowlist;
- perform HTTP requests;
- follow redirects;
- accept Unicode domain names directly;
- percent-decode or normalize path and query components.

Internationalized domains may be supplied later in their ASCII Punycode form.

## Slice A acceptance criteria

- parsing is deterministic and has no side effects;
- accepted URLs return one immutable normalized value object;
- rejected URLs raise one structured exception;
- every rejection contains a stable machine-readable error code;
- fragments are removed from the normalized URL;
- raw paths and queries are preserved without percent-decoding;
- empty ports and ambiguous hosts are rejected before network use;
- tests cover HTTP, HTTPS, custom ports, localhost, IPv4, IPv6, Punycode,
  trailing DNS dots and unsafe input.

## Slice B non-goals

Slice B will not:

- resolve domain names;
- classify IP addresses;
- perform HTTP requests;
- follow redirects;
- allow wildcard hosts;
- allow suffix or parent-domain matching;
- implicitly allow subdomains of an allowed host.

## Slice B acceptance criteria

- `Origin` equality and hashing use only scheme, normalized host and
  effective port;
- path, query and fragment never affect origin identity;
- an exact allowlist match returns normally;
- any other origin raises `ScopeValidationError` with
  `ScopeErrorCode.ORIGIN_NOT_ALLOWED`;
- an empty allowlist rejects every target;
- tests cover default-port equivalence, scheme/port/host mismatches,
  subdomain rejection, IPv4, IPv6 and empty allowlists.

## Slice C non-goals

Slice C will not:

- resolve domain names or hostnames;
- perform DNS lookups;
- perform HTTP requests;
- follow redirects;
- accept hostnames in place of IP addresses;
- introduce a class or service for address policy.

## Slice C acceptance criteria

- `AddressPolicy` exposes stable `public` and `local_lab` values;
- allowed addresses under the selected policy return normally;
- malformed IP input raises `ScopeValidationError` with
  `ScopeErrorCode.INVALID_IP_ADDRESS`;
- disallowed addresses raise `ScopeValidationError` with
  `ScopeErrorCode.ADDRESS_NOT_ALLOWED`;
- `PUBLIC` rejects loopback, private, link-local, unspecified, multicast,
  reserved/special-use, documentation and disallowed IPv4-mapped IPv6
  addresses;
- `LOCAL_LAB` allows loopback, RFC1918, unique-local IPv6 and link-local
  addresses while still rejecting unspecified, multicast, documentation
  and other non-lab special-use ranges;
- classification uses `ipaddress.ip_address()` only;
- tests cover representative PUBLIC and LOCAL_LAB allow and reject cases
  without network or DNS activity.

## Slice D non-goals

Slice D will not:

- resolve domain names or hostnames;
- validate IP addresses after DNS;
- perform HTTP requests;
- enforce redirect hop limits;
- detect redirect loops;
- allow wildcard hosts, suffix matching or implicit subdomain allowance;
- introduce a redirect-specific exception or error enum without a concrete
  need demonstrated by tests.

## Slice D acceptance criteria

- relative `Location` values resolve against the current URL via `urljoin()`;
- absolute and scheme-relative redirects are accepted only for exact
  allowlisted origins;
- default-port equivalence and non-default port preservation match Slice B;
- fragments are removed from the normalized redirect URL;
- raw paths and queries are preserved without percent-decoding beyond
  `urljoin()` resolution;
- unsafe `Location` characters are rejected before `urljoin()`;
- embedded credentials and unsupported schemes raise `UrlValidationError`;
- out-of-allowlist origins raise `ScopeValidationError` with
  `ScopeErrorCode.ORIGIN_NOT_ALLOWED`;
- tests cover success, failure and boundary cases without DNS or network
  activity.

## Slice E non-goals

Slice E will not:

- perform concrete DNS lookups via `socket` or system resolvers;
- implement DNS rebinding protection;
- add caching, retries or timeouts;
- create a DNS service class;
- perform HTTP requests;
- catch and swallow `ScopeValidationError` from address validation.

DNS rebinding protection, caching, timeouts and concrete socket resolution
remain future transport-level work.

## Slice E acceptance criteria

- `AddressResolver` is a structural Protocol with an async `resolve` method;
- `resolve_allowed_addresses` calls the resolver once and returns a tuple of
  canonical textual addresses;
- duplicates and equivalent IPv6 textual forms collapse while preserving
  first-seen order;
- empty resolver output raises `ScopeValidationError` with
  `ScopeErrorCode.NO_RESOLVED_ADDRESSES`;
- invalid resolver output preserves `INVALID_IP_ADDRESS`;
- disallowed resolver output preserves `ADDRESS_NOT_ALLOWED`;
- PUBLIC and LOCAL_LAB policies are both covered by tests;
- tests use an injected fake resolver with no network or DNS activity.
