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

### Slice D: Redirect validation — in progress

- validate every redirect destination;
- prohibit automatic out-of-scope redirects;
- retain an auditable rejection reason.

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
