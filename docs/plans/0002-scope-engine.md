# Scope Engine Plan

- Status: In progress
- Branch: feat/scope-engine
- Started: 2026-08-07

## Purpose

The Scope Engine decides whether a target may be processed by BOUNDARY.

It must reject malformed or ambiguous input before any DNS resolution or
network request occurs.

## Delivery slices

### Slice A: Target URL parsing

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

### Slice B: Origin allowlist

- represent normalized origins;
- allow exact configured origins;
- reject scheme, host and port mismatches;
- make subdomain inclusion explicit.

### Slice C: Address policy

- classify IPv4 and IPv6 addresses;
- reject special-use addresses by default;
- support an explicit local-lab policy;
- validate every resolved address.

### Slice D: Redirect validation

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
