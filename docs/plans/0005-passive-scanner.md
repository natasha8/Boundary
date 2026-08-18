# Passive Security Scanner Plan

- Status: Completed
- Milestone: 4
- Planned: 2026-08-14
- Completed: 2026-08-18
- Implementation: `src/boundary/passive.py`
- Tests: `tests/test_passive_findings.py`, `tests/test_passive_headers.py`,
  `tests/test_passive_cookies.py`, `tests/test_passive_scan.py`
- Decision record: `docs/decisions/0004-passive-security-scanning.md`

## Purpose

The Passive Security Scanner transforms already-fetched `DiscoveredPage` values
into sanitized deterministic findings without performing any additional network
activity.

The composition is:

    crawl(...)
        -> AsyncIterator[DiscoveredPage]
        -> scan_pages(...)
        -> AsyncIterator[PassiveFinding]

Passive Scanner is analysis only. It does not own discovery, transport, scope,
evidence persistence, reporting or active validation.

## Prerequisites

The completed Discovery Engine provides:

- immutable `DiscoveredPage` values;
- `page.target` as requested Discovery identity;
- deterministic, bounded async streaming from `crawl`;
- successful responses only, without accumulating a discovery result.

The completed Controlled HTTP Transport provides:

- immutable `TransportResponse`;
- status, ordered raw header tuples and a bounded body;
- `response.final_target` as the normalized final hop that produced evidence.

The completed Scope Engine provides immutable normalized `TargetUrl` values.
Passive Scanner consumes those values but invokes no scope or DNS operation.

## Delivered architecture

```python
class PassiveFindingKind(StrEnum):
    MISCONFIGURATION = "misconfiguration"
    HARDENING = "hardening"


@dataclass(frozen=True, slots=True)
class PassiveFinding:
    rule_id: str
    kind: PassiveFindingKind
    target: TargetUrl
    requested_target: TargetUrl
    observation: str
    rationale: str
    evidence: tuple[tuple[str, str], ...]

    @property
    def fingerprint(self) -> str: ...


def build_passive_finding(...) -> PassiveFinding: ...


def scan_page(page: DiscoveredPage) -> tuple[PassiveFinding, ...]: ...


async def scan_pages(
    pages: AsyncIterable[DiscoveredPage],
) -> AsyncIterator[PassiveFinding]: ...
```

The module exposes exactly those five names. Header, CSP and cookie parsing
helpers, the parsed-cookie value and the individual rule functions stay
private. `build_passive_finding` is the constructor used by every rule; it
rejects duplicate evidence keys and stores evidence sorted by key.

Every finding uses `response.final_target` as `target` and retains
`page.target` as `requested_target` provenance. All implemented rules are
header-derived synchronous pure functions; none reads the response body.

## Accepted rules as implemented

Contracts, normalized states and evidence keys are specified in ADR 0004. The
delivered rule IDs and execution order are:

1. `passive.hsts.not_enforced.v1` — hardening; HTTPS final target only;
   minimal deterministic `max-age` contract (`> 0` protects, `0` is disabled,
   duplicate singleton header is ambiguous, malformed/non-ASCII is invalid).
2. `passive.nosniff.missing_or_invalid.v1` — hardening; HTML only via
   `discovery.is_html_response`; exactly `nosniff` after supported OWS and case
   normalization protects; missing, invalid, duplicate and non-ASCII fire.
3. `passive.csp.missing_enforced_policy.v1` — hardening; HTML only; one or more
   non-empty ASCII enforced fields satisfy the basic presence rule; report-only
   never does. Not an XSS finding and not full CSP semantics.
4. `passive.framing.missing_protection.v1` — hardening; HTML only; recognized
   `DENY`/`SAMEORIGIN` protects, or an enforced CSP `frame-ancestors` directive
   with a non-empty value protects; report-only does not protect; `ALLOW-FROM`
   does not count; duplicate or invalid XFO does not protect unless CSP
   independently does. No full CSP parser exists.
5. `passive.cookie.secure_missing_https.v1` — misconfiguration; HTTPS
   `final_target` only; one finding per parseable `Set-Cookie` field before
   orchestration deduplication; `Secure` presence is case-insensitive and
   `Secure=0` still counts as present; the cookie value never enters evidence.
6. `passive.cookie.samesite_none_without_secure.v1` — misconfiguration;
   scheme-independent; fires for exactly one recognized `SameSite=None` with no
   `Secure`; duplicate `SameSite` is ambiguous and does not fire; missing,
   `Lax`, `Strict`, empty and unknown values do not fire.

The two cookie rules remain separate: one concerns HTTPS transport
configuration and the other a specific SameSite/Secure incompatibility, so one
cookie can carry both identities.

## Private parsing contracts as implemented

### Header selection

A private helper returns all raw values matching one literal lowercase
header-name byte string. Matching is ASCII-case-insensitive and preserves field
order. It does not combine duplicate fields, split comma-separated values,
decode all headers or normalize response storage.

Singleton cardinality is decided by each rule: HSTS, `X-Content-Type-Options`
and XFO require exactly one relevant field; CSP and `Set-Cookie` are
repeatable. ASCII decoding failures make the value unusable for the current
rule; the bytes never reach evidence or an exception message.

### HTML classification

HTML-context rules call the existing `discovery.is_html_response`: exactly one
`Content-Type`, media type exactly `text/html` case-insensitively, parameters
ignored, no body sniffing. Duplicate, absent, empty, malformed and other media
types are not HTML. No second HTML/content-type contract was created.

### Minimal CSP directive inspection

The frame rule inspects only enforced CSP fields: decode as ASCII, split on
semicolons, strip optional whitespace, split a non-empty segment once at ASCII
whitespace, compare the directive name case-insensitively with
`frame-ancestors` and require a non-empty value. No source-list, nonce, hash,
fallback or duplicate-directive semantics are implemented, and report-only
fields are never passed to this check.

### Minimal Set-Cookie inspection

Each `Set-Cookie` field is processed independently, in header order, and is
never comma-split, so `Expires` commas remain part of one field.

The parser splits segments on semicolons, requires `=` in the first segment
with a non-empty ASCII RFC token name before it, and never decodes, validates,
copies or retains the cookie value. It records only the cookie name, `Secure`
presence (attribute name only, any attribute value ignored) and the normalized
`SameSite` state (`None`, `Lax` or `Strict` only, with duplicates marked
ambiguous). Unknown attributes are ignored.

Malformed cookie identity skips only that field; malformed cookie metadata
never blocks later `Set-Cookie` fields or unrelated rules. No malformed-cookie
finding exists.

## Error-handling policy

Expected untrusted metadata is represented as absent, unusable or ambiguous at
the relevant rule or field. There is no page-wide broad catch and no
`except Exception` in the module.

- malformed Content-Type: HTML-only rules do not apply;
- duplicate singleton security header: it does not satisfy protection;
- non-ASCII singleton value: it does not satisfy protection;
- malformed enforced CSP: it does not satisfy that CSP decision;
- malformed cookie field: skip that field only;
- malformed `SameSite`: skip the SameSite decision for that field;
- valid later header/cookie fields: continue normally.

Programming errors, type violations and page-source (upstream stream) errors
propagate; no per-page orchestration recovery exists.

## Offline testing approach

All tests construct `TargetUrl`, `TransportResponse` and `DiscoveredPage`
objects directly. They do not call Discovery or Transport and require no
response or request mocking.

Dedicated negative guards replace network entry points with fail-fast
assertions solely to prove the passive path cannot reach them: `crawl`,
`request_once`, `request_with_redirects`, resolver methods,
`socket.getaddrinfo`, `socket.create_connection` and `anyio.connect_tcp`. The
orchestration suite additionally asserts that `scan_page` and `scan_pages`
reference no network names. These guards do not mock the passive behavior under
test.

Tests assert complete finding values, ordering, absence of side effects and
absence of sensitive strings, not only finding counts.

## Delivery slices

### Slice A: Finding model, identity and rule composition contract — completed

Tests: `tests/test_passive_findings.py`

Delivered: `PassiveFindingKind` with exactly two members; frozen, slotted
`PassiveFinding` with the approved seven fields and no severity, CVSS,
confidence, identifier or timestamp field; `build_passive_finding`, which
rejects duplicate evidence keys and stores evidence sorted by key; the
`fingerprint` property over canonical JSON (`schema`, `rule_id`, `target.url`,
canonical evidence) hashed with SHA-256.

Acceptance criteria met: the model is minimal, immutable and explicitly typed;
identity is deterministic and locked by an exact canonical-JSON and digest test
vector; identity uses the final target and sanitized evidence only and ignores
`requested_target`, `kind`, observation and rationale; caller pair order does
not affect stored evidence or identity; no severity, CVSS, confirmation,
evidence-archive, time or random value participates; the public surface stays
minimal.

### Slice B: Header inspection and hardening rules — completed

Tests: `tests/test_passive_headers.py`

Delivered: the private literal-name header selector and narrow ASCII helpers;
reuse of `discovery.is_html_response`; the minimal HSTS directive parser;
enforced-CSP selection and minimal `frame-ancestors` recognition; the four
header rule functions in approved order, emitting normalized evidence only.

Acceptance criteria met: all four rule contracts match ADR 0004, including the
delivered `missing` / `ambiguous` / `invalid` / `disabled` and `report_only`
states; HTTPS-only HSTS and HTML-only `nosniff`, CSP and framing boundaries are
explicit and driven by `final_target`; report-only CSP never counts as
enforcement for either the CSP or the framing rule; duplicate singleton
handling fails closed deterministically; one malformed or non-ASCII header
cannot stop another rule and is never copied into evidence; findings make no
exploitability claim.

### Slice C: Safe cookie parsing and cookie rules — completed

Tests: `tests/test_passive_cookies.py`

Delivered: the private immutable parsed-cookie value; byte-level cookie
identity validation without a cookie jar; cookie values discarded before any
parsed result exists; both cookie rules appended to the static tuple after the
header rules.

Acceptance criteria met: each `Set-Cookie` field is independent and evaluated
in header order; `Expires` commas are not separators; malformed identity is
skipped without broad exception handling and without blocking later fields or
unrelated rules; duplicate and conflicting `SameSite` metadata cannot fire the
SameSite rule; `Secure` is recognized by attribute name only, including
`Secure=0` and repeated attributes; no cookie value, complete `Set-Cookie` line
or Authorization value reaches a finding, its evidence or its fingerprint
material; HTTPS-only and scheme-independent applicability match the rule
contracts.

### Slice D: Page and streaming orchestration — completed

Tests: `tests/test_passive_scan.py`

Delivered: `scan_page` over the static private rule tuple with
first-fingerprint-wins deduplication; `scan_pages` as an async generator
iterating the supplied pages directly and retaining only run-local
fingerprints; no transport sender, resolver, socket or HTTP client import.

Acceptance criteria met: findings attach to `response.final_target` and retain
`page.target` provenance; the static tuple fixes exact finding order and
repeated `Set-Cookie` fields keep field order within each cookie rule;
duplicates within a page keep the first occurrence and retained findings are
not rebuilt; `scan_pages` consumes pages lazily and yields the current page's
findings before pulling the next page; page order is preserved without global
sorting; duplicate fingerprints across pages in one run are emitted once while
a new invocation starts with empty state; equal input streams produce equal
output; empty input and fully protected pages yield nothing; rule defects and
page-source exceptions propagate; input pages, responses, headers, bodies and
targets are unchanged; fail-fast guards prove no crawl, request, DNS or socket
path is reached.

### Slice E: HTML/body-derived passive checks — deferred / not implemented

No body-derived rule was justified by the accepted rule set, so Slice E added
no production code, parser or tests. No arbitrary body scanning exists, and no
body-derived security check was invented to complete the milestone.

Reconsider it only when a separately approved deterministic rule:

- requires the already-bounded body;
- has a low-noise evidence contract;
- can sanitize evidence without excerpts or secrets;
- needs no additional request, browser or script execution;
- cannot be decided from existing headers.

## Final security invariants

- passive analysis performs zero network activity: no DNS, HTTP, `crawl`,
  `request_once`, `request_with_redirects`, socket, HTTPCore, browser or
  JavaScript execution;
- rule execution order is static and deterministic;
- only sanitized, rule-authored evidence is emitted;
- cookie values never enter parsed metadata, findings or fingerprint material;
- findings attach to `response.final_target`;
- `requested_target` is retained only as provenance and never affects identity;
- finding identity is a deterministic SHA-256 digest over canonical JSON of the
  versioned rule ID, final target URL and canonical sanitized evidence;
- `scan_page` deduplicates per page, keeping the first fingerprint occurrence;
- `scan_pages` deduplicates at run level with a run-local fingerprint set that
  grows approximately as O(unique emitted fingerprints) and is neither global
  nor persistent;
- `scan_pages` consumes pages lazily and accumulates no pages, bodies or
  complete finding collections;
- no broad exception swallowing: programming and page-source errors propagate;
- no active, browser or JavaScript behavior is introduced;
- no severity, CVSS, confidence or exploitability claim is produced.

## Explicitly deferred candidate rules

Deferred for missing application/browser context:

- cookie missing `HttpOnly`;
- cookie missing `SameSite`;
- permissive CORS from ACAO alone;
- cache-control security claims;
- CSRF detection.

Deferred because they require active requests:

- CORS reflection testing;
- authentication testing;
- authorization and IDOR/BOLA testing;
- SQL injection, XSS and other injection testing;
- active TLS testing.

Deferred for noisy/probabilistic matching or unsafe evidence:

- server banner/version vulnerability claims;
- sensitive-data regex scanning;
- directory-listing heuristics;
- technology fingerprinting;
- outdated-software detection.

## Milestone non-goals

Not added, and still deferred:

- body and secret scanning;
- active validation, payload generation or exploitation;
- an Evidence Engine, evidence replay or request/response archival;
- severity scoring, CVSS or confidence scoring;
- AI analysis and a remediation engine;
- browser execution or JavaScript analysis;
- a findings database, evidence repository or aggregation dashboard;
- SARIF, JSON or other report generation;
- CLI integration;
- authorization testing and IDOR/BOLA;
- CORS reflection testing;
- plugin architecture, dynamic rule loading or rule configuration;
- concurrency inside passive analysis.

## Dependency decision

No dependency was added.

The standard library provided dataclasses, `StrEnum`, SHA-256, canonical JSON
encoding and the byte/string operations needed by the narrow parsers. Existing
`discovery.is_html_response` supplies HTML classification.

## Verification sequence

Repository checks executed at closeout:

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

No test contacts a public target, skips a security assertion or weakens an
existing check.

## Test coverage

Offline passive tests, all passing:

- `tests/test_passive_findings.py`: 25 tests;
- `tests/test_passive_headers.py`: 63 tests;
- `tests/test_passive_cookies.py`: 54 tests;
- `tests/test_passive_scan.py`: 47 tests.

Full repository suite at closeout: 751 tests collected and passing, with no
skipped tests.

## Definition of done

Met:

- Slices A through D meet every acceptance criterion;
- Slice E remains absent and its deferral is documented;
- all six accepted rule contracts are implemented and tested;
- findings use final targets and retain requested-target provenance;
- finding identity, rule order and stream order are deterministic;
- duplicate, casing, malformed-byte and repeated-cookie boundaries are tested;
- report-only CSP and frame-protection combinations are tested;
- cookie values and other sensitive raw values never appear in findings;
- negative guards prove passive code performs zero network activity;
- no active, persistence, reporting or severity capability was added;
- formatting, linting, typing and all tests pass without skipped or weakened
  tests;
- documentation matches the implementation, including deferred items;
- no dependency was added.
