# Passive Security Scanner Plan

- Status: Planned
- Milestone: 4
- Date: 2026-08-14
- Planned implementation: `src/boundary/passive.py`
- Decision record: `docs/decisions/0004-passive-security-scanning.md`

## Purpose

The Passive Security Scanner will transform already-fetched
`DiscoveredPage` values into sanitized deterministic findings without
performing any additional network activity.

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

## Scope and assumptions

This plan adds one future production module and focused offline tests. The
current planning task creates neither.

Implementation assumptions:

- every initial finding uses `response.final_target` as `target`;
- `page.target` is retained as `requested_target` provenance;
- all initial rules are header-derived, so no body parser is needed;
- rules are synchronous pure functions;
- Discovery remains the bounded source of pages;
- rule IDs are versioned when detection semantics change;
- no result is called an exploited or confirmed vulnerability;
- no new dependency is required.

## Security invariants

The implementation must make these properties true by construction:

1. Passive Scanner has no function parameter for a resolver, transport,
   request limits, allowed origins, scan profile or HTTP client.
2. It does not import or call `crawl`, `request_once`,
   `request_with_redirects`, HTTPCore, socket APIs or DNS APIs.
3. A rule receives one `DiscoveredPage` and uses only its existing status,
   headers, bounded body and target metadata.
4. No rule submits forms, executes JavaScript, sends payloads or mutates the
   page or application state.
5. Raw cookie values, Authorization values, bearer tokens, credentials,
   session identifiers and arbitrary body snippets never enter finding
   evidence.
6. Expected malformed response bytes cannot crash unrelated rules.
7. Programming defects are not hidden by broad exception handling.
8. Equal input streams produce equal ordered findings and fingerprints.

## Planned API

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


def scan_page(page: DiscoveredPage) -> tuple[PassiveFinding, ...]: ...


async def scan_pages(
    pages: AsyncIterable[DiscoveredPage],
) -> AsyncIterator[PassiveFinding]: ...
```

The production module will expose only the finding model, kind and two scanner
functions unless tests establish another concrete public need. Header, CSP and
cookie parsing helpers and individual rule functions remain private.

### Evidence contract

Evidence is an immutable tuple of unique string key/value pairs. Rules use
fixed keys and normalized values. Common evidence includes the response status
as a decimal string. Rule-specific evidence may include:

- a literal lowercase header name;
- a normalized state such as `missing`, `invalid`, `ambiguous` or `disabled`;
- a header count;
- whether report-only CSP was present;
- a cookie name;
- normalized `secure` and `same_site` states.

Evidence must not include raw header values, complete Set-Cookie lines, cookie
values, Authorization fields or body data. Observation and rationale text are
fixed rule-authored prose, not interpolated untrusted values except for a
permitted cookie name when necessary.

### Fingerprint contract

Fingerprinting uses only the standard library:

```text
sha256(
    canonical_json(
        {
            "schema": 1,
            "rule_id": finding.rule_id,
            "target": finding.target.url,
            "evidence": sorted(finding.evidence),
        }
    ).encode("utf-8")
).hexdigest()
```

Canonical JSON uses `ensure_ascii=True`, `sort_keys=True` and compact
separators. Evidence keys are unique and sorted by key before encoding.

The exact serialization and at least one expected digest will be locked by a
test vector. `requested_target`, `kind`, observation and rationale do not
participate. Python `hash()`, object identity, UUIDs, timestamps and randomness
are forbidden.

### Explicit composition

Private rule functions share this simple shape:

```python
def _check_rule(page: DiscoveredPage) -> tuple[PassiveFinding, ...]: ...
```

The private static tuple is ordered:

1. HSTS;
2. `X-Content-Type-Options`;
3. enforced CSP;
4. frame protection;
5. HTTPS cookies missing `Secure`;
6. `SameSite=None` cookies missing `Secure`.

`scan_page` executes that tuple in order and removes duplicate fingerprints
while preserving first occurrence. `scan_pages` preserves page order and
maintains only a fingerprint set for run-level duplicate suppression; it does
not accumulate pages, bodies or finding objects.

No generic rule protocol, base class, service object, plugin loader,
registration decorator or dependency-injection mechanism will be introduced.

## Accepted initial rules

### HSTS not enforced

- ID: `passive.hsts.not_enforced.v1`
- Kind: hardening
- Context: final target is HTTPS.
- Satisfied by: exactly one ASCII HSTS field with exactly one decimal
  `max-age` directive greater than zero.
- Fires for: absent/duplicate HSTS, missing/duplicate/invalid `max-age`, and
  `max-age=0`.
- Does not require: `includeSubDomains` or `preload`.
- Claim limit: missing transport hardening, not proven downgrade.

### `nosniff` missing or invalid

- ID: `passive.nosniff.missing_or_invalid.v1`
- Kind: hardening
- Context: exact existing `text/html` response classification.
- Satisfied by: exactly one ASCII field equal to `nosniff` after optional
  whitespace trimming and case folding.
- Fires for: absent, duplicate, malformed or other values.
- Claim limit: MIME hardening observation, not exploitability.

The first contract intentionally does not report on every response. Without
browser request-destination context, findings on every image, font or API
response would be repetitive and weakly contextualized.

### Enforced CSP missing

- ID: `passive.csp.missing_enforced_policy.v1`
- Kind: hardening
- Context: exact existing `text/html` response classification.
- Satisfied by: at least one non-empty ASCII
  `Content-Security-Policy` field.
- Repeated enforced CSP fields are accepted.
- `Content-Security-Policy-Report-Only` does not satisfy the rule.
- The rule does not grade policy quality or claim XSS.

### Frame protection missing

- ID: `passive.framing.missing_protection.v1`
- Kind: hardening
- Context: exact existing `text/html` response classification.
- Satisfied by either:
  - exactly one ASCII `X-Frame-Options` field equal to `DENY` or
    `SAMEORIGIN`; or
  - an enforced CSP field containing a case-insensitive `frame-ancestors`
    directive with a non-empty value.
- Duplicate XFO, `ALLOW-FROM`, malformed XFO and report-only
  `frame-ancestors` do not satisfy the rule.
- CSP source expressions are not fully parsed.
- The rule does not claim a working clickjacking attack.

### HTTPS cookie missing `Secure`

- ID: `passive.cookie.secure_missing_https.v1`
- Kind: misconfiguration
- Context: each parseable Set-Cookie field on an HTTPS final target.
- Fires when: the cookie has no case-insensitive `Secure` attribute.
- Evidence: status, cookie name and normalized secure state only.

### `SameSite=None` without `Secure`

- ID: `passive.cookie.samesite_none_without_secure.v1`
- Kind: misconfiguration
- Context: each parseable Set-Cookie field on HTTP or HTTPS.
- Fires when: exactly one recognized `SameSite=None` exists and `Secure` does
  not.
- Evidence: status, cookie name, normalized SameSite and secure states only.

The two cookie rules remain separate. A cookie can intentionally receive both
identities because one concerns HTTPS transport configuration and the other a
specific SameSite/Secure incompatibility.

## Private parsing contracts

### Header selection

A private helper will return all raw values matching one literal lowercase
header-name byte string. Matching is ASCII-case-insensitive and preserves
field order. It will not:

- combine duplicate fields;
- split comma-separated values generically;
- decode all headers;
- normalize response storage;
- become a request-header or HTTP framework.

Singleton cardinality is decided by each rule. HSTS,
`X-Content-Type-Options` and XFO require exactly one relevant field. CSP and
Set-Cookie remain repeatable.

ASCII decoding failures become an unusable value for the current rule. They do
not raise out of page scanning and the bytes are not copied into evidence or
an exception.

### HTML classification

Header rules that need HTML context call the existing
`discovery.is_html_response`. The contract remains:

- exactly one `Content-Type`;
- media type exactly `text/html`, case-insensitively;
- parameters ignored;
- duplicate, absent, empty, malformed and other media types return false;
- no body sniffing.

No second HTML/content-type contract will be created.

### Minimal CSP directive inspection

The frame rule inspects only enforced CSP fields:

1. Decode one field as ASCII.
2. Split on semicolons.
3. Strip HTTP optional whitespace around each segment.
4. Split a non-empty segment once at ASCII whitespace.
5. Compare the directive name case-insensitively with `frame-ancestors`.
6. Require a non-empty remaining directive value.

No source-list, nonce, hash, fallback or duplicate-directive semantics are
implemented. Report-only fields are never passed to this check.

### Minimal Set-Cookie inspection

Each Set-Cookie field is processed separately and never comma-split.

The parser will:

- split segments on semicolons;
- require a first `name=value` pair;
- require a non-empty ASCII RFC token cookie name;
- validate an unquoted or optionally quoted cookie value as allowed cookie
  bytes without decoding or retaining it;
- discard the value before constructing any parsed result;
- inspect subsequent attribute names case-insensitively;
- record only cookie name, `Secure` presence and normalized SameSite state;
- accept `Secure` based on its attribute name and retain no attribute value;
- normalize only `None`, `Lax` and `Strict`;
- mark duplicate SameSite attributes ambiguous for the SameSite rule;
- ignore unknown attributes.

A malformed cookie pair is skipped. A malformed/unknown/duplicate SameSite
attribute cannot fire the SameSite rule. Neither case blocks later Set-Cookie
fields or unrelated rules. No malformed-cookie informational finding is
created.

## Error-handling policy

Expected untrusted metadata is represented as absent, unusable or ambiguous at
the rule boundary. It is never handled by a page-wide broad catch.

Rule behavior:

- malformed Content-Type: HTML-only rules do not apply;
- duplicate singleton security header: it does not satisfy protection;
- non-ASCII singleton value: it does not satisfy protection;
- malformed enforced CSP: it does not satisfy that CSP decision;
- malformed cookie field: skip that field only;
- malformed SameSite: skip the SameSite decision for that field;
- valid later header/cookie fields: continue normally.

Unexpected type violations, programming errors and upstream stream exceptions
propagate. The implementation must not contain `except Exception` for rule
isolation.

## Offline testing approach

All tests construct `TargetUrl`, `TransportResponse` and `DiscoveredPage`
objects directly. They do not call Discovery or Transport and require no
response/request mocking.

A dedicated negative guard will replace network entry points with fail-fast
assertions solely to prove the passive path cannot reach them:

- `crawl`;
- `request_once`;
- `request_with_redirects`;
- resolver methods;
- `socket.getaddrinfo`;
- real socket connection functions;
- AnyIO TCP connection.

This guard is not a mock of the passive behavior under test. The rules still
receive real immutable domain values and execute their real parsing logic.

Tests assert complete finding values, side effects (none), ordering and absence
of sensitive strings, not only finding counts.

Focused tests run after each slice. After all slices, run the complete relevant
suite and repository checks.

## Delivery slices

### Slice A: Finding model, identity and rule composition contract

Tests are added first in a focused model test module.

#### Tests

- `PassiveFindingKind` has only the approved stable values.
- `PassiveFinding` is frozen and slotted.
- Fields preserve normalized final and requested targets.
- Evidence keys must be unique.
- A fixed canonical input produces an exact expected SHA-256 digest.
- Repeated construction produces the same fingerprint across invocations.
- Changing rule ID, final target or sanitized evidence changes the fingerprint.
- Changing requested target, observation wording or rationale does not change
  the fingerprint.
- Evidence canonicalization is independent of caller pair order.
- No random UUID, timestamp or process hash participates.

#### Implementation

- Add `PassiveFindingKind`.
- Add `PassiveFinding` and deterministic fingerprint property.
- Add the canonical evidence/fingerprint helper privately.
- Document the private rule-function shape and static-order requirement in the
  module.
- Add no security rules, network imports or orchestration yet.

#### Acceptance criteria

- the model is minimal, immutable and explicitly typed;
- identity is deterministic and fixed by a test vector;
- identity uses final target and sanitized evidence only;
- no severity, CVSS, confirmation or evidence-archive model appears;
- focused tests pass offline.

### Slice B: Header inspection and hardening rules

Tests are added before each rule implementation in a focused header-rules test
module.

#### Tests

Header helper behavior is tested through rule output:

- header names and recognized tokens are case-insensitive;
- response order and duplicate fields are preserved;
- singleton duplicates fail closed;
- malformed/non-ASCII values do not crash scanning;
- unrelated raw headers, including Authorization, never enter evidence.

HSTS cases:

- HTTPS missing header fires;
- HTTP missing header does not apply;
- valid positive `max-age` suppresses the finding;
- casing and optional whitespace are accepted;
- duplicate fields and duplicate `max-age` are ambiguous;
- absent, non-decimal, quoted or negative `max-age` is invalid;
- zero `max-age` is disabled;
- unknown directives do not invalidate a positive `max-age`.

`nosniff` cases:

- HTML missing/invalid header fires;
- exactly one case-insensitive `nosniff` suppresses it;
- duplicates and malformed bytes fire;
- HTTP versus HTTPS does not change this rule;
- non-HTML and ambiguous Content-Type do not apply.

CSP cases:

- HTML with no enforced CSP fires;
- report-only CSP alone still fires;
- one non-empty enforced CSP suppresses it;
- multiple enforced CSP fields are accepted;
- malformed/empty enforced fields do not satisfy it;
- non-HTML does not apply.

Frame cases:

- no XFO or frame-ancestors fires;
- one `DENY` or `SAMEORIGIN` suppresses it;
- XFO casing/whitespace is accepted;
- duplicate XFO, `ALLOW-FROM` and malformed XFO do not satisfy it;
- non-empty enforced `frame-ancestors` suppresses it;
- report-only `frame-ancestors` does not;
- unrelated CSP directives do not satisfy it;
- non-HTML does not apply.

#### Implementation

- Add the private literal-name header selector and narrow ASCII helpers.
- Reuse `discovery.is_html_response`.
- Add the minimal HSTS directive parser.
- Add enforced-CSP selection and minimal frame-ancestors recognition.
- Add the four plain header rule functions.
- Add them to the explicit static rule tuple in approved order.
- Generate only normalized evidence; never retain a raw header value.

#### Acceptance criteria

- all four rule contracts match ADR 0004;
- HTTPS/HTTP and HTML/non-HTML boundaries are explicit;
- report-only CSP never counts as enforcement;
- duplicate singleton handling is deterministic;
- one malformed header cannot stop another rule;
- findings make no exploitability claim;
- focused tests pass offline.

### Slice C: Safe cookie parsing and cookie rules

Tests are added first in a focused cookie-rules test module.

#### Tests

Parser and isolation cases:

- multiple Set-Cookie fields are evaluated independently in field order;
- commas in Expires are not treated as cookie separators;
- cookie/attribute casing is handled according to the contract;
- empty valid values can be analyzed but are never retained;
- malformed names, missing `=` and invalid cookie values are skipped;
- one malformed line does not block a later valid cookie or header rule;
- unknown attributes do not crash or appear in evidence;
- duplicate SameSite metadata cannot fire the SameSite rule.

HTTPS `Secure` cases:

- a parseable HTTPS cookie without `Secure` fires;
- `Secure` suppresses it case-insensitively;
- an HTTP cookie without `Secure` does not fire this rule;
- different cookie names produce different fingerprints;
- duplicate identical cookie evidence is emitted once.

SameSite cases:

- `SameSite=None` without `Secure` fires on HTTP and HTTPS;
- `SameSite=None; Secure` does not fire;
- `Lax`, `Strict`, absent, malformed and unknown values do not fire;
- attribute order does not change semantics.

Redaction cases:

- a distinctive cookie value is absent from every finding field;
- it is absent from canonical fingerprint material and exception text;
- complete Set-Cookie lines are absent;
- only the cookie name and normalized attributes appear as evidence.

#### Implementation

- Add a small private immutable parsed-cookie value if tests justify it.
- Implement byte-level cookie-pair validation without a cookie jar.
- Discard values before returning parsed metadata.
- Add the two cookie rule functions to the static tuple after header rules.
- Deduplicate identical rule/target/evidence fingerprints.

#### Acceptance criteria

- each repeatable field is independent and deterministic;
- malformed input is isolated without broad exception handling;
- no cookie value can reach a finding;
- HTTPS and HTTP applicability matches the rule contracts;
- both accepted cookie rules pass success, failure and boundary tests;
- focused tests pass offline.

### Slice D: Page and streaming orchestration

Tests are added first in a focused scanner test module.

#### Tests

- `scan_page` attaches findings to `response.final_target`.
- It retains `page.target` as requested provenance after a redirect.
- Static rule order fixes exact finding order.
- Repeated Set-Cookie fields retain order within each cookie rule.
- Duplicate fingerprints within one page preserve only first occurrence.
- `scan_pages` is an async generator and consumes pages incrementally.
- The first page's finding can be yielded before the next page is requested.
- Page order is preserved without global sorting.
- Duplicate fingerprints across pages are emitted once.
- Repeating an equal page stream produces equal findings and order.
- Empty input and pages with no applicable findings yield nothing.
- Upstream async-iteration exceptions propagate.
- Input `DiscoveredPage`, response, headers, body and targets remain unchanged.
- Fail-fast guards prove no crawl, request, DNS or socket path is reached.

#### Implementation

- Implement `scan_page` over the static private rule tuple.
- Remove duplicate fingerprints while preserving first occurrence.
- Implement `scan_pages` as direct async iteration over supplied pages.
- Retain only run-local fingerprints needed for duplicate suppression.
- Import no transport sender, resolver, socket or HTTP client.

#### Acceptance criteria

- `crawl(...) -> scan_pages(...)` composes without coupling in the opposite
  direction;
- no pages, bodies or complete finding list are accumulated;
- output and deduplication are deterministic;
- passive scanning performs zero network behavior;
- programming and upstream errors propagate;
- focused tests pass offline.

### Slice E: HTML/body-derived passive checks — explicitly deferred

No body-derived rule is justified by the accepted initial set. Slice E creates
no production code, parser or tests.

Reconsider it only when a separately approved deterministic rule:

- requires the already-bounded body;
- has a low-noise evidence contract;
- can sanitize evidence without excerpts or secrets;
- needs no additional request, browser or script execution;
- cannot be decided from existing headers.

Rules must not be invented merely to fill this slice.

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

Do not add:

- active validation or payload generation;
- an Evidence Engine or evidence replay;
- request/response archival;
- severity scoring or CVSS;
- AI analysis;
- browser execution or JavaScript analysis;
- vulnerability exploitation;
- a findings database or evidence repository;
- aggregation dashboards;
- JSON or other report generation;
- CLI integration;
- plugin architecture or dynamic rule configuration.

## Dependency decision

No dependency is required.

The standard library provides dataclasses, `StrEnum`, SHA-256, canonical JSON
encoding and the byte/string operations needed by the narrow parsers. Existing
`discovery.is_html_response` supplies HTML classification. A third-party
cookie, CSP, HTTP or rule-engine package would exceed the approved contracts.

## Verification sequence

During future implementation:

1. write the focused slice tests;
2. run that focused test module and observe the intended failures;
3. implement the smallest behavior for the slice;
4. rerun the focused tests;
5. run all passive tests;
6. run the complete repository checks:

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

No test may contact a public target, skip a security assertion or weaken an
existing check.

## Definition of done

Milestone 4 is complete only when:

- Slices A through D meet every acceptance criterion;
- Slice E remains absent unless separately approved with concrete evidence;
- all six accepted rule contracts are implemented test-first;
- findings use final targets and retain requested-target provenance;
- finding identity and ordering are deterministic;
- duplicate, casing, malformed-byte and repeated-cookie boundaries are tested;
- report-only CSP and frame-protection combinations are tested;
- cookie values and other sensitive raw values never appear in findings;
- negative guards prove passive code performs zero network activity;
- no active, persistence, reporting or severity capability is added;
- formatting, linting, typing and all tests pass;
- documentation is updated if implementation decisions change;
- no dependency is added without separate approval.

## Unresolved design questions

None block implementation. ADR 0004 resolves severity, classification,
fingerprinting, run-level duplicate suppression, HTML applicability, singleton
header ambiguity, malformed cookie behavior and the initial rule set. Any
change to those contracts requires an explicit documentation update before the
corresponding behavior is implemented.
