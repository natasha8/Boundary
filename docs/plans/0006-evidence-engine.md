# Evidence Engine Plan

- Status: Approved, not started
- Milestone: 5
- Planned: 2026-08-18
- Planned implementation: `src/boundary/evidence.py`
- Planned tests: `tests/test_evidence_model.py`,
  `tests/test_evidence_response.py`, `tests/test_evidence_composition.py`
- Decision record: `docs/decisions/0005-evidence-engine.md`

## Purpose

The Evidence Engine turns data that already exists into deterministic,
reproducible, comparable observation records.

It makes two statements possible that the repository cannot make today:

- these observations share one captured response projection;
- two captured projections match or differ on recorded status, retained-body
  length and retained-body digest.

The projection is not the complete HTTP response: headers are excluded.
Matching `body_length` and `body_sha256` is a strong collision-resistant
signal about the retained body bytes, not proof of byte identity, semantic
equivalence or a vulnerability.

The composition is:

    crawl(...)
        -> DiscoveredPage
        -> scan_page(page)              (unchanged)
        -> capture_response_evidence(page.response, ...)
        -> FindingEvidence(finding, response)

Evidence is data capture only. It does not own discovery, transport, scope,
passive rules, validation verdicts, persistence or reporting, and it performs no
network activity.

## Prerequisites

The completed Controlled HTTP Transport provides:

- immutable `TransportResponse` with `status`, `headers`, a bounded `body` and
  `final_target`;
- a fail-closed size limit: `TransportError(RESPONSE_TOO_LARGE)` instead of
  truncation, so a delivered body is complete.

The completed Discovery Engine provides:

- immutable `DiscoveredPage` values streamed lazily by `crawl`;
- `page.target` as the requested Discovery identity.

The completed Passive Scanner provides:

- immutable `PassiveFinding` with the final target, requested-target
  provenance, sanitized rule facts and a deterministic `fingerprint`;
- synchronous `scan_page`, which is the composition point used by this
  milestone.

The completed Scope Engine provides normalized `TargetUrl` values. Embedded
userinfo credentials are rejected at parse time; query strings are retained.
Evidence consumes those values and invokes no scope or DNS operation. Query
parameters are an inherited sensitive-data boundary and are not redacted here.

## Planned architecture

```python
@dataclass(frozen=True, slots=True)
class ResponseEvidence:
    status: int
    final_target: TargetUrl
    requested_target: TargetUrl
    body_length: int
    body_sha256: str

    def __post_init__(self) -> None: ...


def capture_response_evidence(
    response: TransportResponse,
    *,
    requested_target: TargetUrl,
) -> ResponseEvidence: ...


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    finding: PassiveFinding
    response: ResponseEvidence

    def __post_init__(self) -> None: ...

    @property
    def evidence_id(self) -> str: ...
```

The module will expose exactly those three names. `TargetUrl`,
`TransportResponse` and `PassiveFinding` are needed for annotations only and
will be imported under `TYPE_CHECKING`. Runtime imports stay in the standard
library (`hashlib`, `json`, `dataclasses`, and `typing` for `TYPE_CHECKING`).
Naming those domain types in annotations is expected and is not a boundary
violation; what the boundary forbids is invoking network APIs.

`passive.py`, `discovery.py`, `transport.py` and `scope.py` are not modified.

## Vocabulary

- **captured response projection** — the five facts evidence records about one
  response. Headers, timing and connection properties are excluded, so the
  projection is deliberately narrower than the response.
- **response evidence** — `ResponseEvidence`, one captured projection.
- **finding evidence** — one observation paired with the response evidence that
  produced it.
- **evidence identity** — `FindingEvidence.evidence_id`, a SHA-256 digest over
  canonical JSON of the evidence schema version, `finding.fingerprint`, the
  status, the body length and the body digest.
- **byte-equality signal** — equal `body_length` plus equal `body_sha256`,
  treated as a strong collision-resistant indication that the retained bytes
  matched, never as proof of byte identity, semantic equivalence or a
  vulnerability.
- **raw response data** — headers and body bytes; never an evidence field.

## Delivery slices

Tests are written before the implementation of each slice, and a slice is
complete only when its acceptance criteria hold.

### Slice A: Evidence model and deterministic identity

Tests: `tests/test_evidence_model.py`

Slice A is self-contained and independently completable before Slice B. Its
tests construct `ResponseEvidence` directly — which the canonical-state
invariants make safe — so nothing in this slice depends on
`capture_response_evidence`. Slice A tests must not import that function, must
not require it to exist, and must not be left intentionally failing until
Slice B lands.

To deliver:

- frozen, slotted `ResponseEvidence` with exactly the five approved fields;
- the `ResponseEvidence.__post_init__` canonical-state invariants, raising
  `ValueError` when `body_length < 0` or when `body_sha256` is not exactly 64
  lowercase hexadecimal characters;
- frozen, slotted `FindingEvidence` with exactly `finding` and `response`;
- the `FindingEvidence.__post_init__` pairing invariant, raising `ValueError`
  when `finding.target != response.final_target` or
  `finding.requested_target != response.requested_target`;
- `evidence_id` as a computed property over canonical JSON with
  `sort_keys=True`, `ensure_ascii=True`, compact separators, UTF-8 encoding and
  a lowercase hexadecimal SHA-256 digest.

Acceptance criteria:

- both models are frozen and slotted; assignment raises `FrozenInstanceError`
  and instances have no `__dict__`;
- field names and order match the approved model exactly, and neither model has
  a `severity`, `cvss`, `confidence`, `state`, `status_state`, `id`, `uuid`,
  `created_at`, `timestamp`, `headers`, `body` or `raw` field;
- `body_length` of `0` is accepted, and a negative `body_length` raises
  `ValueError`;
- a `body_sha256` that is uppercase, 63 or 65 characters long, non-hexadecimal,
  empty or prefixed with `sha256:` raises `ValueError`, while a valid
  64-character lowercase digest is accepted unchanged;
- invariant failures name the offending field without echoing response content;
- `evidence_id` is not a dataclass field and is never caller-supplied;
- the canonical JSON string and its digest are locked by an exact test vector,
  in the style of the `PassiveFinding.fingerprint` vector, and the material
  contains exactly `schema`, `finding`, `status`, `body_length` and
  `body_sha256`;
- `evidence_id` is 64 lowercase hexadecimal characters;
- identity is stable: repeated construction, separately parsed but equal
  `TargetUrl` instances, and separately built but equal findings produce the
  same `evidence_id`;
- identity changes when `finding.fingerprint` changes, when `status` changes,
  when `body_length` changes and when `body_sha256` changes;
- identity does not change when only `requested_target` changes or when only
  the finding's `observation` or `rationale` changes;
- a mismatched final target and a mismatched requested target each raise
  `ValueError`;
- no timestamp, UUID, `hash()`, randomness or environment value participates in
  identity;
- `ResponseEvidence` and `FindingEvidence` are importable from
  `boundary.evidence` and the module exposes no `EvidenceEngine`,
  `EvidenceRecord`, `EvidenceStore`, `EvidenceRepository`,
  `build_finding_evidence`, `Evidence` protocol or comparison helper. Slice A
  does not assert that `capture_response_evidence` exists. The complete
  public-surface assertion — exactly those two types plus
  `capture_response_evidence` — belongs to Slice B.

### Slice B: Safe response evidence capture

Tests: `tests/test_evidence_response.py`

To deliver:

- `capture_response_evidence(response, *, requested_target=...)` returning a
  `ResponseEvidence` derived only from its arguments.

Acceptance criteria:

- `status` is copied unchanged, including non-2xx and 3xx values;
- `final_target` is `response.final_target` and `requested_target` is the
  supplied target, both preserved as the same normalized values;
- `body_length` equals `len(response.body)` exactly and is never taken from a
  `Content-Length` header, demonstrated with a response whose `Content-Length`
  disagrees with the body;
- `body_sha256` equals `hashlib.sha256(response.body).hexdigest()` for the
  exact retained bytes, locked by test vectors for at least an empty body, a
  short ASCII body and a non-UTF-8 binary body;
- an empty body produces `body_length == 0` and the digest of empty bytes, not
  an empty string or `None`;
- Unicode content is hashed as bytes: two encodings of the same text produce
  different digests, and no decoding, normalization, whitespace, line-ending or
  JSON-key-order canonicalization is applied;
- the digest is byte-sensitive: a one-byte change and a trailing-newline change
  each change it, while equal bytes from distinct objects produce equal
  digests and equal lengths;
- the digest is a 64-character lowercase hexadecimal string, so captured values
  always satisfy the Slice A invariants;
- headers are never read, retained or reflected: a response carrying
  `Authorization`, `Cookie` and `Set-Cookie` fields produces evidence whose
  full `repr` contains none of those names or values;
- no body bytes or decoded body text appear in any evidence field or in the
  value's `repr`;
- the inherited target boundary is documented rather than contradicted: a
  target carrying a query parameter keeps that parameter verbatim in
  `final_target` and `requested_target`, and the suite asserts that observed
  behavior instead of asserting that no sensitive string can appear anywhere;
- capture is pure and repeatable: the input `TransportResponse`, its headers,
  its body and both targets are unchanged, and repeated calls return equal
  values;
- capture is synchronous, performs no I/O, and the offline network guards
  described below are active;
- the module's public surface is now complete and is exactly
  `ResponseEvidence`, `FindingEvidence` and `capture_response_evidence`.

### Slice C: Passive-to-evidence composition

Tests: `tests/test_evidence_composition.py`

To deliver: no new production function. This slice verifies that the
composition chosen in ADR 0005 works against the real passive path and stays
inside the security boundary.

Acceptance criteria:

- for a page producing several findings, one `capture_response_evidence` call
  per page yields one `ResponseEvidence` shared by every `FindingEvidence` of
  that page, and each record's `response` is the same object;
- findings from a page whose `target` differs from `response.final_target`
  compose without error, and each record keeps the redirect provenance;
- distinct findings from one page produce distinct `evidence_id` values, while
  their `response` values are equal;
- the same finding fingerprint captured from two responses that differ in
  status, body length or body bytes produces different `evidence_id` values;
- the same finding fingerprint captured from two redirect-alias pages with
  equal status, equal body length and equal body digest produces equal
  `evidence_id` values, documenting that this is a genuine duplicate;
- a page yielding no findings produces no evidence, and the documented pattern
  performs no digest for it;
- composition over an async page stream stays lazy: consuming one record does
  not pull the next page, page order and `scan_page` finding order are
  preserved, and no pages, bodies or records are accumulated;
- upstream stream errors propagate unchanged;
- response-content secrets never appear: with a `Set-Cookie` value, an
  `Authorization` header and a bearer token present in the response headers and
  body, no evidence field, no `repr`, no identity material and no exception
  message contains them. The secrets used by these assertions are placed only
  in headers and bodies, never in a target query string, because the target
  boundary is inherited and unredacted;
- no mutation: the `DiscoveredPage`, its response, headers, body and targets
  are identical objects afterwards;
- the runtime network boundary holds: with `boundary.discovery.crawl`,
  `boundary.transport.request_once`,
  `boundary.transport.request_with_redirects`,
  `boundary.resolver.SystemAddressResolver.resolve`, `socket.getaddrinfo`,
  `socket.create_connection` and `anyio.connect_tcp` replaced by fail-fast
  assertions, the full capture and composition path completes normally;
- `boundary.evidence` binds no network callable at runtime. Fail-fast guards
  and inspection of runtime-bound names may assert the absence of `crawl`,
  `request_once`, `request_with_redirects`, resolver methods, socket APIs,
  HTTPCore and AnyIO connection objects. Standard-library names and the
  module's public surface are expected. No test may fail merely because
  `TargetUrl`, `TransportResponse` or `PassiveFinding` appear in the source
  as annotations;
- `boundary.passive` does not import `boundary.evidence`, keeping the
  dependency one-way.

### Slice D: Evidence stream orchestration — deferred

Not implemented, and not required by any current consumer.

An evidence stream that consumed `AsyncIterable[DiscoveredPage]` and called
`scan_page` internally would have to restate the run-level fingerprint
suppression rule `scan_pages` already owns, duplicating a delivered contract.
The caller-side loop documented in ADR 0005 needs no such function, and no
`EvidenceEngine` class will be created.

Reconsider only when a concrete consumer — a reporting serializer or the
Authorization Engine — needs a stream, and only if it can be expressed without
duplicating passive deduplication. Any future stream must remain lazy, retain
no bodies and key deduplication on `evidence_id` rather than on
`PassiveFinding.fingerprint`.

### Slice E: Response comparison primitives — deferred

Not implemented.

`ResponseEvidence` is a frozen dataclass, so equality, inequality and per-field
comparison are already available to any consumer. A `compare_responses` helper
would add no validation, transformation or behavior today, and semantic
similarity and authorization verdicts are explicitly out of scope.

Reconsider only with a real authorization comparison case that shows which
difference matters, and only in a milestone that owns the meaning of that
difference.

## Error-handling policy

Milestone 5 parses and decodes nothing, so it isolates nothing:

- hashing bytes and taking their length cannot fail on a well-typed input;
- a non-canonical `ResponseEvidence` state — negative `body_length`, or a
  `body_sha256` that is not 64 lowercase hexadecimal characters — is a
  programming defect and raises `ValueError`;
- inconsistent pairing is a programming defect and raises `ValueError`;
- type violations propagate;
- there will be no `try` / `except` in the module, and in particular no broad
  `except Exception`;
- error messages must contain no response content.

## Offline testing approach

All tests construct `TargetUrl`, `TransportResponse`, `DiscoveredPage` and
`PassiveFinding` values directly, exactly as the passive suites do. No test
contacts a target, and response or transport mocking is not required.

Network entry points are replaced with fail-fast assertions solely to show the
evidence path cannot reach them; the behavior under test is never mocked. Those
guards target executed behavior and runtime-bound network callables, not source
text. Annotations that name `TargetUrl`, `TransportResponse` or
`PassiveFinding` are expected. Standard-library imports such as `typing` are
expected. A source-level scan that fails because a domain type name appears in
an annotation is the wrong test.

Digest and identity expectations are locked by exact vectors rather than by
recomputing the implementation inside the test. Assertions check complete
values, absence of mutation and absence of response-content secrets, not only
types or counts. Secret-absence assertions place their secrets in headers and
bodies, since query-string values inside targets are an inherited, unredacted
boundary and must be documented rather than asserted away.

## Planned security invariants

- evidence performs zero network activity: no DNS, HTTP, `crawl`,
  `request_once`, `request_with_redirects`, socket, HTTPCore, browser or
  JavaScript execution;
- evidence performs no scope decision, no request mutation, no replay and no
  authorization test;
- no response header, header name, header value, body byte or body excerpt is
  ever stored in an evidence field;
- secrets carried in response headers or bodies — `Authorization`, `Cookie`,
  `Set-Cookie`, credentials, bearer tokens, API keys and session identifiers —
  cannot enter evidence, identity material, a `repr` or an exception message;
- sensitive values already present in a normalized target URL's query string
  remain visible, are inherited from Scope and ADR 0004, are not redacted here,
  and must be resolved before persistence or reporting;
- body hashing is SHA-256 over the exact retained bytes with no decoding or
  normalization; equal length plus equal digest is a strong collision-resistant
  byte-equality signal, never proof of byte identity, semantic equivalence or a
  vulnerability, and the digest is never redaction;
- evidence records a captured projection: headers, timing and connection
  properties are outside it, so matching evidence does not mean matching
  responses;
- `body_length` is the retained byte count, never a header value;
- `ResponseEvidence` is only ever in canonical state: `body_length >= 0` and a
  64-character lowercase hexadecimal `body_sha256`;
- observations attach to `final_target`; `requested_target` is provenance and is
  excluded from identity;
- evidence identity is a deterministic SHA-256 digest over canonical JSON of a
  schema version, `PassiveFinding.fingerprint`, the status, the body length and
  the body digest, with no second fingerprint system;
- no timestamp, UUID, `hash()`, randomness, environment value or process state
  participates in evidence or identity;
- capture retains no body beyond the current page's existing lifetime and
  accumulates nothing;
- no broad exception swallowing; programming and upstream errors propagate;
- no validation state, verdict, severity, CVSS or confidence is produced;
- nothing is persisted.

## Milestone non-goals

Not added, and still deferred:

- authorization testing, identity and session management, IDOR and BOLA;
- active validation, payload generation and exploitation;
- request replay, raw request archival and raw response archival;
- persistence of any kind: SQLite, PostgreSQL, evidence directories, JSONL,
  object storage, repository classes, cache layers;
- SARIF, JSON, HTML reporting, CLI rendering and dashboards;
- severity, CVSS, confidence, confirmation states and remediation;
- CVE correlation and vulnerability knowledge bases;
- semantic response similarity and comparison helpers;
- AI analysis, agent orchestration and autonomous tool execution;
- timestamps, run identifiers and evidence deduplication;
- changes to `passive.py`, `discovery.py`, `transport.py` or `scope.py`;
- an `EvidenceEngine` class, builder classes, protocols, registries, factories
  or dependency injection;
- concurrency.

## Dependency decision

No dependency is required.

The standard library provides `dataclasses`, `hashlib` for SHA-256 and `json`
for the canonical identity serialization, which is the same canonicalization
`passive.py` already uses. `Pydantic` is not needed: the values are five
scalars and two references, validated by three explicit invariants written in
a few lines of `__post_init__`.

## Verification sequence

Checks to execute for each slice and at closeout:

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

Focused evidence tests run first, then the complete suite. No test may contact
a public target, skip a security assertion or weaken an existing check.

## Definition of done

The milestone is complete only when:

- Slices A through C meet every acceptance criterion, and Slice A passes on its
  own before Slice B begins;
- Slices D and E remain absent, with their deferral documented;
- the public surface is exactly the three approved names, asserted once the
  third name exists;
- identity and digest vectors are locked by tests, including empty, binary and
  Unicode bodies, with `body_length` participating in identity;
- canonical-state violations, pairing violations, mutation absence and
  response-content secret absence are tested as negative cases;
- offline guards show the evidence path performs zero network activity, without
  banning legitimate annotation names;
- no persistence, reporting, validation state, severity or AI capability was
  added;
- formatting, linting, typing and all tests pass without skipped or weakened
  tests;
- ADR 0005 and this plan match the implementation, including deferred items;
- no dependency was added.
