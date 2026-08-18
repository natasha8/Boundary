# Evidence Engine Plan

- Status: Completed
- Milestone: 5
- Planned: 2026-08-18
- Completed: 2026-08-18
- Implementation: `src/boundary/evidence.py`
- Tests: `tests/test_evidence_model.py`,
  `tests/test_evidence_response.py`, `tests/test_evidence_composition.py`
- Decision record: `docs/decisions/0005-evidence-engine.md`

## Purpose

The Evidence Engine turns data that already exists into deterministic,
reproducible, comparable observation records.

It makes two statements possible that the repository could not make before
this milestone:

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

## Delivered architecture

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

The module exposes exactly those three names. `TargetUrl`,
`TransportResponse` and `PassiveFinding` are needed for annotations only and
are imported under `TYPE_CHECKING`. Runtime imports stay in the standard
library (`hashlib`, `json`, `dataclasses`, and `typing` for `TYPE_CHECKING`).
Naming those domain types in annotations is expected and is not a boundary
violation; what the boundary forbids is invoking network APIs.

`passive.py`, `discovery.py`, `transport.py` and `scope.py` were not modified.
No `EvidenceEngine`, stream API or comparison helper was added.

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

Tests were written before the implementation of each slice, and a slice is
complete only when its acceptance criteria hold.

### Slice A: Evidence model and deterministic identity — completed

Tests: `tests/test_evidence_model.py`

Delivered: frozen, slotted `ResponseEvidence` with exactly the five approved
fields and canonical-state invariants; frozen, slotted `FindingEvidence` with
exactly `finding` and `response` and the pairing invariant; `evidence_id` as a
computed property over canonical JSON with `sort_keys=True`,
`ensure_ascii=True`, compact separators, UTF-8 encoding and a lowercase
hexadecimal SHA-256 digest. Slice A tests construct `ResponseEvidence`
directly and do not import `capture_response_evidence`.

Acceptance criteria met: both models are frozen and slotted with the approved
field names and order and no severity, CVSS, confidence, state, identifier,
timestamp, headers, body or raw field; `body_length` of `0` is accepted and a
negative length raises `ValueError`; a non-canonical `body_sha256` raises
`ValueError` while a valid 64-character lowercase digest is accepted unchanged;
invariant failures name the offending field without echoing response content;
`evidence_id` is not a dataclass field, is never caller-supplied, is 64
lowercase hexadecimal characters, and is locked by an exact canonical-JSON
test vector whose material is exactly `schema`, `finding`, `status`,
`body_length` and `body_sha256`; identity is stable across repeated
construction and separately built equal inputs, changes when fingerprint,
status, body length or body digest changes, and does not change when only
`requested_target`, observation or rationale changes; mismatched final or
requested targets raise `ValueError`; no timestamp, UUID, `hash()`, randomness
or environment value participates; the Slice A public surface is
`ResponseEvidence` and `FindingEvidence` with no `EvidenceEngine` or comparison
helper.

### Slice B: Safe response evidence capture — completed

Tests: `tests/test_evidence_response.py`

Delivered: `capture_response_evidence(response, *, requested_target=...)`
returning a `ResponseEvidence` derived only from its arguments.

Acceptance criteria met: `status` is copied unchanged, including non-2xx and
3xx values; `final_target` is `response.final_target` and `requested_target` is
the supplied target; `body_length` equals `len(response.body)` exactly and is
never taken from `Content-Length`; `body_sha256` is SHA-256 over the exact
retained bytes, locked by empty, short ASCII and non-UTF-8 binary vectors; an
empty body produces length `0` and the digest of empty bytes; Unicode encodings
and JSON key order are hashed as distinct bytes with no decoding or
normalization; a one-byte change and a trailing newline each change the digest,
while equal bytes from distinct objects match; captured digests are 64
lowercase hexadecimal characters; headers and body bytes never appear in
evidence fields or `repr`; a query parameter on a target is preserved as the
inherited unredacted boundary; capture is pure, repeatable, synchronous and
performs no I/O; the public surface is exactly `ResponseEvidence`,
`FindingEvidence` and `capture_response_evidence`.

### Slice C: Passive-to-evidence composition — completed

Tests: `tests/test_evidence_composition.py`

Delivered: no new production function. The caller-side loop chosen in ADR 0005
was verified against the real `scan_page` path and stays inside the security
boundary.

Acceptance criteria met: one `capture_response_evidence` call per page with
findings yields one `ResponseEvidence` shared by every `FindingEvidence` of
that page; redirect provenance composes without error when `page.target`
differs from `response.final_target`; distinct findings from one page have
distinct `evidence_id` values and equal `response` values; the same finding
fingerprint captured from responses that differ in status, body length or body
bytes produces different `evidence_id` values; redirect-alias pages with equal
status, body length and body digest produce equal `evidence_id` values, which
are genuine duplicates; a page yielding no findings produces no evidence and
performs no digest; async composition stays lazy, preserves page order and
`scan_page` finding order, accumulates no pages, bodies or records, and
propagates upstream stream errors unchanged; response-content secrets in
headers and bodies never appear in evidence fields, `repr`, identity material
or exception messages; inputs are not mutated; fail-fast network guards hold
for the full capture and composition path; `boundary.evidence` binds no network
callable at runtime; `boundary.passive` does not import `boundary.evidence`.

### Slice D: Evidence stream orchestration — deferred / not implemented

Not implemented, and not required by any current consumer.

An evidence stream that consumed `AsyncIterable[DiscoveredPage]` and called
`scan_page` internally would have to restate the run-level fingerprint
suppression rule `scan_pages` already owns, duplicating a delivered contract.
The caller-side loop documented in ADR 0005 needs no such function, and no
`EvidenceEngine` class was created.

Reconsider only when a concrete consumer — a reporting serializer or the
Authorization Engine — needs a stream, and only if it can be expressed without
duplicating passive deduplication. Any future stream must remain lazy, retain
no bodies and key deduplication on `evidence_id` rather than on
`PassiveFinding.fingerprint`.

### Slice E: Response comparison primitives — deferred / not implemented

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
- there is no `try` / `except` in the module, and in particular no broad
  `except Exception`;
- error messages contain no response content.

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

## Final security invariants

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

No dependency was added.

The standard library provided `dataclasses`, `hashlib` for SHA-256 and `json`
for the canonical identity serialization, which is the same canonicalization
`passive.py` already uses. `Pydantic` is not needed: the values are five
scalars and two references, validated by three explicit invariants written in
a few lines of `__post_init__`.

## Verification sequence

Repository checks executed at closeout:

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

Focused evidence tests run first, then the complete suite. No test may contact
a public target, skip a security assertion or weaken an existing check.

## Test coverage

Offline evidence tests, all passing:

- `tests/test_evidence_model.py`: 38 tests;
- `tests/test_evidence_response.py`: 28 tests;
- `tests/test_evidence_composition.py`: 20 tests.

Full repository suite at closeout: 837 tests collected and passing, with no
skipped tests.

## Definition of done

Met:

- Slices A through C meet every acceptance criterion, and Slice A passed on
  its own before Slice B began;
- Slices D and E remain absent, with their deferral documented;
- the public surface is exactly `ResponseEvidence`, `FindingEvidence` and
  `capture_response_evidence`;
- identity and digest vectors are locked by tests, including empty, binary and
  Unicode bodies, with `body_length` participating in identity;
- canonical-state violations, pairing violations, mutation absence and
  response-content secret absence are tested as negative cases;
- caller-side Passive-to-Evidence composition is proven against real
  `scan_page` with one shared projection per page, redirect provenance and
  `evidence_id` duplicate/non-duplicate behavior;
- offline guards show the evidence path performs zero network activity, without
  banning legitimate annotation names;
- no persistence, reporting, validation state, severity, AI or authorization
  capability was added;
- formatting, linting, typing and all tests pass without skipped or weakened
  tests;
- ADR 0005 and this plan match the implementation, including deferred items;
- no dependency was added.
