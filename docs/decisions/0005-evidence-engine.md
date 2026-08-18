# ADR 0005: Record deterministic evidence without persistence or verdicts

- Status: Accepted and implemented (Milestone 5)
- Date: 2026-08-18
- Implemented: 2026-08-18
- Implementation: `src/boundary/evidence.py`
- Tests: `tests/test_evidence_model.py`,
  `tests/test_evidence_response.py`, `tests/test_evidence_composition.py`
- Depends on: `docs/decisions/0004-passive-security-scanning.md`
- Implementation plan: `docs/plans/0006-evidence-engine.md`

## Context

BOUNDARY claims reproducible evidence and deterministic validation. Before
this milestone, the completed layers did not yet support that claim:

- `PassiveFinding` carries a rule identity, the final target, requested-target
  provenance and sanitized rule facts, but nothing about the response beyond
  what a rule chose to record;
- `TransportResponse.body` exists on the input value, but no implemented rule
  reads it and `scan_page` discards it;
- nothing in the repository could state that two observations share one captured
  response projection, or that that projection changed between runs.

The next security capability on the roadmap is authorization testing, which
compares controlled requests executed under different identities. That
comparison needs deterministic response facts. Introducing those facts inside
the future Authorization Engine would mean designing evidence under the
pressure of an active-testing feature, which is exactly when shortcuts such as
storing raw responses become attractive.

Milestone 5 therefore defined the evidence layer first, while the only consumer
is passive analysis and the only inputs are values that already exist.

The core principle is:

> Evidence is deterministic data first; interpretation and explanation come
> later.

## Decision

BOUNDARY added one cohesive module, `src/boundary/evidence.py`, containing
immutable values and plain functions in the same style as `scope.py`,
`transport.py`, `discovery.py` and `passive.py`. The sections below describe
the delivered behavior.

### Core invariant

> The Evidence Engine derives facts from data it is given. It performs no
> network activity and reaches no verdict.

The delivered code does not:

- make an HTTP request, or call `crawl`, `request_once` or
  `request_with_redirects`;
- import HTTPCore, sockets, AnyIO connection APIs or `boundary.resolver`;
- resolve DNS or instantiate a resolver;
- decide scan scope or re-check scope;
- send payloads, mutate a request or replay a request;
- execute browser or JavaScript code;
- perform authorization testing or classify a finding as confirmed;
- call an AI or LLM service;
- persist anything;
- become a generic logging or event framework.

Ownership is unchanged: Scope Engine remains authoritative for network
boundaries, Transport for HTTP execution, Discovery for page discovery, Passive
Scanner for passive rule evaluation. Evidence adds only deterministic
observation records.

Only annotations require the other domain modules, so `evidence.py` imports
`TargetUrl`, `TransportResponse` and `PassiveFinding` under `TYPE_CHECKING`
with `from __future__ import annotations`. Runtime imports stay in the
standard library: `hashlib`, `json`, `dataclasses`, and `typing` for
`TYPE_CHECKING`. The dependency direction is one-way: `passive.py` does not
import `evidence.py`.

The boundary is about runtime behavior, not source text. Naming `TargetUrl`,
`TransportResponse` or `PassiveFinding` in a type annotation is legitimate and
required; what must not happen is invoking transport, discovery, resolver or
socket APIs. Any verification of this invariant must target executed behavior
and runtime-bound names, not the presence of a word in the module source.

### Vocabulary: finding, evidence, raw response data

The three concepts are deliberately separated.

1. **Finding** — a security interpretation, for example
   `passive.hsts.not_enforced.v1`. It states that an observed configuration
   matters. `PassiveFinding` owns this, including the sanitized facts the rule
   used to decide.

2. **Evidence** — deterministic facts about the response that produced an
   observation: the status, the byte length of the retained body, the SHA-256
   digest of those retained bytes, the final target and the requested target.
   Evidence supports reproduction and comparison. It makes no claim.

3. **Raw response data** — headers and body bytes. This is untrusted,
   potentially secret-bearing material. It exists in memory for the lifetime of
   the current `DiscoveredPage` and must not automatically become an evidence
   field.

A full raw response dump is therefore not evidence. Evidence is minimal
reproducible metadata derived from the response.

Evidence is a **captured response projection**, not the response. Headers are
deliberately excluded, and so is everything else BOUNDARY does not record:
timing, protocol version, TLS parameters and connection behavior. No document,
message or test may describe `ResponseEvidence` as the complete or exact HTTP
response.

### Response evidence model

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
```

`capture_response_evidence` derives every field from values it is handed:

- `status` is `response.status` unchanged;
- `final_target` is `response.final_target`;
- `requested_target` is the target the request was issued for, before
  redirects;
- `body_length` is `len(response.body)`, the length of the retained bytes —
  never a `Content-Length` header value, which is untrusted and may disagree
  with the body;
- `body_sha256` is the lowercase hexadecimal SHA-256 digest of exactly
  `response.body`.

The builder takes a `TransportResponse` plus an explicit requested target
rather than a `DiscoveredPage`. That keeps `evidence.py` independent of
`discovery.py`, and it means the same primitive serves a future authorization
request, which will have no `DiscoveredPage`. The passive call site stays
explicit:

```python
capture_response_evidence(page.response, requested_target=page.target)
```

`ResponseEvidence` is standalone by design: it is meaningful without any
finding, because response comparison is its future purpose.

Because `request_once` raises `TransportError(RESPONSE_TOO_LARGE)` instead of
truncating, a body that reached a `DiscoveredPage` is complete under the
configured limit. The digest therefore covers the whole retained body, and no
truncation flag is needed. If a later milestone introduces truncation, the
digest contract must be revisited in a new ADR.

#### Canonical-state invariants

`ResponseEvidence.__post_init__` enforces two invariants and nothing else:

- `body_length` must be `>= 0`;
- `body_sha256` must be exactly 64 lowercase hexadecimal characters.

A violation raises `ValueError`. Both fields participate in evidence identity,
so a negative length or a differently formatted digest — uppercase hex, a
truncated digest, a `sha256:` prefix — would silently produce an identity that
cannot be compared with any other run. The invariants keep the value in exactly
one canonical state, which is what makes identity meaningful.

The validation stops there. `ResponseEvidence` does not re-validate or
re-normalize `TargetUrl` values, because Scope owns that and duplicating it
would create a second URL contract. It does not police the status range, since
Transport reports what the server sent. There is no builder class, and
`capture_response_evidence` remains the normal construction path from a real
`TransportResponse`; direct construction stays available to tests and to future
callers precisely because the invariants make it safe.

### Finding evidence model

```python
@dataclass(frozen=True, slots=True)
class FindingEvidence:
    finding: PassiveFinding
    response: ResponseEvidence

    def __post_init__(self) -> None: ...

    @property
    def evidence_id(self) -> str: ...
```

`FindingEvidence` composes the two values by reference and copies no field, so
nothing in `PassiveFinding` is duplicated. It answers "which response produced
this observation" without turning either value into a subset of the other.

`__post_init__` enforces the one invariant that makes the pairing meaningful:

- `finding.target` must equal `response.final_target`;
- `finding.requested_target` must equal `response.requested_target`.

A violation is a programming defect — pairing a finding with a different
response — and raises `ValueError`. This is real validation, not a wrapper, so
`FindingEvidence` is constructed directly; no `build_finding_evidence` helper
was added because it would add no behavior beyond the constructor.

### Division of responsibility

`PassiveFinding` owns the interpretation:

- `rule_id` — the versioned rule identity;
- `kind` — misconfiguration versus hardening classification;
- `observation` and `rationale` — the human-readable claim;
- `evidence` — the sanitized facts the rule decided from.

`ResponseEvidence` owns the deterministic response facts:

- `status`;
- `body_length`, the byte count of the retained body;
- `body_sha256`, the SHA-256 digest of those retained bytes.

Both own the target pair, and `FindingEvidence` requires them to agree.
`FindingEvidence` owns only the linkage between an observation and the response
that produced it, plus that linkage's identity.

`PassiveFinding.evidence` remains the canonical sanitized rule-fact channel.
Milestone 5 added no second metadata channel: no `Mapping[str, Any]`, no
untyped JSON blob, no extra key/value tuple on either evidence value. If a
future consumer needs a fact that is neither a rule fact nor one of the five
response fields, it must be added as a narrow typed field with a documented
reason.

Note that `status` appears both as a `ResponseEvidence` field and, by
convention, in the `status` evidence key of all six implemented rules. That
convention belongs to those rules and is not a model guarantee, so
`ResponseEvidence` records the status independently.

### Deterministic identity

`FindingEvidence.evidence_id` is a computed property, never a stored or
caller-supplied field. It is the lowercase hexadecimal SHA-256 digest of
canonical JSON containing:

1. evidence-identity schema version `1`;
2. `finding.fingerprint`;
3. `response.status`;
4. `response.body_length`;
5. `response.body_sha256`.

Canonical JSON uses the same rules as `PassiveFinding.fingerprint`: UTF-8,
`ensure_ascii=True`, `sort_keys=True` and compact separators. The material has
the shape:

```json
{"body_length":123,"body_sha256":"<64 hex>","finding":"<64 hex>","schema":1,"status":200}
```

There is exactly one fingerprint system. Evidence identity does not re-hash the
rule ID, the target or the sanitized rule facts: it delegates all of that to
`PassiveFinding.fingerprint` and adds only the response facts the fingerprint
does not cover. A fingerprint schema change therefore propagates into evidence
identity by construction, which is the intended relationship. The evidence
schema version is separate so a change to the response fields participating in
identity can be versioned without touching `passive.py`.

`body_length` and `body_sha256` both participate. The length is not treated as
redundant: the byte-equality signal this model records is the pair, and
identity must not depend on the assumption that a digest already implies a
length. Identity therefore changes whenever `body_length` changes, whenever
`body_sha256` changes, whenever the status changes and whenever the finding
fingerprint changes.

Identity deliberately excludes:

- `requested_target`, because the response belongs to the final target
  regardless of which redirect alias reached it — consistent with ADR 0004;
- UUIDs, timestamps, `hash()`, object identity, process state and any random
  value.

Consequences of that choice, all intended:

- the same logical observation over a stable response produces the same
  `evidence_id` in every run and process;
- two pages that are redirect aliases of one final target, with the same
  status, body length and body digest, produce equal `evidence_id` values.
  Those records are genuine duplicates and `evidence_id` is the correct
  deduplication key if a later consumer needs one;
- the same finding fingerprint observed with a different status, body length or
  body digest produces a different `evidence_id`. That is not a duplicate, and
  evidence must not collapse it.

### Body digest contract and limits

Body hashing obeys a narrow contract:

- hash exactly the `TransportResponse.body` bytes;
- SHA-256, lowercase hexadecimal;
- never decode, never normalize whitespace, line endings, encoding or JSON key
  order;
- record `body_length` separately as a byte count;
- an empty body is hashed as empty bytes, not skipped;
- binary bodies and UTF-8 or other text bodies are treated identically, as
  bytes.

The limits are explicit:

- equal `body_length` and equal `body_sha256` are treated as a strong
  collision-resistant signal that the retained bytes were the same. That is a
  cryptographic assumption, not a mathematical proof of byte identity, and the
  wording used anywhere in BOUNDARY must not upgrade it into one;
- the signal covers the captured projection only. Two responses can match on
  status, length and digest while differing in headers, cookies, timing or
  side effects that evidence does not record;
- equal digests do not mean two responses are semantically equivalent, and they
  never constitute proof of a vulnerability;
- different digests do not mean authorization behavior differed. Dynamic
  pages — CSRF tokens, nonces, rendered timestamps, per-request identifiers,
  varying ordering — routinely produce different digests for responses that are
  equivalent for authorization purposes;
- the digest is a comparison primitive, not a redaction mechanism. It does not
  authorize hashing secret material as a way to store it, and for a very short
  or low-entropy body a digest is not a confidentiality guarantee. The
  applicable safeguard remains that BOUNDARY does not persist bodies at all.

Semantic response comparison is not solved in this milestone.

### Provenance

The distinction between the requested target and the responding target is
preserved end to end:

- `final_target` is the normalized resource that actually produced the
  response, and is authoritative for what the evidence describes;
- `requested_target` is provenance: it explains which request produced this
  response, so a redirect alias remains traceable;
- provenance never participates in identity.

### No validation state

`FindingEvidence` has no `OBSERVED` / `VALIDATED` / `REJECTED` state, no
confidence, no severity and no confirmation flag. No current consumer decides
validation, and adding states now would encode a workflow that does not exist.

Evidence capture and vulnerability verdicts stay separated: the Evidence Engine
records facts, and a future engine interprets them and owns whatever validation
vocabulary it needs.

### Passive Scanner to Evidence composition

`scan_page` returns `PassiveFinding` values and `scan_pages` yields them
without the response, so by the time a finding reaches a consumer the body
needed for a digest is gone. Four compositions were compared.

**A. Build evidence inside `scan_page`.** Rejected. It changes the return type
of both `scan_page` and `scan_pages`, breaking their delivered contracts and
the suites that lock them, and it forces evidence — including a body hash — on
every consumer that only wants findings. It also moves body handling into the
module whose ADR states that no rule reads the body.

**B. Make Passive Scanner return a richer finding-plus-evidence object.**
Rejected for the same API churn, plus an ownership inversion: passive analysis
would then own evidence identity and body digests, and a change to the evidence
model would require changing the passive module.

**C. An evidence builder that receives `DiscoveredPage` and `PassiveFinding`
while both are still available.** Accepted in principle: it needs no change to
`passive.py` and keeps ownership clean. Rejected in its literal form, because
taking a `DiscoveredPage` couples `evidence.py` to `discovery.py` and produces
a primitive that a future authorization request — which has no
`DiscoveredPage` — cannot use.

**D. The smaller variant found in the implementation, and the accepted
decision.** Response evidence is captured once per page from the
`TransportResponse` the caller already holds, and the pairing is a plain frozen
dataclass construction. No production API changes, no new orchestration
function, no class:

```python
async for page in crawl(...):
    findings = scan_page(page)
    if not findings:
        continue

    response_evidence = capture_response_evidence(
        page.response,
        requested_target=page.target,
    )
    for finding in findings:
        record = FindingEvidence(finding=finding, response=response_evidence)
```

This composition wins on every required criterion: zero API churn,
deterministic output, streaming compatibility, one digest per page with
findings and none for clean pages, no duplicated body retention, an explicit
Passive/Evidence boundary, and no abstraction beyond two frozen values and one
function.

A fifth option — an evidence stream function that consumes
`AsyncIterable[DiscoveredPage]` and calls `scan_page` internally — was
considered and deferred. It would have to restate the run-level
fingerprint-suppression rule that `scan_pages` already owns, duplicating a
delivered contract for no current consumer. See Slice D in the plan. No
`EvidenceEngine` class was created.

One consequence must be stated plainly: the evidence composition uses
`scan_page`, so the cross-page fingerprint suppression performed by
`scan_pages` is not part of the evidence path. That is correct rather than a
regression, because the same finding fingerprint seen on a different response
carries different evidence and must not be suppressed. Where suppression is
wanted, `evidence_id` is the right key.

### Streaming and memory contract

Evidence capture is synchronous, per page and per finding. It requires no
accumulation of pages, findings or evidence records, and adds no state that
grows with the run. A response body is read once, while the page is in scope,
and is not retained afterwards: `ResponseEvidence` stores a fixed-size digest
and an integer, never the bytes. Evidence introduces no concurrency.

### Error policy

Milestone 5 parses nothing and decodes nothing, so it needs no error
isolation. Hashing bytes and taking their length cannot fail on a well-typed
input, and no untrusted text is interpreted.

Consequently the module contains no `try` / `except` at all, and in
particular no broad `except Exception`. Programming defects propagate. There
are exactly two raising conditions, both `ValueError` and both defects rather
than untrusted input:

- a `ResponseEvidence` constructed with a negative `body_length` or a
  non-canonical `body_sha256`;
- a `FindingEvidence` whose finding and response describe different targets.

Type violations surface as they occur. Error messages carry no response
content. If a later slice introduces metadata that can be malformed, isolation
must be added at the specific field that makes the decision, following ADR
0004.

### Privacy boundary

Response content is excluded by construction rather than by later redaction.
`ResponseEvidence` holds two integers, one hexadecimal digest and two
normalized `TargetUrl` values, and no field can hold response text.

The module does not copy:

- response headers, whole or partial, including header names;
- `Authorization` header values;
- `Cookie` and `Set-Cookie` values;
- response bodies or arbitrary body excerpts;
- credentials, bearer tokens, API keys or session identifiers **that appear in
  response headers or bodies**.

No generic secret scanner is required for that boundary, because no field
accepts free-form response content.

#### What "safe by construction" does not claim

The guarantee is about response-content capture. It is not a claim that no
sensitive value can ever appear anywhere in an evidence value.

`TargetUrl` preserves the query string. `parse_target_url` rejects embedded
userinfo credentials, but it does not inspect query parameters, so a target
such as `https://app.test/reset?token=...` keeps that parameter in
`final_target`, in `requested_target` and inside `PassiveFinding.target` — and
therefore inside the finding fingerprint and the evidence identity material.

This is an inherited sensitive-data boundary:

- it already exists in Scope and in ADR 0004; Milestone 5 does not introduce it
  and does not widen it;
- Milestone 5 does not redact, drop or hash query parameters, because a
  redaction contract would change target identity and belongs to a decision
  that owns URL identity, not to evidence capture;
- it must be resolved before evidence is persisted, exported or rendered,
  since that is the point where a token would leave the process.

Tests must reflect this precisely. Asserting that a `Set-Cookie` value or an
`Authorization` value never reaches evidence is a real guarantee. Asserting the
same for a token deliberately placed in a target query string would assert a
protection that does not exist.

### Determinism

For the same inputs the module produces the same evidence values and the same
`evidence_id`, in this process and in any other:

- no timestamp, clock read, UUID, `hash()`, randomness or environment value is
  read;
- canonicalization is explicit: JSON with `sort_keys=True`,
  `ensure_ascii=True`, compact separators, UTF-8 encoding, and a lowercase hex
  SHA-256 digest;
- digests are taken over exact bytes, with no normalization step that could
  drift.

Timestamps may be useful for reporting later. They are deferred, and if added
they must stay outside identity.

### Delivered surface

`src/boundary/evidence.py` exposes exactly:

- `ResponseEvidence`;
- `FindingEvidence`;
- `capture_response_evidence`.

No `EvidenceEngine`, builder class, abstract base class, protocol, registry,
factory, repository, cache, serializer, stream API or comparison helper.

## Deferred

Explicitly not part of Milestone 5, including Slices D and E:

- an evidence stream API, `EvidenceEngine` class or caller-hiding
  orchestration that would restate `scan_pages` fingerprint suppression;
- a `compare_responses` helper or semantic response-similarity primitive;
- authorization testing, identity and session management, IDOR and BOLA;
- active exploitation and payload generation;
- request replay, raw request archival and raw response archival;
- persistence of any kind: SQLite, PostgreSQL, evidence directories, JSONL,
  object storage, repository classes and cache layers;
- SARIF, JSON, HTML reporting, CLI rendering and dashboards;
- remediation guidance, CVE correlation, CVSS, severity and confidence;
- semantic response similarity and response-comparison helpers;
- validation states and confirmation verdicts;
- AI analysis, agent orchestration and autonomous tool execution;
- timestamps and run identifiers;
- concurrency.

Future deterministic serializers must be able to consume `ResponseEvidence`
and `FindingEvidence` field by field, without parsing human prose. That is why
`observation` and `rationale` stay outside evidence and outside identity.

## Authorization Engine preparation

Milestone 5 added no identity, login flow, session, request mutation or
authorization verdict. It only ensures the generic primitives a later
comparison will need already exist and are deterministic:

- response status;
- final target;
- requested-target provenance;
- the byte length of the retained body;
- the SHA-256 digest of the retained body bytes;
- deterministic evidence identity.

`ResponseEvidence` is intentionally usable without a finding, so a future
authorization test can capture one value per identity from the response it
already holds and compare the fields it chooses. What such a comparison means
is that milestone's decision, not this one's.

## Strategic direction

BOUNDARY remains deterministic-first. Future orchestration or AI may propose
actions or explain results, but deterministic components stay authoritative
for scope, transport safety, evidence and validation. AI is not a source of
evidence, does not decide scope, and any AI-generated interpretation must
remain distinguishable from deterministic observations — which is why
`ResponseEvidence` and `FindingEvidence` contain no free-text field.

## Consequences

Positive:

- two observations can be tied to the same captured response, and one
  observation can be compared across runs;
- evidence identity is deterministic, single-sourced and locked by test
  vectors;
- no response header or body content can enter an evidence field, because no
  field accepts response content;
- the passive pipeline and its delivered contracts are unchanged; the
  composition is a caller-side loop;
- streaming and memory behavior are unchanged, with one digest per page that
  produced findings;
- the future Authorization Engine inherits ready comparison primitives instead
  of inventing them under feature pressure;
- no dependency was added.

Negative:

- body digests are byte-exact, so dynamic pages will differ between runs and
  digest inequality alone will be a weak signal for the future comparison
  work;
- comparison is limited to the captured projection: responses differing only in
  headers are indistinguishable in evidence;
- evidence inherits the query-string exposure of normalized target URLs, so
  "safe by construction" covers response content only and the inherited
  boundary stays open until persistence or reporting is designed;
- evidence cannot answer "why" beyond the finding it references, because no
  headers or body excerpts are retained;
- the evidence composition uses `scan_page`, so a caller that wants run-level
  finding suppression must key it on `evidence_id` itself;
- `FindingEvidence` holds a reference to a `PassiveFinding`, so the two models
  are coupled in one direction and a passive fingerprint change alters
  evidence identity;
- nothing is persisted or reported yet, so evidence is only observable in
  memory and in tests.

## Unresolved questions

1. **Query strings in targets.** Normalized `TargetUrl` values retain query
   parameters, which may carry tokens, and those targets reach the finding
   fingerprint and the evidence identity material. This is inherited from Scope
   and ADR 0004 rather than introduced here. Whether redaction belongs to a
   reporting policy, to scope normalization or to evidence must be decided
   before any evidence leaves the process. It does not block Milestone 5,
   because nothing is persisted or rendered yet.
2. **Digest usefulness for dynamic applications.** Whether byte-exact digests
   are sufficient for the Authorization Engine, or whether a separately
   approved normalization is required, can only be answered with real
   comparison cases.
3. **Deduplication ownership.** No consumer needs evidence deduplication yet.
   Whether it belongs to a future stream, to reporting or nowhere stays open,
   and `evidence_id` is the designated key when it is answered.
4. **Non-passive observations.** `FindingEvidence` references
   `PassiveFinding` because that is the only finding type today. If a future
   engine produces a different observation type, whether it reuses this value
   or gets its own remains an open decision, not a reason to add an abstraction
   now.

Slice status and test coverage are tracked in
`docs/plans/0006-evidence-engine.md`.
