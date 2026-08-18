# ADR 0006: Compare explicit identities without expanding scope or leaking credentials

- Status: Accepted (Milestone 6), implementation pending
- Date: 2026-08-18
- Planned implementation: `src/boundary/authorization.py`, with a narrow
  change to `src/boundary/transport.py`
- Planned tests: `tests/test_authorization_identity.py`,
  `tests/test_transport_credentials.py`,
  `tests/test_authorization_request.py`,
  `tests/test_authorization_compare.py`,
  `tests/test_authorization_observation.py`
- Depends on: `docs/decisions/0002-controlled-http-transport.md`,
  `docs/decisions/0005-evidence-engine.md`
- Implementation plan: `docs/plans/0007-authorization-engine.md`

## Context

BOUNDARY's next security capability is authorization testing: controlled
IDOR/BOLA-style comparisons between explicitly configured identities on an
explicit target.

The completed layers already provide the required primitives:

- Scope Engine is authoritative for URL identity, exact-origin allowlisting,
  DNS/address policy and redirect destination admission;
- Transport sends `GET` requests through pinned connections, bounded bodies,
  timeouts and manual in-scope redirects;
- Evidence records a captured response projection (`status`, `final_target`,
  `requested_target`, `body_length`, `body_sha256`) without headers or body
  bytes;
- Passive Scanner and Discovery do not send credentials and must not start
  doing so.

Two gaps block a safe authorization layer:

1. Nothing in the repository can name an identity in a finding without also
   holding the secret that authenticates it.
2. `request_with_redirects` forwards the caller-supplied `headers` bag to every
   hop, including allowlisted cross-origin destinations. That contract is safe
   for Discovery's empty/non-secret headers. It is not safe for
   `Authorization` or `Cookie` values.

Authorization testing is active: it sends additional requests. It must still
obey the product rules that Scope remains authoritative, active testing stays
disabled by default at the product surface, and AI never decides scope,
identities, targets or verdicts.

The core principle is:

> Authorization Engine compares two explicit identities on one explicit
> target. It does not discover, authenticate, persist or judge exploitability.

## Decision

BOUNDARY will add one cohesive module, `src/boundary/authorization.py`,
composed of immutable values and plain functions in the same style as
`scope.py`, `transport.py`, `discovery.py`, `passive.py` and `evidence.py`.

A narrow Transport change is required so origin-bound credentials cannot follow
a cross-origin redirect. That change is isolated as its own implementation
slice. Discovery's uncredentialed path stays unchanged.

No `AuthorizationEngine` class, planner, Flow/Task/Subtask system, vault,
login automation, cookie jar or second HTTP client will be added.

### Core invariant

> Scope Engine remains authoritative. Credentials are origin-bound runtime
> material. AI never decides scope, identities, targets or authorization
> verdicts.

The delivered code must not:

- parse, crawl or otherwise expand the approved target set;
- call `crawl` or invent a second HTTP client;
- bypass `request_with_redirects`, DNS revalidation, IP pinning, body limits,
  timeouts or redirect admission;
- forward credentials to an origin other than the exact bound origin;
- persist, log, fingerprint, report or `repr` credential values;
- treat equal captured projections as proof of IDOR/BOLA;
- assign CVSS, severity, confidence or a confirmed-vulnerability state;
- call an AI or LLM service, or accept an agent-chosen identity, target or
  verdict.

Ownership stays unchanged: Scope for network boundaries, Transport for HTTP
execution, Evidence for captured projections, Discovery for page discovery,
Passive Scanner for header-derived observations. Authorization adds only
pairwise identity comparison.

### Vocabulary

- **identity** — a deterministic public label such as `anonymous`, `user-a` or
  `user-b`. It is safe to store in findings and fingerprints.
- **credentials** — secret-bearing request headers supplied at execution time.
  They authenticate an identity to one exact origin and are never evidence.
- **authorization case** — one explicit target plus two explicit identities.
- **captured projection** — existing `ResponseEvidence`. Headers and body
  bytes are outside it.
- **response comparison** — four boolean facts about two projections. It is
  not a verdict.
- **authorization observation** — a deterministic record of a completed pair
  comparison. It is not a validated vulnerability.

## Identity model

The smallest identity that can appear in findings is a label:

```python
@dataclass(frozen=True, slots=True)
class Identity:
    identity_id: str

    def __post_init__(self) -> None: ...
```

`identity_id` is a non-empty ASCII token matching `^[A-Za-z0-9._-]+$`, so
`anonymous`, `user-a` and `user-b` are valid and spaces, slashes or header-like
values are rejected. The validator raises `ValueError` and must not echo a
rejected value that could itself be a pasted secret.

`Identity` holds no headers, cookies, tokens or passwords. Two `Identity`
values compare equal when their `identity_id` values are equal.

There is no enum of well-known identities and no special type for anonymous
access. The documented convention is:

- unauthenticated requests use `identity_id="anonymous"` with no credentials;
- authenticated requests use a caller-chosen label such as `user-a` together
  with origin-bound credentials.

`request_as` does not require the string `anonymous`. It does require that
credentials, when present, match the target origin, and that a pairwise case
uses two different `identity_id` values.

This model is not a vault, session store, user directory or login result.

## Credential containment

### Why Transport must change

`request_with_redirects` currently passes the same `headers` tuple to every
`request_once` call. The suite locks that behavior, including across
allowlisted cross-origin hops.

Discovery never supplies `Authorization` or `Cookie` headers, so the existing
contract does not leak credentials today. Authorization cannot reuse that
contract. Wrapping Transport in authorization.py cannot make leakage
impossible: the forwarding happens inside Transport before the wrapper sees
the next hop.

Reimplementing redirects in authorization.py with `request_once` would
duplicate hop limits, loop detection, origin checks, DNS revalidation and
pinning. ADR 0003 forbids a second implementation of those controls.

Restricting authorization requests to `max_redirects=0` would avoid leakage
only by refusing same-origin redirects that real APIs use. That is too narrow.

Therefore Transport gains an explicit origin-bound credential parameter.
Generic `headers` keep today's forwarding behavior for non-secret fields.
Credential headers are a separate bag and are never placed in that forwarded
bag.

### OriginBoundCredentials

The ephemeral representation lives in `transport.py`, because Transport is
the enforcement point:

```python
@dataclass(frozen=True, slots=True)
class OriginBoundCredentials:
    origin: Origin
    headers: tuple[tuple[bytes, bytes], ...]

    def __post_init__(self) -> None: ...

    def __repr__(self) -> str: ...
```

Rules:

- `origin` is the existing Scope `Origin` (`scheme`, `host`, `port`);
- `headers` is a non-empty tuple of `(name, value)` byte pairs;
- the only permitted names are `Authorization` and `Cookie`, matched
  case-insensitively (`authorization`, `AUTHORIZATION` and `Cookie` are
  accepted; `X-Api-Key`, `X-Auth-Token`, `Api-Key`, `host` and any other
  name raise `ValueError`);
- names are unique, case-insensitive: two `Authorization` fields, or
  `Authorization` plus `authorization`, raise `ValueError`;
- one of the two names, or both, may be present; the bag cannot be empty;
- custom API-key and other application headers are deferred;
- values are never decoded, normalized, hashed, logged or copied into other
  types;
- `__repr__` and `__str__` report only the origin and the field count, never
  header names or values;
- `ValueError` and `TransportError` messages name the offending constraint
  (`origin`, header allowlist, duplicate name) and never include header
  names or values;
- the object is not persisted, not a dataclass field on any observation, and
  not accepted by Evidence.

Anonymous requests pass `credentials=None`. Generic non-secret request
headers, if any, stay in the existing `headers=` bag and are not credentials.

### Fail-closed redirect contract

Credentials are bound to one exact origin. Exact origin means the existing
`Origin` equality: scheme, host and port. `http` and `https`, a non-default
port, or a different host are different origins even when the Scope allowlist
admits both.

**Strip and continue is rejected.** Dropping credentials on the next hop would
turn a credentialed request into an unauthenticated one while the caller still
believes the comparison identity was used. That silent conversion could be
recorded as an authorization observation. Fail-closed abort is the smaller
honest contract: the pair is incomplete, no observation is emitted, and the
error propagates.

Credentialed redirect handling has a fixed order. Scope remains authoritative;
credential containment runs only after Scope has admitted the destination:

1. Resolve and validate the `Location` with the existing Scope path
   (`resolve_allowed_redirect`): unsafe, malformed, credential-bearing or
   out-of-allowlist destinations keep today's `UrlValidationError` /
   `ScopeValidationError`. Those errors must not be replaced by
   `CROSS_ORIGIN_CREDENTIAL_REDIRECT`.
2. If Scope admits the destination and that destination's `Origin` equals
   `credentials.origin`, follow the redirect and retain the bound headers.
3. If Scope admits the destination and that destination's `Origin` differs
   from `credentials.origin`, raise `TransportError` with stable code
   `CROSS_ORIGIN_CREDENTIAL_REDIRECT` **before** any next-hop `request_once`.
   An allowlist entry is not a credential audience.
4. Never strip credentials and continue.

The initial request target origin must equal `credentials.origin`, or
`ValueError` is raised before network I/O (programming defect). Same-origin
relative and absolute redirects therefore keep the bound headers.

The `CROSS_ORIGIN_CREDENTIAL_REDIRECT` message states that the redirect
destination origin differs from the bound origin. It does not include header
names, header values, or the `Location` value.

Allowlisted cross-origin redirects remain valid for uncredentialed Discovery
requests (`credentials=None`).

### What does not change

- `request_once` remains a dumb sender of the headers it is given;
- `crawl` still calls `request_with_redirects` without credentials;
- uncredentialed `request_with_redirects` still forwards generic `headers` to
  every admitted hop;
- Scope still admits or rejects redirect destinations independently of
  credentials.

## Request scope

Milestone 6 authorization requests are `GET` only, with no request body and no
caller-supplied Host header.

Current Transport already provides that primitive. Form submission, request
bodies, `POST` / `PUT` / `PATCH` / `DELETE`, cookie-jar continuation, CSRF
workflows and browser flows are deferred until a concrete authorized-mutation
case exists.

`request_as` rejects any method other than `GET` with `ValueError` before
network I/O. Transport's generic `method=` parameter stays available to
existing uncredentialed callers; authorization does not use it.

No destructive requests are issued.

## Authorization case

The engine does not discover resources. The caller supplies the case:

```python
@dataclass(frozen=True, slots=True)
class AuthorizationCase:
    target: TargetUrl
    baseline: Identity
    comparison: Identity

    def __post_init__(self) -> None: ...
```

`target` is already a normalized Scope `TargetUrl`. The two identities must
have different `identity_id` values or construction raises `ValueError`.

Discovery may later yield candidate `TargetUrl` values. Feeding them into
`AuthorizationCase` is a caller-side loop. Authorization must not import
`crawl`, enqueue URLs or otherwise expand scope.

## Execution

Every authorization request uses the existing controlled path:

    Scope origin allowlist
        -> DNS / address policy
        -> IP pinning
        -> bounded body and timeouts
        -> redirect admission
        -> origin-bound credentials (new)

The orchestration is one function, not a class:

```python
async def request_as(
    target: TargetUrl,
    identity: Identity,
    *,
    credentials: OriginBoundCredentials | None,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: AddressResolver,
    limits: RequestLimits,
    max_redirects: int,
) -> TransportResponse: ...
```

`request_as` calls `request_with_redirects` with `method="GET"` and
`credentials=...`. It does not call `request_once`, HTTPCore, sockets or
`crawl`.

If `credentials` is not `None`, `credentials.origin` must equal
`target.origin` (`ValueError` otherwise). The `Identity` is not sent on the
wire; it exists so the later observation can name who was compared.

Pair execution is sequential and explicit:

1. request as baseline, capture `ResponseEvidence`, drop the
   `TransportResponse`;
2. request as comparison, capture `ResponseEvidence`, drop the
   `TransportResponse`;
3. compare the two projections;
4. build one `AuthorizationObservation`.

If step 1 fails, step 2 is not attempted. If step 2 fails, the baseline
projection is discarded and not turned into an observation. A transport,
scope or request failure is never converted into `DISTINCT_PROJECTION`,
`EQUIVALENT_PROJECTION`, or any other `AuthorizationObservation`. See Error
policy.

## Response evidence

Milestone 5 `ResponseEvidence` and `capture_response_evidence` are the only
response snapshot. Authorization will not add a second snapshot type, will not
archive bodies, and will not copy response headers into authorization values.

For each identity the captured facts are exactly:

- `status`
- `final_target`
- `requested_target` (the case target)
- `body_length`
- `body_sha256`

`capture_response_evidence` already takes `TransportResponse` plus an explicit
requested target, which is the shape a non-`DiscoveredPage` authorization
request needs.

## Comparison

Comparison lives in `authorization.py`, not in `evidence.py`. Evidence remains
capture-only; the four booleans are an authorization reading of two
projections. Milestone 5 deferred a generic `compare_responses` helper for
this reason.

```python
@dataclass(frozen=True, slots=True)
class ResponseComparison:
    status_equal: bool
    body_length_equal: bool
    body_sha256_equal: bool
    final_target_equal: bool


def compare_response_evidence(
    baseline: ResponseEvidence,
    comparison: ResponseEvidence,
) -> ResponseComparison: ...
```

Equality is field equality of the captured projection. `final_target_equal`
uses `TargetUrl` equality. Length plus digest remain the Milestone 5
byte-equality signal: collision-resistant, not proof of byte identity,
semantic equivalence or a vulnerability.

Equal projections are **not** proof of IDOR/BOLA. Distinct projections are
**not** proof that authorization is correct. Dynamic pages, CSRF tokens,
timestamps and non-authorization headers routinely make those implications
false. Semantic similarity and LLM comparison are out of scope.

## Authorization observation

Observation is separated from validated vulnerability. Milestone 6 produces
only the former.

```python
class AuthorizationObservationKind(StrEnum):
    EQUIVALENT_PROJECTION = "equivalent_projection"
    DISTINCT_PROJECTION = "distinct_projection"


@dataclass(frozen=True, slots=True)
class AuthorizationObservation:
    rule_id: str
    kind: AuthorizationObservationKind
    target: TargetUrl
    baseline_identity: Identity
    comparison_identity: Identity
    baseline_response: ResponseEvidence
    comparison_response: ResponseEvidence
    comparison: ResponseComparison
    observation: str
    rationale: str

    def __post_init__(self) -> None: ...

    @property
    def fingerprint(self) -> str: ...
```

One completed pair produces exactly one observation. Kind is classification,
not severity:

- `EQUIVALENT_PROJECTION` when all four comparison flags are true;
- `DISTINCT_PROJECTION` otherwise.

The observation states the deterministic fact. The rationale states the limit:
equivalent projections are an authorization anomaly requiring human review,
not a confirmed IDOR/BOLA; distinct projections are not a demonstration that
access control worked.

There is no `CONFIRMED` / `VALIDATED` / `REJECTED` state, no CVSS, no
confidence, no remediation and no exploitability claim. `FindingEvidence` is
not reused: it pairs a `PassiveFinding` with one `ResponseEvidence`, while an
authorization observation holds two projections.

Pairing invariants:

- `baseline_identity != comparison_identity`;
- both `requested_target` values equal `target`;
- `comparison` equals `compare_response_evidence` of the two projections;
- `kind` matches the four flags.

A violation is a programming defect and raises `ValueError` without echoing
response content or credentials.

The first rule ID is `authorization.pair.projection.v1`. A later milestone
that changes what the observation means must version the ID.

## Evidence identity

`AuthorizationObservation.fingerprint` is a computed property: lowercase
hexadecimal SHA-256 over canonical JSON, using the same canonicalization as
`PassiveFinding.fingerprint` and `FindingEvidence.evidence_id` (`sort_keys`,
`ensure_ascii`, compact separators, UTF-8).

The pair is ordered and directional. Baseline is first; comparison is second.
`user-a` as baseline against `user-b` is a different observation from `user-b`
as baseline against `user-a`, even when both captured projections are equal.
The engine does not sort, canonicalize or commute the two identities.

Material, in this meaning if not this key order (canonical JSON applies
`sort_keys=True`):

1. identity schema version `1`;
2. `rule_id`;
3. `target.url`;
4. `baseline_identity.identity_id`;
5. `comparison_identity.identity_id`;
6. baseline projection: `status`, `body_length`, `body_sha256`,
   `final_target.url`;
7. comparison projection: `status`, `body_length`, `body_sha256`,
   `final_target.url`.

The four booleans are omitted because they are determined by those fields.
`requested_target` is the case target already present as `target.url`.

The material contains only deterministic non-secret facts. Excluded:

- credentials, header names, header values, body bytes and body excerpts;
- observation text and rationale;
- timestamps, UUIDs, `hash()`, randomness, environment and process state.

Identity is stable for the same ordered inputs in any process. It changes
when any of the following changes:

- the ordered identity pair (`baseline_identity.identity_id` or
  `comparison_identity.identity_id`, including swapping the two);
- the case `target.url`;
- either response projection (`status`, `body_length`, `body_sha256` or
  `final_target.url`).

It does not change when only observation wording or rationale changes.

## Baseline strategy

Comparison is explicit pairwise:

    identity A -> target
    identity B -> same target

The caller chooses both identities and the target. The engine does not pick
identities, permute roles, search for interesting objects or spawn subtasks.
No planner, agent, Flow, Task or Subtask type exists in this module.

Baseline is requested first. That order is part of the contract so tests,
traces and `AuthorizationObservation.fingerprint` stay deterministic: the
ordered pair is identity material, and swapping the two identities is a
different observation.

## Error policy

Network, scope and transport errors propagate unchanged:
`TransportError`, `UrlValidationError`, `ScopeValidationError` and resolver
exceptions abort the pair.

One identity failing must not become evidence that authorization is correct or
incorrect. Incomplete comparisons produce no `AuthorizationObservation`. There
is no "error vs 403" synthesis, no filling a missing projection with a
synthetic deny, no treating a failed hop as `DISTINCT_PROJECTION`, and no
per-identity recovery. A thrown `TransportError`, `UrlValidationError`,
`ScopeValidationError` or resolver exception is the result of the pair.

Programming defects raise `ValueError` before I/O where possible: invalid
`identity_id`, identical pair identities, method other than `GET`, credential
origin mismatch on the initial target, empty credentials, duplicate credential
header names, or a credential header name other than `Authorization` or
`Cookie`.

The authorization module contains no `try` / `except` around Transport or
Scope calls, and no `except Exception`. Error messages contain no credential
values, no `Authorization` / `Cookie` bytes and no response bodies.

`CROSS_ORIGIN_CREDENTIAL_REDIRECT` is a transport failure of the pair, not an
observation that the comparison identity was denied.

## Privacy

Authorization secrets are runtime execution material, not evidence.

They must never enter:

- `Identity`, `AuthorizationCase`, `ResponseEvidence`, `ResponseComparison`
  or `AuthorizationObservation`;
- fingerprints or identity material;
- exception messages;
- logs;
- `repr` / `str` of credential-bearing objects;
- any persisted output (nothing is persisted in this milestone).

Response-content secrets remain excluded by `ResponseEvidence`'s field set.
Target query strings remain the inherited Scope/ADR 0004/0005 sensitive-data
boundary: they are visible on `TargetUrl` and therefore on observation
`target` / `final_target` values and inside fingerprints. Milestone 6 does
not redact query parameters. Tests must place credential secrets only in
request headers, never in a target query string, when asserting absence.

## Streaming and memory

Each `TransportResponse` exists only long enough to call
`capture_response_evidence`. The observation retains two `ResponseEvidence`
values (fixed-size digest plus integers and targets) and drops body bytes and
response headers. Pair execution accumulates neither raw bodies nor a list of
cases. No concurrency is introduced.

## Planned surface

`src/boundary/authorization.py` will expose exactly:

- `Identity`
- `AuthorizationCase`
- `request_as`
- `ResponseComparison`
- `compare_response_evidence`
- `AuthorizationObservationKind`
- `AuthorizationObservation`

`src/boundary/transport.py` additionally exposes `OriginBoundCredentials` and
accepts `credentials=` on `request_with_redirects`. The new error code is
`TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT`.

No `AuthorizationEngine`, builder, protocol, registry, factory, repository,
cookie jar, login client, comparison-in-`evidence.py`, or stream helper.

Pair sequencing (`request_as` twice, capture, compare, observe) is a caller-
side function in the same module only if tests show duplication of a real
contract. Until then the documented loop in the plan is sufficient, matching
Milestone 5's refusal to add an evidence stream.

## Deferred

Explicitly not part of Milestone 6:

- automated login flows, password handling, credential discovery and vaults;
- browser sessions, cookie jars and CSRF workflow automation;
- `POST` / `PUT` / `PATCH` / `DELETE` authorization testing, request bodies
  and mass assignment;
- function-level authorization and GraphQL-specific auth logic;
- semantic or normalized body similarity;
- AI verdicts, autonomous planning, Flow/Task/Subtask cores;
- persistence, SARIF/reporting, remediation, dashboards;
- confidence, CVSS, severity and confirmed-vulnerability states;
- concurrency;
- a generic agent execution gateway;
- custom API-key or other application credential headers beyond
  `Authorization` and `Cookie`.

## Strategic direction

The deterministic core stays independent of future agentic orchestration.
A future AI Analyst may explain an `AuthorizationObservation` or propose a
case. It must not choose allowed origins, identities, credentials, targets or
verdicts. Any later execution layer inspired by agentic systems sits behind an
explicit policy/execution boundary and Scope Engine approval. That gateway is
not added in this milestone.

Active authorization testing remains disabled at the product surface until a
later scan-profile decision. This milestone only defines the engine and its
offline tests.

## Alternatives considered

**Allow arbitrary credential header names (`X-Api-Key`, …).** Deferred: the
first bag is only `Authorization` and `Cookie`, case-insensitive, so tests
and `repr` redaction stay finite. Application-specific headers need their
own origin-binding case.

**Put credentials on `Identity`.** Rejected: findings and fingerprints would
then be one field away from secrets, and `repr` of a finding would be unsafe
by default.

**Strip credentials on cross-origin redirect and continue.** Rejected: the
follow-up request is no longer the named identity, but the observation would
still name that identity.

**Keep Transport unchanged and use `max_redirects=0`.** Rejected: same-origin
redirects are legitimate and would be indistinguishable from a containment
failure.

**Follow redirects in authorization.py via `request_once`.** Rejected:
duplicates Transport's hop, loop, scope and pinning controls.

**Build evidence inside Transport.** Rejected: Transport would own body
digests and identity comparison, mixing execution with interpretation.

**Reuse `FindingEvidence` / add `compare_responses` to `evidence.py`.**
Rejected: `FindingEvidence` is a `PassiveFinding` plus one projection.
Comparison meaning belongs to Authorization, which is the consumer Milestone 5
waited for.

**Emit observations only when projections match.** Rejected: a distinct pair
is still a completed deterministic test; omitting it would make "no finding"
look like "not run".

**Planner chooses identities or targets.** Rejected: that is agentic scope
expansion.

## Consequences

Positive:

- IDOR/BOLA-style tests can run as explicit pairwise `GET`s without a second
  HTTP stack;
- credentials cannot follow a cross-origin redirect even when that origin is
  allowlisted;
- observations name identities without containing secrets;
- response comparison reuses Milestone 5 projections;
- equal projections are recorded as anomalies, not as confirmed
  vulnerabilities;
- Discovery and uncredentialed Transport behavior stay intact;
- no new dependency is required.

Negative:

- allowlisted cross-origin redirects abort credentialed pairs instead of
  completing them;
- byte-exact digests will differ on dynamic pages, so distinct projections
  are a weak "access control worked" signal;
- there is still no login, cookie jar or mutating-method coverage;
- query-string tokens on targets remain visible in observation identity;
- nothing is persisted or reported, so observations exist in memory and tests
  only.

## Unresolved questions

None of these block Milestone 6:

1. **Query strings in targets.** Inherited from Scope and ADR 0005. Must be
   resolved before any observation leaves the process.
2. **Digest usefulness on dynamic applications.** Equivalent-projection
   anomalies may be noisy; a later milestone may add approved normalization
   if a real comparison case shows which bytes to ignore. Semantic similarity
   stays out of scope until then.
3. **Login and session continuation.** Callers must supply origin-bound
   headers. How those headers are obtained is a later credential-management
   decision, not this engine's.
4. **Product-surface enablement.** Scan-profile / CLI activation of
   authorization requests is deferred; the engine must not be wired to public
   targets by this milestone.

Slice status and test coverage are tracked in
`docs/plans/0007-authorization-engine.md`.
