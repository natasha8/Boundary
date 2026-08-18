# Authorization Engine Plan

- Status: Approved, not started
- Milestone: 6
- Planned: 2026-08-18
- Planned implementation: `src/boundary/authorization.py`, with a narrow
  change to `src/boundary/transport.py`
- Planned tests: `tests/test_authorization_identity.py`,
  `tests/test_transport_credentials.py`,
  `tests/test_authorization_request.py`,
  `tests/test_authorization_compare.py`,
  `tests/test_authorization_observation.py`
- Decision record: `docs/decisions/0006-authorization-engine.md`

## Purpose

The Authorization Engine performs controlled IDOR/BOLA-style comparisons
between two explicitly configured identities on one explicitly configured
target.

It makes two statements possible that the repository cannot make today:

- these two named identities produced these two captured response projections
  for the same requested target;
- those projections match or differ on status, retained-body length,
  retained-body digest and final target.

Equal projections are an authorization anomaly, not proof of IDOR/BOLA.
Distinct projections are not proof that access control worked.

The composition is:

    AuthorizationCase(target, baseline, comparison)
        -> request_as(target, baseline, credentials=...)
        -> capture_response_evidence(...)
        -> request_as(target, comparison, credentials=...)
        -> capture_response_evidence(...)
        -> compare_response_evidence(...)
        -> AuthorizationObservation

Authorization does not own discovery, scope, transport pinning, passive rules,
persistence or reporting. It does not expand scope. AI does not choose
identities, targets or verdicts.

## Prerequisites

The completed Scope Engine provides `TargetUrl`, `Origin`, exact-origin
allowlisting, address policy and `resolve_allowed_redirect`. Embedded userinfo
credentials are already rejected at parse time. Query strings are retained and
remain an inherited sensitive-data boundary.

The completed Controlled HTTP Transport provides pinned `GET` execution,
bounded bodies, timeouts, manual in-scope redirects and
`request_with_redirects`. Today it forwards the generic `headers` bag to every
hop, including allowlisted cross-origin destinations. That is unsafe for
credentials and is why Slice B exists.

The completed Evidence Engine provides `ResponseEvidence` and
`capture_response_evidence`. Authorization reuses them and does not add a
second snapshot type.

Discovery and Passive Scanner remain uncredentialed. They are not modified
except that Transport's new optional `credentials=` parameter defaults to
`None`, so existing callers are unchanged.

## Planned architecture

```python
@dataclass(frozen=True, slots=True)
class Identity:
    identity_id: str

    def __post_init__(self) -> None: ...


@dataclass(frozen=True, slots=True)
class OriginBoundCredentials:
    origin: Origin
    headers: tuple[tuple[bytes, bytes], ...]

    def __post_init__(self) -> None: ...

    def __repr__(self) -> str: ...


@dataclass(frozen=True, slots=True)
class AuthorizationCase:
    target: TargetUrl
    baseline: Identity
    comparison: Identity

    def __post_init__(self) -> None: ...


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

`OriginBoundCredentials` and `credentials=` on `request_with_redirects` live
in `transport.py`. Everything else lives in `authorization.py`.

`authorization.py` runtime imports stay in the standard library plus the
existing BOUNDARY modules it must call (`transport`, `scope`, `evidence`).
It does not import `discovery` or `passive`. `evidence.py` and `passive.py`
do not import `authorization.py`.

No `AuthorizationEngine` class is planned. Pair sequencing is the documented
caller-side loop above, the same shape Milestone 5 used for evidence
composition.

## Why Transport must change

`request_with_redirects` forwards caller `headers` unchanged to every hop.
The redirect suite asserts that contract, including allowlisted cross-origin
redirects.

Authorization cannot make credential leakage impossible without Transport
participation: a wrapper cannot intercept headers that Transport has already
sent. Rebuilding redirects on `request_once` would duplicate hop, loop, scope
and pinning control. `max_redirects=0` would refuse legitimate same-origin
redirects.

Slice B therefore adds origin-bound credentials as an optional Transport
parameter, fail-closed on cross-origin follow-up, without changing the
uncredentialed Discovery path.

Redirect order is Scope first, then credential containment: an out-of-scope
`Location` keeps the existing Scope/URL error; only an allowlisted destination
whose `Origin` differs from the bound origin raises
`CROSS_ORIGIN_CREDENTIAL_REDIRECT`, and only before the next hop.

Strip-and-continue is rejected: a stripped hop is no longer the named
identity, and recording it would falsify the comparison.

## Vocabulary

- **identity** — public label; safe in findings and fingerprints.
- **credentials** — origin-bound request headers; runtime-only secrets.
- **authorization case** — one target and two identities.
- **captured projection** — `ResponseEvidence`.
- **response comparison** — four booleans; not a verdict.
- **authorization observation** — completed pair record; not a validated
  vulnerability.

## Delivery slices

Tests are written before the implementation of each slice, and a slice is
complete only when its acceptance criteria hold.

### Slice A: Safe identity metadata and ephemeral credentials

Tests: `tests/test_authorization_identity.py`

To deliver:

- frozen, slotted `Identity` with exactly `identity_id`;
- `identity_id` canonical-state checks (`^[A-Za-z0-9._-]+$`, non-empty);
- frozen, slotted `OriginBoundCredentials` on the transport module, with
  redacted `__repr__` / `__str__`;
- credential header names restricted to `Authorization` and `Cookie`,
  case-insensitive, with no duplicate names; custom API-key headers deferred;
- `AuthorizationCase` with two distinct, ordered identities.

Acceptance criteria:

- `Identity` has no headers, tokens, cookies or password fields;
- assignment raises `FrozenInstanceError`; instances have no `__dict__`;
- invalid `identity_id` values raise `ValueError` without requiring a
  secret-shaped rejected value to be echoed;
- `OriginBoundCredentials.repr` and `str` contain the origin and a count, and
  never header names or values, demonstrated with `Authorization` and `Cookie`
  secrets;
- `ValueError` messages for invalid credentials contain no header names or
  values;
- empty credentials, duplicate names (`Authorization` twice), and any name
  other than `Authorization` or `Cookie` (including `X-Api-Key` and `host`)
  raise `ValueError`;
- `Authorization` plus `Cookie` in either case combination is accepted;
- identical baseline and comparison identities raise `ValueError`;
- no vault, login helper, secret manager or `AuthorizationEngine` exists;
- fail-fast network guards are active; construction performs no I/O.

### Slice B: Transport origin-bound credential containment

Tests: `tests/test_transport_credentials.py`

This is the isolated Transport change. It exists because uncredentialed
header forwarding is not a safe credential contract.

To deliver:

- `TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT`;
- keyword-only `credentials: OriginBoundCredentials | None = None` on
  `request_with_redirects`;
- per-hop rule: send bound headers only when `current.origin ==
  credentials.origin`;
- initial origin mismatch raises `ValueError` before network I/O;
- credentialed redirect order: Scope `resolve_allowed_redirect` first; then
  origin-bound containment;
- uncredentialed calls keep today's generic header forwarding.

Acceptance criteria:

- same-origin relative and absolute redirects still send the bound headers;
- an out-of-allowlist or unsafe `Location` still raises the existing Scope /
  URL error, not `CROSS_ORIGIN_CREDENTIAL_REDIRECT`, even when credentials
  are bound;
- an allowlisted redirect whose `Origin` differs from `credentials.origin`
  raises `CROSS_ORIGIN_CREDENTIAL_REDIRECT` and does not issue the next
  request, proven by a recording fake backend;
- credentials are never stripped to continue a cross-origin hop;
- uncredentialed allowlisted cross-origin redirects still succeed;
- Discovery-shaped calls (`credentials=None`, empty headers) remain
  unchanged;
- generic `headers` and credential headers are distinct bags; overlapping
  names raise `ValueError`;
- error messages, `repr` and `str` contain no credential values, no
  credential header names, and no `Location` bytes;
- existing redirect, hop-limit and loop tests keep passing;
- `request_once` signature is unchanged;
- `crawl` is not modified.

### Slice C: Credential-aware request and response-pair capture

Tests: `tests/test_authorization_request.py`

To deliver:

- `request_as(...)` as a thin GET-only call through
  `request_with_redirects`;
- caller-side capture of one `ResponseEvidence` per identity using
  `capture_response_evidence(response, requested_target=target)`.

Acceptance criteria:

- `request_as` is GET-only; other methods raise `ValueError` before I/O;
- no request body is sent;
- Scope, resolver, pinning, limits and `max_redirects` are forwarded
  unchanged to Transport;
- `Identity` is not serialized onto the wire;
- anonymous (`credentials=None`) and credentialed paths both work;
- the caller captures with `capture_response_evidence` and drops the
  `TransportResponse`; captured values have no headers or body bytes;
- inputs are not mutated;
- fail-fast guards replace `crawl`, sockets and AnyIO connect; the path
  still completes using the Transport fake already used by transport tests;
- `authorization.py` does not import `discovery` or `passive`.

### Slice D: Deterministic comparison primitives

Tests: `tests/test_authorization_compare.py`

To deliver:

- frozen, slotted `ResponseComparison` with exactly the four booleans;
- `compare_response_evidence(baseline, comparison)`.

Acceptance criteria:

- each flag is independent: a status-only change flips only `status_equal`,
  and likewise for length, digest and final target;
- equal projections produce all four true;
- comparison is a pure function, performs no I/O, and does not read
  credentials or headers;
- `evidence.py` still has no `compare_responses` helper;
- equal flags are not named IDOR, BOLA, vulnerable or confirmed anywhere in
  the type, field names or default observation text produced later in
  Slice E.

### Slice E: Minimal observation for one explicit pair

Tests: `tests/test_authorization_observation.py`

To deliver:

- `AuthorizationObservationKind`;
- frozen, slotted `AuthorizationObservation`;
- pairing invariants and `fingerprint` over the locked canonical JSON schema
  in ADR 0006;
- documented caller-side loop that emits one observation for a completed
  pair and none when a request fails.

Acceptance criteria:

- a completed pair always yields exactly one observation;
- supplied `kind` must match the four flags: all four
  `ResponseComparison` flags true => `EQUIVALENT_PROJECTION`; otherwise
  `DISTINCT_PROJECTION`;
- observation/rationale state facts and explicitly deny that equality is
  proof of IDOR/BOLA or that inequality proves correct access control;
- `fingerprint` is 64 lowercase hex, the SHA-256 digest of UTF-8 canonical
  JSON with `sort_keys=True`, `ensure_ascii=True` and `separators=(",", ":")`,
  over exactly this schema (`schema` is the integer `1`):

  ```json
  {
    "schema": 1,
    "rule_id": <rule_id>,
    "target": <target.url>,
    "baseline_identity": <baseline_identity.identity_id>,
    "comparison_identity": <comparison_identity.identity_id>,
    "baseline_response": {
      "status": <status>,
      "body_length": <body_length>,
      "body_sha256": <body_sha256>,
      "final_target": <final_target.url>
    },
    "comparison_response": {
      "status": <status>,
      "body_length": <body_length>,
      "body_sha256": <body_sha256>,
      "final_target": <final_target.url>
    }
  }
  ```

  Nested `status` and `body_length` are JSON numbers; nested `body_sha256`
  and `final_target` are JSON strings. Top-level `rule_id`, `target`,
  `baseline_identity` and `comparison_identity` are JSON strings.
  `sort_keys=True` makes the block above the object shape, not the
  serialized byte order. The ordered
  baseline/comparison identity pair is preserved by distinct keys, not by
  object insertion order. The schema excludes `requested_target`, `kind`,
  the four `ResponseComparison` booleans, `observation`/`rationale` prose,
  credentials, secrets, UUIDs, time, randomness and object identity;
- the pair is ordered: swapping baseline and comparison identities yields a
  different `fingerprint` even when both projections are unchanged;
- identity changes when either ordered identity id, the case target, or
  either response projection (`status`, `body_length`, `body_sha256`,
  `final_target.url`) changes, and does not change when only observation
  wording, rationale or `kind` changes;
- a transport, scope or request failure on either identity propagates
  unchanged, produces no `AuthorizationObservation`, and is never rewritten
  as `DISTINCT_PROJECTION` or any other benign observation;
- baseline failure skips the comparison request;
- secrets in `Authorization` / `Cookie` request headers never appear in
  fields, `repr`, fingerprint material or exception messages;
- query-string tokens on the target remain visible as the inherited
  boundary;
- no CVSS, severity, confidence or confirmation state exists;
- no `AuthorizationEngine`, stream helper or planner exists.

## Error-handling policy

- Transport, scope and resolver errors propagate unchanged;
- incomplete pairs emit no observation and are never classified as
  equivalent or distinct projections;
- out-of-scope redirects keep the existing Scope/URL error;
- `CROSS_ORIGIN_CREDENTIAL_REDIRECT` is raised only after Scope has admitted
  an allowlisted destination whose origin differs from the bound origin;
- programming defects raise `ValueError` without credential names, values or
  body content;
- no `try` / `except` around Transport/Scope in `authorization.py`;
- no `except Exception` anywhere added by this milestone.

## Offline testing approach

All tests construct `TargetUrl`, `Origin`, `TransportResponse` and
`ResponseEvidence` locally, or drive Transport through the existing recording
fake backend. No test contacts a public target.

Network entry points remain replaced by fail-fast assertions in suites that
claim zero DNS/TCP. Credential-absence assertions place secrets only in
request headers, never in target query strings.

## Planned security invariants

- Scope Engine remains authoritative; authorization does not expand scope;
- every request uses `request_with_redirects` (GET, pinned, bounded, timed);
- credentials are bound to an exact `Origin` and never follow a different
  origin;
- credential header names are only `Authorization` and `Cookie`;
- credentials never enter evidence, findings, fingerprints, logs, `repr`s,
  `str` or exception messages;
- AI never decides scope, identities, targets or verdicts;
- equal projections are not treated as proof of IDOR/BOLA;
- no persistence, reporting, login, cookie jar or mutating method;
- query-string exposure on `TargetUrl` is inherited and unredacted.

## Milestone non-goals

Not added, and deferred:

- automated login, password handling, credential discovery, vaults;
- browser sessions, cookie jars, CSRF automation;
- POST/PUT/PATCH/DELETE, request bodies, mass assignment;
- function-level authorization, GraphQL-specific auth logic;
- semantic body similarity, LLM comparison;
- AI verdicts, autonomous planning, Flow/Task/Subtask cores;
- persistence, SARIF/reporting, remediation;
- CVSS, severity, confidence, confirmed-vulnerability states;
- concurrency;
- an agent execution gateway;
- custom API-key or other application credential headers beyond
  `Authorization` and `Cookie`.

## Dependency decision

No dependency is required.

The standard library provides dataclasses, `StrEnum`, SHA-256 and canonical
JSON. Transport, Scope and Evidence already exist. HTTPCore remains the
single runtime HTTP dependency; authorization does not add another client.

## Verification sequence

Checks to execute for each slice and at closeout:

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

Focused authorization and transport-credential tests run first, then the
complete suite. No test may contact a public target, skip a security
assertion or weaken an existing check.

## Definition of done

The milestone is complete only when:

- Slices A through E meet every acceptance criterion;
- Transport credential containment is fail-closed and isolated from
  uncredentialed Discovery behavior;
- `ResponseEvidence` is reused; no second snapshot type exists;
- observations name identities without containing credentials;
- equality is recorded as an anomaly, not a confirmed vulnerability;
- incomplete comparisons emit nothing and propagate errors;
- no `AuthorizationEngine`, planner, vault, login flow or AI verdict exists;
- formatting, linting, typing and all tests pass without skipped or weakened
  tests;
- ADR 0006 and this plan match the implementation, including deferred items;
- no dependency was added.
