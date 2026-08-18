# ADR 0004: Analyze discovered responses without additional network activity

- Status: Accepted and implemented (Milestone 4)
- Date: 2026-08-14
- Implemented: 2026-08-18
- Implementation: `src/boundary/passive.py`
- Tests: `tests/test_passive_findings.py`, `tests/test_passive_headers.py`,
  `tests/test_passive_cookies.py`, `tests/test_passive_scan.py`
- Depends on: `docs/decisions/0003-controlled-discovery.md`

## Context

BOUNDARY needs passive security checks over responses already collected by the
Discovery Engine. The scanner must preserve the project's safety, evidence and
low-noise principles: an observation is useful only when it follows
deterministically from bounded response evidence, and a passive observation
must not be presented as proof of exploitability.

The completed layers already provide the required input:

- `DiscoveredPage.target` is the normalized target dequeued by Discovery;
- `DiscoveredPage.response.final_target` is the normalized final redirect hop
  that produced the observed response;
- `TransportResponse` contains the status, raw header tuples and bounded body.

Turning passive analysis into a second crawler, transport client, generic rule
framework or evidence repository would duplicate responsibilities and weaken
the boundary between observation and active testing.

## Decision

BOUNDARY added one cohesive passive-analysis module composed of immutable
values and plain functions. It consumes `DiscoveredPage` values and emits
sanitized deterministic findings. The sections below describe the delivered
behavior.

The core invariant is:

> Passive Scanner analyzes existing evidence only.

Passive analysis performs zero network activity. The delivered code does not:

- make an HTTP request or invoke `crawl`;
- call `request_once` or `request_with_redirects`;
- import or reach HTTPCore, socket APIs or AnyIO connection APIs;
- resolve DNS or instantiate a resolver;
- send probes, submit forms or generate active payloads;
- execute JavaScript or browser code;
- mutate application state;
- fetch supplemental data for a rule.

The only rule inputs are:

- `TransportResponse.status`;
- `TransportResponse.headers`;
- `DiscoveredPage.target`;
- `TransportResponse.final_target`.

`TransportResponse.body` remains available on the input value but no
implemented rule reads it. Its presence does not authorize general body
inspection.

### Input identity and redirect provenance

`DiscoveredPage` is the fundamental input, not a bare `TransportResponse`.

Every finding is attached to `page.response.final_target`, because that is the
normalized resource that produced the evidence. The finding also keeps
`page.target` as `requested_target` so a redirected Discovery request remains
traceable. `requested_target` is provenance only and does not participate in
finding identity.

Rules never attach response observations to `page.target` when it differs from
`response.final_target`. Rule applicability that depends on the scheme uses the
final target scheme.

### Finding representation

The implemented public representation is:

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


def build_passive_finding(
    *,
    rule_id: str,
    kind: PassiveFindingKind,
    target: TargetUrl,
    requested_target: TargetUrl,
    observation: str,
    rationale: str,
    evidence: Collection[tuple[str, str]] = (),
) -> PassiveFinding: ...
```

Findings are immutable: `PassiveFinding` is frozen and slotted, and `evidence`
is a tuple.

`build_passive_finding` is the constructor every rule uses. It canonicalizes
evidence before the frozen value exists: duplicate evidence keys raise
`ValueError`, and the accepted pairs are stored deterministically sorted by
key. `fingerprint` is a computed property, not a stored field and never caller
supplied.

The fields have deliberately narrow meanings:

- `rule_id` is a stable, versioned identifier for one deterministic rule;
- `kind` distinguishes a concrete configuration issue from a hardening
  observation without pretending to score risk;
- `target` is `response.final_target`;
- `requested_target` is `page.target`;
- `observation` states what was observed without claiming exploitation;
- `rationale` states why the observation matters;
- `evidence` is a small immutable tuple of sanitized key/value strings.

The delivered evidence keys are:

- `status` — the decimal response status, present in every finding;
- `header` — the literal lowercase header name (HSTS, `nosniff`, CSP);
- `state` — a normalized rule state;
- `count` — the number of relevant fields (HSTS, `nosniff`, enforced CSP);
- `cookie` — the cookie name (cookie rules);
- `secure`, `same_site` — normalized cookie attribute states.

Evidence never contains raw header values, complete `Set-Cookie` lines, cookie
values, Authorization values or body excerpts. Rule authors are responsible for
supplying already-sanitized evidence; there is no generic redaction engine and
hashing is not treated as redaction.

The model does not include confirmation status, remediation, confidence,
request/response archives or replay data. Those require the later Evidence
Engine and reporting contracts.

### Classification instead of severity

`PassiveFinding` does not contain severity. The implemented checks cannot
determine business exposure, reachable attack paths or impact from response
headers alone. Assigning even a small severity label would encode risk scoring
without the context needed to support it.

`PassiveFindingKind` is not severity:

- `MISCONFIGURATION` means the observed configuration itself violates the
  rule's deterministic contract;
- `HARDENING` means a defense-in-depth control was absent or unusable, without
  claiming a vulnerability.

No informational-exposure rule met the required low-noise contract, so an
unused informational enum member was not added. It can be added with the first
accepted deterministic exposure rule.

CVSS and a severity/risk-scoring framework remain explicitly deferred.

### Deterministic finding identity

Each rule ID includes a semantic version suffix, for example
`passive.hsts.not_enforced.v1`. A behavior change that alters what evidence
fires a rule requires a new rule version.

The fingerprint is the lowercase hexadecimal SHA-256 digest of canonical JSON
containing:

1. fingerprint schema version `1`;
2. the versioned `rule_id`;
3. the final normalized target URL, `target.url`;
4. the canonical sanitized `evidence`, as two-element arrays in the key order
   fixed at construction.

Canonical JSON uses UTF-8, `ensure_ascii=True`, `sort_keys=True` and compact
separators. The exact serialization and one digest are locked by a test vector.

Identity deliberately excludes:

- `requested_target`, because the evidence belongs to the final target
  regardless of which redirect alias reached it;
- `kind`, because classification is versioned by `rule_id`;
- `observation` and `rationale`, because wording changes must not create a
  duplicate;
- object identity, `hash()`, timestamps, UUIDs and any random value.

The fingerprint material contains only already-sanitized evidence: raw values
must never enter the material in the first place.

### Streaming composition

The implemented composition surface is:

```python
def scan_page(page: DiscoveredPage) -> tuple[PassiveFinding, ...]: ...


async def scan_pages(
    pages: AsyncIterable[DiscoveredPage],
) -> AsyncIterator[PassiveFinding]: ...
```

`scan_page` is synchronous because it performs pure in-memory analysis. It
executes each rule exactly once in the static order, deduplicates the produced
findings by `fingerprint`, keeps the first occurrence, preserves rule and
within-rule output order, and does not rebuild retained findings.

`scan_pages` is an async generator. It consumes pages lazily, yields the
current page's retained findings before pulling the next page, preserves page
order and finding order, and applies run-local fingerprint suppression so a
duplicate fingerprint produced across pages in one invocation is emitted once.
A new `scan_pages` invocation starts with empty deduplication state; the
fingerprint set is neither global nor persistent.

The caller composes Discovery and passive analysis:

```python
async for finding in scan_pages(crawl(...)):
    ...
```

Passive Scanner accepts the stream; it does not import or invoke `crawl`.
Upstream iteration errors propagate.

#### Memory contract

`scan_pages` does not accumulate `DiscoveredPage` objects, response bodies or
all `PassiveFinding` objects. It is not, however, constant memory for a
complete scan: its run-level fingerprint set grows with the number of unique
emitted finding fingerprints, so the retained metadata is approximately

    O(unique emitted fingerprints)

of fixed-size digests. That cost is accepted deliberately so redirect aliases
or duplicate observations within one run do not produce duplicate final
findings.

### Rule composition

Rules are private, cohesive functions with one convention:

```python
def _check_rule(page: DiscoveredPage) -> tuple[PassiveFinding, ...]: ...
```

An explicit private tuple inside `scan_page` fixes the execution order:

1. HSTS;
2. `nosniff`;
3. enforced CSP;
4. frame protection;
5. HTTPS cookie `Secure`;
6. `SameSite=None` cookie `Secure`.

Rule execution is explicit and deterministic. There is no `RuleEngine`, plugin
architecture, registry, dynamic or YAML rule loading, registration decorator,
dependency-injection container, base rule class or one-implementation rule
interface. `Set-Cookie` findings retain response-field order within each cookie
rule.

The module's public surface is exactly `PassiveFindingKind`, `PassiveFinding`,
`build_passive_finding`, `scan_page` and `scan_pages`.

### Raw header inspection

`TransportResponse.headers` remains the source of truth as ordered
`tuple[tuple[bytes, bytes], ...]`.

A small private helper selects all values for one literal lowercase header name
by comparing header-name bytes case-insensitively. Its scope is only passive
response inspection. It:

- preserves field order and duplicate fields;
- never comma-joins values;
- never decodes an unrelated header;
- returns raw values for the calling rule to interpret.

ASCII decoding is handled explicitly by the calling rule, and a malformed or
non-ASCII value is unusable for that rule without ever being exposed.

Each rule owns its field cardinality. HSTS, `X-Content-Type-Options` and
`X-Frame-Options` are singleton decisions: duplicate fields are ambiguous and
do not satisfy protection. Repeated `Content-Security-Policy` fields are
allowed because each policy is enforced. Repeated `Set-Cookie` fields remain
separate.

HTML applicability reuses `discovery.is_html_response`: exactly one
`Content-Type` with a case-insensitive `text/html` media type, ignoring
parameters. Missing, duplicate, empty, malformed or non-HTML Content-Type
fields do not establish HTML context.

### Implemented rule set

Six checks are implemented, all decided from the existing response.

#### 1. HSTS absent or ineffective on HTTPS

- Rule ID: `passive.hsts.not_enforced.v1`
- Kind: `HARDENING`
- Applies only when `response.final_target.scheme == "https"`.
- A minimal deterministic `max-age` contract decides protection: exactly one
  ASCII field containing exactly one case-insensitive `max-age` directive whose
  unquoted value is decimal and greater than zero protects and emits nothing.
- Normalized states: `missing` (no field), `ambiguous` (duplicate fields, or
  duplicate `max-age` directives in one field), `invalid` (non-ASCII value, or
  absent, non-decimal, quoted, signed or fractional `max-age`), `disabled`
  (`max-age=0`).
- Evidence: `header`, `state`, `count` of HSTS fields, `status`.
- Unknown extension directives are ignored. `includeSubDomains` and `preload`
  are not required.

This is a transport-hardening observation. It is not proof that traffic can be
downgraded or intercepted.

#### 2. Missing or invalid `X-Content-Type-Options: nosniff`

- Rule ID: `passive.nosniff.missing_or_invalid.v1`
- Kind: `HARDENING`
- Applies only to responses classified as HTML by `discovery.is_html_response`;
  the response scheme is irrelevant.
- Exactly one field whose ASCII value is exactly `nosniff` after supported
  optional-whitespace trimming and case folding satisfies the rule.
- Missing, invalid, duplicate and non-ASCII values fire the rule with state
  `missing`, `invalid` or `ambiguous`.
- Evidence: `header`, `state`, `count`, `status`.

Applying this rule to every asset would emit repetitive low-context findings.
Discovery does not retain browser request-destination context needed to assess
script and stylesheet MIME enforcement reliably, so the first contract uses the
existing deterministic HTML classification; broader resource contexts are
deferred.

#### 3. HTML response without an enforced CSP

- Rule ID: `passive.csp.missing_enforced_policy.v1`
- Kind: `HARDENING`
- Applies only to deterministic HTML responses.
- One or more non-empty ASCII enforced `Content-Security-Policy` fields satisfy
  this basic presence rule; repeated enforced policies are legitimate.
- `Content-Security-Policy-Report-Only` never satisfies it.
- Normalized states: `missing` (no CSP field at all), `report_only` (only
  report-only policies), `invalid` (enforced fields exist but all are empty or
  non-ASCII).
- Evidence: `header`, `state`, `count` of enforced fields, `status`; policy
  contents are never recorded.

This rule verifies delivery of an enforced CSP header, not the policy's
strength or completeness. It is not an XSS finding, does not implement full CSP
semantics and does not claim that XSS exists when CSP is absent.

#### 4. HTML response without recognized frame protection

- Rule ID: `passive.framing.missing_protection.v1`
- Kind: `HARDENING`
- Applies only to deterministic HTML responses.
- A single ASCII `X-Frame-Options` value of `DENY` or `SAMEORIGIN`, compared
  case-insensitively after optional-whitespace trimming, protects.
- Alternatively, any enforced `Content-Security-Policy` field with a
  case-insensitive `frame-ancestors` directive and a non-empty directive value
  protects, independently of `X-Frame-Options`.
- `ALLOW-FROM`, duplicate `X-Frame-Options` fields and malformed values do not
  protect unless an enforced CSP independently does.
- `frame-ancestors` in a report-only policy does not protect.
- Evidence: `state` (`missing`) and `status` only, because the rule reports one
  deterministic combined state.

The CSP check only splits policies into semicolon-delimited directives,
identifies the directive name and requires a value. No full CSP parser exists.

The finding is a hardening observation, not proof that a useful clickjacking
attack exists.

#### 5. HTTPS cookie without `Secure`

- Rule ID: `passive.cookie.secure_missing_https.v1`
- Kind: `MISCONFIGURATION`
- Applies only when `response.final_target.scheme == "https"`, independently of
  content type.
- Produces one finding per parseable `Set-Cookie` field, in response-field
  order, before `scan_page` deduplication collapses identical fingerprints.
- `Secure` presence is decided case-insensitively from the attribute name
  alone: `Secure=0` and repeated `Secure` attributes still count as the
  attribute being present.
- Evidence: `cookie` name, `secure` state, `status`. The cookie value is never
  retained in finding evidence.

#### 6. `SameSite=None` cookie without `Secure`

- Rule ID: `passive.cookie.samesite_none_without_secure.v1`
- Kind: `MISCONFIGURATION`
- Scheme-independent and content-type independent.
- Fires for a parseable cookie with exactly one recognized `SameSite` attribute
  whose value is `None` and no `Secure` attribute.
- Duplicate or conflicting `SameSite` attributes are ambiguous and do not fire.
  Missing, `Lax`, `Strict`, empty and unknown `SameSite` values do not fire.
- Evidence: `cookie` name, `same_site`, `secure`, `status`.

A cookie satisfying both cookie rules produces both rule identities. They state
different deterministic configuration problems; duplicate occurrences of either
identity are removed by fingerprint.

### Minimal safe Set-Cookie parsing

Each `Set-Cookie` header field represents one candidate cookie and is parsed
independently, in response-header order. Fields are never comma-split, so
`Expires` commas remain part of one field.

The private parser is intentionally narrower than a cookie jar:

1. Split the field on semicolons.
2. Require the first segment to contain `=` and a non-empty ASCII RFC token
   name before it.
3. Never decode, validate, copy or log the cookie value; it is not retained in
   the parsed metadata or in any finding.
4. Inspect later attribute names case-insensitively.
5. Treat an attribute named `Secure` as present without retaining any supplied
   attribute value.
6. Recognize `SameSite` only when its ASCII value, after optional-whitespace
   trimming, is exactly `None`, `Lax` or `Strict`, case-insensitively.
7. Treat duplicate or conflicting `SameSite` attributes as ambiguous for the
   SameSite rule.

Unknown attributes are ignored. A malformed cookie identity — an empty field,
a missing `=`, a non-token or non-ASCII name — skips only that field. Malformed
cookie metadata never aborts other `Set-Cookie` fields or unrelated passive
checks.

There is no malformed-cookie finding yet. A malformed line does not prove that
a user agent accepted a security-relevant cookie, and preserving the raw line
as evidence would conflict with the no-secret requirement.

Cookie values, bearer tokens, authorization values, credentials, session
identifiers and arbitrary response-body snippets never appear in a finding,
fingerprint input, exception message or test failure representation.

### HTML and body policy

The implemented HTML rules inspect headers only. They reuse the existing exact
`text/html` classification and do not parse the response body.

Milestone 4 does not:

- sniff HTML from body bytes;
- scan arbitrary bodies for secrets or sensitive-data patterns;
- introduce another HTML parser;
- execute scripts;
- infer DOM behavior.

The bounded body remains available for a later specifically approved,
deterministic rule. Merely having a body is not sufficient justification, and
no body-derived check was invented to complete the milestone.

### Error policy

Raw response metadata is untrusted. Expected malformed input is isolated at the
relevant rule or field where the decision is made:

- malformed singleton security-header values are unusable for that rule;
- ambiguous singleton duplicates do not satisfy protection;
- malformed CSP values do not satisfy the CSP-dependent decision but do not
  stop other rules;
- one malformed `Set-Cookie` field is skipped while later fields continue;
- malformed Content-Type does not establish HTML applicability.

Helpers handle expected byte-decoding failures explicitly. There is no broad
`except Exception` anywhere in the module and no per-page orchestration
recovery. Programming errors, violated typed invariants and page-source
(upstream async-iteration) errors propagate rather than being silently
converted into findings.

### Ordering and purity

For the same `DiscoveredPage` values, the scanner produces the same findings,
fingerprints and order:

- input page order is retained;
- the static rule tuple fixes rule order;
- repeated fields retain response order;
- duplicate suppression preserves first occurrence;
- no timestamps, randomness, process hash values or external state are read.

Rule functions do not mutate `DiscoveredPage`, `TransportResponse`, headers,
body, targets or application state.

## Deferred checks

The following candidate checks are deferred because current evidence cannot
support a low-noise, high-confidence claim:

- cookie missing `HttpOnly`: client-side script access can be intentional and
  script/application context is unavailable;
- cookie missing `SameSite`: browser defaults and cross-site workflow
  requirements make absence alone ambiguous;
- permissive CORS from `Access-Control-Allow-Origin` alone: public resources
  may intentionally allow it, and credential/request-origin context is absent;
- reflected CORS: requires controlled requests with varied `Origin` values and
  is therefore active validation;
- server banner or version vulnerability claims: banners may be incomplete or
  false, and version matching needs a maintained vulnerability knowledge base;
- sensitive-data regular expressions: high false-positive risk and unsafe body
  excerpt handling;
- directory-listing heuristics: body templates are server-specific and noisy;
- technology fingerprinting and outdated-software detection: probabilistic
  matching and external version intelligence are required;
- cache-control security claims: sensitivity, authentication and route purpose
  are not known from the response alone;
- CSRF, authentication, IDOR/BOLA, injection and active TLS checks: each
  requires request mutation, account/browser context or additional probes.

## Milestone exclusions

Milestone 4 delivered none of the following, and they remain deferred:

- body and secret scanning;
- active validation and vulnerability exploitation;
- request/response archival and raw evidence persistence;
- an Evidence Engine or evidence capture/replay;
- a findings database, dashboard or aggregation repository;
- severity scoring, CVSS and confidence scoring;
- AI analysis and a remediation engine;
- SARIF, JSON or other report generation;
- CLI integration;
- authorization testing and IDOR/BOLA;
- CORS reflection testing;
- browser execution, JavaScript analysis and exploitation;
- dynamic rule loading;
- concurrency inside passive analysis.

## Strategic direction

Passive Scanner remains deterministic-first. Any future AI capability must
consume already-validated findings and sanitized evidence; it must not decide
scope, replace deterministic checks or become the source of a finding. The
Scope Engine remains authoritative for network boundaries, and any future
execution orchestration must stay behind explicit policy-controlled execution
boundaries.

## Alternatives considered

**Let rules fetch supplemental evidence.** Rejected because a rule that makes a
request is active scanning and bypasses Discovery, Scope and Transport
orchestration.

**Pass only `TransportResponse`.** Rejected because redirect provenance and the
requested Discovery identity would be lost.

**Build a generic rule engine or plugin system.** Rejected because six static
rules do not justify dynamic registration, lifecycle or extension machinery.

**Collect all pages, sort findings globally and then return a report.** Rejected
because it breaks streaming and couples analysis to reporting/persistence.

**Use a third-party header, cookie or CSP package.** Rejected because the
accepted contracts require only small parsing subsets and no identified
standard-library limitation justifies another dependency.

**Assign severity now.** Rejected because passive header presence does not
establish impact or exploitability.

## Consequences

Positive:

- passive analysis cannot expand scan scope or perform hidden network work;
- findings follow reproducibly from immutable, bounded existing evidence;
- final-target attachment remains correct across redirects;
- streaming avoids retaining pages, bodies or complete result collections;
- evidence is structured for deterministic identity without storing raw
  secrets;
- the rule set remains explicit, reviewable and offline-testable;
- no new dependency was required.

Negative:

- the scanner intentionally misses context-dependent and active
  vulnerabilities;
- malformed cookie lines are skipped rather than diagnosed;
- CSP delivery and frame-ancestor recognition are deliberately narrower than a
  full CSP audit;
- no severity, remediation, persistence, aggregation or report is produced;
- run-level duplicate suppression retains one fixed-size fingerprint per unique
  emitted finding, so `scan_pages` is not constant memory for a complete run.

Delivery, slice status and test coverage are recorded in
`docs/plans/0005-passive-scanner.md`.
