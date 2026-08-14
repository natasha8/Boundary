# ADR 0004: Analyze discovered responses without additional network activity

- Status: Accepted for implementation (Milestone 4)
- Date: 2026-08-14
- Planned implementation: `src/boundary/passive.py`
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

BOUNDARY will add one cohesive passive-analysis module composed of immutable
values and plain functions. It consumes `DiscoveredPage` values and emits
sanitized deterministic findings.

The core invariant is:

> Passive Scanner analyzes existing evidence only.

Passive code must not:

- make an HTTP request or invoke `crawl`;
- call `request_once` or `request_with_redirects`;
- resolve DNS or instantiate a resolver;
- send probes, submit forms or generate active payloads;
- execute JavaScript or browser code;
- mutate application state;
- fetch supplemental data for a rule.

The only rule inputs are:

- `TransportResponse.status`;
- `TransportResponse.headers`;
- `TransportResponse.body`;
- `DiscoveredPage.target`;
- `TransportResponse.final_target`.

The initial rules do not need the body. Its presence in `TransportResponse`
does not authorize general body inspection.

### Input identity and redirect provenance

`DiscoveredPage` is the fundamental input, not a bare `TransportResponse`.

Every initial finding is attached to `page.response.final_target`, because that
is the normalized resource that produced the evidence. The finding also keeps
`page.target` as `requested_target` so a redirected Discovery request remains
traceable. `requested_target` is provenance only and does not change the
finding identity.

Rules must not attach response observations to `page.target` when it differs
from `response.final_target`.

### Finding representation

The planned public representation is:

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
```

The fields have deliberately narrow meanings:

- `rule_id` is a stable, versioned identifier for one deterministic rule;
- `kind` distinguishes a concrete configuration issue from a hardening
  observation without pretending to score risk;
- `target` is `response.final_target`;
- `requested_target` is `page.target`;
- `observation` states what was observed without claiming exploitation;
- `rationale` states why the observation matters;
- `evidence` is a small immutable tuple of sanitized key/value strings;
- `fingerprint` is computed from identity-bearing fields and cannot be supplied
  inconsistently by a caller.

Initial evidence contains only normalized states, counts, the decimal response
status and, for cookie rules, the cookie name. It never contains raw response
header values or body excerpts.

The model does not include confirmation status, remediation, confidence,
request/response archives or replay data. Those require the later Evidence
Engine and reporting contracts.

### Classification instead of severity

`PassiveFinding` will not contain severity in this milestone. The initial
checks cannot determine business exposure, reachable attack paths or impact
from response headers alone. Assigning even a small severity label would
encode risk scoring without the context needed to support it.

`PassiveFindingKind` is not severity:

- `MISCONFIGURATION` means the observed configuration itself violates the
  rule's deterministic contract;
- `HARDENING` means a defense-in-depth control was absent or unusable, without
  claiming a vulnerability.

No initial informational-exposure rule meets the required low-noise contract,
so an unused informational enum member will not be added yet. It can be added
with the first accepted deterministic exposure rule.

CVSS and a severity/risk-scoring framework are explicitly deferred.

### Deterministic finding identity

Each rule ID includes a semantic version suffix, for example
`passive.hsts.not_enforced.v1`. A behavior change that alters what evidence
fires a rule requires a new rule version.

The fingerprint is the lowercase hexadecimal SHA-256 digest of canonical JSON
containing:

1. fingerprint schema version `1`;
2. `rule_id`;
3. `target.url`;
4. sanitized `evidence`, sorted by unique evidence key.

Canonical JSON uses UTF-8, `ensure_ascii=True`, sorted object keys and compact
separators. Evidence keys must be unique. Python's randomized `hash()`, object
identity, timestamps and UUIDs are not used.

`requested_target`, prose fields and `kind` are excluded:

- the evidence belongs to the final target regardless of which redirect alias
  reached it;
- wording changes must not create a duplicate;
- rule semantics and classification are versioned by `rule_id`.

The fingerprint material contains only already-sanitized evidence. Hashing is
not treated as redaction for raw secrets: raw values must never enter the
material in the first place.

`scan_page` removes duplicate fingerprints while preserving the first finding.
`scan_pages` also keeps only a set of fixed-size fingerprints for the current
bounded Discovery stream, so duplicate evidence reached through two queued
redirect aliases is not emitted twice. It does not retain page bodies or
finding objects.

### Streaming composition

The planned composition surface is:

```python
def scan_page(page: DiscoveredPage) -> tuple[PassiveFinding, ...]: ...


async def scan_pages(
    pages: AsyncIterable[DiscoveredPage],
) -> AsyncIterator[PassiveFinding]: ...
```

`scan_page` is synchronous because it performs pure in-memory analysis.
`scan_pages` consumes one page at a time, yields its findings immediately and
does not materialize the page stream or a complete finding collection.

The caller composes Discovery and passive analysis:

```python
async for finding in scan_pages(crawl(...)):
    ...
```

Passive Scanner accepts the stream; it does not import or invoke `crawl`.
Upstream iteration errors propagate.

### Rule composition

Rules are private, cohesive functions with one convention:

```python
def _check_rule(page: DiscoveredPage) -> tuple[PassiveFinding, ...]: ...
```

An explicit private tuple defines execution order:

1. HSTS;
2. `nosniff`;
3. enforced CSP;
4. frame protection;
5. HTTPS cookie `Secure`;
6. `SameSite=None` cookie `Secure`.

No rule discovery, registration decorator or runtime mutation exists.
Set-Cookie findings retain response-field order within each cookie rule.

The milestone will not introduce:

- a plugin architecture or dynamic loading;
- a dependency-injection container;
- base rule classes or one-implementation interfaces;
- a generic `RuleEngine`;
- decorators or registration magic;
- YAML rule definitions.

### Raw header inspection

`TransportResponse.headers` remains the source of truth as ordered
`tuple[tuple[bytes, bytes], ...]`.

A small private helper may select all values for one literal lowercase header
name by comparing header-name bytes case-insensitively. Its scope is only
passive response inspection. It must:

- preserve field order and duplicate fields;
- never comma-join values;
- never decode an unrelated header;
- return raw values for the calling rule to interpret;
- treat a malformed or non-ASCII value as unusable for that rule without
  exposing it.

Each rule owns its field cardinality. HSTS, `X-Content-Type-Options` and
`X-Frame-Options` are treated as singleton decisions: duplicate fields are
ambiguous and do not satisfy protection. Repeated
`Content-Security-Policy` fields are allowed because each policy is enforced.
Repeated `Set-Cookie` fields are required to remain separate.

HTML applicability reuses `discovery.is_html_response`: exactly one
`Content-Type` with a case-insensitive `text/html` media type, ignoring
parameters. Missing, duplicate, empty, malformed or non-HTML Content-Type
fields do not establish HTML context.

### Initial rule set

The initial set is deliberately limited to six checks that can be decided from
the existing response.

#### 1. HSTS absent or ineffective on HTTPS

- Rule ID: `passive.hsts.not_enforced.v1`
- Kind: `HARDENING`
- Applies only when `response.final_target.scheme == "https"`.
- Exactly one ASCII `Strict-Transport-Security` field is required.
- A minimal directive parser requires exactly one case-insensitive `max-age`
  directive whose unquoted value is decimal and greater than zero.
- A missing field, duplicate fields, missing/duplicate/invalid `max-age`, or
  `max-age=0` fires the rule with a sanitized state such as `missing`,
  `ambiguous`, `invalid` or `disabled`.
- Unknown extension directives are ignored. `includeSubDomains` and `preload`
  are not required.

This is a transport-hardening observation. It is not proof that traffic can be
downgraded or intercepted.

#### 2. Missing or invalid `X-Content-Type-Options: nosniff`

- Rule ID: `passive.nosniff.missing_or_invalid.v1`
- Kind: `HARDENING`
- Applies only to responses classified as HTML by
  `discovery.is_html_response`.
- Exactly one field whose ASCII value, after optional whitespace trimming, is
  case-insensitively equal to `nosniff` satisfies the rule.
- Missing, duplicate, malformed or other values fire the rule.

Applying this rule to every asset would emit repetitive low-context findings.
Discovery does not retain browser request-destination context needed to assess
script and stylesheet MIME enforcement reliably. The first contract therefore
uses the existing deterministic HTML classification; broader resource contexts
are deferred.

#### 3. HTML response without an enforced CSP

- Rule ID: `passive.csp.missing_enforced_policy.v1`
- Kind: `HARDENING`
- Applies only to deterministic HTML responses.
- One or more non-empty ASCII `Content-Security-Policy` fields satisfy the
  presence rule; repeated enforced policies are legitimate.
- `Content-Security-Policy-Report-Only` never satisfies it.
- If only report-only policies exist, evidence records only that normalized
  state, not policy contents.

This rule verifies delivery of an enforced CSP header, not the policy's
strength or completeness. It does not claim that XSS exists when CSP is
absent.

#### 4. HTML response without recognized frame protection

- Rule ID: `passive.framing.missing_protection.v1`
- Kind: `HARDENING`
- Applies only to deterministic HTML responses.
- A single ASCII `X-Frame-Options` value of `DENY` or `SAMEORIGIN`,
  case-insensitively and after optional whitespace trimming, satisfies the
  rule.
- `ALLOW-FROM`, duplicate fields and malformed values do not provide recognized
  protection.
- Alternatively, any enforced `Content-Security-Policy` field with a
  case-insensitive `frame-ancestors` directive and a non-empty directive value
  satisfies the rule.
- A `frame-ancestors` directive in report-only CSP does not satisfy it.

The CSP check only splits policies into semicolon-delimited directives,
identifies the directive name and requires a value. It does not implement full
CSP source-expression semantics.

The finding is a hardening observation, not proof that a useful clickjacking
attack exists.

#### 5. HTTPS cookie without `Secure`

- Rule ID: `passive.cookie.secure_missing_https.v1`
- Kind: `MISCONFIGURATION`
- Applies to each parseable `Set-Cookie` field independently when
  `response.final_target.scheme == "https"`.
- It fires when the cookie has no case-insensitive `Secure` attribute.
- Evidence contains the cookie name, status and normalized attribute state
  only.

#### 6. `SameSite=None` cookie without `Secure`

- Rule ID: `passive.cookie.samesite_none_without_secure.v1`
- Kind: `MISCONFIGURATION`
- Applies on both HTTP and HTTPS responses.
- It fires for a parseable cookie with exactly one recognized
  case-insensitive `SameSite=None` attribute and no `Secure` attribute.
- Evidence contains the cookie name and normalized attributes only.

A cookie satisfying both cookie rules may produce both rule identities. They
state different deterministic configuration problems; duplicate occurrences
of either identity are removed by fingerprint.

### Minimal safe Set-Cookie parsing

Each `Set-Cookie` header field represents one candidate cookie and is parsed
independently. Fields are never comma-split because `Expires` legitimately
contains commas.

The private parser is intentionally narrower than a cookie jar:

1. Split the field on semicolons.
2. Require the first segment to contain a non-empty ASCII RFC token name and a
   structurally valid cookie value.
3. Validate the value as bytes, including the optional quoted form, but discard
   it immediately without decoding, copying into the result or logging it.
4. Inspect later attribute names case-insensitively.
5. Treat an attribute named `Secure` as present without retaining any supplied
   attribute value.
6. Normalize `SameSite` only when its ASCII value is exactly `None`, `Lax` or
   `Strict`, case-insensitively.
7. Treat duplicate `SameSite` attributes as ambiguous for the SameSite rule.

Unknown attributes are ignored. A structurally malformed cookie pair produces
no cookie finding for that field. Malformed or ambiguous SameSite metadata
produces no SameSite finding. Neither condition aborts other cookie fields or
non-cookie rules.

There is no dedicated malformed-cookie finding. A malformed line does not
prove that a user agent accepted a security-relevant cookie, and preserving
the raw line as evidence would conflict with the no-secret requirement.

Cookie values, bearer tokens, authorization values, credentials, session
identifiers and arbitrary response-body snippets must never appear in a
finding, fingerprint input, exception message or test failure representation.

### HTML and body policy

The accepted HTML rules inspect headers only. They reuse the existing exact
`text/html` classification and do not parse the response body.

Milestone 4 will not:

- sniff HTML from body bytes;
- scan arbitrary bodies for secrets or sensitive-data patterns;
- introduce another HTML parser;
- execute scripts;
- infer DOM behavior.

The bounded body remains available for a later specifically approved,
deterministic rule. Merely having a body is not sufficient justification.

### Error isolation

Raw response metadata is untrusted. Expected malformed input is isolated to
the smallest relevant decision:

- malformed singleton security-header values are unusable for that rule;
- ambiguous singleton duplicates do not satisfy protection;
- malformed CSP values do not satisfy the CSP-dependent decision but do not
  stop other rules;
- one malformed Set-Cookie field is skipped while later fields continue;
- malformed Content-Type does not establish HTML applicability.

Helpers handle expected byte-decoding failures explicitly. There is no broad
`except Exception` around rule execution. Programming defects, violated typed
invariants and upstream async-iteration failures propagate rather than being
silently converted into findings.

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

Milestone 4 also excludes:

- active validation and vulnerability exploitation;
- an evidence capture/replay engine;
- request/response archival;
- raw evidence persistence;
- a findings database, dashboard or aggregation repository;
- JSON or other report generation;
- severity scoring and CVSS;
- AI analysis;
- authorization testing and IDOR/BOLA;
- CORS reflection testing;
- browser execution and JavaScript analysis;
- CLI integration.

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
- streaming avoids retaining page bodies or complete result collections;
- evidence is structured for deterministic identity without storing raw
  secrets;
- the rule set remains explicit, reviewable and offline-testable;
- no new dependency is required.

Negative:

- the initial scanner intentionally misses context-dependent and active
  vulnerabilities;
- malformed cookie lines are skipped rather than diagnosed;
- CSP delivery and frame-ancestor recognition are deliberately narrower than a
  full CSP audit;
- no severity, remediation, persistence, aggregation or report is produced;
- run-level duplicate suppression retains one fixed-size fingerprint per unique
  finding for the bounded input stream.

There are no unresolved architectural questions blocking implementation. The
implementation plan fixes test vectors and slice acceptance criteria in
`docs/plans/0005-passive-scanner.md`.
