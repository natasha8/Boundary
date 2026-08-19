# ADR 0008: Project ScanResult into a safe, deterministic report

- Status: Accepted (Milestone 8), implementation pending
- Date: 2026-08-19
- Planned implementation: `src/boundary/reporting.py`, with a later thin
  `--format` adapter in `src/boundary/cli.py`
- Planned tests: `tests/test_reporting_target.py`,
  `tests/test_reporting_model.py`, `tests/test_reporting_json.py`,
  `tests/test_reporting_sarif.py`, and CLI coverage only in Slice E
- Depends on: `docs/decisions/0004-passive-security-scanning.md`,
  `docs/decisions/0005-evidence-engine.md`,
  `docs/decisions/0007-scan-orchestration.md`
- Implementation plan: `docs/plans/0009-reporting.md`

## Context

Milestone 7 returns an in-memory `ScanResult`: an ordered tuple of
`FindingEvidence`. That object is a fact set, not a report. ADR 0007
deferred JSON, SARIF and any other serializer, and left an inherited
sensitive-data boundary unresolved:

> Query strings in `TargetUrl` remain visible on findings, evidence,
> fingerprints and therefore on `ScanResult`. Redaction is a precondition
> of Milestone 8 export.

ADR 0005 already recorded the same boundary and forbade treating a digest
as redaction. `PassiveFinding.fingerprint` hashes `target.url`.
`FindingEvidence.evidence_id` hashes that fingerprint. A token, API key,
session identifier or other secret in the query therefore participates in
both internal identifiers.

The product still needs a developer-usable export of the existing passive
scan. Reporting must be a projection boundary: it reads domain values and
emits a smaller, explicitly allowlisted model. It must not serialize
`ScanResult`, `FindingEvidence`, `PassiveFinding`, `ResponseEvidence`,
`TargetUrl` or `ScanConfig` with `dataclasses.asdict()`, `__dict__`, a
generic object encoder, or reflection.

Domain models remain authoritative and unchanged. Reporting concerns must
not move onto them.

The core principle is:

> A report is a fail-closed projection of already-computed facts. It never
> becomes a second finding store, and it never emits raw target queries.

## Decision

BOUNDARY will add one cohesive module, `src/boundary/reporting.py`,
composed of immutable values and plain functions in the same style as
`scope.py`, `passive.py`, `evidence.py` and `scan.py`.

The first reporting workflow is:

    TargetUrl (scan seed) + ScanResult
        -> project_report_target (safe URL)
        -> ScanReport (safe findings)
        -> render_scan_report_json / render_scan_report_sarif

No `Reporter`, plugin registry, serialization framework, template engine,
output path manager, GitHub client, dashboard or persistence layer will be
added.

M8 reports the existing uncredentialed passive `ScanResult` only.
`AuthorizationObservation` remains a separate type and is not mapped.

### Core invariant

> Reporting serializes only the safe reporting model. If a field cannot be
> projected safely, reporting raises; it never falls back to raw domain
> serialization or silently drops the field.

The delivered code must not:

- read `TargetUrl.url` when constructing a report URL;
- emit raw query keys or values;
- emit `PassiveFinding.fingerprint` or `FindingEvidence.evidence_id`;
- emit response headers, response bodies, credentials, cookies, tokens,
  resolver objects or `ScanConfig`;
- call `crawl`, `request_once`, `request_with_redirects`, `request_as`,
  `run_passive_scan`, or any resolver/socket API;
- persist, upload, or write files;
- invent severity, CVSS, confidence, remediation, run ids or timestamps;
- invent repository file paths for HTTP findings;
- mix `FindingEvidence` and `AuthorizationObservation` into one generic
  finding type;
- change `ScanConfig`, `ScanResult`, `FindingEvidence`, `PassiveFinding`,
  `ResponseEvidence` or `TargetUrl`.

Ownership stays unchanged. Scope remains authoritative for URL identity.
Passive Scanner remains authoritative for observations. Evidence remains
authoritative for captured projections. Orchestration remains authoritative
for the scan workflow. Reporting projects those facts for export.

## Vocabulary

- **reporting projection** — a new immutable value built from allowlisted
  fields of existing facts. It is not the domain object.
- **safe URL / report URL** — the deterministic string produced from
  `TargetUrl` fields with the complete query replaced by one marker when a
  query exists.
- **scan report** — `ScanReport`: the safe seed target plus ordered safe
  findings.
- **renderer** — a pure function from `ScanReport` to one canonical text
  document (JSON or SARIF).
- **operational CLI output** — the existing `{n} findings` line. It is not
  a report.

## ReportUrl model

`ReportUrl` is the only URL type that may appear on a report. It does not
store a `TargetUrl`. It is not a `str` subclass.

```python
QUERY_REDACTION_MARKER = "REDACTED"


@dataclass(frozen=True, slots=True)
class ReportUrl:
    url: str

    def __post_init__(self) -> None: ...
```

### Constructor and fields

- Generated signature: `ReportUrl(url: str)` and `ReportUrl(url=...)`.
  Not keyword-only. No field default.
- Exact field name: `url`. Field order: `url` only.
- Python type of `url`: `str`.
- `frozen=True`, `slots=True`: assignment raises `FrozenInstanceError`;
  instances have no `__dict__`.
- Equality and hashing are the default frozen-dataclass behaviour on
  `url`.
- **No custom `__str__`, `__repr__`, or `__format__`.** Default dataclass
  `repr` may include the already-safe `url` value. Renderers and SARIF
  locations must read `report_url.url`; they must not use `str(report_url)`
  or `repr(report_url)` as a URI.

### Marker

```python
QUERY_REDACTION_MARKER: str = "REDACTED"
```

Exact value: the eight ASCII characters `REDACTED`. Not `[redacted]`,
not `***`, not percent-encoded, not a `key=value` pair.

### `__post_init__` invariants

Direct construction is allowed for tests. It must not be a bypass for raw
queries. Raise `ValueError` and do not store the value when:

1. `url == ""`;
2. `"#" in url` (fragments are absent from `TargetUrl` and remain absent);
3. `"?" in url` and the substring after the first `?` is not exactly
   `QUERY_REDACTION_MARKER`.

Messages name the constraint. They must not echo a rejected query string.

A URL with no `?` is accepted by this check even if the path contains a
token. That is path preservation, not query leakage. See Residual risk.

### Rendered URL algorithm

`project_report_target(target: TargetUrl) -> ReportUrl` is the only
production path from a domain target. It must not read `target.url`.
It must not retain `target`. Inputs are exactly:

- `target.scheme`
- `target.host`
- `target.port`
- `target.path`
- whether `target.query != ""` (presence only; the query string is never
  copied)

Reporting-local default ports, matching Scope display semantics:

```python
{"http": 80, "https": 443}
```

Do not import Scope's private `_DEFAULT_PORTS` / `_format_netloc`.

Locked algorithm:

```python
def project_report_target(target: TargetUrl) -> ReportUrl:
    defaults = {"http": 80, "https": 443}
    if target.scheme not in defaults:
        raise ValueError("unsupported URL scheme")
    if target.host == "" or target.path == "":
        raise ValueError("host and path are required")
    display_host = f"[{target.host}]" if ":" in target.host else target.host
    default_port = defaults[target.scheme]
    netloc = (
        display_host if target.port == default_port else f"{display_host}:{target.port}"
    )
    query_component = QUERY_REDACTION_MARKER if target.query != "" else ""
    rendered = urlunsplit((target.scheme, netloc, target.path, query_component, ""))
    return ReportUrl(url=rendered)
```

`urlunsplit` reconstructs from components. It does not search or replace
substrings inside `TargetUrl.url`. Heuristic detection of sensitive
parameter names is forbidden: every non-empty query is untrusted and
becomes the single marker.

Query presence is `target.query != ""`, not `"?" in target.url`.

Port text is `str(target.port)` via the f-string above: decimal, no
leading zeros, no `:` when the port equals the scheme default.

The fifth `urlunsplit` component is always `""` (no fragment).

### Locked examples

Given already-normalized `TargetUrl` values:

| Input identity | `ReportUrl.url` |
| --- | --- |
| `https://app.test/reset?token=secret&session=abc` | `https://app.test/reset?REDACTED` |
| `https://app.test/reset` | `https://app.test/reset` |
| `https://EXAMPLE.com:443/path?x=1` after parse | `https://example.com/path?REDACTED` |
| `http://127.0.0.1:3000/health` | `http://127.0.0.1:3000/health` |
| `http://[::1]:8080/health?q=1` | `http://[::1]:8080/health?REDACTED` |
| `https://app.test/a%2fb/../etc?x=%2e%2e` | `https://app.test/a%2fb/../etc?REDACTED` |

Two targets that differ only in query content share one `ReportUrl.url`.
That collapse is intentional. Distinct `ScanResult` rows remain distinct
report rows; they are not merged.

`ReportUrl` v1 guarantees **query redaction**, not universal URL-secret
redaction. See Residual risk.

## Derived identifiers

### Canonical inputs today

`PassiveFinding.fingerprint` is SHA-256 over canonical JSON of:

1. fingerprint schema version `1`;
2. `rule_id`;
3. `target.url` (raw query included);
4. canonical sanitized `evidence`.

`FindingEvidence.evidence_id` is SHA-256 over canonical JSON of:

1. evidence-identity schema version `1`;
2. `finding.fingerprint` (therefore transitively `target.url`);
3. `response.status`;
4. `response.body_length`;
5. `response.body_sha256`.

M8 does not change either digest.

### Threat

A SHA-256 digest is not equivalent to secret redaction.

- A high-entropy secret hashed with known context (schema, rule id,
  evidence, URL pattern) is not recoverable as a practical matter, but the
  secret has still left the process as a derivative. ADR 0005 forbids
  treating that as a confidentiality control.
- A low-entropy token (short codes, sequential ids, guessable reset
  parameters) can be brute-forced against the digest because every other
  fingerprint input is either public or already in the report.
- Publishing the digest also creates a stable correlation handle for the
  exact secret-bearing URL.

### Decision

**Omit `fingerprint` and `evidence_id` from report v1.**

Do not add a replacement report identifier in v1. A finding in the report
is identified by its allowlisted fields and by its stable position in
`ScanResult` order.

A later milestone may add a `report_id` only if a consumer needs a compact
key. That digest must be taken over the safe reporting projection and other
explicitly safe fields. It must not hash `TargetUrl.url`,
`PassiveFinding.fingerprint` or `FindingEvidence.evidence_id`.

Duplicate `evidence_id` values from redirect aliases (ADR 0005 / 0007) are
**kept** as separate report findings, in stream order. Collapsing them
would change cardinality relative to `ScanResult`. Reporting does not
introduce a second fingerprint system.

## ScanReport and ReportFinding

```python
REPORT_SCHEMA_VERSION = 1  # Python int; JSON number 1


@dataclass(frozen=True, slots=True)
class ReportFinding:
    rule_id: str
    kind: PassiveFindingKind
    target: ReportUrl
    requested_target: ReportUrl
    observation: str
    rationale: str
    evidence: tuple[tuple[str, str], ...]
    status: int
    body_length: int
    body_sha256: str

    def __post_init__(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ScanReport:
    schema: int
    target: ReportUrl
    findings: tuple[ReportFinding, ...]

    def __post_init__(self) -> None: ...
```

Both are `frozen=True`, `slots=True`, with no field defaults. Field order
above is the constructor order, the dataclass field order, and the JSON
object key order (with `kind` emitted as its value string). No custom
`__str__` / `__repr__`.

Neither type stores `TargetUrl`, `FindingEvidence`, `PassiveFinding`,
`ResponseEvidence`, `ScanResult`, or `ScanConfig`.

### ScanReport fields

| Order | Field | Python type | Source | Transform |
| --- | --- | --- | --- | --- |
| 1 | `schema` | `int` | constant `REPORT_SCHEMA_VERSION` | none; must equal `1` |
| 2 | `target` | `ReportUrl` | `project_report_target(seed)` where `seed` is the `target` argument of `build_scan_report` | query-safe URL projection |
| 3 | `findings` | `tuple[ReportFinding, ...]` | `result.findings` in that order | 1:1 map to `ReportFinding`; never drop, sort, or collapse |

`ScanReport.__post_init__` raises `ValueError` if `schema != 1` or if
`findings` is not a `tuple`.

### ReportFinding fields

Authoritative source is the current `FindingEvidence` row, written here as
`record`. Reporting does **not** accept either of two equal domain fields.
The pairing invariant already guaranteed by `FindingEvidence.__post_init__`
is:

- `record.finding.target == record.response.final_target`
- `record.finding.requested_target == record.response.requested_target`

Reporting therefore reads observation identity from the finding and
captured response facts from the response, and does not re-check pairing.

| Order | Field | Python type | Authoritative source | Transform |
| --- | --- | --- | --- | --- |
| 1 | `rule_id` | `str` | `record.finding.rule_id` | none; identity copy |
| 2 | `kind` | `PassiveFindingKind` | `record.finding.kind` | none; same enum member. JSON/SARIF emit `kind.value`. Supported values: `MISCONFIGURATION` (`"misconfiguration"`) and `HARDENING` (`"hardening"`) only |
| 3 | `target` | `ReportUrl` | `record.finding.target` | `project_report_target(...)`. **Not** `record.response.final_target` |
| 4 | `requested_target` | `ReportUrl` | `record.finding.requested_target` | `project_report_target(...)`. **Not** `record.response.requested_target`. Always present, even when equal to `target` after projection |
| 5 | `observation` | `str` | `record.finding.observation` | none; identity copy. See observation contract |
| 6 | `rationale` | `str` | `record.finding.rationale` | none; identity copy. See observation contract |
| 7 | `evidence` | `tuple[tuple[str, str], ...]` | `record.finding.evidence` | none; same tuple, same order. Shape-checked. See evidence projection |
| 8 | `status` | `int` | `record.response.status` | none; identity copy. **Not** the evidence-key string `"status"` |
| 9 | `body_length` | `int` | `record.response.body_length` | none; identity copy |
| 10 | `body_sha256` | `str` | `record.response.body_sha256` | none; identity copy |

`requested_target` stays a stable schema field. Redirect provenance is a
documented finding fact (ADR 0004). Once both URLs are `ReportUrl`
values, including the equal case does not add query content.

### ReportFinding `__post_init__`

Raise `ValueError` rather than accepting or coercing:

- `kind` is not `PassiveFindingKind.MISCONFIGURATION` and not
  `PassiveFindingKind.HARDENING` (bare strings and any future enum member
  are unsupported until reporting is updated);
- `observation`, `rationale`, `rule_id`, or `body_sha256` is not `str`;
- `status` or `body_length` is not `int`;
- `evidence` fails the shape contract below;
- `target` or `requested_target` is not a `ReportUrl`.

Do not re-validate `FindingEvidence` pairing, `TargetUrl` normalization,
`body_length >= 0`, or the 64-hex `body_sha256` form. Those belong to
Evidence.

### Forbidden material

The report model has no field that can hold:

- `TargetUrl`, `TargetUrl.url`, or `TargetUrl.query`;
- `PassiveFinding.fingerprint` or `FindingEvidence.evidence_id`;
- response headers or body bytes;
- `Authorization` / `Cookie` / `Set-Cookie` values;
- credentials, tokens, or session material from request headers;
- `AddressResolver`, sockets, or other network objects;
- `ScanConfig`, allowlists, address policy, limits, or timeouts;
- run id, timestamps, duration, hostname, argv, `pages_visited`;
- severity, CVSS, confidence, confirmation, remediation.

## Evidence projection

`PassiveFinding.evidence` is already
`tuple[tuple[str, str], ...]` with unique keys, sorted by key at
`build_passive_finding`. ADR 0004 requires those strings to be sanitized
rule facts (header **names**, states, counts, cookie **names**, status
decimal as a string). It forbids raw header values, complete `Set-Cookie`
lines, cookie values, Authorization values and body excerpts.

That content contract is why v1 may copy evidence across the reporting
boundary: the values are not response bytes and not query strings. There
is still no generic redaction engine. Hashing is not redaction.

### Report representation

- Python type on `ReportFinding.evidence`: `tuple[tuple[str, str], ...]`.
- Store `record.finding.evidence` unchanged: same pairs, same order, no
  re-sort, no trim, no case fold, no key rewrite.
- JSON shape: an array of two-element arrays of JSON strings,
  `[[key, value], ...]`, in that stored order. Not a JSON object. Not a
  list of dicts. Keys and values remain strings (`status` in evidence is
  `"200"`, while `ReportFinding.status` is the number `200`).
- Empty evidence `()` becomes JSON `[]`.
- Do not use `dataclasses.asdict`, `json.dumps` on the tuple with a
  default encoder, or any generic object walk.

### Shape fail-closed

Reporting does not allowlist evidence **key names** (that would be a rule
registry). It does allowlist the **shape**. Raise `ValueError` if:

- `evidence` is not a `tuple`;
- any item is not a `tuple` of length exactly 2;
- either element is not `str`.

Reject `list`, `dict`, `bytes`, `int`, nested objects, a bare `str`,
`TargetUrl`, and one-element or three-element pairs. Do not coerce. Do not
drop the bad pair and keep the rest. Do not serialize `repr(obj)`.

A future rule that puts a secret **inside** an otherwise valid
`(str, str)` pair would pass this shape check. That is the same class of
trust as observation prose: it is a Passive Scanner contract, not a
reporting secret scanner. A future rule type whose evidence is not
`tuple[tuple[str, str], ...]` must get an explicit safe projection before
it can be reported; v1 will refuse the shape.

## Observation / rationale trust boundary

v1 copies `record.finding.observation` and `record.finding.rationale`
because current passive rules treat those fields as **rule-generated,
non-secret prose**. Implemented M4 strings are static per rule. They do
not interpolate `TargetUrl`, header values, body bytes, cookies, or
credentials.

Reporting must:

- copy the two strings with no edit, trim, concatenation, or format;
- **never** interpolate `TargetUrl`, `TargetUrl.url`, `TargetUrl.query`,
  `ReportUrl.url`, headers, body, credentials, fingerprints, or argv into
  those strings;
- **not** run heuristic secret scanning on the prose.

JSON `observation` / `rationale` and SARIF `message.text` /
`properties.rationale` are those copied strings.

A future rule type that interpolates untrusted or secret material into
prose is outside this contract. It requires an explicit safe projection
(or a rule-side stop on interpolation) before reporting may copy the
fields. That decision is a new ADR. M8 does not add a prose redactor.

## `build_scan_report` invariants

```python
def build_scan_report(
    *,
    target: TargetUrl,
    result: ScanResult,
) -> ScanReport: ...
```

The function is a 1:1 projection. It does not mutate `target` or `result`.

### What it validates

1. **Seed URL projection.** `ScanReport.target` is
   `project_report_target(target)`. Unsupported scheme, empty host/path,
   or a `ReportUrl` invariant failure raises `ValueError` and yields no
   report.
2. **Per-finding URL projection.** `ReportFinding.target` and
   `requested_target` are produced with the same function from
   `record.finding.target` and `record.finding.requested_target`.
   Failure on any row fails the whole build. Rows already projected are
   discarded; there is no partial `ScanReport`.
3. **Supported kind and evidence shape.** Enforced by
   `ReportFinding.__post_init__` when the builder constructs each row:
   only the two `PassiveFindingKind` members; evidence is
   `tuple[tuple[str, str], ...]`.
4. **Observation / rationale types.** They must be `str` (identity copies
   from the finding). Non-strings raise `ValueError`.
5. **Schema.** `ScanReport(schema=REPORT_SCHEMA_VERSION, ...)` with
   `schema == 1`.

`len(report.findings)` equals `len(result.findings)` by construction,
including zero.

### What it does not validate

Do not duplicate domain construction:

- `FindingEvidence` pairing (`finding.target == response.final_target`
  and requested-target equality);
- `TargetUrl` parse/normalize rules;
- unique evidence keys (owned by `build_passive_finding`);
- `ResponseEvidence` `body_length >= 0` and 64-hex `body_sha256`;
- that finding URLs are in the scan allowlist or equal to the seed.

Library callers must pass the seed they scanned. Reporting does not
compare the seed to finding targets.

### Fail-closed

Unsupported values raise `ValueError`. Reporting never omits a finding to
make the document succeed, never emits `TargetUrl.url` as a fallback, and
never substitutes `repr` of an arbitrary object for evidence.

Error messages name the constraint. They must not include `TargetUrl.url`,
`TargetUrl.query`, response bodies, or credential bytes.

## Zero-finding context

`ScanResult` has no seed target. `ScanResult(findings=())` is a successful
clean scan (ADR 0007) and would otherwise be an empty document.

Reporting does **not** mutate `ScanResult` to store the seed. It does **not**
add run ids, timestamps, `pages_visited` or environment metadata.

CLI Slice E passes `config.target`. Discovery may have visited pages that
produced no findings; those pages are not listed. The projected seed is
the smallest honest identity of what was scanned.

## Determinism

For the same seed `TargetUrl` and the same `ScanResult`, every renderer
produces the same text in this process and any other.

- no UUID, clock, `time`, `random`, `hash()`, object identity, hostname or
  environment value is read;
- finding order is `ScanResult.findings` order. Findings are **not**
  sorted by `rule_id`, target, kind or any other key;
- JSON object keys use insertion order from the explicit dicts below.
  `sort_keys` is `False`;
- both renderers call
  `json.dumps(..., ensure_ascii=True, separators=(",", ":"), sort_keys=False)`
  with no `default=` encoder and no `indent`;
- the library renderer return value is a `str` with **no trailing
  newline** (`\n` or `\r\n`);
- `ensure_ascii=True` makes the JSON ASCII.

No pretty/compact switch. Renderers construct dicts by explicit
allowlisted keys. They do not call `dataclasses.asdict()`, `vars()`,
`.__dict__`, or `json.dumps(default=...)` on `ScanReport`,
`ReportFinding`, `ReportUrl`, or any domain type.

## JSON mapping

```python
REPORT_SCHEMA_VERSION = 1  # Python int
```

JSON schema field is the number `1`, not `"1"`.

```python
def render_scan_report_json(report: ScanReport) -> str: ...
```

stdlib `json` only. Argument type is `ScanReport`. Passing `ScanResult` is
not part of the API.

If `report.schema != 1`, raise `ValueError` and produce no document.

### `ReportUrl` → JSON string

JSON type: string. Value: `report_url.url` exactly. Not
`{"url": "..."}`. Not `str(report_url)`.

### `ReportFinding` → JSON object

Exact keys, this order, no others:

| JSON key | JSON type | From |
| --- | --- | --- |
| `rule_id` | string | `finding.rule_id` |
| `kind` | string | `finding.kind.value` (`"misconfiguration"` or `"hardening"`) |
| `target` | string | `finding.target.url` |
| `requested_target` | string | `finding.requested_target.url` |
| `observation` | string | `finding.observation` |
| `rationale` | string | `finding.rationale` |
| `evidence` | array of 2-element string arrays | `[[k, v] for k, v in finding.evidence]` |
| `status` | number | `finding.status` |
| `body_length` | number | `finding.body_length` |
| `body_sha256` | string | `finding.body_sha256` |

### `ScanReport` → top-level JSON object

Exact keys, this order, no others:

| JSON key | JSON type | From |
| --- | --- | --- |
| `schema` | number | `report.schema` (`1`) |
| `target` | string | `report.target.url` |
| `findings` | array of finding objects | `report.findings` in tuple order |

Locked empty-scan example, seed `https://example.com/` (empty query):

```json
{"schema":1,"target":"https://example.com/","findings":[]}
```

A seed whose query is non-empty uses the projected `?REDACTED` URL as
`target` and still has `"findings":[]`.

## SARIF v1 shape

```python
def render_scan_report_sarif(report: ScanReport) -> str: ...
```

Target: **SARIF 2.1.0**. Same `json.dumps` arguments as the JSON renderer.
If `report.schema != 1`, raise `ValueError` and produce no document.

### Valid SARIF versus GitHub Code Scanning

**Valid SARIF 2.1.0** allows a result to point at any URI-addressable
artifact, including an HTTP resource.

**GitHub Code Scanning** expects repository file paths, prefers
`partialFingerprints` from those files, and uploads via Actions or API.
Inventing `src/...` paths or dummy files would fabricate locations.

**v1 does not claim GitHub Code Scanning compatibility.** GitHub upload,
API integration, Actions wiring, `checkout_uri` mapping, and any
file-location adapter remain deferred.

### Top-level document

Exactly three keys, this order:

1. `$schema` — included. Exact string:
   `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`
2. `version` — exact string `"2.1.0"`
3. `runs` — array of length exactly 1

No other top-level keys. The `$schema` URI is a string in the document,
not a network fetch.

### One run

`runs[0]` has exactly three keys, this order:

1. `tool`
2. `results`
3. `properties`

`tool` is exactly `{"driver": <driver>}`.

`driver` has exactly two keys, this order:

1. `name` — exact string `"BOUNDARY"`
2. `rules` — array of rule descriptors (possibly empty)

Omitted on driver and run: `version`, `semanticVersion`, `informationUri`,
`invocations`, `originalUriBaseIds`, `automationDetails`, timestamps,
`commandLine`, argv, environment, package metadata.

`runs[0].properties` is exactly one key:

    {"scan_target": "<ScanReport.target.url>"}

Always present, including when there are findings and when there are none.
Value is the safe seed URL string, never `TargetUrl.url`.

### Rule descriptors

Dedup key: `ReportFinding.rule_id`. Order: first-seen while walking
`report.findings` from index 0. No plugin registry.

Each descriptor is exactly two keys, this order:

```json
{"id":"<rule_id>","name":"<rule_id>"}
```

Both strings equal `finding.rule_id`. No `shortDescription`,
`fullDescription`, `help`, `helpUri`, `defaultConfiguration`, or
`properties`. Observation is not copied onto the rule.

If a later finding repeats a `rule_id` with a different `kind` than the
first-seen row, raise `ValueError`. Same `rule_id` always yields the same
`{id, name}` object.

### Results

`runs[0].results` has one element per `report.findings` row, **same
order** (ScanResult order). No sort.

Each result has these keys in this order:

1. `ruleId` — `finding.rule_id`
2. `ruleIndex` — `int` index of that `rule_id` in `driver.rules`
3. `level` — exact string `"note"` for every finding
4. `message` — exactly `{"text": "<finding.observation>"}`
5. `locations` — array of length 1
6. `relatedLocations` — **omitted** (key absent, not `[]` / `null`) when
   `finding.requested_target.url == finding.target.url`; otherwise array
   of length 1 as below
7. `properties` — exactly the keys below

`message.text` source is `ReportFinding.observation` only. Do not
interpolate any URL.

`locations[0]` is exactly:

```json
{
  "physicalLocation": {
    "artifactLocation": {
      "uri": "<finding.target.url>"
    }
  }
}
```

URI source: `ReportFinding.target.url` (safe absolute HTTP(S) URL). No
`uriBaseId`, no `region`, no `startLine`, no `file://`, no repository
path.

When present, `relatedLocations[0]` is exactly:

```json
{
  "physicalLocation": {
    "artifactLocation": {
      "uri": "<finding.requested_target.url>"
    }
  },
  "message": {
    "text": "requested target"
  }
}
```

The related-location message is the static ASCII string `requested target`.
URI source: `ReportFinding.requested_target.url`. If two raw URLs differ
only in query content, both project to the same safe string and
`relatedLocations` is omitted.

`result.properties` has exactly these keys, this order, all from the
`ReportFinding`:

| Key | JSON type | Source |
| --- | --- | --- |
| `kind` | string | `finding.kind.value` |
| `rationale` | string | `finding.rationale` |
| `evidence` | array of 2-element string arrays | same mapping as JSON |
| `status` | number | `finding.status` |
| `body_length` | number | `finding.body_length` |
| `body_sha256` | string | `finding.body_sha256` |

No fingerprints, `partialFingerprints`, `rank`, `baselineState`,
`suppressions`, `webRequest`, `webResponse`, `fixes`, `codeFlows`, raw
`TargetUrl.url`, `evidence_id`, headers, body bytes, argv, or tool
version.

### Empty report

Seed `https://example.com/` (no query) renders as exactly:

```json
{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"BOUNDARY","rules":[]}},"results":[],"properties":{"scan_target":"https://example.com/"}}]}
```

`rules` and `results` are empty arrays, not omitted. There is still one
run. `scan_target` is the safe seed. No fake result is invented.

### Kind and level

`PassiveFindingKind` is classification, not severity. **Every SARIF
`level` is `"note"`.** Kind is only `result.properties.kind`.

## CLI boundary

Reporting is a library first. `boundary scan` remains a thin adapter.

M8 Slice E may add **one** optional flag:

    --format {text,json,sarif}

Default: `text` (today's `{n} findings` line).

`json` and `sarif` write the renderer output to stdout. The process adds a
single trailing newline via `print`. There is no `--output`, no file
writer, no pretty-print flag. Shell redirection is the file story:

    boundary scan ... --format json > report.json

CLI constructs `ScanReport` as
`build_scan_report(target=config.target, result=result)` after
`run_passive_scan` returns. It does not crawl again, does not log argv,
and does not print the raw seed URL.

Not added:

- configuration files;
- reporter plugins;
- progress UI;
- network upload;
- GitHub API / `upload-sarif`;
- `--markdown` / `--html`.

Until Slice E exists, the public reporting API is the render functions
only. That is enough for tests and for a caller who already holds
`ScanConfig` and `ScanResult`.

## Error semantics

Reporting is pure and offline. It performs no I/O.

| Failure | Behavior |
| --- | --- |
| Unsupported scheme, empty host/path, or other projection invariant | `ValueError`. No report. |
| `ReportUrl` with a raw query or a fragment | `ValueError`. |
| Unsupported kind or evidence shape | `ValueError`. |
| Non-str observation/rationale | `ValueError`. |
| `ScanReport.schema != 1` | `ValueError`. |
| SARIF rule-id/kind mismatch | `ValueError`. |
| JSON encoding failure | Propagates. No fallback encoder. |

Never:

- omit a finding because its URL could not be projected;
- emit the raw `TargetUrl.url` as a fallback;
- emit a partial JSON/SARIF document and call it success;
- catch `Exception`;
- convert a reporting error into a `PassiveFinding`.

A projection or render failure does not mutate `ScanResult` or
`ScanReport`. Incomplete output is not a defined successful report.

## Authorization boundary

M8 maps `FindingEvidence` only.

`AuthorizationObservation` holds two `ResponseEvidence` values, identity
labels, and a different kind enum. Forcing both into one generic `Finding`
would erase that distinction (ADR 0006 / 0007).

A future report may add a separate tuple or a separate builder. It must
not reuse `ReportFinding` by stuffing a second projection into
`evidence`.

## Planned surface

`src/boundary/reporting.py` will expose exactly:

- `QUERY_REDACTION_MARKER`
- `REPORT_SCHEMA_VERSION`
- `ReportUrl`
- `ReportFinding`
- `ScanReport`
- `project_report_target`
- `build_scan_report`
- `render_scan_report_json`
- `render_scan_report_sarif`

`scan.py`, `passive.py`, `evidence.py` and `scope.py` are not modified.
`reporting.py` may import `TargetUrl`, `ScanResult`, `FindingEvidence` and
`PassiveFindingKind` as inputs. It must not call orchestration or network
APIs. `scan.py` must not import `reporting.py`.

No class hierarchy, protocol, registry, factory or stream helper.

## Residual risk

`ReportUrl` v1 guarantees **query redaction**: a non-empty `TargetUrl.query`
never appears as keys, values, or raw substring in `ReportUrl.url`. It
does **not** guarantee universal URL-secret redaction.

Documented residual risks, out of v1 scope:

- **Path tokens.** `TargetUrl.path` is copied into the safe URL. A secret
  in a path segment such as `/reset/SECRET` remains visible. v1 does not
  add path-token heuristics.
- **`body_sha256`.** The digest of retained body bytes is copied from
  `ResponseEvidence`. It is a comparison primitive, not redaction of body
  secrets (ADR 0005), especially for short or low-entropy bodies. Body
  bytes are not emitted. M8 does not persist bodies.
- **Evidence and prose content.** Shape-checked `(str, str)` evidence and
  rule-generated observation/rationale are copied because current passive
  rules treat them as non-secret. Reporting does not scan those strings
  for secrets.

Embedded userinfo credentials are already rejected by `parse_target_url`
and are not a reporting field.

## Deferred

Explicitly not part of Milestone 8:

- GitHub upload, GitHub API, Actions `upload-sarif`;
- GitHub Code Scanning file-location adapters or dummy repo paths;
- Markdown / HTML reports;
- persistence, databases, evidence directories, JSONL;
- dashboards;
- authorization reporting;
- run ids, timestamps, `pages_visited`, argv snapshots;
- severity, CVSS, confidence, confirmation states;
- remediation text;
- AI Analyst;
- Bug Bounty Evidence Pack;
- reporter plugins;
- active / mutating scanning;
- collapsing findings by `evidence_id` or by safe URL;
- a second report identifier hashed from internal fingerprints;
- query-parameter allowlisting / heuristic secret-name detection;
- path-segment redaction;
- `webRequest` / `webResponse` SARIF objects.

BOUNDARY remains a modular monolith (ADR 0001). Reporting is another
internal module, not a service.

## Alternatives considered

**`json.dumps(asdict(scan_result))`.** Rejected: `TargetUrl`, raw queries,
fingerprints and nested domain objects would leave the process.

**Redact by regex/substring on `TargetUrl.url`.** Rejected: brittle, easy
to miss encodings, and forbidden by the requirement to construct from
fields.

**Drop query keys whose names look sensitive.** Rejected: all query
content is untrusted. Name heuristics fail closed too late and fail open
on `q`, `t`, `s`, `id`.

**Emit `fingerprint` / `evidence_id` because SHA-256 is one-way.**
Rejected: hashing is not redaction; low-entropy queries remain at risk;
M8 must not change domain fingerprints to "fix" that.

**Add `seed_target` onto `ScanResult`.** Rejected: mutates the fact object
for a presentation concern. The caller already holds the seed.

**Sort or collapse findings for a cleaner report.** Rejected: order and
cardinality are scan facts. Redirect-alias duplicates stay.

**Map kind to SARIF `warning` / `error`.** Rejected: invents severity.

**Claim GitHub Code Scanning support via a dummy file path.** Rejected:
fabricated locations. Defer GitHub ingestion entirely.

**Put `webRequest` in SARIF for "real" HTTP findings.** Rejected: the
object is a magnet for headers and query parameters.

**Pretty-print flag or output framework.** Rejected: two encodings for one
schema. Compact is the only v1 representation.

**Generic `Finding` covering authorization observations.** Rejected:
different evidence shape (one projection vs two identities).

**Read `response.final_target` or `response.requested_target` as the
report URL source.** Rejected as an alternate source: pairing already
makes them equal to the finding targets; reporting locks one path
(`record.finding.target` / `record.finding.requested_target`) so tests do
not allow either.

**Custom `ReportUrl.__str__` returning `.url`.** Rejected: renderers must
use the field explicitly; `str()` stays default dataclass behaviour.

**Allowlist evidence key names in reporting.** Rejected: that is a rule
registry. Shape (`tuple[tuple[str, str], ...]`) is the fail-closed gate.

## Consequences

Positive:

- `ScanResult` can leave the process without carrying raw queries;
- domain models stay free of renderer concerns;
- JSON and SARIF share one safe projection;
- GitHub incompatibility is explicit instead of implied by producing SARIF;
- zero-finding scans remain identifiable without run metadata;
- constructors, sources, evidence shape and renderer dicts are testable
  without guessing;
- no new dependency is required.

Negative:

- internal fingerprints cannot be used to correlate a report row with an
  in-memory `FindingEvidence` without recomputing from domain objects;
- two findings that differed only in query content look alike after
  projection (they remain separate rows);
- path tokens are not redacted;
- `body_sha256` of a secret-bearing body remains in the report as a
  digest;
- SARIF will not render as GitHub Code Scanning file annotations;
- operators must pass the seed target into `build_scan_report`;
- a new `PassiveFindingKind` member or non-pair evidence shape cannot be
  reported until reporting is updated.

## Unresolved questions

None of these block the M8 architecture:

1. **Path tokens.** Redact only if a later milestone has a concrete,
   fail-closed path contract. Do not invent heuristics here.
2. **Report identifier.** Add only when a consumer needs a compact key
   derived from the *safe* projection.
3. **GitHub Code Scanning.** Requires a separate mapping that can name
   real repository files without fabrication, plus upload integration.
4. **Authorization reporting.** Separate builder/tuple when product-surface
   authorization exists.
5. **CLI default format.** Slice E keeps `text` as default so M7 behavior
   remains until an explicit `--format` is passed. Switching the default
   to JSON is a later product decision.
