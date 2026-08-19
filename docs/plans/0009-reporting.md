# Reporting Plan

- Status: Completed
- Milestone: 8
- Planned: 2026-08-19
- Completed: 2026-08-19
- Implementation: `src/boundary/reporting.py`, with a thin `--format`
  adapter in `src/boundary/cli.py` only in Slice E
- Tests: `tests/test_reporting_url.py`,
  `tests/test_reporting_model.py`, `tests/test_reporting_json.py`,
  `tests/test_reporting_sarif.py`, plus CLI updates in Slice E
- Decision record: `docs/decisions/0008-reporting.md`

## Purpose

Reporting turns an existing passive `ScanResult` into a deterministic,
query-safe document.

It makes two statements possible that the repository could not make before
this milestone:

- this seed target, after fail-closed query redaction, produced this
  ordered list of allowlisted findings;
- those findings can be written as canonical JSON or as valid SARIF 2.1.0
  without serializing domain dataclasses or raw `TargetUrl.url`.

The final reporting flow is:

    ScanResult
        -> build_scan_report
        -> safe ReportUrl projection
        -> ScanReport
        -> JSON or SARIF renderer

Reporting does not own scope, transport, discovery, passive rules,
evidence hashing, authorization comparison, persistence or scan
orchestration. It performs no network activity.

## Prerequisites

The completed Scope Engine provides normalized `TargetUrl` values:
`scheme`, `host`, `port`, `path`, `query`, `url`. Embedded userinfo is
already rejected. Query strings are retained. Default ports are omitted
from `TargetUrl.url`; non-default ports are included; IPv6 hosts are
bracketed. Fragments are dropped.

The completed Passive Scanner provides `PassiveFinding` with `rule_id`,
`kind`, final and requested targets, observation, rationale, sanitized
`tuple[tuple[str, str], ...]` evidence and a fingerprint that hashes
`target.url`. Current observation/rationale strings are rule-generated
static prose.

The completed Evidence Engine provides `ResponseEvidence` and
`FindingEvidence`. Pairing requires `finding.target == response.final_target`
and `finding.requested_target == response.requested_target`.
`evidence_id` hashes `finding.fingerprint` and therefore transitively
hashes `target.url`. Headers and body bytes are not stored.

The completed Scan Orchestration provides `ScanConfig`, `ScanResult` and
`run_passive_scan`. `ScanResult` is only
`findings: tuple[FindingEvidence, ...]`. Clean scans are
`ScanResult(findings=())` with no seed field. Before this milestone,
`boundary scan` printed `{n} findings` and had no report flags.

Authorization Engine exists and is **not** an input of this milestone.

ADR 0005, 0006 and 0007 left query-string export unresolved. This
milestone is that decision. Exact constructors, sources and renderer
shapes remain locked in ADR 0008.

## Delivered architecture

```python
QUERY_REDACTION_MARKER = "REDACTED"
REPORT_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ReportUrl:
    url: str

    def __post_init__(self) -> None: ...


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


def project_report_target(target: TargetUrl) -> ReportUrl: ...


def build_scan_report(
    *,
    target: TargetUrl,
    result: ScanResult,
) -> ScanReport: ...


def render_scan_report_json(report: ScanReport) -> str: ...


def render_scan_report_sarif(report: ScanReport) -> str: ...
```

The delivered public surface is:

- `QUERY_REDACTION_MARKER`
- `REPORT_SCHEMA_VERSION`
- `ReportUrl`
- `ReportFinding`
- `ScanReport`
- `project_report_target`
- `build_scan_report`
- `render_scan_report_json`
- `render_scan_report_sarif`
- `boundary scan --format {text,json,sarif}`

`reporting.py` exposes exactly the names above except the CLI flag.
Runtime imports stay in the standard library plus the BOUNDARY types it
reads (`TargetUrl`, `ScanResult`, `FindingEvidence`, `PassiveFindingKind`).
It does not import `authorization`, `discovery`, `transport` request
functions, or `resolver`.

`scan.py`, `passive.py`, `evidence.py` and `scope.py` are not modified.
`scan.py` does not import `reporting.py`.

No `Reporter` class, plugin registry or serialization framework.

Exact field sources, `ReportUrl` algorithm, evidence shape, builder
checks, JSON dicts and SARIF key order are in ADR 0008. This plan does
not relax them.

## Why this shape

`ScanResult` cannot grow a seed field just so a renderer has context:
the caller already holds `ScanConfig.target`. Passing both values keeps
the fact object stable and gives zero-finding reports an identity.

Safe URLs cannot be substring-redacted from `TargetUrl.url`. Reconstructing
with `urlunsplit` from `scheme` / `host` / `port` / `path` / query-presence
matches Scope port semantics without copying the raw query.

Internal fingerprints cannot be exported. They hash `target.url`. SHA-256
is not redaction. v1 omits them rather than inventing a parallel digest.

JSON and SARIF both consume `ScanReport`. Neither renderer sees
`ScanResult`. That is the projection boundary.

SARIF 2.1.0 can name an HTTP artifact. GitHub Code Scanning cannot, unless
we fabricate a repository file. The architecture produces valid SARIF and
explicitly refuses the GitHub claim.

`ReportUrl` is a one-field frozen value, not a `str` subclass, so
renderers must use `.url` and cannot accidentally `str()` a dataclass
into a URI.

## Vocabulary

- **safe URL** — `ReportUrl.url` produced by `project_report_target`.
- **scan report** — `ScanReport`; the only object renderers may serialize.
- **operational CLI output** — `{n} findings`; not a report.
- **SARIF 2.1.0 validity** — OASIS document correctness.
- **GitHub Code Scanning compatibility** — file-location ingestion plus
  upload; out of scope.
- **query redaction** — v1 `ReportUrl` guarantee. Not universal
  URL-secret redaction.

## Delivery slices

Tests were written before the implementation of each slice. A slice is
complete only when its acceptance criteria hold.

Completed sequence: **A, B, C, D, E**.

- Slice A: safe `ReportUrl` projection
- Slice B: `ScanReport` / `ReportFinding` projection
- Slice C: deterministic JSON renderer
- Slice D: deterministic SARIF 2.1.0 renderer
- Slice E: CLI `--format {text,json,sarif}`

Slices A–D are the reporting architecture. Slice E is the minimal CLI
adapter, justified because the product brief lists JSON report output and
ADR 0007 assigned serializers to M8. Without E, operators have no
supported way to emit the projection from `boundary scan`. E stayed last
and remains a thin argparse/`print` adapter.

### Slice A: Safe URL / report target projection — completed

Tests: `tests/test_reporting_url.py`

Delivered:

- `QUERY_REDACTION_MARKER = "REDACTED"` (exact eight ASCII characters)
- frozen, slotted `ReportUrl` with exactly one field, `url: str`
- constructor `ReportUrl(url: str)` / `ReportUrl(url=...)`; no defaults;
  not keyword-only
- no `TargetUrl` field; no custom `__str__` / `__repr__`
- `project_report_target` implementing the ADR algorithm with
  `urlunsplit`; **does not read `TargetUrl.url`**

`ReportUrl.__post_init__` raises `ValueError` on `url == ""`, `"#" in url`,
or a `?` whose remainder is not exactly `REDACTED`.

Query presence is `target.query != ""`.

Acceptance criteria met:

- `ReportUrl` is frozen and slotted; no `__dict__`; fields are exactly
  `("url",)`;
- `QUERY_REDACTION_MARKER == "REDACTED"`;
- `https://app.test/reset?token=secret&session=abc` projects to
  `https://app.test/reset?REDACTED`;
- the original query, `token`, `session`, `secret` and `abc` are absent
  from `ReportUrl.url`;
- `https://app.test/reset` projects to `https://app.test/reset` (no `?`,
  no marker);
- two targets that differ only in query content share one `ReportUrl.url`
  and compare equal;
- `https://Example.COM:443/path?x=1` (via `parse_target_url`) projects to
  `https://example.com/path?REDACTED`;
- `http://127.0.0.1:3000/health` keeps port `3000`;
- `http://example.com/api` omits port `80`;
- `http://[::1]:8080/health?q=1` projects to
  `http://[::1]:8080/health?REDACTED`;
- encoded paths are preserved (`/a%2fb/../etc?x=%2e%2e` →
  `https://example.com/a%2fb/../etc?REDACTED`);
- `ReportUrl(url="https://app.test/reset?token=secret")` raises
  `ValueError` and does not keep the raw query;
- `ReportUrl` with `#fragment` raises `ValueError`;
- empty `ReportUrl.url` raises `ValueError`;
- `ReportUrl(url="https://app.test/reset?REDACTED")` is accepted;
- `project_report_target` with an unsupported scheme or empty host/path
  raises `ValueError` and does not emit a URL;
- the function does not mutate the input `TargetUrl` and does not store
  it on `ReportUrl`;
- renderers must use `.url`; tests may show `str(ReportUrl(...))`
  is not equal to `.url` (no custom `__str__`);
- error messages do not include `target.query` or `target.url`;
- no DNS, sockets or HTTP.

### Slice B: Safe report models + `build_scan_report` — completed

Tests: `tests/test_reporting_model.py`

Delivered:

- `ReportFinding`, `ScanReport`, `REPORT_SCHEMA_VERSION = 1` (`int`)
- `build_scan_report(*, target, result) -> ScanReport`

Mapping is 1:1 in `ScanResult` order. Each `FindingEvidence` becomes one
`ReportFinding` using the ADR source table:

- `target` ← `project_report_target(record.finding.target)`
- `requested_target` ← `project_report_target(record.finding.requested_target)`
- `kind` ← `record.finding.kind`
- `evidence` ← `record.finding.evidence` (unchanged tuple)
- `status` / `body_length` / `body_sha256` ← `record.response.*`

Do not read `record.response.final_target` or
`record.response.requested_target` as URL sources. Document pairing as
already guaranteed; do not re-assert it in `build_scan_report`.

Do not copy `fingerprint` or `evidence_id`. Do not store `TargetUrl`.
Do not read `ScanConfig`. Do not collapse redirect-alias duplicates.
Do not interpolate URLs into `observation` / `rationale`.

`ReportFinding.__post_init__` rejects unsupported kinds, non-`(str, str)`
evidence tuples, and non-str observation/rationale. Shape failures raise
`ValueError` for the whole build; no row is omitted.

Acceptance criteria met:

- `ScanReport` / `ReportFinding` are frozen and slotted; field names and
  order match the ADR;
- `REPORT_SCHEMA_VERSION` is the `int` `1`; `ScanReport.schema == 1`;
  `schema != 1` raises `ValueError`;
- `len(report.findings) == len(result.findings)` always, including zero;
- zero findings still yields `ScanReport.target` equal to
  `project_report_target(seed)`;
- finding order equals `ScanResult.findings` order;
- `kind` is the `PassiveFindingKind` member from the finding, not a bare
  string; a bare `"hardening"` or any other object raises `ValueError`;
- evidence is the same `tuple[tuple[str, str], ...]` in stored order;
  a `list`/`dict`/`bytes` evidence value raises `ValueError`;
- `status` is `record.response.status` (`int`), not the evidence-key
  string;
- `requested_target` is present even when its `.url` equals `target.url`;
- a finding whose requested and final *raw* targets differ keeps distinct
  `ReportUrl` values when the safe URLs differ;
- `fingerprint` and `evidence_id` are not attributes of `ReportFinding`
  or `ScanReport`;
- a seed or finding URL with a query token does not appear in any
  `ReportUrl.url`;
- `observation` / `rationale` equal the finding strings; the builder does
  not concatenate `TargetUrl.url` into them;
- `build_scan_report` does not mutate `result` or any nested finding;
- one failing projection or shape check produces no `ScanReport`;
- `boundary.reporting` does not import `boundary.authorization`;
- `boundary.scan` still does not import `boundary.reporting`;
- domain modules are unchanged;
- public surface after this slice is A plus B (renderers added in C and D).

### Slice C: Deterministic JSON renderer — completed

Tests: `tests/test_reporting_json.py`

Delivered:

- `render_scan_report_json(report: ScanReport) -> str`

stdlib `json` only. Explicit dicts per ADR mapping:

- `ReportUrl` → JSON string via `.url`
- `ReportFinding` → object with the ten keys in ADR order
- `ScanReport` → `schema`, `target`, `findings` in that order

`json.dumps(..., ensure_ascii=True, separators=(",", ":"), sort_keys=False)`.
No `indent`, no `default=`, no trailing newline.

Lock at least two golden strings: the ADR empty report, and one finding
whose seed/finding URLs had a query.

Acceptance criteria met:

- empty report golden string is exactly
  `{"schema":1,"target":"https://example.com/","findings":[]}`
  for that seed;
- `schema` is the number `1`;
- `kind` values are `"hardening"` / `"misconfiguration"`;
- `status` / `body_length` are numbers; `body_sha256` is a string;
- `evidence` is `[[key, value], ...]` of strings, stored order;
- `target` and `requested_target` are strings (`ReportUrl.url`), not
  objects;
- renderer output contains no raw query keys/values from the seed or
  findings;
- renderer output contains none of: `fingerprint`, `evidence_id`,
  `"headers"`, body bytes, `ScanConfig` fields, timestamps, UUIDs;
- two findings remain in `ScanResult` order (not sorted by `rule_id`);
- duplicate redirect-alias rows both appear;
- the function returns no trailing newline;
- repeating the call produces identical text;
- `dataclasses.asdict`, `__dict__` and `json.dumps(default=...)` are not
  used on domain objects or as the ScanReport serialization path;
- a `ScanReport` with `schema != 1` raises `ValueError` and produces no
  document;
- no partial JSON on failure.

### Slice D: SARIF 2.1.0 renderer — completed

Tests: `tests/test_reporting_sarif.py`

Delivered:

- `render_scan_report_sarif(report: ScanReport) -> str`

Same JSON encoding rules as Slice C. Exact document shape is ADR 0008
(top-level keys, one run, driver, rules, results, locations, properties).

Acceptance criteria met:

- empty report for seed `https://example.com/` is exactly the ADR golden
  SARIF string (`$schema` included, `version` `"2.1.0"`, one run,
  `rules: []`, `results: []`,
  `properties.scan_target` is `https://example.com/`);
- top-level keys are exactly `$schema`, `version`, `runs` in that order;
- `tool.driver` keys are exactly `name`, `rules`; `name` is `"BOUNDARY"`;
- `tool.driver.version` and `invocations` are absent;
- `runs[0].properties` is exactly `{"scan_target": <safe seed .url>}`
  when findings exist as well;
- each report finding becomes one result, same order;
- `message.text` is `finding.observation` only (no URL, no raw query);
- `level` is exactly `"note"`;
- `locations[0].physicalLocation.artifactLocation.uri` is
  `finding.target.url`;
- no `uriBaseId`, no `region`, no `webRequest`, no `webResponse`;
- no repository-relative file path, no `file://`, no invented `src/`
  location;
- `relatedLocations` key is absent when safe requested equals safe final;
  when present, URI is `finding.requested_target.url` and
  `message.text` is exactly `requested target`;
- `result.properties` keys are exactly `kind`, `rationale`, `evidence`,
  `status`, `body_length`, `body_sha256` in that order;
- `fingerprints` and `partialFingerprints` are absent;
- `driver.rules` is unique `rule_id`s in first-seen order; each rule is
  exactly `{"id":...,"name":...}` with both equal to `rule_id`;
- two findings with the same `rule_id` and different `kind` raise
  `ValueError`;
- raw query content is absent from the entire SARIF text;
- `ruleIndex` agrees with `driver.rules`;
- no GitHub upload, no network fetch of the `$schema` URI;
- no trailing newline; repeated calls match.

The renderer does **not** emit a dummy repo path for HTTP findings. GitHub
Code Scanning file-annotation compatibility is not claimed.

### Slice E: Minimal CLI output wiring — completed

Tests: extend `tests/test_cli_scan.py` (keep no-argument help coverage)

Justified: library renderers alone cannot satisfy the product-brief JSON
output from `boundary scan`. The adapter is argparse plus `print`.

Delivered:

- `--format` with choices `text`, `json`, `sarif`;
- default `text` → existing `{n} findings`;
- `json` / `sarif` →
  `build_scan_report(target=config.target, result=result)` then the
  matching renderer, printed to stdout;
- no `--output`, no file API, no pretty flag, no upload.

Acceptance criteria met:

- omitted `--format` still prints exactly `{n} findings`;
- `--format json` stdout is the canonical JSON plus the single newline
  `print` adds;
- `--format sarif` likewise;
- invalid `--format` is an argparse error;
- `scan -h` documents `--format` and does not document Markdown, HTML,
  output paths, plugins, cookies or GitHub flags;
- CLI passes `config.target`, not argv text, into `build_scan_report`;
- a seed URL with a query token does not appear in json/sarif stdout;
- CLI still does not import `crawl`, `scan_page` or
  `capture_response_evidence`;
- wiring tests may replace `run_passive_scan`; they must not mock
  `parse_target_url` or the reporting projection;
- no test contacts a public Internet target;
- no credential flags are added.

## Error-handling policy

- `reporting.py` contains no `try` / `except Exception`;
- invariant failures raise `ValueError` and produce no document;
- reporting never emits raw `TargetUrl.url` as a fallback;
- reporting never drops a finding to avoid a redaction failure;
- unsupported kind or evidence shape raises rather than coercing or
  `repr`-serializing;
- render failure does not mutate `ScanResult`;
- error messages contain no query strings, response bodies or
  credentials;
- scan/transport failures remain orchestration's concern and still do
  not return a report.

## Offline testing approach

All slices are offline. Construct `TargetUrl` with `parse_target_url`
and `ScanResult` / `FindingEvidence` with existing builders and local
fixtures. Do not call `run_passive_scan` in A–D.

Negative privacy tests place secrets in **query strings** and assert they
are absent from `ReportUrl`, JSON and SARIF. That is the opposite of
earlier evidence tests, which placed secrets in headers/bodies and
correctly did **not** assert query protection.

Do not mock `project_report_target` when testing `build_scan_report`.
Do not mock `build_scan_report` when testing renderers except where a
test is specifically about renderer encoding of an already-built
`ScanReport`.

No test fetches the SARIF `$schema` URL. No test uploads to GitHub.
No test requires path-token redaction. Assert path preservation and
query redaction separately so the residual risk stays visible.

## Final security invariants

- raw `TargetUrl.url` is never serialized directly;
- `TargetUrl.url` is not a reporting input;
- every non-empty query is replaced by `?REDACTED`; empty query adds no
  `?`;
- `ReportUrl` v1 is query redaction, not universal URL-secret redaction;
- domain `fingerprint` and `evidence_id` remain excluded from reports;
- headers, bodies, credentials and `ScanConfig` never appear in a report;
- no generic serializer (`dataclasses.asdict`, `__dict__`,
  `json.dumps(default=...)`) is used on domain objects or `ScanReport`;
- evidence crossing the boundary is `tuple[tuple[str, str], ...]` only;
- observation/rationale are copied, never interpolated by reporting;
- JSON/SARIF serialize `ScanReport` only;
- SARIF HTTP locations are safe `ReportUrl.url` values, not fabricated
  GitHub-specific source paths;
- GitHub Code Scanning compatibility is not claimed;
- authorization reporting remains separate; authorization observations
  are not mapped;
- reporting performs no I/O;
- the application remains a modular monolith with one new internal
  module.

## Residual risks

`ReportUrl` v1 guarantees query redaction, not universal URL-secret
redaction. These remain documented residual risks, not defects in the
Milestone 8 architecture:

- path tokens are not redacted;
- `body_sha256` is not a confidentiality mechanism;
- safe projection can collapse findings that differ only by query
  (distinct `ScanResult` rows remain distinct report rows);
- future evidence/prose must continue satisfying the reporting-safe
  contract.

## Milestone non-goals

Not added, and still deferred:

- GitHub upload / API / Actions integration;
- GitHub-specific source-location fabrication;
- Markdown / HTML reports;
- persistence / database / dashboard;
- authorization reporting;
- run ids / timestamps / `pages_visited`;
- severity / CVSS / confidence;
- remediation;
- AI Analyst;
- Bug Bounty Evidence Pack;
- reporter plugins;
- active / mutating scanning;
- `--output` file writing;
- configuration files;
- path-token heuristics;
- evidence-key name registries.

## Dependency decision

No dependency was added.

stdlib `json`, `dataclasses` and `urllib.parse.urlunsplit` are
sufficient. SARIF is emitted as JSON text, not via a SARIF SDK.

## Verification sequence

Repository checks executed at closeout:

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
git diff --check
```

CLI focused (`tests/test_cli.py`, `tests/test_cli_scan.py`): 82 passed.
Full repository suite: 1521 passed.
ruff: clean.
mypy: clean.
`git diff --check`: clean.

Focused CLI tests ran first, then the complete suite. No test contacted a
public target, skipped a security assertion or weakened an existing check.

## Test coverage

CLI focused (`tests/test_cli.py`, `tests/test_cli_scan.py`): 82 passed.

Full repository suite at closeout: 1521 tests collected and passing, with
no skipped tests.

## Unresolved boundaries

These remain deferred residual risks and product non-goals. They are not
defects in the Milestone 8 architecture. This closeout does not specify a
later milestone design:

- path-segment tokens;
- `body_sha256` as a digest, not redaction of body secrets;
- safe-URL collapse of findings that differed only in query content;
- a later `report_id` derived only from the safe projection;
- GitHub Code Scanning mapping without fabricated files;
- authorization reporting;
- switching CLI default `--format` from `text` to `json`.

## Definition of done

Met:

- Slices A–E meet every acceptance criterion;
- the delivered public surface is `QUERY_REDACTION_MARKER`,
  `REPORT_SCHEMA_VERSION`, `ReportUrl`, `ReportFinding`, `ScanReport`,
  `project_report_target`, `build_scan_report`,
  `render_scan_report_json`, `render_scan_report_sarif`, and
  `boundary scan --format {text,json,sarif}`;
- domain models are unchanged;
- formatting, linting, typing and all tests pass without skipped or
  weakened tests;
- ADR 0008 and this plan match the implementation, including deferred
  items;
- no secret-bearing query, header or body appears in report output;
- no dependency was added.
