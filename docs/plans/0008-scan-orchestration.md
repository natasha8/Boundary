# Scan Orchestration Plan

- Status: Planned
- Milestone: 7
- Planned: 2026-08-18
- Planned implementation: `src/boundary/scan.py`, with a thin `scan`
  subcommand in `src/boundary/cli.py`
- Planned tests: `tests/test_scan_config.py`,
  `tests/test_scan_orchestration.py`, `tests/test_cli_scan.py`
- Decision record: `docs/decisions/0007-scan-orchestration.md`

## Purpose

Scan Orchestration turns the existing BOUNDARY primitives into one
deterministic, uncredentialed scan workflow.

It makes one statement possible that the repository cannot make today:

- this explicit `ScanConfig` produced this ordered `ScanResult` of
  `FindingEvidence` values, or it failed with the original Scope / Transport
  / URL / programming exception.

The composition is:

    ScanConfig
        -> require_allowed_origin
        -> crawl(...)
        -> scan_page(page)
        -> capture_response_evidence(...)
        -> FindingEvidence(...)
        -> ScanResult

Orchestration does not own URL parsing rules, origin/IP policy, HTTP
execution, crawling, passive rules, evidence hashing, authorization
comparison, persistence or reporting.

## Prerequisites

The completed Scope Engine provides `TargetUrl`, `Origin`,
`require_allowed_origin`, `AddressPolicy`, `AddressResolver` and
`SystemAddressResolver`. Embedded userinfo credentials are already rejected
at parse time. Query strings are retained and remain an inherited
sensitive-data boundary.

The completed Controlled HTTP Transport provides `RequestLimits`,
`request_with_redirects` and fail-closed body, timeout and redirect
controls. Discovery is the only caller of `request_with_redirects` in this
workflow.

The completed Discovery Engine provides `DiscoveryLimits`, `DiscoveredPage`
and `crawl`. `crawl` is a bounded async generator. It does not accumulate a
discovery result. It sends uncredentialed `GET`s.

The completed Passive Scanner provides `scan_page` and `scan_pages`. This
milestone uses `scan_page` so evidence can be captured while the page is
still in scope. `scan_pages` remains available for finding-only consumers
and is not called by orchestration.

The completed Evidence Engine provides `ResponseEvidence`, `FindingEvidence`
and `capture_response_evidence`. The accepted composition loop is already
specified in ADR 0005; this milestone is its first production consumer.

The completed Authorization Engine provides `AuthorizationCase`,
`request_as` and `AuthorizationObservation`. Those primitives are **not**
wired into M7. Credential/session acquisition does not exist and will not be
invented here.

The current CLI prints help for any invocation and has no `scan`
subcommand.

## Planned architecture

```python
@dataclass(frozen=True, slots=True)
class ScanConfig:
    target: TargetUrl
    allowed_origins: tuple[Origin, ...]
    policy: AddressPolicy
    resolver: AddressResolver
    request_limits: RequestLimits
    max_redirects: int
    discovery_limits: DiscoveryLimits

    def __post_init__(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[FindingEvidence, ...]


async def run_passive_scan(config: ScanConfig) -> ScanResult: ...
```

The final implemented surface of `scan.py` is exactly those three names.

`cli.py` adds a `scan` subcommand that:

1. parses required target, allowlist, policy, page/depth/redirect/body
   budgets and optional timeout flags;
2. calls `parse_target_url` for the target and each `--allow-origin`;
3. builds `ScanConfig` with `SystemAddressResolver()`;
4. calls `asyncio.run(run_passive_scan(config))`;
5. prints `{n} findings` on success.

`scan.py` runtime imports are the standard library plus the BOUNDARY
modules it composes (`scope`, `discovery`, `passive`, `evidence`, and
transport types already required by those signatures). It does not import
`authorization` or `cli`. Lower-layer modules do not import `scan.py`.

No `ScanEngine` class is added.

## Why this shape

ADR 0005 already chose the per-page `scan_page` + `capture_response_evidence`
loop over changing Passive APIs or adding an evidence stream. M7 places that
loop in one function and gives it an explicit config and result.

`ScanConfig` has no defaults so orchestration cannot silently widen scope or
drop budgets. Nested types keep their own invariants; orchestration only
adds the pre-network origin gate and the `max_redirects >= 0` check so an
invalid budget cannot start `crawl`.

`ScanResult` holds only `FindingEvidence` because that is the fact M8 will
serialize. Run ids, timestamps and page counts are not required to execute
or test the workflow: request counts are observable from the existing
recording transport fake.

Authorization stays unwired because M6 still requires the caller to supply
origin-bound credentials at `request_as` time. Putting those on `ScanConfig`
or CLI flags would invent a vault.

## Vocabulary

- **scan configuration** — `ScanConfig`.
- **scan result** — `ScanResult`; facts, not a report.
- **operational CLI output** — `{n} findings`; replaced by M8 reporting.
- **uncredentialed workflow** — Discovery `GET`s with `credentials=None`.

## Delivery slices

Tests are written before the implementation of each slice. A slice is
complete only when its acceptance criteria hold. Do not start Slice B until
Slice A passes on its own.

Adjusted sequence: **A, B, D**. Slice C (extra run metadata) and Slice E
(authorization orchestration) are deferred because the architecture does not
need them for the first M7 workflow.

### Slice A: Scan configuration value model

Tests: `tests/test_scan_config.py`

Deliver:

- frozen, slotted `ScanConfig` with exactly the seven approved fields, in
  that order, and no defaults;
- `__post_init__` calling `require_allowed_origin(target, allowed_origins)`
  and rejecting `max_redirects < 0` with `ValueError`;
- no `ScanResult` / `run_passive_scan` requirement yet if that keeps the
  slice smaller; adding the empty `ScanResult` type in Slice A is allowed
  only as the frozen findings tuple with no extra fields.

Acceptance criteria:

- `ScanConfig` is frozen and slotted; assignment raises
  `FrozenInstanceError`; instances have no `__dict__`;
- there is no dataclass default on any field, including `policy`,
  `max_redirects`, `allowed_origins` and `resolver`;
- there is no credentials, identity, header, method, profile, output,
  timestamp or run-id field;
- a target whose origin is in `allowed_origins` constructs successfully
  without I/O;
- a target whose origin is missing, including an empty allowlist, raises
  `ScopeValidationError` with `ORIGIN_NOT_ALLOWED` and performs no DNS or
  HTTP;
- `require_allowed_origin` is the origin check — no copied allowlist loop
  in `scan.py`;
- `max_redirects == 0` is accepted; `max_redirects < 0` raises `ValueError`
  before any resolver call;
- invalid `DiscoveryLimits` / `RequestLimits` still fail in those types,
  not via a second copied validator;
- `ScanConfig` does not construct `SystemAddressResolver` and does not
  import `boundary.authorization`;
- fail-fast guards prove construction does not call `crawl`,
  `request_once`, `request_with_redirects`, `request_as`,
  `socket.getaddrinfo` or AnyIO connect;
- error messages contain no response bodies and no credential bytes
  (there are none to echo).

### Slice B: Passive scan orchestration and result

Tests: `tests/test_scan_orchestration.py`

Deliver:

- frozen, slotted `ScanResult` with exactly `findings: tuple[FindingEvidence, ...]`;
- `async def run_passive_scan(config: ScanConfig) -> ScanResult`;
- the ADR 0005 loop inside that function, calling real `crawl`, real
  `scan_page` and real `capture_response_evidence`.

Offline technique matches `tests/test_discovery_crawl.py`: recording
resolver plus scripted `request_once`, with autouse guards against real
DNS/sockets. Do not mock `scan_page`, do not reimplement rules, and do not
replace `crawl` with a stub when testing the workflow — fake the transport
hop, not the orchestration behavior.

Acceptance criteria:

- `crawl` is called with `seed=config.target` and the config's
  `allowed_origins`, `policy`, `resolver`, `request_limits`,
  `max_redirects` and `discovery_limits` (as `limits=`);
- every discovery hop is an uncredentialed `GET` (`credentials` absent /
  `None`, empty crawler headers);
- findings order is crawl page order then `scan_page` order;
- a page with no findings contributes nothing and does not call
  `capture_response_evidence` (no digest of clean pages);
- a page with several findings shares one `ResponseEvidence` across its
  `FindingEvidence` values;
- redirect provenance composes: `page.target` as `requested_target`,
  `response.final_target` as finding/evidence target;
- `ScanResult(findings=())` is success for a completed clean crawl;
- `scan_pages` is not invoked;
- `request_as` is not invoked; `boundary.scan` does not import
  `boundary.authorization`;
- `TransportError`, `ScopeValidationError`, resolver errors and
  `UnicodeDecodeError` from `crawl` propagate; no `ScanResult` is returned;
  no error is rewritten as a `PassiveFinding`;
- a failure after the first page has been composed still raises — no
  partial `ScanResult`;
- response headers, bodies, `Authorization` / `Set-Cookie` values and
  credential-shaped secrets placed in those fields never appear in
  `ScanResult`, `repr`, or exception messages;
- query-string tokens on the target remain visible as the inherited
  boundary and are not asserted away;
- inputs (`ScanConfig` nested values, scripted responses) are not mutated;
- no pages, bodies or `TransportResponse` values are retained on
  `ScanResult`;
- duplicate `evidence_id` values from redirect aliases are kept in stream
  order (no new suppression policy);
- public surface of `scan.py` is exactly `ScanConfig`, `ScanResult` and
  `run_passive_scan`.

### Slice C: Run metadata — deferred / not implemented

Not required to execute or test the M7 workflow.

Do not add run id, timestamps, duration, `pages_visited`, argv snapshots or
a copy of `ScanConfig` onto `ScanResult`. Reconsider only when a Milestone 8
serializer has a concrete field it cannot obtain from the caller-held
`ScanConfig` plus `ScanResult.findings`.

### Slice D: CLI `scan` command wiring

Tests: `tests/test_cli_scan.py` (keep `tests/test_cli.py` covering
no-argument help)

Deliver:

- `scan` subcommand on the existing argparse parser;
- required flags listed in ADR 0007;
- optional timeout flags mapping onto `RequestLimits`;
- `SystemAddressResolver()` injected in `cli.py` only;
- `asyncio.run(run_passive_scan(config))`;
- stdout `{n} findings` on success.

`cli.py` stays thin. URL parsing uses `parse_target_url`. Origin allowlist
entries are origins of parsed URLs. Policy is `AddressPolicy(value)`. CLI
must not import `crawl`, `scan_page` or `capture_response_evidence`.

Preserve `main([])` printing help and exiting 0.

Acceptance criteria:

- `boundary` with no arguments still prints the existing help text and does
  not start a scan;
- `scan -h` documents the required flags and does not document JSON, SARIF,
  Markdown, progress, plugin, cookie, identity or profile flags;
- missing `--allow-origin`, `--address-policy`, `--max-pages`,
  `--max-depth`, `--max-redirects` or `--max-body-bytes` is an argparse
  error;
- omitted timeout flags produce `RequestLimits` timeouts of `None`;
- embedded URL credentials, unsupported schemes and other
  `UrlValidationError` cases fail via real `parse_target_url` before
  network;
- a target origin not listed in `--allow-origin` fails via real
  `ScanConfig` / `require_allowed_origin` before network — the seed origin
  is not auto-inserted;
- invalid `--address-policy` is rejected;
- wiring tests may replace `run_passive_scan` to capture the constructed
  `ScanConfig` and a fake `ScanResult`; they must not mock
  `parse_target_url` or `require_allowed_origin`;
- production CLI path uses `SystemAddressResolver`; captured config from a
  wiring test shows that resolver type (or a test-injected constructor
  seam that defaults to it);
- no CLI flag exists for credentials, identities, `--header`, report
  format, output path, concurrency or plugins;
- success stdout is exactly one operational line matching `{n} findings`
  (n from `len(result.findings)`), not a finding dump;
- no test contacts a public Internet target.

### Slice E: Authorization orchestration — deferred / not implemented

M6 contracts can execute one explicit pair only when the caller already
holds identities and origin-bound credentials. There is still no vault,
login flow, CLI credential channel or scan profile.

Implementing Slice E now would require inventing one of those. Do not.

`run_passive_scan` stays uncredentialed. A later milestone may add a
**separate** function over caller-supplied `AuthorizationCase` values
without:

- teaching `crawl` to pick identities;
- putting secrets on `ScanConfig` or `ScanResult`;
- letting AI construct cases;
- changing Scope authority;
- merging `AuthorizationObservation` into `FindingEvidence`.

## Error-handling policy

- `scan.py` contains no `try` / `except` around Scope, Discovery, Transport,
  Passive or Evidence, and no `except Exception`;
- config/URL/scope errors happen before `crawl` when they can;
- mid-crawl failures abort the scan and do not return `ScanResult`;
- Passive's per-rule isolation of malformed headers is unchanged and is not
  a per-page recovery policy;
- failures are never converted into findings;
- error messages contain no response bodies and no credentials.

## Offline testing approach

Slice A constructs `ScanConfig` with a fake `AddressResolver` and never
opens a network path.

Slice B reuses the discovery-crawl recording fake for `request_once` and a
scripted resolver. Pages, findings and evidence come from real
`crawl` / `scan_page` / `capture_response_evidence`. Guards fail the test if
real `getaddrinfo`, sockets or AnyIO connect run.

Slice D tests argparse, `parse_target_url`, `ScanConfig` construction and
the operational stdout line. When they invoke `main` for a successful
wiring case, `run_passive_scan` is replaced so the CLI suite does not crawl.

No test contacts a public target. Credential-absence assertions place
secrets in response headers/bodies, never in a target query string, when
claiming they do not leak into `ScanResult`.

## Final security invariants

- Scope Engine remains authoritative for URL, origin and address policy;
- every HTTP request of this workflow goes through `crawl` →
  `request_with_redirects` (pinned, bounded, timed, in-scope `GET`);
- orchestration never calls `request_once`, `request_with_redirects` or
  `request_as` directly;
- scan configuration has no hidden allowlist, policy, page, body or
  redirect default;
- scan configuration holds no credentials;
- `boundary scan` sends no identity headers;
- evidence capture retains no bodies on `ScanResult`;
- AI does not choose targets, origins, identities or verdicts;
- incomplete scans do not look like successful scans;
- query-string exposure on `TargetUrl` is inherited and unredacted;
- the application remains a modular monolith with one new internal module.

## Milestone non-goals

Not added:

- SARIF, JSON, Markdown, HTML reporting, dashboards;
- persistence of any kind;
- run metadata (`pages_visited`, timestamps, run id);
- `evidence_id` collapsing;
- concurrent / distributed scanning;
- plugin architecture, scheduler;
- AI Analyst, agent execution gateway;
- login automation, vault, cookie jar, browser automation;
- mutating active tests, Bug Bounty profile;
- custom API-key credential headers;
- User-Agent / extra crawler headers;
- authorization orchestration on the CLI or inside `run_passive_scan`;
- configuration files;
- a `ScanEngine` class.

## Dependency decision

No dependency will be added.

Argparse, dataclasses, asyncio and the existing BOUNDARY modules are
sufficient. HTTPCore remains the single runtime HTTP dependency, reached
only through Transport as today.

## Verification sequence

Repository checks at closeout of each implemented slice, and at milestone
closeout:

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
git diff --check
```

Focused new tests run first, then the complete suite. No test may contact a
public target, skip a security assertion or weaken an existing check.

This architecture-only change must itself pass those documentation-
compatible gates without adding production code or tests.

## Definition of done (when implementation is later executed)

- Slices A, B and D meet every acceptance criterion;
- Slices C and E remain absent, with deferral documented;
- public `scan.py` surface is exactly `ScanConfig`, `ScanResult`,
  `run_passive_scan`;
- `boundary scan` is a thin adapter and produces no report format;
- authorization is not imported or invoked;
- formatting, linting, typing and all tests pass without skipped or
  weakened tests;
- ADR 0007 and this plan match the implementation, including deferred
  items;
- no dependency was added.

Architecture-only definition of done (this change):

- ADR 0007 and this plan exist and agree;
- no production code, tests or dependency changes;
- no commit;
- documentation-compatible quality gates pass.
