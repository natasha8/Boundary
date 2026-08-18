# ADR 0007: Orchestrate one bounded scan without duplicating existing authorities

- Status: Accepted (Milestone 7), implementation pending
- Date: 2026-08-18
- Planned implementation: `src/boundary/scan.py`, with a thin `scan`
  subcommand in `src/boundary/cli.py`
- Planned tests: `tests/test_scan_config.py`,
  `tests/test_scan_orchestration.py`, `tests/test_cli_scan.py`
- Depends on: `docs/decisions/0003-controlled-discovery.md`,
  `docs/decisions/0004-passive-security-scanning.md`,
  `docs/decisions/0005-evidence-engine.md`,
  `docs/decisions/0006-authorization-engine.md`
- Implementation plan: `docs/plans/0008-scan-orchestration.md`

## Context

BOUNDARY now has the primitives of a scan and no product-level workflow that
runs them together:

- Scope Engine owns URL identity, exact-origin allowlisting, address policy
  and DNS admission;
- Transport owns pinned HTTP execution, body/timeout limits and in-scope
  redirects;
- Discovery owns bounded breadth-first `GET` crawling and yields
  `DiscoveredPage` values;
- Passive Scanner owns header-derived findings from pages it is given;
- Evidence owns captured response projections and `FindingEvidence` pairing;
- Authorization owns identity labels, origin-bound credentials, `request_as`
  and pairwise observations.

ADR 0004 documents `scan_pages(crawl(...))` as a finding-only composition.
ADR 0005 documents the evidence-bearing caller-side loop over `crawl` and
`scan_page`, and deferred any stream or engine that would hide that loop.
Nothing in the repository yet owns that loop, a scan configuration value, a
structured scan result, or a `boundary scan` command.

Without an orchestration layer, every future consumer — CLI, reporting, a
later scan profile — would restate the same wiring and would be tempted to
reimplement limits, recovery, credential handling or finding identity.

The core principle is:

> Orchestration sequences existing primitives. It does not become a second
> Scope, Transport, Discovery, Passive, Evidence or Authorization engine.

## Decision

BOUNDARY will add one cohesive module, `src/boundary/scan.py`, composed of
immutable configuration/result values and one async function, in the same
style as `scope.py`, `transport.py`, `discovery.py`, `passive.py`,
`evidence.py` and `authorization.py`.

The first Milestone 7 slice runs exactly one uncredentialed workflow:

    ScanConfig
        -> require_allowed_origin (Scope)
        -> crawl (Discovery)
        -> scan_page (Passive)
        -> capture_response_evidence + FindingEvidence (Evidence)
        -> ScanResult

No `ScanEngine`, `Orchestrator`, service class, plugin registry, scheduler,
result store, scan profile, credential vault or report serializer will be
added.

CLI parsing stays in `cli.py` and calls the orchestration API. CLI does not
contain discovery, passive, evidence or authorization logic.

### Core invariant

> Existing authorities remain unchanged. Orchestration may call them; it may
> not copy their rules, catch their failures into findings, or add hidden
> defaults that widen scope or remove limits.

The delivered code must not:

- parse URLs, allowlist origins, classify addresses or resolve DNS except by
  calling Scope (and, for production CLI only, constructing
  `SystemAddressResolver` as the injected resolver);
- call `request_once`, `request_with_redirects` or `request_as` — Discovery
  remains the only network path of this workflow, and it already calls
  `request_with_redirects` without credentials;
- extract HTML, maintain a frontier, or reimplement `max_pages` / `max_depth`;
- evaluate passive rules or canonicalize finding evidence;
- hash bodies or invent a second evidence type;
- choose identities, supply credentials, or emit
  `AuthorizationObservation` values;
- persist, serialize to JSON/SARIF/Markdown, or render a report;
- follow redirects itself, pin IPs, or set `retries` / connection pooling;
- default `AddressPolicy`, allowed origins, `DiscoveryLimits`,
  `RequestLimits.max_body_bytes` or `max_redirects`.

Ownership stays unchanged. `scan.py` is a composition root for one scan.

### Vocabulary

- **scan configuration** — `ScanConfig`: the complete explicit input of one
  uncredentialed passive scan, including the resolver dependency.
- **scan result** — `ScanResult`: the complete in-memory facts of one
  finished scan, currently an ordered tuple of `FindingEvidence`.
- **orchestration** — the function that validates configuration, runs
  Discovery, composes Passive and Evidence, and returns `ScanResult` or
  raises.
- **operational CLI output** — a non-report completion line. Reporting
  formats are Milestone 8.
- **authorization case** — existing M6 `AuthorizationCase`. Not an input of
  the first M7 scan.

## Scan configuration

Configuration is a frozen, slotted value with **no field defaults**. Every
safety-relevant input is supplied by the caller. Hidden defaults that would
invent an allowlist, select `LOCAL_LAB` or `PUBLIC`, or leave page/body
budgets unbounded are forbidden.

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
```

### Fields

| Field | Owner of meaning | Constraint |
| --- | --- | --- |
| `target` | Scope `TargetUrl` | Already normalized. Orchestration does not parse strings. |
| `allowed_origins` | Scope exact-origin allowlist | Immutable tuple. Empty or missing seed origin fails via `require_allowed_origin`. Orchestration does not auto-insert `target.origin`. |
| `policy` | Scope `AddressPolicy` | Explicit `PUBLIC` or `LOCAL_LAB`. No default. |
| `resolver` | Scope `AddressResolver` | Required dependency. `ScanConfig` does not construct `SystemAddressResolver`. Production CLI injects it. Tests inject a fake. |
| `request_limits` | Transport `RequestLimits` | Mandatory `max_body_bytes` and the four timeout fields as already validated by that type. Timeouts may be `None` because that is the existing Transport contract, not a new unlimited default invented here. |
| `max_redirects` | Transport hop budget | Integer `>= 0`, matching `request_with_redirects`. Validated on `ScanConfig` so an invalid budget cannot start `crawl`. |
| `discovery_limits` | Discovery `DiscoveryLimits` | Mandatory `max_pages > 0` and `max_depth >= 0` as already validated by that type. |

`__post_init__` performs only orchestration-level checks that the nested
types do not already perform:

1. `require_allowed_origin(self.target, self.allowed_origins)` — Scope
   remains authoritative; this is the scan's pre-network target gate;
2. `max_redirects >= 0` — the same fail-closed rule Transport already
   enforces, applied before any page is requested.

It must not re-parse `target`, re-validate IP addresses, re-validate
`RequestLimits` / `DiscoveryLimits` fields, or copy allowlist-matching
logic.

### What ScanConfig does not contain

- credentials, `OriginBoundCredentials`, `Authorization` / `Cookie` headers,
  tokens, passwords or session identifiers;
- `Identity`, `AuthorizationCase`, or any identity list;
- HTTP method, request body, generic header bag, or User-Agent (Discovery
  remains `GET` with no crawler-supplied headers; identifying User-Agent
  policy stays the Discovery deferral);
- run id, timestamps, output path, report format, verbosity, plugin list,
  concurrency, or scan-profile name;
- a raw URL string.

Generic scan configuration therefore carries no secrets. Milestone 6 already
requires credentials to be origin-bound runtime material supplied per
`request_as` call. That contract is not satisfied by putting secrets on
`ScanConfig`, so they stay off it.

## Orchestration boundary

The minimal public API of `src/boundary/scan.py` is exactly:

- `ScanConfig`
- `ScanResult`
- `run_passive_scan`

```python
async def run_passive_scan(config: ScanConfig) -> ScanResult: ...
```

One function is sufficient. There is no mutable run object, no engine
lifecycle, no context manager, and no callback/plugin hook.

`run_passive_scan` is async because `crawl` is async. There is no synchronous
wrapper. The CLI is the process that calls `asyncio.run`.

Library callers pass a constructed `ScanConfig`. They do not pass raw URL
strings into `scan.py`. String parsing stays in CLI (and in any future
caller) via `parse_target_url`.

## Execution order

The workflow is a single sequence. Each arrow is a call into an existing
authority, not a reimplementation.

```text
1. Caller builds ScanConfig
      target is already a Scope TargetUrl
      __post_init__ -> require_allowed_origin(target, allowed_origins)
                    -> max_redirects >= 0
      no DNS, no HTTP

2. run_passive_scan(config)
      crawl(
          seed=config.target,
          allowed_origins=config.allowed_origins,
          policy=config.policy,
          resolver=config.resolver,
          request_limits=config.request_limits,
          max_redirects=config.max_redirects,
          limits=config.discovery_limits,
      )
      # Transport re-checks origin, resolves DNS, pins IP, applies
      # body/timeout limits and redirect admission on every hop.

3. For each yielded DiscoveredPage, while the page (and body) is in scope:
      findings = scan_page(page)
      if no findings: drop the page; do not hash the body
      else:
          response = capture_response_evidence(
              page.response,
              requested_target=page.target,
          )
          for finding in findings:
              FindingEvidence(finding=finding, response=response)
      drop the DiscoveredPage / TransportResponse

4. Return ScanResult(findings=tuple_in_stream_order)
```

This is the loop ADR 0005 accepted. Milestone 7 is the first production
consumer of that loop. The loop lives inside `run_passive_scan`. No helper
that only forwards to `scan_page` or `capture_response_evidence` is added.

### Why `scan_page` and not `scan_pages`

Both functions remain the Passive Scanner public API. This workflow uses
`scan_page` only.

`scan_pages` yields `PassiveFinding` values and suppresses duplicate
fingerprints across pages. By the time a finding is yielded, the response
body needed for a digest is gone. ADR 0005 rejected composing evidence from
that stream: the same finding fingerprint on a different captured projection
is not a duplicate, and `evidence_id` is the later deduplication key.

Using `scan_pages` here would either drop evidence or restate Passive
deduplication. Orchestration therefore iterates `crawl` itself and calls
`scan_page` per page.

The ADR 0004 composition `scan_pages(crawl(...))` remains valid for a
finding-only consumer. It is not the M7 scan.

### What orchestration does not do during the loop

- It does not call `request_as` or attach credentials to `crawl`;
- It does not mark extra frontier URLs, change depth, or raise page budget;
- It does not recover from a failed page and continue;
- It does not accumulate `DiscoveredPage`, headers or bodies;
- It does not suppress by `PassiveFinding.fingerprint` across pages;
- It does not suppress by `evidence_id` (see Result model).

## Result model

Facts are separated from presentation. `ScanResult` is the in-memory fact
object. JSON, SARIF, Markdown, stdout tables and persistence are Milestone 8
consumers of this object, not fields on it.

```python
@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[FindingEvidence, ...]
```

That is the smallest structured result M7 needs:

- success with observations is a tuple of existing `FindingEvidence` values;
- success with a clean target is `ScanResult(findings=())`;
- failure is an exception, not a result with a status field.

Order is deterministic: Discovery page order, then `scan_page` finding
order (static rule tuple, then in-rule `Set-Cookie` field order). Callers
must not sort globally.

Each `FindingEvidence` already carries:

- the `PassiveFinding` (rule id, kind, targets, observation, rationale,
  sanitized evidence, `fingerprint`);
- the `ResponseEvidence` (status, targets, body length, body digest);
- `evidence_id`.

Milestone 8 can serialize those fields without parsing prose. Observation
and rationale remain on the finding for later human reports; they are not
scan-result identity.

### What ScanResult does not contain

- run id, timestamps, duration, hostname, CLI argv;
- `pages_visited`, skipped-candidate lists, or a copy of `ScanConfig`
  (the caller already holds the config; Discovery still does not record
  skipped candidates — ADR 0003 Slice E);
- `DiscoveredPage`, `TransportResponse`, headers, bodies;
- credentials, identities, `AuthorizationObservation`;
- severity, CVSS, confidence, confirmation, remediation;
- report bytes or an output path.

Run metadata is deferred until a concrete serializer needs a fact that is
not already on `ScanConfig` plus `ScanResult.findings`. Tests that need to
prove crawl issued N requests use the existing recording transport fake,
not a new counter on the result.

Duplicate `evidence_id` values may appear when redirect-alias pages share
status, retained-body length and digest (ADR 0005). M7 keeps them, in
stream order. Collapsing them is a reporting choice for M8, keyed on
`evidence_id`, not a second fingerprint system.

## Streaming versus accumulation

Internal execution stays streaming and page-bounded:

- `crawl` remains a lazy async generator and still does not build a
  `DiscoveryResult`;
- one `DiscoveredPage` is processed at a time;
- `capture_response_evidence` runs while `page.response.body` is reachable;
- the page, headers and body are not retained after the page's loop
  iteration;
- no generic finding/page store, cache, queue or database is introduced.

The only accumulation is the list of `FindingEvidence` that becomes
`ScanResult.findings`.

Justification: a later serializer and the CLI completion path need the
finished fact set. `FindingEvidence` holds no response bytes — only a
finding, two targets, two integers and a digest — so the retained set is
bounded by Discovery's `max_pages` and by per-page rule output (six static
rules plus at most one cookie finding per parseable `Set-Cookie` field,
itself bounded by `max_body_bytes`). That is not an unbounded result store.

Memory shape of one successful run is approximately:

    Discovery frontier (already bounded by max_pages)
        + current page body (already bounded by max_body_bytes)
        + O(emitted FindingEvidence)

`scan_pages`'s run-local fingerprint set is not used.

An `AsyncIterator[FindingEvidence]` public API is rejected: it would be
the evidence stream ADR 0005 Slice D deferred, and every current consumer
would immediately accumulate it. `run_passive_scan` returns `ScanResult`.

## Error semantics

Orchestration adds no `ScanError` type and no `try` / `except` around
Scope, Discovery, Transport, Passive or Evidence calls. Failures stay the
exceptions the owning layer already raises.

| Failure | When | Behavior |
| --- | --- | --- |
| `UrlValidationError` | CLI / caller parsing a string | Propagates before `ScanConfig` exists. Not a finding. |
| `ScopeValidationError` (`ORIGIN_NOT_ALLOWED`, …) | `ScanConfig` construction, or later Transport hop | Propagates. Construction failure means no crawl. Hop failure aborts the scan. |
| `ValueError` (`max_redirects`, invalid nested limits, pairing invariants) | Config or programming defect | Propagates. No network if raised from `ScanConfig`. |
| `TransportError` (size, hop limit, loop, invalid redirect, credential code unused here) | A discovery request | Aborts `crawl` and therefore the scan. |
| Resolver / DNS / connection exceptions | A discovery request | Propagate and abort. |
| `UnicodeDecodeError` | Discovery HTML decode after a page was yielded | Existing Discovery contract: the page may already have been composed; the exception still aborts the scan. |
| Passive malformed-header isolation | Inside `scan_page` | Unchanged: unusable fields do not satisfy a rule; they do not abort other rules. |
| Upstream async-iteration errors | `crawl` | Propagate. |
| Evidence `ValueError` | Inconsistent `FindingEvidence` pairing | Programming defect; propagates. |

Incomplete scans do not return `ScanResult`. Findings already appended for
earlier pages are discarded with the stack unwind. That is fail-fast, not
data loss of a defined partial result: Discovery itself has no per-page
recovery (ADR 0003), and converting a mid-crawl `TransportError` into a
successful result with a subset of findings would swallow a scan failure.

Orchestration must not:

- turn `TransportError`, `ScopeValidationError`, `UrlValidationError` or
  resolver failures into `PassiveFinding` / `FindingEvidence`;
- invent an `error` kind, `scan_failed` finding, or synthetic deny;
- continue after a failed page;
- catch `Exception`.

`CROSS_ORIGIN_CREDENTIAL_REDIRECT` cannot occur on this workflow because
`crawl` does not pass credentials. Authorization failures remain M6's
contract and are not remapped here.

## Authorization integration boundary

Milestone 6 already provides the comparison primitives. Milestone 7 does
**not** orchestrate them.

M6 is sufficient to execute one explicit pair when the caller already has:

- an `AuthorizationCase` (target + two identities);
- optional `OriginBoundCredentials` for each identity, bound to that
  target origin;
- the same Scope/Transport limits a scan uses.

M6 is **not** sufficient to put authorization on the product scan surface
without inventing session management. Missing pieces, all explicitly out of
scope here:

- how the operator supplies `Authorization` / `Cookie` values to the CLI;
- login automation, password prompts, vaults, `.netrc`, env-file loaders;
- cookie jars, CSRF continuation, browser sessions;
- a scan profile that enables active pairwise `GET`s by default;
- mapping every discovered URL to an `AuthorizationCase`.

Therefore Slice E is deferred. `scan.py` must not import
`boundary.authorization`. `ScanConfig` / `ScanResult` must not grow identity
or credential fields in M7. `boundary scan` must not accept credential
flags, `--header Authorization`, or cookie files.

### How authorization can later be composed without breaking authorities

A later approved slice may add a **separate** function, not a silent branch
inside `run_passive_scan`, for example a caller-side loop that already
exists in ADR 0006:

```text
for case in caller_supplied_cases:          # never chosen by Discovery or AI
    baseline = await request_as(case.target, case.baseline, credentials=...,
                                allowed_origins=..., policy=..., ...)
    capture_response_evidence(baseline, requested_target=case.target)
    comparison = await request_as(case.target, case.comparison, credentials=...,
                                  ...)
    capture_response_evidence(...)
    compare_response_evidence(...)
    AuthorizationObservation(...)
```

Rules for that future composition, recorded now so M7 does not paint them
over:

1. **Discovery does not choose identities.** `crawl` stays uncredentialed.
   Yielding a `TargetUrl` is not permission to test it as every known user.
2. **Discovery does not choose cases.** Feeding discovered URLs into
   `AuthorizationCase` is a caller/profile decision, not an automatic
   post-crawl step inside `run_passive_scan`.
3. **AI does not choose cases, origins, identities, credentials or
   verdicts.** A future Analyst may explain an observation. It must not
   construct `AuthorizationCase` or `ScanConfig.allowed_origins`.
4. **Credentials stay off generic scan configuration and off results.**
   They remain `OriginBoundCredentials` arguments to `request_as`. They
   never become `ScanConfig` fields, `FindingEvidence` fields,
   `PassiveFinding.evidence`, fingerprints, logs or `repr`s.
5. **Scope stays authoritative.** Authorization still goes through
   `request_with_redirects` with the same allowlist, policy, resolver,
   limits and redirect budget. Orchestration must not call `request_once`
   to “make auth work”.
6. **Observations stay a distinct tuple.** `FindingEvidence` pairs a
   `PassiveFinding` with one projection. `AuthorizationObservation` holds
   two. A future `ScanResult` may grow an `authorization_observations`
   field; it must not reuse `findings` for that purpose (ADR 0006).
7. **Active authorization remains disabled at the product surface** until
   a scan-profile decision. Shipping `request_as` in M6 did not enable it
   on `boundary scan`.

Until credential acquisition exists, inventing CLI flags or a session
object would be a vault in disguise. Deferral is the smaller honest
boundary.

## CLI boundary

`boundary scan` is a thin adapter over `run_passive_scan`.

```text
argv
    -> argparse (cli.py)
    -> parse_target_url / Origin / AddressPolicy / RequestLimits /
       DiscoveryLimits (existing types)
    -> ScanConfig(..., resolver=SystemAddressResolver())
    -> asyncio.run(run_passive_scan(config))
    -> operational completion line
```

`cli.py` may parse, construct values, inject the production resolver, run
the event loop, and print a completion line. It may not crawl, scan pages,
hash bodies, catch transport errors into findings, or format SARIF/JSON
Markdown reports.

### Required arguments

Safety-relevant inputs have no omitted-means-safe CLI default:

- positional `target` — raw URL, parsed with `parse_target_url`;
- `--allow-origin` — repeatable, required at least once, each value parsed
  as a URL whose `.origin` is collected; the seed origin is **not**
  auto-inserted;
- `--address-policy` — required, choices `public` and `local_lab`
  (`AddressPolicy` values);
- `--max-pages` — required integer;
- `--max-depth` — required integer;
- `--max-redirects` — required integer;
- `--max-body-bytes` — required integer.

### Optional arguments that map to an existing contract

- `--connect-timeout`, `--read-timeout`, `--write-timeout`,
  `--pool-timeout` — optional floats. Omission passes `None` into
  `RequestLimits`, which already means “no BOUNDARY-imposed timeout”
  (HTTPCore). This is documented 1:1 mapping, not a hidden numeric default
  and not a scope widening.

No `--timeout` convenience mega-flag is added in M7 (that would be a
second mapping to invent and test). No configuration file, environment
profile, or plugin loader is added.

### Resolver

CLI constructs `SystemAddressResolver()` when building `ScanConfig`. That
choice lives in `cli.py`, not as a `ScanConfig` default. Tests of the
orchestration API inject a fake resolver. CLI tests that only check wiring
may replace `run_passive_scan`; they must not contact public targets.

### Output and exit

- Preserve today’s `boundary` with no arguments: print help, exit 0.
- `boundary scan -h` shows scan flags. No progress bar, spinner, live page
  log, or TTY UI.
- On a returned `ScanResult`, print one operational line to stdout:
  `{n} findings`. That is not a report: no rule table, no rationale, no
  evidence dump, no JSON.
- On argparse errors, argparse’s `SystemExit` stands.
- On scan/config/URL/scope/transport failures, the exception propagates.
  No mapping onto a custom exit-code enum in M7.

Milestone 8 replaces the operational line with a real serializer. It must
consume `ScanResult`, not re-crawl.

### What CLI must not add

- `--json` / `--sarif` / `--markdown` / `--output`;
- `--cookie` / `--header` / `--identity` / `--auth`;
- `--profile bug-bounty`;
- `--concurrency` / `--plugin`;
- interactive login.

## Privacy

M7 introduces no new place that can hold response headers, bodies, or
credential bytes. It reuses `FindingEvidence`, whose fields cannot store
response content (ADR 0005).

Inherited sensitive-data boundary: `TargetUrl` query strings remain visible
on findings, evidence, fingerprints and therefore on `ScanResult`. M7 does
not persist or render those values beyond the operational finding count.
Redaction remains a precondition of Milestone 8 export, not an
orchestration task.

CLI argv may contain a target URL with a query token. Orchestration must
not log argv, headers, or resolver dumps.

## Planned surface

`src/boundary/scan.py` exposes exactly:

- `ScanConfig`
- `ScanResult`
- `run_passive_scan`

`src/boundary/cli.py` gains a `scan` subcommand that constructs `ScanConfig`
and calls `run_passive_scan`. Existing no-argument help remains.

No class, protocol, registry, factory, repository, stream helper, or
authorization entry point.

## Deferred

Explicitly not part of Milestone 7:

- SARIF, JSON, Markdown, HTML reporting and dashboards;
- persistence, databases, evidence directories, JSONL;
- run id, timestamps, `pages_visited`, skipped-candidate evidence;
- `evidence_id` collapsing in the result;
- distributed or concurrent scanning, workers, queues;
- plugin architecture and dynamic rule loading;
- scheduler / cron;
- AI Analyst and agent execution gateway;
- login automation, vault, cookie jar, browser automation;
- mutating active tests and payload-bearing scan profiles;
- Bug Bounty profile;
- custom API-key credential headers;
- User-Agent / scan-profile request headers;
- wiring `request_as` / `AuthorizationCase` into `boundary scan`;
- configuration files and environment-based profiles;
- a `ScanEngine` class.

BOUNDARY remains a modular monolith (ADR 0001). Orchestration is another
internal module, not a service.

## Alternatives considered

**`ScanEngine` / service class.** Rejected: there is no lifecycle or
polymorphic backend. A frozen config plus one async function matches every
delivered engine.

**Compose with `scan_pages(crawl(...))`.** Rejected: ADR 0005. Evidence
needs the page and the findings together; fingerprint suppression across
pages would hide distinct captured projections.

**Public `AsyncIterator[FindingEvidence]`.** Rejected: restates deferred
evidence-stream orchestration; current consumers need a finished tuple.

**Accumulate `DiscoveredPage` then analyze.** Rejected: retains every body
up to `max_pages * max_body_bytes` and breaks the streaming contract
Discovery already implemented.

**Auto-insert `target.origin` into the allowlist.** Rejected: hidden
allowlist mutation. Operators pass `--allow-origin` explicitly, including
the seed origin.

**Default `AddressPolicy.PUBLIC` (or `LOCAL_LAB`) and numeric limits in
CLI.** Rejected: omitted policy or unbounded pages/body/redirects would
weaken safety. Required flags are the smaller contract.

**Put `OriginBoundCredentials` on `ScanConfig` so CLI can “just scan as a
user”.** Rejected: generic configuration would become a secret bag, and
Discovery would still be the wrong place to send those headers. M6 binds
credentials per `request_as` call.

**Auto-run M6 pairs on every discovered URL.** Rejected: Discovery would
choose authorization targets; credentials would have to enter the generic
workflow; active testing would become the default product surface.

**Return partial `ScanResult` on mid-crawl failure.** Rejected: Discovery
and Authorization already fail the unit of work. A successful result with
silent gaps would look like a complete scan.

**JSON to stdout now, “so M8 is easier”.** Rejected: that is reporting.
`ScanResult` is the stable fact object M8 will serialize.

## Consequences

Positive:

- one explicit, testable workflow from target to evidenced findings;
- Scope, Transport, Discovery, Passive, Evidence and Authorization keep
  their contracts;
- scan limits cannot be omitted at the configuration boundary;
- credentials stay out of the generic scan and off the CLI;
- streaming bodies remain bounded; only fixed-size evidence is retained;
- failures remain failures;
- M8 can serialize `ScanResult` without this milestone choosing a format.

Negative:

- operators must pass allowlist, policy and budgets on every CLI
  invocation until a later config/profile decision;
- omitted CLI timeouts still mean `None` (existing Transport contract);
- mid-scan transport failures discard in-memory findings from earlier
  pages;
- authorization remains a library primitive, not a `boundary scan`
  feature;
- query-string tokens on targets remain visible inside findings when M8
  exports them.

## Unresolved questions

None of these block the M7 architecture:

1. **Query strings in targets.** Inherited from Scope / ADR 0004 / 0005 /
   0006. Must be decided before `ScanResult` is persisted or printed as a
   report. M7 only prints a finding count.
2. **Duplicate `evidence_id` collapsing.** M7 keeps stream order. M8 should
   decide whether a report shows genuine redirect-alias duplicates once.
3. **Run metadata for reports.** If M8 needs `pages_visited`, timestamps or
   a run id, add them then, outside finding identity.
4. **Credential acquisition.** Blocks product-surface authorization
   orchestration. Do not invent it inside M7.
5. **Identifying User-Agent.** Still the Discovery deferral. Orchestration
   does not add headers of its own.
