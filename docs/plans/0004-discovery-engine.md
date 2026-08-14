# Discovery Engine Plan

- Status: Completed
- Branch: feat/discovery-engine
- Started: 2026-08-13
- Completed: 2026-08-14
- Implementation: `src/boundary/discovery.py`
- Decision record: `docs/decisions/0003-controlled-discovery.md`

## Purpose

The Discovery Engine finds the reachable application resources of an approved
target so later milestones have an attack surface to test.

It is a bounded, deterministic, scope-gated traversal — not a general crawler.
It performs no network I/O of its own: it produces validated `TargetUrl` values
and delegates every page request to `request_with_redirects`.

## Prerequisites

The Scope Engine (`src/boundary/scope.py`) provides:

- strict HTTP/HTTPS parsing via `parse_target_url`;
- immutable `TargetUrl` / `Origin` value objects with fragments removed;
- exact origin allowlisting via `require_allowed_origin`;
- `PUBLIC` and `LOCAL_LAB` address policies;
- `AddressResolver` and `resolve_allowed_addresses`;
- `resolve_allowed_redirect`.

The Controlled HTTP Transport (`src/boundary/transport.py`) provides:

- `request_with_redirects`, which revalidates origin, re-resolves DNS, validates
  every returned address and pins a freshly validated IP on every hop;
- `RequestLimits` with a mandatory response-size cap and timeouts;
- hop-limit, redirect-loop and malformed-`Location` fail-closed handling;
- `TransportResponse.final_target` reporting the final hop.

Discovery adds only traversal. It reimplements none of the above.

## Delivered architecture

```python
@dataclass(frozen=True, slots=True)
class DiscoveryLimits:
    max_pages: int  # must be > 0
    max_depth: int  # must be >= 0


@dataclass(frozen=True, slots=True)
class FrontierItem:
    target: TargetUrl
    depth: int


class Frontier:
    def enqueue(self, target: TargetUrl, depth: int) -> bool: ...
    def mark_seen(self, target: TargetUrl) -> bool: ...
    def dequeue(self) -> FrontierItem | None: ...
    def __len__(self) -> int: ...


def resolve_candidate(
    base: TargetUrl,
    reference: str,
    allowed_origins: Collection[Origin],
) -> TargetUrl | None: ...


def is_html_response(headers: Collection[tuple[bytes, bytes]]) -> bool: ...
def extract_html_references(body: bytes) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class DiscoveredPage:
    target: TargetUrl
    depth: int
    response: TransportResponse


async def crawl(
    seed: TargetUrl,
    *,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: AddressResolver,
    request_limits: RequestLimits,
    max_redirects: int,
    limits: DiscoveryLimits,
) -> AsyncIterator[DiscoveredPage]: ...
```

`crawl` yields pages as they are fetched. Discovery owns no storage, reporting
or persistence.

### Traversal vocabulary

- **discovered** — a reference that survived resolution and scope validation.
- **queued** — a discovered target admitted to the FIFO and recorded in `seen`.
- **visited** — a queued target that was dequeued and for which
  `request_with_redirects` was called. Visiting counts against `max_pages`.

Rules:

- identity is permanent `TargetUrl.url`;
- seed is enqueued at depth 0;
- child depth is parent depth + 1; redirect hops do not change depth;
- after each successful response, `response.final_target` is `mark_seen`;
- orchestration keeps `visited_count + queued_count <= max_pages`;
- first valid candidates in document order win remaining budget slots.

## Non-goals for the milestone

Discovery did not introduce:

- browser automation or JavaScript execution;
- HTML tree libraries or crawler frameworks;
- concurrency, workers or async fan-out;
- a `max_frontier` parameter;
- persistent connection pooling;
- form submission, non-`GET` methods or request bodies;
- `robots.txt` fetching or enforcement;
- findings, evidence records, reporting or CLI scan commands;
- wildcard / suffix / subdomain scope matching.

## Delivery slices

### Slice A: Discovery limits and frontier identity — completed

Tests: `tests/test_discovery_frontier.py`

Delivered:

- frozen `DiscoveryLimits` with `max_pages > 0` and `max_depth >= 0`;
- `Frontier` / `FrontierItem` FIFO with permanent `TargetUrl.url` identity;
- `enqueue`, `dequeue`, `mark_seen`, `__len__`;
- enqueue-time duplicate suppression; `mark_seen` records without queueing.

Acceptance criteria met: immutability and limit validation; normalized-URL
identity collapse; strict FIFO; duplicate and `mark_seen` behavior; zero network
I/O in the suite.

### Slice B: Candidate URL resolution and filtering — completed

Tests: `tests/test_discovery_candidates.py`

Delivered:

- `resolve_candidate` strips only HTML ASCII attribute whitespace, then reuses
  Scope Engine redirect/URL validation;
- accepted references return a normalized in-scope `TargetUrl`;
- rejected references return `None` (no raise for expected untrusted input);
- exact-origin allowlisting remains authoritative; no scheme blocklist duplicate.

Acceptance criteria met: path/root/absolute/scheme-relative/query references;
allowlisted cross-origin; unsupported schemes, credentials, malformed and
out-of-scope references rejected; no I/O.

### Slice C: Minimal HTML link extraction — completed

Tests: `tests/test_discovery_html.py`

Delivered:

- `is_html_response` accepts exactly one `Content-Type` whose media type is
  `text/html` (case-insensitive; parameters ignored). It rejects
  `application/xhtml+xml`, non-HTML types, absent/empty/ambiguous headers, and
  performs no content sniffing;
- `extract_html_references` decodes HTML as strict UTF-8 (invalid UTF-8 raises
  `UnicodeDecodeError`);
- extracts `a[href]`, `form[action]`, `script[src]`, `link[href]` in document
  order, preserving duplicates;
- does not honor `<base href>`; does not extract iframe/img/meta-refresh/CSS/
  inline-script URLs.

Acceptance criteria met for the delivered `text/html`-only gate, approved
attributes, excluded sources, entity unescaping once, and pure extraction.

### Slice D1: Transport reports the final hop — completed

Implementation: `src/boundary/transport.py`  
Tests: `tests/test_transport_request.py`, `tests/test_transport_redirects.py`

Delivered:

- required `TransportResponse.final_target: TargetUrl`;
- `request_once` sets it to the hop target it sent;
- `request_with_redirects` therefore reports the final hop.

Acceptance criteria met: non-redirect, followed-redirect and unfollowed-3xx
cases report the correct final hop; transport remains frozen/slotted.

### Slice D2: Breadth-first crawl — completed

Tests: `tests/test_discovery_crawl.py`

Delivered:

- `crawl` as a single-flight async generator over one `Frontier`;
- seed enqueued at depth 0; FIFO processing; `visited_count` increments on
  dequeue immediately before the Discovery request;
- every page requested only through `request_with_redirects` (`GET`);
- yield `DiscoveredPage` before expanding children;
- `mark_seen(response.final_target)` after success;
- expand only when `item.depth < max_depth` and `is_html_response`;
- resolve candidates against `response.final_target`;
- enforce `visited_count + len(frontier) <= max_pages` before enqueue;
- propagate transport, scope and resolver errors with no per-page recovery.

Acceptance criteria met: BFS order; depth tracking; `max_depth` / `max_pages`
bounds; first-candidates-win budget; duplicate suppression; redirect
`final_target` resolution and `mark_seen` suppression; cross-origin allow/deny;
RequestLimits identity and policy/resolver forwarding; offline DNS/socket
guards.

### Slice E: Skipped-candidate evidence — deferred / not implemented

There is no evidence or reporting consumer yet. Milestone 3 keeps
`resolve_candidate` returning `None` for rejected references and does not
record skipped or budget-declined candidates. Revisit only when a concrete
reporting need appears; any future record must reuse existing
`UrlErrorCode` / `ScopeErrorCode` values and must still never request the
skipped URL.

## Final security invariants

- traversal is bounded by mandatory `max_pages` and `max_depth`;
- ordering is deterministic FIFO breadth-first, single-flight;
- duplicate suppression uses permanent normalized `TargetUrl.url` identity;
- exact-origin allowlisting gates every admitted candidate;
- every Discovery page request uses `request_with_redirects` (never
  `request_once` / HTTPCore from discovery);
- redirects report `final_target`, do not increase Discovery depth, and are
  registered via `mark_seen`;
- per-hop DNS resolution, address validation and IP pinning remain Transport /
  Scope responsibilities;
- out-of-scope and unsupported-scheme references are never requested;
- no JavaScript execution, browser automation or form submission;
- `crawl` does not accumulate unbounded page results.

## Test coverage

Offline discovery and related tests, all passing:

- `tests/test_discovery_frontier.py`: 31 tests;
- `tests/test_discovery_candidates.py`: 34 tests;
- `tests/test_discovery_html.py`: 38 tests;
- `tests/test_discovery_crawl.py`: 26 tests.

Full repository suite at closeout: 562 tests collected and passing, with no
skipped tests.

## Definition of done for the milestone

Met:

- slices A–D2 meet their acceptance criteria;
- Slice E deferral is documented;
- success, failure and security-boundary cases are tested;
- `ruff format --check`, `ruff check`, `mypy` and `pytest` pass without skipped
  or weakened tests;
- no new dependency was added;
- documentation matches the implementation, including deferred items;
- automated tests never contact public Internet targets.
