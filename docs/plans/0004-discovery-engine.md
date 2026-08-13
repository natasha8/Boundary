# Discovery Engine Plan

- Status: Planned (Milestone 3)
- Branch: feat/discovery-engine
- Started: 2026-08-13
- Planned implementation: `src/boundary/discovery.py`
- Decision record: `docs/decisions/0003-controlled-discovery.md`

## Purpose

The Discovery Engine finds the reachable application resources of an approved
target so later milestones have an attack surface to test.

It is a bounded, deterministic, scope-gated traversal — not a general crawler.
It performs no network I/O of its own: it produces validated `TargetUrl` values
and delegates every request to `request_with_redirects`.

## Prerequisites

The Scope Engine (`src/boundary/scope.py`) already provides:

- strict HTTP/HTTPS parsing via `parse_target_url`;
- immutable `TargetUrl` / `Origin` value objects with fragments removed;
- exact origin allowlisting via `require_allowed_origin`;
- `PUBLIC` and `LOCAL_LAB` address policies;
- `AddressResolver` and `resolve_allowed_addresses`;
- `resolve_allowed_redirect`.

The Controlled HTTP Transport (`src/boundary/transport.py`) already provides:

- `request_with_redirects`, which revalidates origin, re-resolves DNS, validates
  every returned address and pins a freshly validated IP on every hop;
- `RequestLimits` with a mandatory response-size cap and connect/read/write/pool
  timeouts;
- hop-limit, redirect-loop and malformed-`Location` fail-closed handling.

Discovery adds only traversal. It reimplements none of the above.

## Core security invariant

Every discovered URL passes through the Scope Engine before it can reach the
HTTP Transport:

    seed TargetUrl
        -> frontier
        -> request_with_redirects
        -> bounded TransportResponse
        -> extract candidates
        -> resolve candidate URLs
        -> scope validation
        -> deduplicate
        -> frontier

Discovery must not bypass `parse_target_url` / `TargetUrl` normalization, the
origin allowlist, `AddressPolicy`, `request_with_redirects`, per-hop DNS
revalidation, response-size limits, or request timeouts.

## Architecture

Grow one module, `src/boundary/discovery.py`, in the same style as `scope.py`
and `transport.py`: functions plus small cohesive value objects, no service
layer, no repository, no plugin registry.

Planned surface:

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
    """FIFO frontier that admits each normalized URL identity at most once."""

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

`crawl` is an async generator: it yields each page as it is fetched, so nothing
accumulates beyond the current response and the caller decides what to retain.
Discovery owns no storage, no reporting and no persistence.

## Traversal vocabulary

These three words are defined once here and used with exactly these meanings, so
the crawler cannot request a duplicate.

**discovered** — a reference extracted from a response that survived
`urljoin`, `parse_target_url` and `require_allowed_origin`, and is therefore a
normalized `TargetUrl`. A target can be discovered many times, on many pages.

**queued** — a discovered target whose identity `TargetUrl.url` was not already
present in the frontier's permanent `seen` set, which fits in the remaining page
budget, and which was appended to the FIFO together with its depth. `enqueue`
returns `True` only for this case, and records the identity in `seen` at that
moment. A given identity is queued at most once for the lifetime of the crawl;
`seen` is never pruned.

**visited** — a queued target that was dequeued and for which
`request_with_redirects` was called. Visiting counts against `max_pages`,
whether the request succeeds or fails.

Rules that follow from those definitions:

- `visited` and the pending `queued` entries are disjoint subsets of `seen`,
  which additionally holds final redirect targets registered by `mark_seen`;
- the seed is enqueued first, at depth 0, so it also occupies `seen`;
- a candidate discovered on a page at depth `d` gets depth `d + 1` and is
  enqueued only when `d + 1 <= max_depth`; the redirect hops taken while
  fetching a page do not change that page's depth;
- after a request completes, `response.final_target` is also registered as seen,
  so a redirect destination is never fetched again as a candidate; this
  registration queues nothing and consumes no page budget, because one request
  is one page;
- an identity is therefore requested at most once, and duplicate suppression
  happens at enqueue time rather than at dequeue time.

## Frontier memory bound

There is no `max_frontier` configuration. Frontier memory is bounded by
`max_pages`, because orchestration never enqueues more targets than can still be
visited within the page budget:

    visited_count + queued_count <= max_pages

Once the remaining page budget is already represented in the FIFO, additional
valid discovered candidates are not enqueued. Candidate processing stays
deterministic and document-order based, so the first eligible candidates within
the remaining budget win.

The `seen` set therefore records only targets actually admitted to the frontier,
plus final redirect targets registered after successful requests. A candidate
declined because the budget was full is not recorded as seen: it was never
admitted. That is inert in practice, since `visited_count + queued_count` never
decreases, so a full budget stays full.

## Page identity on `DiscoveredPage`

- `DiscoveredPage.target` is the `TargetUrl` that discovery dequeued and
  requested.
- `DiscoveredPage.response.final_target` is the normalized final-hop `TargetUrl`
  that actually produced the returned response after redirects.
- `DiscoveredPage.depth` is the depth of the dequeued target. Redirects do not
  increase discovery depth, however many hops were followed.

Discovery must resolve HTML relative references against `response.final_target`,
never against `DiscoveredPage.target` when the two differ. No `requested_target`
or `final_target` field is added to `DiscoveredPage`, because `target` already is
the requested identity and `TransportResponse` already carries the final hop.

## Non-goals for the milestone

Discovery will not introduce:

- Playwright, Selenium or any browser automation;
- JavaScript execution;
- BeautifulSoup, lxml or any HTML tree library;
- Scrapy or any crawler framework;
- databases, queues or worker frameworks;
- concurrency, parallel workers or async fan-out;
- a `max_frontier` configuration parameter;
- connection pooling or keep-alive reuse (still deferred by ADR 0002);
- form submission, non-`GET` methods or request bodies;
- `robots.txt` fetching or enforcement;
- active payloads of any kind;
- findings, evidence records, reporting or CLI scan commands;
- wildcard, suffix or subdomain scope matching.

## Testing approach

- Add or update tests before implementing each slice.
- Slices A to C are pure and require no async machinery and no transport.
- Use deterministic local HTML fixtures defined inline in the test modules.
- Inject a fake `AddressResolver` and a scripted `request_once` double for
  Slice D; do not mock the traversal behavior under test.
- Keep the autouse guards used by the transport suites, rejecting
  `socket.getaddrinfo`, `socket.create_connection` and `anyio.connect_tcp`, so a
  discovery test that performs DNS or real socket I/O fails immediately.
- Automated tests must never contact public Internet targets.
- Security controls get negative tests: unsupported schemes, out-of-scope
  origins, credential-bearing URLs, malformed references and limit violations
  must each be proven to be rejected.

## Delivery slices

### Slice A: Discovery limits and frontier identity

Tests: `tests/test_discovery_frontier.py`

Behavior:

- introduce frozen `DiscoveryLimits` with `max_pages` and `max_depth`, validated
  in `__post_init__`, raising `ValueError` like `RequestLimits` does;
- introduce frozen `FrontierItem` pairing a normalized `TargetUrl` with a depth;
- introduce `Frontier`, a small cohesive FIFO over `collections.deque` plus a
  permanent `seen` set of `TargetUrl.url` values;
- `enqueue` returns `True` when the identity is new and was appended, `False`
  when it was already seen;
- `mark_seen` records an identity as seen without queueing it, returning `True`
  when the identity is new; orchestration uses it for `response.final_target`;
- `dequeue` returns items in first-in-first-out order and `None` when empty;
- `__len__` reports pending items, not seen identities.

#### Slice A non-goals

Slice A will not:

- perform HTTP requests or DNS resolution;
- parse HTML;
- resolve or validate candidate URLs;
- accept or apply `DiscoveryLimits`: enforcing `max_depth` and the page-budget
  rule `visited_count + queued_count <= max_pages` is orchestration work in
  Slice D;
- add a Protocol or an alternative frontier implementation;
- add priority, scoring or reordering.

#### Slice A acceptance criteria

- `DiscoveryLimits` is immutable: mutation raises `FrozenInstanceError`;
- `max_pages` of `0` and any negative value raise `ValueError`;
- `max_pages` of `1` is accepted;
- `max_depth` of `0` is accepted and any negative value raises `ValueError`;
- frontier identity is the normalized `TargetUrl.url`, so
  `https://app.test:443/a` and `https://APP.test/a` collapse to one identity, as
  do `/a#one` and `/a#two`;
- distinct query strings are distinct identities, and identical queries in a
  different order are also distinct (no query canonicalization);
- ordering is strict FIFO across interleaved enqueues and dequeues, and is
  unaffected by depth;
- a duplicate `enqueue` returns `False`, does not grow the queue, and does not
  displace or reorder the existing entry;
- re-enqueueing an identity that was already dequeued still returns `False`;
- `mark_seen` adds no pending item, leaves `__len__` unchanged, makes a later
  `enqueue` of that identity return `False`, and returns `False` for an identity
  that was already seen;
- `dequeue` on an empty frontier returns `None`;
- the suite performs zero HTTP requests and zero DNS lookups.

### Slice B: Candidate URL resolution and filtering

Tests: `tests/test_discovery_candidates.py`, plus a Scope Engine regression in
`tests/test_scope.py` that `resolve_allowed_redirect` converts `urljoin` parse
failures into `UrlValidationError` (`MALFORMED_URL`).

Behavior:

- implement `resolve_candidate(base, reference, allowed_origins)`;
- strip only leading and trailing HTML URL-attribute ASCII whitespace
  (`" \t\n\f\r"`) from the extracted reference; do not use unrestricted
  `str.strip()`;
- this HTML preprocessing is not applied to HTTP `Location` values, which
  remain validated raw by `resolve_allowed_redirect`;
- delegate the stripped reference to `resolve_allowed_redirect`, which already
  rejects a reference that cannot identify a new resource — empty or beginning
  with `#` — then resolves with `urljoin`, `parse_target_url` and
  `require_allowed_origin`;
- return the normalized `TargetUrl` on success;
- return `None` for any rejected reference, converting `UrlValidationError` and
  `ScopeValidationError` into "no candidate" rather than propagating them, since
  rejecting untrusted page content is the expected outcome;
- do not catch arbitrary `ValueError`: the Scope Engine wraps `urljoin` parse
  failures such as `http://[::1` as `UrlValidationError` with
  `UrlErrorCode.MALFORMED_URL`;
- never perform a request, a DNS lookup or any I/O.

#### Slice B non-goals

Slice B will not:

- perform HTTP requests or DNS resolution;
- maintain a scheme blocklist duplicating `parse_target_url`;
- record or report skipped candidates;
- honor `<base href>`;
- canonicalize queries, percent-decode, or normalize path segments beyond
  `urljoin`;
- allow wildcard, suffix or subdomain scope matching;
- change HTTP `Location` whitespace or control-character validation;
- catch arbitrary `ValueError` from `resolve_candidate`.

#### Slice B acceptance criteria

Accepted, returning a normalized in-scope `TargetUrl`:

- a path-relative reference (`about.html`, `sub/page`, `../up`);
- a root-relative reference (`/api/v1/items`);
- an absolute same-origin URL;
- a scheme-relative reference (`//app.test/x`) inheriting the base scheme;
- a query-only reference (`?page=2`) resolved against the base path;
- an absolute URL on a different but allowlisted origin, including a distinct
  port and a distinct scheme when those exact origins are configured;
- a reference whose only difference from the base is its fragment, which returns
  the base identity and is therefore suppressed later as a duplicate;
- a reference padded with surrounding HTML URL-attribute ASCII whitespace
  (`"  /api/users  "`, `"\n/api/users\n"`, `"\t/api/users\r\n"`), which is
  stripped before resolution.

Rejected, returning `None`:

- an empty reference and a whitespace-only reference, which denote the page
  being processed and can identify nothing new;
- a fragment-only reference (`#section`);
- every unsupported scheme, covered individually: `javascript:alert(1)`,
  `data:text/html,<x>`, `mailto:a@b.test`, `tel:+100`, `file:///etc/passwd`;
- a credential-bearing URL (`https://u:p@app.test/`);
- a malformed URL, an invalid or empty port, and an ambiguous host;
- a reference containing an internal raw backslash, space, tab, CR, LF or other
  control character (`/api/\nusers`, `/api/\rusers`, `/api/\tusers`), which is
  never stripped away to make the reference usable;
- vertical tab, NBSP or other non-HTML whitespace used as padding, which
  unrestricted `str.strip()` would have removed;
- an absolute URL on a non-allowlisted origin, including an unapproved
  subdomain, an unapproved port and an unapproved scheme;
- every reference when the allowlist is empty.

Also required:

- resolution is deterministic and side-effect free;
- rejection never raises out of `resolve_candidate`;
- the returned value's origin is present in the allowlist for every accepted
  case;
- no request is performed in this slice, proven by the DNS and socket guards.

### Slice C: Minimal HTML link extraction

Tests: `tests/test_discovery_extract.py`

Behavior:

- implement `is_html_response(headers)`, matching the `Content-Type` media type
  case-insensitively against `text/html` and `application/xhtml+xml`, ignoring
  parameters after `;`;
- implement `extract_html_references(body)` over bytes already bounded by
  `RequestLimits.max_body_bytes`, performing no I/O of its own;
- decode with UTF-8 and `errors="replace"`; do not sniff `<meta charset>` and do
  not pass target-supplied codec names to a lookup;
- parse with `html.parser.HTMLParser` and collect attribute values for
  `a[href]`, `form[action]`, `script[src]` and `link[href]`;
- return references in document order, without deduplication, leaving identity
  and duplicate suppression to the frontier.

#### Slice C non-goals

Slice C will not:

- request anything, resolve anything, or validate scope;
- execute JavaScript or evaluate inline event handlers;
- submit forms or read form fields;
- sniff content type when the header is absent;
- honor `<base href>`;
- extract `iframe[src]`, `img[src]`, `source`/`srcset`, `area[href]`,
  `object[data]`, `meta` refresh targets, CSS `url()` values or URLs found in
  inline script text;
- build a DOM or introduce an HTML tree dependency.

#### Slice C acceptance criteria

- `is_html_response` accepts `text/html`, `Text/HTML`,
  `text/html; charset=utf-8` and `application/xhtml+xml`;
- `is_html_response` rejects `application/json`, `text/plain`,
  `application/javascript`, `text/htmlx`, an absent `Content-Type` and an empty
  value, with no content sniffing anywhere;
- all four supported attributes are extracted, and extraction is
  tag-name-case-insensitive and attribute-name-case-insensitive;
- output order is document order, with duplicates preserved;
- a `form` without an `action` produces no reference, while a `form` with
  `action=""` produces one empty reference that Slice B then rejects as a
  self-reference;
- an `a` without an `href` and an `href=""` behave the same way;
- excluded elements produce nothing, proven for at least `iframe[src]`,
  `img[src]` and a `meta` refresh;
- URLs appearing only inside inline `<script>` text are not extracted;
- HTML entities in attribute values are unescaped once (`&amp;` becomes `&`),
  and no double unescaping occurs;
- malformed, truncated and unclosed markup does not raise and still yields the
  references parsed before the damage;
- an empty body and a non-UTF-8 body do not raise;
- extraction is a pure function: the same bytes always yield the same tuple.

### Slice D: Breadth-first crawl orchestration

This slice has two steps. D1 is a small, explicitly approved transport
amendment that D2 depends on.

#### Slice D1: Transport reports the final hop

Implementation: `src/boundary/transport.py`
Tests: `tests/test_transport_request.py`, `tests/test_transport_redirects.py`

Behavior:

- add a required `final_target: TargetUrl` field to `TransportResponse`;
- `request_once` populates it with the target it sent, so
  `request_with_redirects` reports the final hop with no extra plumbing;
- update the existing transport tests that construct `TransportResponse`
  directly.

Acceptance criteria:

- a non-redirected request reports `final_target` equal to the requested
  normalized target;
- a followed redirect chain reports `final_target` equal to the last hop's
  target, not the originally requested one;
- a 3xx response that is returned rather than followed (no `Location`) reports
  the target that produced it;
- `TransportResponse` remains frozen and slotted;
- no other transport behavior changes: pinning, limits, timeouts, hop limits and
  loop detection keep their existing tests passing.

#### Slice D2: Breadth-first crawl

Tests: `tests/test_discovery_crawl.py`

Behavior:

- implement `crawl` as an async generator over a single `Frontier`;
- enqueue the seed at depth 0, then loop while the frontier is non-empty and
  fewer than `max_pages` pages have been requested;
- request every page through `request_with_redirects`, passing the caller's
  `allowed_origins`, `policy`, `resolver`, `request_limits` and `max_redirects`;
- use `GET` only, with no request body and no crawler-supplied headers;
- yield `DiscoveredPage(target, depth, response)` for each requested page;
- register `response.final_target` through `mark_seen`, so a redirect
  destination is never queued later;
- when `is_html_response(response.headers)` holds, extract references from
  `response.body`, resolve each against `response.final_target`, and enqueue
  every accepted candidate at `depth + 1` when that does not exceed
  `max_depth`;
- decline further enqueues once `visited_count + queued_count` has reached
  `max_pages`, so the frontier never holds more than the remaining page budget;
- process candidates in extraction order so traversal order is deterministic and
  the first eligible candidates within the remaining budget win;
- let transport and scope errors propagate; Milestone 3 adds no per-page error
  recovery.

#### Slice D2 non-goals

Slice D2 will not:

- call `request_once` directly;
- call HTTPCore directly or construct a network backend;
- implement its own redirect following, DNS resolution, timeout or size limit;
- add concurrency, delays, retries or backoff;
- record skipped candidates;
- swallow `TransportError`, `UrlValidationError` or `ScopeValidationError`
  raised while requesting an already admitted target.

#### Slice D2 acceptance criteria

- the seed is requested first, at depth 0, and is yielded before its candidates;
- traversal is breadth-first: with a seed linking to `/a` and `/b`, where `/a`
  links to `/a1`, the yield order is seed, `/a`, `/b`, `/a1`;
- depth is tracked per page and candidates receive parent depth plus one;
- `max_depth = 0` requests only the seed even though it links elsewhere;
- `max_depth = 1` requests the seed and its direct links only;
- `max_pages` stops the crawl exactly at the cap, with the remaining frontier
  entries left unrequested, proven by counting requests;
- `max_pages = 1` requests only the seed;
- `visited_count + queued_count` never exceeds `max_pages`: a page linking to
  more in-scope candidates than the remaining budget enqueues only the first
  eligible ones in document order, and the frontier is empty once the last page
  has been visited;
- no `max_frontier` parameter exists, and `DiscoveryLimits` still carries exactly
  `max_pages` and `max_depth`;
- a page linking to itself, a two-page cycle and a repeated link across
  different pages each cause exactly one request per identity;
- a URL reached both directly and as a redirect destination is requested once,
  proven through `final_target` registration;
- relative references on a redirected page resolve against
  `response.final_target`, not against `DiscoveredPage.target`, and a redirected
  page keeps the depth of the dequeued target;
- non-HTML responses are yielded but contribute no candidates;
- out-of-scope and unsupported-scheme references are never requested, proven by
  asserting the exact set of requested URLs;
- every request goes through `request_with_redirects`: the injected
  `AddressResolver` is called at least once per requested page, proving the
  revalidating path ran, and the discovery module neither imports nor references
  `request_once` or `httpcore`;
- `request_limits` and `max_redirects` are forwarded unchanged to every request;
- every request uses method `GET` and carries no body;
- a `TransportError` such as `RESPONSE_TOO_LARGE` and a `ScopeValidationError`
  raised at request time propagate out of `crawl`;
- the suite performs no real network I/O, enforced by the DNS and socket guards.

### Slice E: Skipped-candidate evidence

Not implemented in Milestone 3.

There is no evidence, findings or reporting channel yet, so a skipped-candidate
record would have no consumer and would be a speculative module. Milestone 3
therefore keeps `resolve_candidate` returning `None`, and out-of-scope origins
are never requested.

This slice is revisited only when a concrete need appears — for example, a
report section that must state which adjacent origins were observed but
excluded. At that point the record must be a value object produced by the same
resolution path, still without requesting the skipped URL, and must carry the
existing `UrlErrorCode` / `ScopeErrorCode` as the rejection reason rather than a
new parallel enum.

## Security invariants to prove

- no URL is requested unless it passed `parse_target_url` and
  `require_allowed_origin` before entering the frontier;
- every request goes through `request_with_redirects`, so origin, DNS and
  address policy are revalidated on every hop and every connection is pinned to
  a validated IP;
- unsupported schemes cannot enter the frontier, enforced by the single existing
  scheme allowlist;
- out-of-scope origins are never requested, not even to read a status code;
- request count is capped by `max_pages`, traversal by `max_depth`, and each
  response body by `RequestLimits.max_body_bytes`;
- frontier memory is capped by `max_pages` through
  `visited_count + queued_count <= max_pages`, with no extra configuration;
- one identity is requested at most once, with duplicate suppression at enqueue
  time and redirect destinations registered as seen;
- discovery is `GET`-only, sends no request body, executes no JavaScript, drives
  no browser and submits no forms;
- `robots.txt` is neither fetched nor treated as authorization;
- concurrency is 1 by construction;
- tests contact no public Internet target and fail immediately on DNS or real
  socket use.

## Open questions

- Should discovery send a stable identifying `User-Agent` and an `Accept`
  header? Milestone 3 sends no crawler-supplied headers; header policy probably
  belongs to scan profiles.
- Per-page error tolerance: Milestone 3 propagates transport and scope errors,
  so one oversized page ends a crawl. Tolerating and recording per-page failures
  requires the evidence channel that does not exist yet.
- Do `<base href>` support and charset-aware decoding need to be added, and does
  `iframe[src]` belong in the candidate set? All three are deferred until a
  fixture demonstrates missed surface.

## Definition of done for the milestone

- slices A to D meet their acceptance criteria, and Slice E's deferral is
  documented;
- success, failure and boundary cases are tested for each slice;
- security boundaries have negative tests: unsupported schemes, out-of-scope
  origins, credential-bearing URLs, malformed references, and `max_pages` /
  `max_depth` enforcement;
- `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy` and
  `uv run pytest` pass with no skipped or weakened tests;
- no new dependency was added;
- documentation matches the implementation, including every stated limitation;
- automated tests never contact public Internet targets.
