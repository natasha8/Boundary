# ADR 0003: Controlled discovery instead of general crawling

- Status: Accepted; architecture approved, implementation pending (Milestone 3)
- Date: 2026-08-13
- Planned implementation: `src/boundary/discovery.py`
- Depends on: `docs/decisions/0002-controlled-http-transport.md`

## Context

BOUNDARY needs attack-surface discovery: the operator supplies one seed target,
and the scanner must find the reachable application resources that later
milestones will test.

A general-purpose crawler is the wrong tool. Crawlers optimize for coverage and
throughput; BOUNDARY must optimize for staying inside an approved boundary and
producing reproducible results. An uncontrolled crawler would follow arbitrary
page content into arbitrary origins, which is precisely the behavior the Scope
Engine exists to prevent.

Discovery is also the first component whose input is fully attacker-controlled
in the general case: every URL reference comes from a response body. A page can
contain off-origin links, `javascript:` URLs, credential-bearing URLs, control
characters, cycles, and infinite generated link trees.

The two completed milestones already own the safety-critical work:

- the Scope Engine (`src/boundary/scope.py`) provides `parse_target_url`,
  immutable `TargetUrl` / `Origin`, exact origin allowlisting, `AddressPolicy`,
  `resolve_allowed_addresses`, and `resolve_allowed_redirect`;
- the Controlled HTTP Transport (`src/boundary/transport.py`) provides
  `request_with_redirects`, which revalidates origin, re-resolves DNS, validates
  every address, and pins a freshly validated IP on every hop, under mandatory
  response-size limits and timeouts.

Discovery must therefore add traversal only, and must add no second
implementation of any control that already exists.

## Decision

BOUNDARY implements a **deterministic, bounded, scope-gated discovery engine**
in one cohesive module, `src/boundary/discovery.py`, in the same functional
style as `scope.py` and `transport.py`.

### Core security invariant

Discovery never performs network I/O of its own. It produces candidate URLs and
admits them to a frontier only after each one has passed
`parse_target_url` and `require_allowed_origin`, and it issues every request
through `request_with_redirects`.

Discovery must not bypass, reimplement, or weaken:

- `parse_target_url` and `TargetUrl` normalization;
- the exact-origin allowlist;
- `AddressPolicy`;
- `request_with_redirects`;
- per-hop DNS revalidation;
- response-size limits;
- request timeouts.

The pipeline is:

    seed TargetUrl
        -> frontier
        -> request_with_redirects
        -> bounded TransportResponse
        -> extract candidates
        -> resolve candidate URLs
        -> scope validation
        -> deduplicate
        -> frontier

### 1. Deterministic breadth-first traversal

The first implementation is breadth-first, single-flight and sequential: one
FIFO frontier, one outstanding request at a time, no scheduling heuristics, no
priority queue, no randomization. Given the same responses, the traversal order
and the produced set of pages are identical on every run, which is a
prerequisite for reproducible evidence.

### 2. HTTP and HTTPS resources only

Discovery operates only on HTTP/HTTPS resources. This is enforced by reusing
`parse_target_url`, which accepts only `http` and `https`. Discovery does not
define a second scheme list.

### 3. Exact-origin allowlist scope

Scope remains an exact `(scheme, host, port)` allowlist checked through
`require_allowed_origin`. No wildcard domains, no suffix matching, no implicit
subdomain allowance is introduced. A candidate on `api.example.com` is crawled
only if that exact origin is configured, exactly as for redirects.

### 4. The frontier stores normalized `TargetUrl` values

Nothing raw ever enters the frontier. A candidate becomes a frontier entry only
as a normalized `TargetUrl` produced by `parse_target_url`, paired with its
depth. Normalization (lowercased scheme and host, default-port collapsing,
fragment removal) therefore happens once, before the value can be queued.

### 5. Deduplication identity is `TargetUrl.url`

The single identity for duplicate suppression is the normalized
`TargetUrl.url`. This mirrors the redirect-loop detection already used by
`request_with_redirects`, so the crawler and the transport agree on what "the
same URL" means. Discovery does not invent a canonicalization of its own; in
particular it does not reorder query parameters, does not percent-decode, and
does not normalize path segments beyond what `urljoin` and `parse_target_url`
already do.

### 6. Explicit mandatory limits

Discovery configuration is immutable and both limits are mandatory:

- `max_pages` must be greater than zero and caps the total number of pages
  requested;
- `max_depth` must be zero or greater and caps traversal distance from the
  seed, where the seed is depth 0.

`max_depth = 0` is a meaningful configuration: request the seed, extract nothing
into the frontier.

### 7. No unbounded crawling

There is no "crawl until finished" mode. Traversal stops when the frontier is
empty or when `max_pages` requests have been made, whichever comes first. Each
response body is capped by `RequestLimits.max_body_bytes`, so total bytes read
is bounded as well.

Frontier memory is bounded by `max_pages` alone; **no `max_frontier`
configuration is introduced.** Orchestration must never enqueue more targets
than can still be visited within the page budget, so at every point in a crawl:

    visited_count + queued_count <= max_pages

Once the remaining page budget is already represented in the FIFO, additional
valid discovered candidates are not enqueued. Candidate processing remains
deterministic and document-order based, so the first eligible candidates within
the remaining budget win.

The permanent `seen` set therefore records only targets actually admitted to the
frontier, plus final redirect targets registered after successful requests. A
candidate declined because the budget is full is not recorded as seen, because
it was never admitted — `seen` means "admitted", nothing looser.

### 8. Minimal HTML candidate set

The initial extractor considers only explicit navigation and resource URLs that
carry application attack surface:

- `a[href]` — navigable application routes;
- `form[action]` — request-handling endpoints, the highest-value surface for
  later authorization and parameter testing;
- `script[src]` — application JavaScript, which locates further routes and is
  itself worth inspecting;
- `link[href]` — declared related resources, including `rel="manifest"` and
  `rel="alternate"`, which frequently reveal API roots.

Explicitly **not** extracted in the first implementation: `iframe[src]`,
`img[src]`, `source`/`srcset`, `area[href]`, `object[data]`, `meta` refresh
targets, `srcset` candidate lists, CSS `url()` references, and inline JavaScript
string mining. Each of these would widen the request surface without a
demonstrated security-testing need; they are candidates for a later slice once a
fixture shows a concrete gap.

Because discovery is GET-only and never submits forms, a `form[action]` URL is
recorded as a resource to fetch, not as a form to fill. Its declared method is
ignored for extraction purposes: a `GET` to an endpoint that expects `POST` is a
non-mutating probe that still proves the endpoint exists.

### 9. Candidate resolution reuses existing validation

A candidate reference is resolved with standard URL-reference resolution
(`urllib.parse.urljoin`) against the URL the body was actually served from, then
validated by `parse_target_url` and `require_allowed_origin`. This is the same
sequence `resolve_allowed_redirect` already uses for `Location`, so redirect
destinations and page links are subject to identical rules.

Surrounding ASCII whitespace in an HTML URL attribute is stripped before
resolution, matching how HTML URL attributes are read. Whitespace and control
characters *inside* a reference are not stripped and cause rejection: emulating
browser tolerance here would silently repair exactly the malformed input that
`_contains_unsafe_character` is meant to reject.

### 10. Fragments are irrelevant to identity

`TargetUrl` already removes fragments, so `/a#one` and `/a#two` collapse to one
identity and are requested once.

A reference that cannot identify a new resource — empty, or fragment-only such
as `#section` — yields no candidate at all. This mirrors the rule
`resolve_allowed_redirect` already applies to `Location` values, and loses no
surface: such a reference denotes the page currently being processed, which is
already in the frontier.

### 11. Unsupported schemes can never enter the frontier

`javascript:`, `data:`, `mailto:`, `tel:`, `file:` and every other non-HTTP(S)
scheme are rejected because `parse_target_url` allows only `http` and `https`
and raises `UrlErrorCode.UNSUPPORTED_SCHEME`. Discovery deliberately does **not**
maintain its own blocklist of dangerous schemes: a duplicated allow/deny
contract is a place for the two copies to drift apart. The existing allowlist is
the single contract, and it fails closed for schemes nobody has enumerated yet.

### 12. Rejected candidates are skipped, not requested

A candidate that fails resolution or scope validation is skipped and never
requested. Rejection is silent in Milestone 3: it produces no evidence record,
because there is no evidence or reporting channel yet, and inventing one now
would be speculative. Out-of-scope origins in particular are never requested,
not even to observe a status code.

This creates a deliberate asymmetry with the transport layer, which propagates
`UrlValidationError` and `ScopeValidationError`. The distinction is the source
of the input:

- during candidate filtering, rejection is the *expected* outcome for untrusted
  page content — a page containing `mailto:` links or third-party scripts is
  entirely normal, so rejection returns "no candidate" rather than raising;
- at request time, a failure means an *already admitted* target failed a runtime
  control, which is exceptional and propagates unchanged.

### 13-17. No browser, no JavaScript, no state change

Discovery does not execute JavaScript, does not drive a browser, does not submit
forms, does not mutate application state, and uses `GET` only. No request body
is ever sent, and no method other than `GET` is used by the crawler.

Residual risk, stated explicitly: an application that mutates state on `GET`
cannot be protected by any crawler, including this one. Following a link such as
`/logout` or `/items/1/delete` is indistinguishable from following any other
link at the HTTP layer. Mitigation belongs to operator-controlled path exclusion
in a later scan-profile slice, and is deliberately not designed now.

### 18. robots.txt is not an authorization boundary

Milestone 3 does not fetch and does not enforce `robots.txt`.

BOUNDARY operates only against targets the operator owns or is explicitly
authorized to test. Authorization comes from that explicit approval and from the
configured origin allowlist — never from a file served by the target itself.
Treating `Disallow` as a permission boundary would be wrong in two directions:
it would grant no real safety (any target could publish an empty file), and it
would hide exactly the administrative and legacy paths a security test must
inspect. Silently honoring it would also make findings depend on target-supplied
content, breaking reproducibility.

`robots.txt` and `sitemap.xml` remain attractive future *inputs* to discovery:
`Disallow` entries and sitemap URLs are useful path hints. If that is added, it
must be an explicit operator opt-in that treats the file as a source of
candidate URLs — each still passing full scope validation — and never as a
source of permission.

### 19. Standard library only; no new dependency

The first HTML extraction implementation uses only the Python standard library:
`html.parser.HTMLParser` for attribute extraction, `urllib.parse.urljoin` for
reference resolution, and `collections.deque` for the frontier.

`HTMLParser` is sufficient because discovery needs attribute values in document
order, not a spec-conformant DOM tree. It is lenient on malformed markup, and it
is not an XML parser, so external-entity and entity-expansion attacks do not
apply. XML parsers are avoided deliberately for the same reason.

No new dependency is required. Explicitly excluded: Playwright, Selenium and any
browser automation; BeautifulSoup, lxml and other HTML tree libraries; Scrapy or
any crawler framework; JavaScript engines; databases; queues or worker
frameworks; and concurrency of any kind.

### Response base URL: `TransportResponse.final_target`

Correct reference resolution requires the URL the body was served from, which is
not the requested URL when a redirect was followed. `TransportResponse`
currently carries only status, headers and body, so that information is lost.

`TransportResponse` therefore gains a `final_target: TargetUrl` field:
`request_once` sets it to the target it sent, so `request_with_redirects`
naturally reports the final hop. Discovery resolves every reference against
`response.final_target`, never against the originally requested target.

This is an approved, explicitly scoped amendment to the completed transport
module of ADR 0002. It adds no new control and no new failure mode: the reported
value is a `TargetUrl` that already passed origin validation and address
validation on the hop that produced the response. The alternative — resolving
against the requested URL — would silently mis-resolve relative links on every
redirected page (`/docs` versus `/docs/`), producing wrong-but-in-scope requests
and missed surface.

The same field gives the crawler a second correctness property: after a request,
both the requested identity and `response.final_target.url` are registered as
seen, so a redirect destination is never fetched again as a candidate.

### Page identity on `DiscoveredPage`

`DiscoveredPage` distinguishes the two URLs that matter:

- `DiscoveredPage.target` is the `TargetUrl` that discovery dequeued and
  requested;
- `DiscoveredPage.response.final_target` is the normalized final-hop `TargetUrl`
  that actually produced the returned response after redirects.

Discovery must resolve HTML relative references against
`response.final_target`, never against `DiscoveredPage.target` when the two
differ. Redirects do not increase discovery depth: `DiscoveredPage.depth` is the
depth of the dequeued target, however many hops were followed to serve it.

No `requested_target` or `final_target` fields are added to `DiscoveredPage`:
`target` already is the requested identity and `TransportResponse` already
carries the final hop, so duplicating either would create a second source of
truth that can disagree.

### `<base href>` and character encoding

Two deliberate simplifications, both documented as limitations:

- `<base href>` is ignored. Honoring it adds branching (first element wins, only
  when it has an `href`, itself resolved and scope-checked) for no demonstrated
  need. Pages relying on `<base>` will produce mis-resolved candidates that
  remain in scope; this is revisited when a fixture proves it matters.
- HTML bytes are decoded as UTF-8 with `errors="replace"`. Discovery does not
  sniff `<meta charset>` and does not pass a target-supplied charset name to a
  codec lookup, which would let response content select the decoder. URL
  attributes that survive validation are effectively ASCII, and non-ASCII hosts
  are already rejected, so replacement characters in surrounding text cannot
  produce a request that validation would not otherwise reject.

### Concurrency and rate control

Milestone 3 has structural rate control rather than a configured one:
concurrency is 1 by construction and `max_pages` caps total requests, so a
crawl cannot burst. An explicit inter-request delay or token-bucket rate limit
is deferred until concurrency is introduced, at which point it becomes
necessary rather than decorative.

### Planned surface

The discovery module will contain only:

- `DiscoveryLimits` (immutable `max_pages` / `max_depth`);
- `Frontier` and `FrontierItem`;
- `resolve_candidate`;
- `is_html_response` and `extract_html_references`;
- `DiscoveredPage`;
- `crawl`, an async generator yielding pages as they are fetched.

`crawl` streams results instead of accumulating them: nothing is buffered beyond
the current page, and the caller decides what to retain. This keeps discovery
free of storage and reporting responsibilities that belong to later milestones.

## Alternatives considered

**A general crawler framework (Scrapy).** Brings its own scheduler, middleware
stack, duplicate filter and settings system. Every one of those would need to be
constrained back to BOUNDARY's scope rules, and its request path would bypass
the pinned transport entirely, reopening the DNS-rebinding window ADR 0002
closed.

**A headless browser (Playwright/Selenium).** Would find JavaScript-rendered
routes, at the cost of executing untrusted code from the target inside the
scanner, a large binary dependency, non-deterministic timing, and requests
issued by the browser's own network stack — outside scope validation, address
policy and IP pinning. Rejected for the first release; if dynamic discovery is
ever added it must feed candidate URLs through the same validation gate rather
than issue its own requests.

**An HTML tree library (BeautifulSoup/lxml).** Better HTML5 conformance than
`HTMLParser`, but the requirement is "attribute values in document order", which
the standard library already satisfies. It fails the minimal-dependency
principle.

**Depth-first traversal.** Equally deterministic, but reaches deep generated
link chains before covering the seed's immediate surface, which makes a
`max_pages`-truncated crawl far less representative.

## Consequences

Positive:

- every requested URL passed `parse_target_url` and the origin allowlist before
  it entered the frontier, and passed DNS and address validation again at
  request time;
- unsupported schemes and out-of-scope origins cannot be requested, and are
  excluded by the existing single contract rather than a duplicated blocklist;
- traversal is reproducible: same responses, same order, same page set;
- request count, traversal depth, response size, read bytes and frontier size are
  all bounded, the last by `max_pages` rather than by another parameter;
- no browser, no JavaScript execution, no form submission and no state-changing
  method is possible in this design;
- no new dependency; the module stays testable offline with local fixtures.

Negative:

- JavaScript-rendered routes and dynamically constructed URLs are not
  discovered;
- pages using `<base href>` and non-UTF-8 pages may yield mis-resolved
  candidates until those limitations are revisited;
- sequential single-flight crawling is slow against large targets, and no
  connection reuse exists yet, so each page pays a full connect;
- Milestone 3 propagates per-page transport and scope errors rather than
  tolerating them, so one oversized or failing page ends a crawl;
- skipped candidates leave no record, so out-of-scope surface observed during a
  crawl is not reportable yet, and neither are candidates declined because the
  page budget was already full;
- `TransportResponse` gains a required field, so existing transport tests that
  construct it directly must be updated.
