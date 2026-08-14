# ADR 0003: Controlled discovery instead of general crawling

- Status: Accepted and implemented (Milestone 3)
- Date: 2026-08-13
- Implemented: 2026-08-14
- Implementation: `src/boundary/discovery.py`
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

The completed Scope Engine and Controlled HTTP Transport already own the
safety-critical work. Discovery therefore adds traversal only, and adds no
second implementation of any control that already exists.

## Decision

BOUNDARY implements a **deterministic, bounded, scope-gated discovery engine**
in one cohesive module, `src/boundary/discovery.py`, in the same functional
style as `scope.py` and `transport.py`. The sections below describe the
delivered behavior.

### Core security invariant

Discovery never performs network I/O of its own. It produces candidate URLs and
admits them to a frontier only after each one has passed Scope Engine
validation, and it issues every page request through `request_with_redirects`.

Discovery does not bypass, reimplement, or weaken:

- `parse_target_url` and `TargetUrl` normalization;
- the exact-origin allowlist;
- `AddressPolicy`;
- `request_with_redirects`;
- per-hop DNS revalidation, address validation and IP pinning;
- response-size limits and request timeouts.

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

### Delivered architecture

- `DiscoveryLimits` is immutable and mandatory: `max_pages > 0`,
  `max_depth >= 0`.
- `Frontier` is a deterministic FIFO over normalized `TargetUrl` values.
- Discovery identity is permanent `TargetUrl.url`; duplicate suppression happens
  at enqueue time.
- `mark_seen` registers redirect final targets without queueing them and without
  consuming page budget.
- There is no separate `max_frontier` configuration. Orchestration maintains:

      visited_count + queued_count <= max_pages

  The first valid candidates in document order win the remaining budget slots.
  A candidate declined only because the budget is full is not marked seen.
- `crawl` is an async generator. It yields each successful page and does not
  accumulate results into a `DiscoveryResult` or any other buffer.
- `DiscoveredPage.target` is the dequeued/requested Discovery target.
- `TransportResponse.final_target` is the actual final hop after redirects.
- Redirects do not increase Discovery depth and do not count as Discovery pages.
- Relative HTML references resolve against `response.final_target`, never against
  `DiscoveredPage.target` when the two differ.
- Every actual page request goes through `request_with_redirects`. Discovery
  never calls `request_once` or HTTPCore directly, and never instantiates
  `SystemAddressResolver`.
- Non-HTML responses are yielded but not expanded. Expansion requires exactly
  one `Content-Type` whose media type is `text/html` (case-insensitive;
  parameters after `;` ignored). `application/xhtml+xml` is not expanded.
- HTML extraction considers exactly `a[href]`, `form[action]`, `script[src]` and
  `link[href]`, in document order, preserving duplicates.
- Extracted HTML attribute references strip only leading/trailing HTML ASCII
  whitespace (`" \t\n\f\r"`) before candidate resolution.
- Candidate validation reuses Scope Engine behavior via `resolve_candidate` /
  `resolve_allowed_redirect`. Exact-origin allowlisting remains authoritative.
- Crawl is `GET` only, with no request body and no crawler-supplied headers.
- No JavaScript execution, browser automation, form submission, concurrency,
  persistent pooling, logging, retries, or evidence / skipped-candidate storage.

### Delivered surface

- `DiscoveryLimits`, `Frontier`, `FrontierItem`
- `resolve_candidate`
- `is_html_response`, `extract_html_references`
- `DiscoveredPage`
- `crawl`

### Page identity and redirects

- `DiscoveredPage.target` — dequeued Discovery request identity.
- `DiscoveredPage.response.final_target` — normalized final hop that produced
  the response body.
- `DiscoveredPage.depth` — depth of the dequeued target; redirect hops do not
  change it.
- After each successful response, `frontier.mark_seen(response.final_target)`
  prevents the redirect destination from becoming a later Discovery request.

### HTML decoding

HTML bodies are decoded as strict UTF-8. Invalid UTF-8 raises
`UnicodeDecodeError`. Discovery does not sniff `<meta charset>` and does not
honor `<base href>`.

### Error policy

- `TransportError` from page requests propagates and aborts the crawl.
- `UrlValidationError` and `ScopeValidationError` raised while requesting an
  already admitted target propagate and abort the crawl.
- Resolver exceptions propagate and abort the crawl.
- Invalid candidate references are expected untrusted input:
  `resolve_candidate` returns `None` and they are never requested.
- No per-page recovery exists in Milestone 3.

### Intentionally deferred

Not implemented; must not be described as delivered:

- skipped-candidate evidence / reporting (Slice E);
- per-page error tolerance;
- identifying `User-Agent` / scan-profile header policy;
- `<base href>` support;
- charset-aware HTML decoding;
- `iframe[src]` and broader HTML URL extraction;
- JavaScript-generated discovery;
- concurrency;
- persistent connection reuse;
- `robots.txt` as optional discovery input only — never as authorization.
  Milestone 3 neither fetches nor enforces `robots.txt`.

## Alternatives considered

**A general crawler framework (Scrapy).** Would need its scheduler, middleware,
duplicate filter and request path constrained back to BOUNDARY scope and pinned
transport rules. Rejected.

**A headless browser (Playwright/Selenium).** Would find JavaScript-rendered
routes by executing untrusted target code and issuing requests outside Scope and
Transport controls. Rejected for Milestone 3.

**An HTML tree library (BeautifulSoup/lxml).** Unnecessary for document-order
attribute extraction; the standard library `HTMLParser` is sufficient.

**Depth-first traversal.** Deterministic, but reaches deep generated chains
before covering the seed's immediate surface under a `max_pages` budget.

## Consequences

Positive:

- every requested URL passed Scope validation before entering the frontier, and
  DNS / address validation again at request time through Transport;
- unsupported schemes and out-of-scope origins cannot be requested;
- traversal is reproducible: same responses, same order, same page set;
- request count, depth, response size and frontier memory are bounded;
- no browser, JavaScript execution, form submission or non-`GET` crawl method;
- no new dependency; offline-testable with local fixtures.

Negative:

- JavaScript-rendered and dynamically constructed routes are not discovered;
- pages using `<base href>` or non-UTF-8 encoding may mis-resolve or fail decode;
- sequential single-flight crawling is slow; each page still pays a full connect
  because persistent pooling remains deferred by ADR 0002;
- one failing page aborts the crawl;
- skipped or budget-declined candidates leave no evidence record yet.
