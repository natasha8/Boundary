# BOUNDARY — Security, Correctness, Architecture and Test Audit (post-M1–M8)

- **Date:** 2026-08-19
- **Scope:** Repository implementation after Milestones 1–8
- **Mode:** Read-only. No production code, tests, docs, dependencies, configuration or git history were modified during the audit.
- **Architectural authority:** ADRs, plans, `AGENTS.md` and Cursor rules

## 1. Executive summary

BOUNDARY is in unusually good shape for its stage. All four deterministic gates pass cleanly, the 1521-test suite has no skips, xfails or weakened assertions, and the architectural boundaries described in the ADRs are genuinely enforced in code rather than merely asserted in prose. Scope is the sole admission authority, Transport is the only network execution path, credentials are structurally origin-bound with a redacting `__repr__`, evidence retains hashes rather than bodies, and Reporting builds its JSON and SARIF documents field-by-field with no reflective serialization fallback. I could not find a credential-leak path, a serialization path that emits a raw query string, a hidden retry, or a way to reach the network without passing through Scope.

Two Medium-severity gaps sit in the Scope engine, which is the component that matters most. First, the `PUBLIC` address policy delegates classification to `ipaddress.is_global`, which returns `True` for several IANA special-use IPv6 ranges — most importantly the NAT64 well-known prefix `64:ff9b::/96`, which embeds an arbitrary IPv4 address and, on a network with a NAT64 gateway, reaches it. Plan 0002 explicitly states that `PUBLIC` must reject reserved and special-use ranges, so this is a documented invariant that is not actually enforced. Second, `parse_target_url` validates that the *host* is ASCII but applies no such check to the path or query; `httpcore` then rejects the resulting URL with a bare `TypeError`, aborting the scan. This is reachable from ordinary crawling, and the test suite currently asserts the behavior that feeds it — `tests/test_discovery_html.py:380` asserts that `<a href="/café">` is extracted as a candidate.

One governance issue: `ConnectionReuseKey` and `connection_reuse_key` in `src/boundary/transport.py` are called by nothing in production. They exist only to support connection reuse, which ADR 0002 explicitly defers, and they carry a 250-line test file. That is precisely the speculative-module pattern the project rules forbid.

The most significant test-quality observation is systemic rather than local: roughly 35 assertions across the suite use `inspect.getsource` to grep implementation text (`assert "ValueError" in source`, `assert "indent" not in source`, `assert "plugin" not in source.lower()`). Several of these duplicate behavioral tests that already exist in the same file, and several cannot fail meaningfully — a source-text check for `"asdict" not in source` passes if someone writes `from dataclasses import asdict as _dump`.

**Verdict: READY WITH HARDENING.** No Critical or High findings. The two Medium findings should be closed before BOUNDARY is pointed at anything outside a controlled lab.

## 2. Tool and gate results

| Gate | Version | Result |
|---|---|---|
| `ruff format --check .` | ruff 0.16.1 | 61 files already formatted |
| `ruff check .` | ruff 0.16.1 | All checks passed |
| `mypy` (strict) | mypy 2.3.0 | Success, no issues in 42 source files |
| `pytest` | pytest 9.1.1 | 1521 passed in 14.93s |
| `bandit -r src` | — | Unavailable |
| `pip-audit` | — | Unavailable |

Python is 3.13.14, matching the `requires-python = ">=3.13,<3.14"` pin. Bandit and pip-audit are not in the `dev` dependency group (which contains exactly mypy, pytest and ruff) and are not otherwise resolvable, so they were not installed and are reported as unavailable. Ruff's lint selection is `E4, E7, E9, F, I, UP, B`; bugbear (`B`) is enabled, which is why the broad-except and mutable-default classes of defect are already structurally suppressed.

Every gate is genuinely green rather than green-by-exclusion: mypy runs over `tests` as well as `src`, and pytest uses `--strict-config --strict-markers`. The suite was inspected for suppression markers: no `skip`, `xfail`, or `pytest.ini` filter would hide a failure.

A later combined shell also recorded `1521 passed in 21.22s` with `EXIT_PYTEST=0`, then `No module named bandit` and `No module named pip_audit`. That confirms the unavailable line rather than contradicting the green pytest result.

## 3. Architecture assessment

**Scope holds sole admission authority, and this survived attempts to find a second path.** `require_allowed_origin` is the only origin check, and it is called from `parse`-adjacent code, from `resolve_allowed_redirect`, and from `ScanConfig.__post_init__`. Grepping `src` for `import socket`, `getaddrinfo`, `httpx`, `requests`, `urllib.request` and `aiohttp` returns exactly one hit: `src/boundary/resolver.py:2`, which is the sanctioned resolver. There is no alternate DNS or HTTP path anywhere in the package.

**Transport pinning is effective and does not weaken TLS.** `PinnedAsyncNetworkBackend.connect_tcp` (`transport.py:154-168`) substitutes the prevalidated IP for the host while `connect_unix_socket` raises `NotImplementedError`, closing the UDS escape. Critically, the backend overrides only `connect_tcp`; TLS is still performed by the inner stream via httpcore's `_connect`, which uses `default_ssl_context()` (`ssl.create_default_context()` plus certifi) and passes `server_hostname` = the real origin host. So the TCP connection goes to the pinned IP while certificate validation and SNI use the true hostname — the correct construction. `request_once` passes `retries=0` explicitly (`transport.py:211`), which disables httpcore's exponential-backoff retry loop at `_async/connection.py:159-165`. There are no hidden retries.

**Discovery is genuinely bounded, including its internal state.** `crawl` (`discovery.py:192-235`) checks `visited_count + len(frontier) >= limits.max_pages` before every enqueue, so the frontier queue cannot exceed the page budget. Because `Frontier._seen` is only written by `enqueue` and `mark_seen`, both of which are budget-gated or once-per-fetched-page, the seen-set is bounded at roughly `2 × max_pages` entries rather than growing with link count. The amplification case (a hostile page with a million short hrefs resolving against a long base path) is prevented from reaching memory by the budget check.

**Passive, Evidence, Authorization, Scan and Reporting each stay in their lane.** Passive performs no I/O. Evidence stores SHA-256 digests, not bodies. `Identity` carries no credentials, and `OriginBoundCredentials.__post_init__` (`transport.py:62-82`) enforces an allowlist of header names, rejects duplicates and rejects non-bytes pairs, while `__repr__`/`__str__` emit only `header_count`. `run_passive_scan` (`scan.py:48-71`) is 24 lines that coordinate and nothing more — it re-implements no scope, discovery or rule logic, and it builds `ScanResult` only after the async iterator completes, so an exception mid-crawl produces no partial result. `reporting.py` is never imported by `scan.py` (asserted at `tests/test_reporting_model.py:1063`), keeping the report projection strictly downstream. CLI is a 95-line adapter with a single `asyncio.run` call and deterministic three-way format routing.

**One responsibility leak and one piece of dead authority.** The dead code is BND-03 below. The minor leak is that `crawl` imports `request_with_redirects` inside the function body (`discovery.py:186`) while declaring transport types only under `TYPE_CHECKING`. There is no import cycle to break here — transport imports scope, not discovery — so the deferred import exists for late binding under monkeypatching. It works and is harmless, but it is a test-shaped detail living in production code.

## 4. Confirmed findings, ordered by severity

### BND-01 — `PUBLIC` address policy admits special-use IPv6 ranges, including NAT64

- **Severity:** Medium
- **Confidence:** High (invariant violation), Medium (end-to-end exploitability)
- **Category:** Security — SSRF / scope bypass
- **Location:** `src/boundary/scope.py:345-364`, `_is_address_allowed`

The policy check reduces to a single delegation:

```python
def _is_address_allowed(
    address: IPv4Address | IPv6Address,
    policy: AddressPolicy,
) -> bool:
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return _is_address_allowed(address.ipv4_mapped, policy)

    if address.is_global and not address.is_multicast:
        return True
```

The `ipv4_mapped` unwrap at line 349 correctly handles `::ffff:0:0/96`, and 6to4 is correctly rejected because Python models `sixtofour`. But `is_global` returns `True` for several other special-use ranges. Measured against the actual implementation:

| Address | `PUBLIC` | `LOCAL_LAB` | Range |
|---|---|---|---|
| `64:ff9b::7f00:1` | **ALLOW** | ALLOW | NAT64 well-known prefix (embeds 127.0.0.1) |
| `64:ff9b::c0a8:101` | **ALLOW** | ALLOW | NAT64 (embeds 192.168.1.1) |
| `::ffff:0:7f00:1` | **ALLOW** | ALLOW | IPv4-translated `::ffff:0:0:0/96` |
| `::7f00:1` | **ALLOW** | ALLOW | Deprecated IPv4-compatible `::/96` |
| `fec0::1` | **ALLOW** | ALLOW | Deprecated site-local `fec0::/10` |
| `2001:20::1` | **ALLOW** | ALLOW | ORCHIDv2 |
| `5f00::1` | **ALLOW** | ALLOW | SRv6 SIDs |
| `2002:7f00:1::` | block | block | 6to4 (correctly handled) |
| `::ffff:127.0.0.1` | block | ALLOW | IPv4-mapped (correctly handled) |

**Why it matters to BOUNDARY.** The `PUBLIC` policy exists for exactly one purpose: to guarantee that a scan cannot reach a non-public address. Plan 0002 states this twice — line 94-96 requires `PUBLIC` to reject "reserved/special-use, documentation ranges", and line 250-251 requires `LOCAL_LAB` to reject "other non-lab special-use ranges". Neither is enforced. NAT64 is the materially exploitable case: on a network running an RFC 6146 translator with the RFC 6052 well-known prefix (common in IPv6-only, mobile and some cloud networks), a packet to `64:ff9b::7f00:1` is translated and delivered to `127.0.0.1`. Transport then pins to that address and dials it, so every downstream control is already satisfied.

**Reproducible trigger.** Operator allowlists `https://app.test/` and runs with `--address-policy public`. The AAAA record for `app.test` (attacker-controlled, or a rebinding response) returns `64:ff9b::7f00:1`. `resolve_allowed_addresses` admits it, `request_once` pins to it, and the request lands on loopback via the translator. Directly reproducible today with `require_allowed_address("64:ff9b::7f00:1", AddressPolicy.PUBLIC)`, which returns without raising.

**Existing coverage.** None. `tests/test_scope.py:357-386` parametrizes a `PUBLIC` reject list covering loopback, RFC1918, link-local, unspecified, multicast, documentation ranges and IPv4-mapped, but contains no NAT64, IPv4-translated, IPv4-compatible or site-local case. The `LOCAL_LAB` reject list at lines 407-416 has the same gap.

**Remediation direction.** Add an explicit tuple of denied IPv6 networks (`64:ff9b::/96`, `64:ff9b:1::/48`, `::ffff:0:0:0/96`, `::/96`, `fec0::/10`, `2001:20::/28`, `2001::/32`, `5f00::/16`) and test membership *before* the `is_global` short-circuit, so the deny-list wins under both policies. Keep using only `ipaddress`, consistent with the Slice C constraint.

**Regression test.** Extend both reject parametrizations with the four rows above and assert `ScopeErrorCode.ADDRESS_NOT_ALLOWED`. Add a `resolve_allowed_addresses` case where a fake resolver returns `("64:ff9b::7f00:1",)` for an allowlisted host and assert the scan fails closed before any transport call is recorded.

### BND-02 — Non-ASCII path or query is admitted by Scope and crashes Transport with `TypeError`

- **Severity:** Medium
- **Confidence:** High
- **Category:** Correctness / availability / error-contract violation
- **Location:** `src/boundary/scope.py:167-190` (`parse_target_url`) and `:273-288` (`_extract_host`), surfacing at `src/boundary/transport.py:214-219`

`_extract_host` enforces ASCII on the host and raises `UrlErrorCode.NON_ASCII_HOST`. No equivalent check applies to `path` or `query`, and `_contains_unsafe_character` (`scope.py:395-402`) only rejects backslash, whitespace and C0/DEL — non-ASCII passes. The normalized `TargetUrl.url` therefore carries raw Unicode into `pool.stream(method, target.url, ...)`, and httpcore raises `TypeError: url strings may not include unicode characters.`

**Reproducible trigger, verified end to end.** `extract_html_references` on `<a href="/café">` returns `("/café",)`; `resolve_candidate` admits it and returns a `TargetUrl` whose `url` is `https://app.test/café`; `httpcore.Request("GET", "https://app.test/café")` raises `TypeError`. The same crash occurs for a seed URL supplied directly on the command line.

**Why it matters to BOUNDARY.** This is a target-controlled crash. A scanned page containing one non-ASCII link aborts the entire scan with an untyped `TypeError` instead of a `UrlValidationError`/`TransportError`, so the failure carries no stable error code and no partial report. ADR 0007:526 documents that scan failures propagate to the CLI unhandled, which is deliberate — but that decision assumes the propagating exception is one of BOUNDARY's structured errors. Non-ASCII paths are entirely ordinary on the modern web, so this is a routine availability failure, not an exotic one.

**Existing coverage.** Inverted. `tests/test_discovery_html.py:380-382` asserts `extract_html_references('<p>Привет</p><a href="/café">'.encode()) == ("/café",)`, locking in extraction of the input that later crashes. No test carries a non-ASCII path through `resolve_candidate` into transport. ADR 0003:183 documents that non-UTF-8 *bodies* may fail decode — it says nothing about non-ASCII URLs — and that decode path is properly covered at `tests/test_scan_run.py:1276`.

**Remediation direction.** Choose one contract and apply it in `parse_target_url` before constructing `TargetUrl`: either percent-encode non-ASCII bytes in path and query during normalization (preferred, since it preserves crawl reach and keeps `TargetUrl.url` canonical and ASCII-safe), or reject with a new `UrlErrorCode`. Whichever is chosen, `TargetUrl.url.isascii()` should become an invariant so the transport boundary cannot receive a URL httpcore will refuse.

**Regression test.** Assert the chosen contract directly on `parse_target_url("https://app.test/café?q=café")`; assert `TargetUrl.url.isascii()` for every parse result in the existing parametrizations; and add a crawl test where a stub response body contains `<a href="/café">` and assert the crawl either fetches the encoded form or raises `UrlValidationError` — never `TypeError`.

### BND-03 — `ConnectionReuseKey` and `connection_reuse_key` are unreachable production code

- **Severity:** Low
- **Confidence:** High
- **Category:** Architecture / governance — speculative module
- **Location:** `src/boundary/transport.py:94-114`; tests at `tests/test_transport_reuse.py`

Both symbols are referenced only by `tests/test_transport_reuse.py` (roughly 35 call sites across 250 lines) and by ADR 0002 / plan 0003. No production code path calls them. This is structurally guaranteed: `request_once` constructs a fresh `AsyncConnectionPool` per request with `max_keepalive_connections=0`, so there is no reuse for a reuse key to identify. ADR 0002:152 and plan 0003:303 both state that connection reuse is deferred because the lifecycle machinery "is not justified until" a concrete need exists.

**Why it matters to BOUNDARY.** The governance rules say "Do not generate speculative modules for future features" and "Do not create wrapper functions that add no validation, transformation or behavior." This is both. The concrete cost is that 250 lines of tests contribute to the green-suite signal while exercising no production behavior, which inflates apparent coverage of the transport module. There is no security impact.

**Remediation direction.** Remove both symbols and their test file, and mark the reuse-key design in ADR 0002 as design-only-not-implemented; or, if the key is intended as a committed contract, say so explicitly in the ADR. Do not keep it in the ambiguous current state.

**Regression test.** None required. A cheap guard is a test that walks the public surface of `boundary.transport` and asserts every exported symbol is referenced from at least one other production module.

## 5. Hardening opportunities

**H-01 — `LOCAL_LAB` admits the cloud instance-metadata endpoint.** `_LOCAL_LAB_IPV4_NETWORKS` includes `169.254.0.0/16` (`scope.py:79`), so `169.254.169.254` is allowed under `LOCAL_LAB`. This follows from the documented decision to permit link-local in lab mode, and the origin allowlist still gates reachability, so it is not a finding. But if BOUNDARY is ever run from a cloud VM in lab mode against a host whose DNS resolves to the metadata address, it will fetch IMDS. Carving `169.254.169.254/32` and `169.254.170.2/32` out even under `LOCAL_LAB` costs nothing and removes the most valuable SSRF target from the lab profile.

**H-02 — The default CLI invocation has no timeouts and no wall-clock budget.** `--connect-timeout` and its three siblings are optional (`cli.py:35-38`) and `None` means "no BOUNDARY-imposed timeout". ADR 0007:500-504 documents this as an intentional 1:1 mapping, so it is not drift. However, rule 10 requires timeouts on network operations, and today a slow-loris or never-closing target stalls `crawl` indefinitely with no scan-level deadline. A documented default (or a scan deadline enforced in `run_passive_scan`) would close the gap without adding a mega-flag.

**H-03 — There is no repository-wide network guard for tests.** There is no `conftest.py` anywhere in the repo; each test module installs its own fakes and stubs. That works today, but nothing structurally prevents a future test from opening a real socket, and the rules require that automated tests never contact public Internet targets. A session-scoped autouse fixture that patches `socket.socket` and `loop.getaddrinfo` to raise would make the invariant enforced rather than conventional.

**H-04 — Candidate resolution runs before the page-budget check.** In `crawl` (`discovery.py:223-235`), `resolve_candidate` — which performs a `urljoin` plus a full `parse_target_url` — is invoked for every extracted reference, and only then is `visited_count + len(frontier) >= limits.max_pages` evaluated. On a page with a very large number of links the budget is exhausted almost immediately, yet parsing continues for every remaining reference. Memory stays bounded, so this is CPU only, and it is linear rather than quadratic. Moving the budget check above the resolve call is a two-line change that removes a target-controlled CPU amplifier.

**H-05 — `parse_target_url`'s return value is discarded as a validity probe.** At `discovery.py:94-98` the call exists purely to classify the reference, and the distinction between "relative, so fall through" and "absolute but invalid" rides on `UrlErrorCode.MALFORMED_URL` being the code raised for a missing scheme. That coupling is correct today but implicit; a named helper such as `is_absolute_reference` would make the intent legible without adding an abstraction layer.

## 6. Missing and adversarial test coverage

The suite's behavioral coverage is strong; the gaps are concentrated in adversarial address handling and in the systemic over-use of source-text assertions.

**Highest-value missing tests.** The special-use IPv6 cases from BND-01 are the single most important gap: no test asserts that `64:ff9b::7f00:1`, `::ffff:0:7f00:1`, `::7f00:1` or `fec0::1` are rejected, and adding them today would fail. The adversarial scenario to encode is a DNS answer for an allowlisted host that returns a NAT64-prefixed address, asserted at both the `require_allowed_address` unit level and the `resolve_allowed_addresses` level with a fake resolver, verifying that no transport call is recorded. The second gap is BND-02: no test carries a non-ASCII path from HTML extraction through `resolve_candidate` into a transport call, which is why the `TypeError` survived eight milestones.

A third scenario worth encoding is a multi-answer DNS response where one address is public and one is private under `PUBLIC` policy. `resolve_allowed_addresses` validates every address in the list and raises on the first disallowed one, which is the correct fail-closed behavior, but no test pins it with a mixed answer set — that is exactly the shape a rebinding-adjacent attacker would produce.

**Tests that assert implementation rather than behavior.** There are roughly 35 `inspect.getsource` assertions, concentrated in `test_reporting_sarif.py` (11), `test_reporting_json.py` (8) and `test_scan_run.py` (4). Some encode real architectural invariants worth guarding — "no alternate HTTP client appears in `request_as`" is legitimate. Many do not. Example: `test_renderer_fail_closes_on_schema_before_emitting_a_document` greps source for `"report.schema"`, `"ValueError"` and `"!= 1"`, while the very next test, `test_invalid_schema_fails_before_rendering`, proves the same property behaviorally. Similar cases: `assert "indent" not in source` (already proven by the exact-output equality assertions), `assert ".url" in source and ".value" in source` (near-tautological for any renderer that touches the model), and `assert "plugin" not in source.lower()` / `assert "registry" not in source.lower()` (cannot fail; no plugin system exists or is planned). More importantly, these guards do not enforce what they claim: `assert "asdict" not in source` passes if someone writes `from dataclasses import asdict as _dump`. The behavioral guard in the same file — the forbidden-key check over the parsed output — is the one doing real work. Keep the alternate-client guards, keep one "no reflective serialization" guard per renderer, and retire the rest in favor of the output-equality tests already present.

**What was checked and not found.** No skipped, xfailed or conditionally-disabled tests. No tautological assertions of the `assert x == x` form. No type-impossible comparisons. No test that mocks the component under test — the redirect, credential, discovery and scan suites all stub the layer *below* the unit (`request_once`, the resolver) rather than the unit itself. No evidence of production drifting away from a RED test.

## 7. Dependency findings

The supply-chain posture is the strongest part of the project and there are no findings here. `pyproject.toml` declares exactly one runtime dependency, `httpcore[asyncio]>=1.0.9,<2`, with a correct major-version ceiling and the `asyncio` extra properly declared rather than relying on an ambient `anyio`. The dev group is three tools. The runtime closure in `uv.lock` is anyio 4.14.2, certifi 2026.7.22, h11 0.16.0, idna 3.18 and typing-extensions 4.16.0 — five transitive packages for an HTTP scanner is very lean.

Two points worth recording rather than fixing. h11 is pinned at 0.16.0, which is the version that fixed the leading-whitespace chunked-encoding request-smuggling issue in h11 < 0.16.0; the floor is correct. And certifi is BOUNDARY's actual TLS trust root, reached indirectly through `httpcore/_ssl.py:8` (`context.load_verify_locations(certifi.where())`); it is locked but not declared, which is normal for a transitive, and worth knowing when reasoning about trust-store updates.

No package is imported without being declared or reachable through a declared extra, and no declared package is unused. `.agents/skills` was excluded from consideration; ruff already excludes it via `extend-exclude`.

## 8. Documentation drift

**D-01 (Medium) — Plan 0002 documents a special-use rejection invariant that is not enforced.** Lines 94-96 and 246-251 require `PUBLIC` to reject "reserved/special-use" ranges and `LOCAL_LAB` to reject "other non-lab special-use ranges". Neither holds, as measured in BND-01. This is a documented invariant that is not actually enforced.

**D-02 (Low) — ADR 0006 describes a `request_as` parameter that does not exist.** Lines 264-265 state that "`request_as` rejects any method other than `GET` with `ValueError` before network I/O", and line 557 lists "method other than `GET`" as a test case. The implementation has no `method` parameter at all; it hardcodes `method="GET"` at `authorization.py:70`. Passing `method=` raises `TypeError`, and `tests/test_authorization_request.py:536-559` asserts exactly that. The implementation is *stronger* than the ADR — GET-only by construction beats GET-only by validation — so this is stale prose, not a defect. The ADR should describe the real surface.

**D-03 (Low) — ADR 0002's connection-reuse section reads as implemented contract.** Lines 136-165 describe `ConnectionReuseKey` and `connection_reuse_key` as part of the transport surface while line 152 defers reuse itself. A reader cannot tell that these symbols are unreachable. This is the mirror image of BND-03 and should be resolved with it.

No case of implemented-but-undocumented security behavior was found, no public API mismatch beyond D-02, and no implemented surface still marked incomplete.

## 9. Explicitly reviewed non-issues

These were examined closely and concluded not to be defects, recorded so the reasoning is not repeated.

**TLS verification is not weakened by IP pinning.** Because `PinnedAsyncNetworkBackend` overrides only `connect_tcp`, httpcore still performs `start_tls` on the returned stream with `default_ssl_context()` (`ssl.create_default_context()` + certifi, so `CERT_REQUIRED` and `check_hostname=True`) and `server_hostname` set to the real origin host (`_async/connection.py:140-157`). Certificate and hostname validation therefore run against the intended hostname while the socket goes to the validated IP. This is correct and is the whole point of the design. A probe of `AsyncConnectionPool()._ssl_context` returned `None` because the context is created lazily inside `_connect`; the conclusion comes from reading `httpcore/_ssl.py` and `_async/connection.py`, not from that failed probe.

**No hidden retries.** httpcore has a backoff retry loop at `_async/connection.py:159-165`, but `request_once` passes `retries=0` (`transport.py:211`), so `retries_left <= 0` re-raises immediately on the first `ConnectError`/`ConnectTimeout`.

**Peak memory is one response body, not `max_pages` bodies.** `crawl` is an async generator that yields each `DiscoveredPage` (`discovery.py:211`), and `run_passive_scan` consumes them one at a time without retaining pages (`scan.py:51-70`). Only `FindingEvidence` accumulates, and it holds hashes rather than bodies. Body streaming enforces `max_body_bytes` incrementally during `aiter_stream` (`transport.py:220-229`) rather than after buffering, so an oversized response is aborted mid-stream.

**Unhandled exception propagation from the CLI is intentional.** `cli.py` has no `try`/`except`, so `UrlValidationError`, `ScopeValidationError` and `TransportError` surface as tracebacks. ADR 0007:526 documents this ("the exception propagates. No mapping onto a custom exit-code enum in M7"). It is also fail-closed: no failure path can produce a successful zero-finding scan. Separately, every error message in `scope.py` and `transport.py` is a static string — the only interpolation anywhere is `f"Unsupported URL scheme: {scheme}."` — so no URL, query string, header or credential can leak through an exception message or traceback.

**`<base href>` is ignored, deliberately.** `_HtmlReferenceParser` extracts only `a[href]`, `form[action]`, `script[src]` and `link[href]`. ADR 0003:124, :143 and :183 explicitly decline `<base href>` support and document the mis-resolution consequence. Ignoring it is also the safer choice, since honoring it would let a page redirect crawl resolution wholesale.

**Protocol-relative and `javascript:` references are handled correctly.** `resolve_candidate` returns `None` for `javascript:` (rejected as `UNSUPPORTED_SCHEME`) and for credential-bearing URLs (`EMBEDDED_CREDENTIALS`), while `//evil.test/x` falls through to `urljoin` and is then caught by the origin allowlist. `is_html_response` requires exactly one `Content-Type` header, so a duplicated or non-ASCII content type suppresses extraction rather than being guessed at.

**Frontier growth is bounded.** Covered in the architecture section — the budget check gates every enqueue, so `_seen` and the queue are both bounded by the page budget rather than by link count.

**`ipv4_mapped` and 6to4 are already handled.** `::ffff:127.0.0.1` is rejected under `PUBLIC` and `2002:7f00:1::` is rejected under both policies. BND-01 is specifically about the ranges *beyond* these two, which is why it is scoped that way rather than claiming the whole IPv6 path is broken.

## 10. Recommended remediation order

1. BND-01 — the special-use IPv6 deny-list, because it is the only finding that crosses a security boundary.
2. BND-02 — the non-ASCII URL contract, because it is the only finding a target can trigger unintentionally.
3. D-01 and D-02 — reconcile plan 0002 and ADR 0006 with the code, immediately after the fixes that make plan 0002 true.
4. BND-03 with D-03 — delete the dead reuse-key surface and its ADR ambiguity together.
5. H-01 through H-05 — opportunistically, in that order.

---

## AUDIT VERDICT: READY WITH HARDENING

- All four gates pass on a suite of 1521 tests with zero skips, xfails or weakened assertions, and mypy runs strict over both `src` and `tests`.
- The architectural boundaries the ADRs claim are actually enforced: Scope is the only admission authority, `resolver.py:2` is the only `socket` import in `src`, credentials are structurally origin-bound with a redacting repr, and Reporting has no reflective-serialization fallback.
- No Critical or High finding. A credential leak, a raw-query-string emission, a network call bypassing Transport, or a partial result on failure could not be constructed.
- Two Medium findings sit in the highest-value component: `PUBLIC` admits NAT64 and four other special-use IPv6 ranges in violation of plan 0002, and Scope emits URLs that Transport cannot execute, turning an ordinary non-ASCII link into an untyped scan crash.
- Neither Medium is reachable in a controlled lab against fixtures, which is why this is hardening rather than remediation-required — but BND-01 should be closed before BOUNDARY is aimed at any target whose DNS the operator does not control.
- One governance cleanup: `ConnectionReuseKey` is speculative surface for an explicitly deferred feature, and its 250-line test file inflates the transport module's apparent coverage.

---

## REMEDIATION PLAN

Four independent, test-first slices. No slice depends on another, so they can be sequenced or parallelized freely.

**Slice 1 — Special-use IPv6 deny-list (BND-01, D-01)**

Evidence is the measured allow/block table above, reproduced by calling `require_allowed_address("64:ff9b::7f00:1", AddressPolicy.PUBLIC)` and observing that it returns rather than raising. Write the RED regression first: extend the `PUBLIC` and `LOCAL_LAB` reject parametrizations in `tests/test_scope.py` with `64:ff9b::7f00:1`, `::ffff:0:7f00:1`, `::7f00:1` and `fec0::1`, plus a `resolve_allowed_addresses` case where a fake resolver returns a NAT64 address for an allowlisted host and no transport call is recorded. The minimal fix is a module-level tuple of denied IPv6 networks tested before the `is_global` short-circuit in `_is_address_allowed`, using only `ipaddress`. Run `pytest tests/test_scope.py tests/test_resolver_scope.py`, then correct plan 0002 lines 94-96 and 246-251 to describe what is now enforced, then the full gate set, then commit.

**Slice 2 — ASCII-safe `TargetUrl` (BND-02)**

Evidence is the verified chain: `extract_html_references` yields `/café`, `resolve_candidate` admits it, `httpcore.Request` raises `TypeError`. The RED test asserts the chosen contract on `parse_target_url("https://app.test/café?q=café")` and adds a crawl-level test with `<a href="/café">` in a stub body asserting that no `TypeError` escapes. Decide the contract first — percent-encoding in normalization is preferred over rejection, since rejection silently shrinks crawl reach. The minimal fix encodes non-ASCII bytes in path and query inside `parse_target_url` before constructing `TargetUrl`, and adds `TargetUrl.url.isascii()` as an asserted invariant. Note that `tests/test_discovery_html.py:380-382` currently asserts the raw `/café` extraction; that assertion describes HTML extraction, which is a separate layer and should stay as-is — the encoding belongs in `parse_target_url`, not in the parser. Run `pytest tests/test_scope.py tests/test_discovery_crawl.py tests/test_transport_request.py`, then full gates, then commit.

**Slice 3 — Remove the dead reuse-key surface (BND-03, D-03)**

Evidence is the reference search showing `connection_reuse_key` reachable only from tests and docs. There is no RED test here because the change removes behavior rather than adding it; the guard is that the suite must stay green after deleting `transport.py:94-114` and `tests/test_transport_reuse.py`. Optionally add a small dead-public-symbol check over `boundary.transport`. Update ADR 0002 lines 136-165 to mark the reuse-key design as not implemented. Run the full gates and commit.

**Slice 4 — Documentation reconciliation (D-02) and elective hardening**

Correct ADR 0006 lines 264-265 and 557 to describe `request_as` as GET-only by construction with no `method` parameter, matching `authorization.py:70` and the existing `TypeError` test. Then, if the hardening items are taken, each is independently small: the IMDS carve-out (H-01) reuses the Slice 1 deny-list mechanism and needs one reject test per address; the timeout default or scan deadline (H-02) needs a test proving a stalled read terminates; the session-wide network guard (H-03) is a new `conftest.py` with an autouse fixture and a self-test proving it raises. Full gates and a separate commit per item.
