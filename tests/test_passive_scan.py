"""Offline tests for passive scanner page and stream orchestration (Slice D)."""

from __future__ import annotations

import asyncio
import inspect
import socket
from collections.abc import (
    AsyncGenerator,
    AsyncIterable,
    AsyncIterator,
    Collection,
    Sequence,
)
from typing import cast, get_type_hints

import anyio
import pytest

from boundary.discovery import DiscoveredPage
from boundary.passive import (
    PassiveFinding,
    PassiveFindingKind,
    _check_cookie_secure,
    _check_hsts,
    _check_samesite_none_secure,
    scan_page,
    scan_pages,
)
from boundary.scope import parse_target_url
from boundary.transport import TransportResponse

_HSTS_ID = "passive.hsts.not_enforced.v1"
_NOSNIFF_ID = "passive.nosniff.missing_or_invalid.v1"
_CSP_ID = "passive.csp.missing_enforced_policy.v1"
_FRAME_ID = "passive.framing.missing_protection.v1"
_SECURE_ID = "passive.cookie.secure_missing_https.v1"
_SAMESITE_ID = "passive.cookie.samesite_none_without_secure.v1"
_SECRET = "opaque-session-token-9f3a"
_HTTPS_HTML_INSECURE_COOKIE_ORDER = (
    _HSTS_ID,
    _NOSNIFF_ID,
    _CSP_ID,
    _FRAME_ID,
    _SECURE_ID,
    _SAMESITE_ID,
)
_PROTECTED_CSP = b"default-src 'self'; frame-ancestors 'none'"


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("passive orchestration must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if orchestration reaches discovery, transport, DNS, or sockets."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)
    monkeypatch.setattr("boundary.discovery.crawl", _reject_network)
    monkeypatch.setattr("boundary.transport.request_once", _reject_network)
    monkeypatch.setattr("boundary.transport.request_with_redirects", _reject_network)
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.resolve",
        _reject_network,
    )


class _ObservingPages:
    """Async page source that records how many pages were pulled."""

    def __init__(self, pages: Sequence[DiscoveredPage]) -> None:
        self._pages = tuple(pages)
        self.requested = 0

    def __aiter__(self) -> _ObservingPages:
        return self

    async def __anext__(self) -> DiscoveredPage:
        if self.requested >= len(self._pages):
            raise StopAsyncIteration
        page = self._pages[self.requested]
        self.requested += 1
        return page


class _BoomAfterFirst:
    """Yields one page, then raises on the next pull."""

    def __init__(self, page: DiscoveredPage, error: BaseException) -> None:
        self._page = page
        self._error = error
        self.requested = 0

    def __aiter__(self) -> _BoomAfterFirst:
        return self

    async def __anext__(self) -> DiscoveredPage:
        self.requested += 1
        if self.requested == 1:
            return self._page
        raise self._error


def _page(
    *,
    url: str = "https://app.test/",
    requested: str | None = None,
    status: int = 200,
    headers: Collection[tuple[bytes, bytes]] = (),
    body: bytes = b"<html></html>",
    depth: int = 0,
) -> DiscoveredPage:
    final_target = parse_target_url(url)
    requested_target = (
        parse_target_url(requested) if requested is not None else final_target
    )
    return DiscoveredPage(
        target=requested_target,
        depth=depth,
        response=TransportResponse(
            status=status,
            headers=tuple(headers),
            body=body,
            final_target=final_target,
        ),
    )


def _cookie(name: str, *attributes: str) -> bytes:
    pair = f"{name}={_SECRET}"
    if attributes:
        return "; ".join((pair, *attributes)).encode("ascii")
    return pair.encode("ascii")


def _html(*headers: tuple[bytes, bytes]) -> tuple[tuple[bytes, bytes], ...]:
    return ((b"content-type", b"text/html"), *headers)


def _json(*headers: tuple[bytes, bytes]) -> tuple[tuple[bytes, bytes], ...]:
    return ((b"content-type", b"application/json"), *headers)


def _protected_html(
    *headers: tuple[bytes, bytes],
    include_hsts: bool = True,
) -> tuple[tuple[bytes, bytes], ...]:
    fields: list[tuple[bytes, bytes]] = [
        (b"content-type", b"text/html"),
        (b"x-content-type-options", b"nosniff"),
        (b"content-security-policy", _PROTECTED_CSP),
    ]
    if include_hsts:
        fields.insert(1, (b"strict-transport-security", b"max-age=31536000"))
    fields.extend(headers)
    return tuple(fields)


def _insecure_samesite_none_html() -> DiscoveredPage:
    return _page(
        headers=_html((b"set-cookie", _cookie("session", "SameSite=None"))),
    )


def _rule_ids(findings: Sequence[PassiveFinding]) -> tuple[str, ...]:
    return tuple(finding.rule_id for finding in findings)


async def _agen_pages(pages: Sequence[DiscoveredPage]) -> AsyncIterator[DiscoveredPage]:
    for page in pages:
        yield page


def _run_scan_pages(pages: Sequence[DiscoveredPage]) -> list[PassiveFinding]:
    async def collect() -> list[PassiveFinding]:
        return [finding async for finding in scan_pages(_agen_pages(pages))]

    return asyncio.run(collect())


def _take_first_finding(pages: AsyncIterable[DiscoveredPage]) -> PassiveFinding:
    collected: list[PassiveFinding] = []

    async def take_one() -> None:
        stream = scan_pages(pages)
        try:
            collected.append(await stream.__anext__())
        finally:
            await cast(AsyncGenerator[PassiveFinding], stream).aclose()

    asyncio.run(take_one())
    assert collected
    return collected[0]


def _assert_no_secret(finding: PassiveFinding) -> None:
    rendered = " ".join(
        [
            finding.observation,
            finding.rationale,
            *(value for _key, value in finding.evidence),
        ]
    )
    assert _SECRET not in rendered
    assert f"session={_SECRET}" not in rendered


def _assert_no_network_names(function: object) -> None:
    code = getattr(function, "__code__", None)
    assert code is not None
    names = code.co_names
    for forbidden in (
        "crawl",
        "request_once",
        "request_with_redirects",
        "socket",
        "httpcore",
        "getaddrinfo",
        "create_connection",
        "connect_tcp",
        "SystemAddressResolver",
    ):
        assert forbidden not in names


def test_scan_page_returns_a_tuple() -> None:
    findings = scan_page(_insecure_samesite_none_html())

    assert isinstance(findings, tuple)
    assert findings
    assert all(isinstance(finding, PassiveFinding) for finding in findings)


def test_scan_page_returns_empty_tuple_when_no_rule_applies() -> None:
    page = _page(headers=_protected_html())

    findings = scan_page(page)

    assert findings == ()
    assert isinstance(findings, tuple)


def test_scan_page_uses_deterministic_rule_composition_order() -> None:
    page = _insecure_samesite_none_html()

    findings = scan_page(page)

    assert _rule_ids(findings) == _HTTPS_HTML_INSECURE_COOKIE_ORDER
    assert findings[0].kind is PassiveFindingKind.HARDENING
    assert findings[4].kind is PassiveFindingKind.MISCONFIGURATION
    assert findings[5].kind is PassiveFindingKind.MISCONFIGURATION


def test_scan_page_executes_every_existing_rule_exactly_once_per_page() -> None:
    page = _insecure_samesite_none_html()

    findings = scan_page(page)

    assert set(_rule_ids(findings)) == set(_HTTPS_HTML_INSECURE_COOKIE_ORDER)
    assert len(findings) == 6


@pytest.mark.parametrize(
    ("url", "headers", "expected"),
    [
        (
            "https://app.test/",
            _protected_html(include_hsts=False),
            (_HSTS_ID,),
        ),
        (
            "https://app.test/",
            _html(
                (b"strict-transport-security", b"max-age=31536000"),
                (b"content-security-policy", _PROTECTED_CSP),
            ),
            (_NOSNIFF_ID,),
        ),
        (
            "https://app.test/",
            _html(
                (b"strict-transport-security", b"max-age=31536000"),
                (b"x-content-type-options", b"nosniff"),
                (b"x-frame-options", b"DENY"),
            ),
            (_CSP_ID,),
        ),
        (
            "https://app.test/",
            _html(
                (b"strict-transport-security", b"max-age=31536000"),
                (b"x-content-type-options", b"nosniff"),
                (b"content-security-policy", b"default-src 'self'"),
            ),
            (_FRAME_ID,),
        ),
        (
            "https://app.test/",
            _protected_html((b"set-cookie", _cookie("session"))),
            (_SECURE_ID,),
        ),
        (
            "http://app.test/",
            _protected_html(
                (b"set-cookie", _cookie("session", "SameSite=None")),
                include_hsts=False,
            ),
            (_SAMESITE_ID,),
        ),
    ],
    ids=(
        "hsts",
        "nosniff",
        "csp",
        "frame",
        "cookie_secure",
        "cookie_samesite",
    ),
)
def test_each_existing_rule_participates_when_only_that_control_is_missing(
    url: str,
    headers: tuple[tuple[bytes, bytes], ...],
    expected: tuple[str, ...],
) -> None:
    findings = scan_page(_page(url=url, headers=headers))

    assert _rule_ids(findings) == expected


@pytest.mark.parametrize(
    ("url", "headers", "expected"),
    [
        ("http://app.test/", _json(), ()),
        ("https://app.test/", _json(), (_HSTS_ID,)),
        ("http://app.test/", _html(), (_NOSNIFF_ID, _CSP_ID, _FRAME_ID)),
        (
            "https://app.test/",
            _html(),
            (_HSTS_ID, _NOSNIFF_ID, _CSP_ID, _FRAME_ID),
        ),
        (
            "https://app.test/",
            _html((b"server", b"test")),
            (_HSTS_ID, _NOSNIFF_ID, _CSP_ID, _FRAME_ID),
        ),
        ("https://app.test/", _protected_html(), ()),
        (
            "http://app.test/",
            _protected_html(include_hsts=False),
            (),
        ),
        (
            "https://app.test/",
            _json((b"set-cookie", _cookie("session", "SameSite=None"))),
            (_HSTS_ID, _SECURE_ID, _SAMESITE_ID),
        ),
        (
            "http://app.test/",
            _json((b"set-cookie", _cookie("session", "SameSite=None"))),
            (_SAMESITE_ID,),
        ),
        (
            "http://app.test/",
            _json((b"set-cookie", _cookie("session"))),
            (),
        ),
    ],
    ids=(
        "http_non_html",
        "https_non_html",
        "http_html",
        "https_html",
        "https_html_without_set_cookie",
        "https_html_fully_protected",
        "http_html_fully_protected",
        "https_json_insecure_samesite_none",
        "http_json_insecure_samesite_none",
        "http_json_insecure_cookie_without_samesite",
    ),
)
def test_scan_page_applicability_by_scheme_content_type_and_cookies(
    url: str,
    headers: tuple[tuple[bytes, bytes], ...],
    expected: tuple[str, ...],
) -> None:
    findings = scan_page(_page(url=url, headers=headers))

    assert _rule_ids(findings) == expected
    assert isinstance(findings, tuple)


def test_scan_page_collapses_duplicate_cookie_fingerprints_keeping_first() -> None:
    page = _page(
        headers=_json(
            (b"set-cookie", _cookie("session")),
            (b"set-cookie", _cookie("session")),
        ),
    )
    rule_findings = _check_cookie_secure(page)

    findings = scan_page(page)

    assert len(rule_findings) == 2
    assert rule_findings[0].fingerprint == rule_findings[1].fingerprint
    assert _rule_ids(findings) == (_HSTS_ID, _SECURE_ID)
    cookie_findings = [finding for finding in findings if finding.rule_id == _SECURE_ID]
    assert len(cookie_findings) == 1
    assert cookie_findings[0].fingerprint == rule_findings[0].fingerprint
    assert cookie_findings[0].evidence == rule_findings[0].evidence
    assert dict(cookie_findings[0].evidence)["cookie"] == "session"


def test_scan_page_retains_distinct_cookie_names() -> None:
    page = _page(
        headers=_json(
            (b"set-cookie", _cookie("sid")),
            (b"set-cookie", _cookie("tracking")),
        ),
    )

    findings = scan_page(page)
    cookie_findings = [finding for finding in findings if finding.rule_id == _SECURE_ID]

    assert [dict(finding.evidence)["cookie"] for finding in cookie_findings] == [
        "sid",
        "tracking",
    ]
    assert cookie_findings[0].fingerprint != cookie_findings[1].fingerprint


def test_scan_page_does_not_sort_cookie_findings_after_rule_execution() -> None:
    page = _page(
        headers=_json(
            (b"set-cookie", _cookie("zeta")),
            (b"set-cookie", _cookie("alpha")),
        ),
    )

    findings = scan_page(page)
    cookie_names = [
        dict(finding.evidence)["cookie"]
        for finding in findings
        if finding.rule_id == _SECURE_ID
    ]

    assert cookie_names == ["zeta", "alpha"]
    assert cookie_names != sorted(cookie_names)


def test_scan_page_gathers_cookie_rules_sequentially_not_interleaved() -> None:
    page = _page(
        headers=_html(
            (b"set-cookie", _cookie("sid", "SameSite=None")),
            (b"set-cookie", _cookie("tracking", "SameSite=None")),
        ),
    )

    assert _rule_ids(scan_page(page)) == (
        _HSTS_ID,
        _NOSNIFF_ID,
        _CSP_ID,
        _FRAME_ID,
        _SECURE_ID,
        _SECURE_ID,
        _SAMESITE_ID,
        _SAMESITE_ID,
    )
    cookie_names = [
        (finding.rule_id, dict(finding.evidence)["cookie"])
        for finding in scan_page(page)
        if finding.rule_id in {_SECURE_ID, _SAMESITE_ID}
    ]
    assert cookie_names == [
        (_SECURE_ID, "sid"),
        (_SECURE_ID, "tracking"),
        (_SAMESITE_ID, "sid"),
        (_SAMESITE_ID, "tracking"),
    ]


def test_scan_page_retains_both_cookie_rule_identities_for_one_cookie() -> None:
    page = _page(headers=_json((b"set-cookie", _cookie("session", "SameSite=None"))))
    secure = _check_cookie_secure(page)[0]
    samesite = _check_samesite_none_secure(page)[0]

    findings = scan_page(page)

    assert _rule_ids(findings) == (_HSTS_ID, _SECURE_ID, _SAMESITE_ID)
    assert findings[1].fingerprint == secure.fingerprint
    assert findings[2].fingerprint == samesite.fingerprint
    assert findings[1].fingerprint != findings[2].fingerprint


def test_scan_page_does_not_merge_different_rules_with_similar_evidence() -> None:
    page = _page(headers=_html())

    findings = scan_page(page)
    states = [dict(finding.evidence).get("state") for finding in findings]

    assert _rule_ids(findings) == (_HSTS_ID, _NOSNIFF_ID, _CSP_ID, _FRAME_ID)
    assert states.count("missing") >= 2
    fingerprints = [finding.fingerprint for finding in findings]
    assert len(fingerprints) == len(set(fingerprints))


def test_scan_page_preserves_underlying_rule_fingerprints() -> None:
    page = _insecure_samesite_none_html()
    direct_hsts = _check_hsts(page)[0]

    findings = scan_page(page)

    assert findings[0].fingerprint == direct_hsts.fingerprint
    assert findings[0].evidence == direct_hsts.evidence
    assert findings[0].target is page.response.final_target
    assert findings[0].requested_target is page.target


def test_scan_page_preserves_final_and_requested_target_identity() -> None:
    page = _page(
        url="https://app.test/final",
        requested="https://app.test/start",
        headers=_html((b"set-cookie", _cookie("session", "SameSite=None"))),
    )

    findings = scan_page(page)

    assert findings
    for finding in findings:
        assert finding.target is page.response.final_target
        assert finding.requested_target is page.target
        assert finding.target.url == "https://app.test/final"
        assert finding.requested_target.url == "https://app.test/start"
        _assert_no_secret(finding)


def test_scan_page_does_not_mutate_the_discovered_page() -> None:
    headers = _html((b"set-cookie", _cookie("session", "SameSite=None")))
    body = b"<html>unchanged</html>"
    target = parse_target_url("https://app.test/start")
    final_target = parse_target_url("https://app.test/final")
    page = DiscoveredPage(
        target=target,
        depth=2,
        response=TransportResponse(
            status=200,
            headers=headers,
            body=body,
            final_target=final_target,
        ),
    )

    scan_page(page)

    assert page.target is target
    assert page.depth == 2
    assert page.response.headers is headers
    assert page.response.body is body
    assert page.response.final_target is final_target
    assert page.response.status == 200


def test_repeated_scan_page_calls_are_deterministic() -> None:
    page = _insecure_samesite_none_html()

    first = scan_page(page)
    second = scan_page(page)

    assert _rule_ids(first) == _rule_ids(second)
    assert [finding.fingerprint for finding in first] == [
        finding.fingerprint for finding in second
    ]
    assert [finding.evidence for finding in first] == [
        finding.evidence for finding in second
    ]


def test_scan_pages_is_an_async_generator() -> None:
    assert inspect.isasyncgenfunction(scan_pages)
    assert not inspect.iscoroutinefunction(scan_page)
    assert not inspect.isasyncgenfunction(scan_page)
    assert inspect.signature(scan_page).parameters.keys() == {"page"}
    assert inspect.signature(scan_pages).parameters.keys() == {"pages"}


def test_scan_pages_accepts_async_iterable_not_only_async_iterator() -> None:
    hints = get_type_hints(scan_pages)
    pages_type = hints["pages"]
    origin = getattr(pages_type, "__origin__", pages_type)

    assert origin is AsyncIterable
    return_origin = getattr(hints["return"], "__origin__", hints["return"])
    assert return_origin is AsyncIterator


def test_scan_pages_preserves_page_order_then_finding_order() -> None:
    first = _insecure_samesite_none_html()
    second = _page(url="https://app.test/api", headers=_json())

    findings = _run_scan_pages((first, second))

    assert _rule_ids(findings) == _HTTPS_HTML_INSECURE_COOKIE_ORDER + (_HSTS_ID,)
    assert findings[0].target is first.response.final_target
    assert findings[-1].target is second.response.final_target
    assert findings[-1].target.url == "https://app.test/api"


def test_scan_pages_is_lazy_and_does_not_request_the_next_page_early() -> None:
    first = _insecure_samesite_none_html()
    second = _page(url="https://app.test/api", headers=_json())
    source = _ObservingPages((first, second))

    finding = _take_first_finding(source)

    assert source.requested == 1
    assert finding.rule_id == _HSTS_ID
    assert finding.target is first.response.final_target


def test_scan_pages_does_not_eagerly_consume_a_raising_later_page() -> None:
    first = _insecure_samesite_none_html()

    async def source() -> AsyncIterator[DiscoveredPage]:
        yield first
        raise AssertionError("later page consumed too early")

    finding = _take_first_finding(source())

    assert finding.rule_id == _HSTS_ID
    assert finding.target is first.response.final_target


def test_scan_pages_does_not_accumulate_all_pages_before_yielding() -> None:
    first = _page(headers=_protected_html())
    second = _insecure_samesite_none_html()
    third = _page(url="https://app.test/api", headers=_json())
    source = _ObservingPages((first, second, third))

    finding = _take_first_finding(source)

    assert source.requested == 2
    assert finding.rule_id == _HSTS_ID
    assert finding.target is second.response.final_target


def test_scan_pages_suppresses_duplicate_fingerprints_across_pages() -> None:
    """ADR 0004: run-level fingerprint set for the current bounded stream."""
    first = _page(
        url="https://app.test/final",
        requested="https://app.test/a",
        headers=_json(),
    )
    second = _page(
        url="https://app.test/final",
        requested="https://app.test/b",
        headers=_json(),
    )

    findings = _run_scan_pages((first, second))

    assert len(findings) == 1
    assert findings[0].rule_id == _HSTS_ID
    assert findings[0].target is first.response.final_target
    assert findings[0].requested_target is first.target
    assert findings[0].fingerprint == scan_page(second)[0].fingerprint


def test_scan_pages_emits_the_same_rule_on_distinct_final_targets() -> None:
    first = _page(url="https://app.test/a", headers=_json())
    second = _page(url="https://app.test/b", headers=_json())

    findings = _run_scan_pages((first, second))

    assert _rule_ids(findings) == (_HSTS_ID, _HSTS_ID)
    assert findings[0].fingerprint != findings[1].fingerprint
    assert findings[0].target is first.response.final_target
    assert findings[1].target is second.response.final_target


def test_scan_pages_does_not_retain_fingerprint_state_across_invocations() -> None:
    pages = (_page(headers=_json()),)

    first = _run_scan_pages(pages)
    second = _run_scan_pages(pages)

    assert first
    assert _rule_ids(first) == _rule_ids(second)
    assert [finding.fingerprint for finding in first] == [
        finding.fingerprint for finding in second
    ]


def test_scan_pages_empty_source_yields_nothing() -> None:
    assert _run_scan_pages(()) == []


def test_scan_pages_skips_pages_with_no_applicable_findings() -> None:
    empty = _page(headers=_protected_html())
    later = _page(url="https://app.test/api", headers=_json())

    findings = _run_scan_pages((empty, later))

    assert _rule_ids(findings) == (_HSTS_ID,)
    assert findings[0].target is later.response.final_target


def test_scan_pages_propagates_source_exceptions_before_any_page() -> None:
    class UpstreamError(RuntimeError):
        pass

    class Boom:
        def __aiter__(self) -> Boom:
            return self

        async def __anext__(self) -> DiscoveredPage:
            raise UpstreamError("discovery failed")

    async def collect() -> list[PassiveFinding]:
        return [finding async for finding in scan_pages(Boom())]

    with pytest.raises(UpstreamError, match="discovery failed"):
        asyncio.run(collect())


def test_scan_pages_propagates_source_exceptions_after_yielding_a_page() -> None:
    class UpstreamError(RuntimeError):
        pass

    page = _page(headers=_json())
    source = _BoomAfterFirst(page, UpstreamError("discovery failed"))

    async def collect() -> list[PassiveFinding]:
        seen: list[PassiveFinding] = []
        try:
            async for finding in scan_pages(source):
                seen.append(finding)
        except UpstreamError:
            return seen
        raise AssertionError("expected UpstreamError")

    seen = asyncio.run(collect())

    assert _rule_ids(seen) == (_HSTS_ID,)
    assert source.requested == 2


def test_scan_page_propagates_rule_programming_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RuleDefect(RuntimeError):
        pass

    def boom(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
        raise RuleDefect("injected rule failure")

    monkeypatch.setattr("boundary.passive._check_hsts", boom)

    with pytest.raises(RuleDefect, match="injected rule failure"):
        scan_page(_page(headers=_json()))


def test_scan_pages_propagates_rule_programming_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RuleDefect(RuntimeError):
        pass

    def boom(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
        raise RuleDefect("injected rule failure")

    monkeypatch.setattr("boundary.passive._check_hsts", boom)

    async def collect() -> list[PassiveFinding]:
        return [finding async for finding in scan_pages(_agen_pages((_page(),)))]

    with pytest.raises(RuleDefect, match="injected rule failure"):
        asyncio.run(collect())


def test_orchestration_does_not_call_network_or_discovery_entry_points() -> None:
    _assert_no_network_names(scan_page)
    _assert_no_network_names(scan_pages)

    scan_page(_insecure_samesite_none_html())
    _run_scan_pages(
        (
            _insecure_samesite_none_html(),
            _page(url="https://app.test/api", headers=_json()),
        )
    )


def test_public_orchestration_api_exists() -> None:
    import boundary.passive as passive

    assert hasattr(passive, "PassiveFindingKind")
    assert hasattr(passive, "PassiveFinding")
    assert hasattr(passive, "build_passive_finding")
    assert hasattr(passive, "scan_page")
    assert hasattr(passive, "scan_pages")
    assert not hasattr(passive, "Rule")
    assert not hasattr(passive, "RuleEngine")
    assert not hasattr(passive, "RuleProtocol")
    assert not hasattr(passive, "register_rule")
    assert getattr(passive, "__all__", None) is None
