"""Offline tests for Passive Scanner to Evidence composition (Slice C)."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import (
    AsyncGenerator,
    AsyncIterable,
    AsyncIterator,
    Collection,
    Sequence,
)
from dataclasses import fields
from typing import cast

import anyio
import pytest

from boundary.discovery import DiscoveredPage
from boundary.evidence import (
    FindingEvidence,
    ResponseEvidence,
    capture_response_evidence,
)
from boundary.passive import scan_page
from boundary.scope import TargetUrl, parse_target_url
from boundary.transport import TransportResponse

_HSTS_ID = "passive.hsts.not_enforced.v1"
_NOSNIFF_ID = "passive.nosniff.missing_or_invalid.v1"
_CSP_ID = "passive.csp.missing_enforced_policy.v1"
_FRAME_ID = "passive.framing.missing_protection.v1"
_SECURE_ID = "passive.cookie.secure_missing_https.v1"
_SAMESITE_ID = "passive.cookie.samesite_none_without_secure.v1"
_HTTPS_HTML_INSECURE_COOKIE_ORDER = (
    _HSTS_ID,
    _NOSNIFF_ID,
    _CSP_ID,
    _FRAME_ID,
    _SECURE_ID,
    _SAMESITE_ID,
)
_PROTECTED_CSP = b"default-src 'self'; frame-ancestors 'none'"
_AUTH_VALUE = "Bearer secret-authorization-token-7f3a"
_SET_COOKIE_VALUE = "session=secret-set-cookie-value-4d88; SameSite=None"
_BODY_TOKEN = "secret-body-bearer-token-c41e"
_BODY_SECRET = f"Bearer {_BODY_TOKEN}".encode("ascii")
_NETWORK_BOUND_NAMES = (
    "socket",
    "httpcore",
    "anyio",
    "crawl",
    "request_once",
    "request_with_redirects",
    "SystemAddressResolver",
    "getaddrinfo",
    "create_connection",
    "connect_tcp",
    "DiscoveredPage",
    "scan_page",
    "scan_pages",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("evidence composition must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if composition reaches network entry points."""
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


def _html(*headers: tuple[bytes, bytes]) -> tuple[tuple[bytes, bytes], ...]:
    return ((b"content-type", b"text/html"), *headers)


def _json(*headers: tuple[bytes, bytes]) -> tuple[tuple[bytes, bytes], ...]:
    return ((b"content-type", b"application/json"), *headers)


def _protected_html() -> tuple[tuple[bytes, bytes], ...]:
    return (
        (b"content-type", b"text/html"),
        (b"strict-transport-security", b"max-age=31536000"),
        (b"x-content-type-options", b"nosniff"),
        (b"content-security-policy", _PROTECTED_CSP),
    )


def _insecure_html(
    *,
    url: str = "https://app.test/",
    requested: str | None = None,
    status: int = 200,
    body: bytes = b"<html></html>",
) -> DiscoveredPage:
    return _page(
        url=url,
        requested=requested,
        status=status,
        headers=_html((b"set-cookie", b"session=ok; SameSite=None")),
        body=body,
    )


def _compose_page(page: DiscoveredPage) -> tuple[FindingEvidence, ...]:
    """Caller-side composition from ADR 0005: one capture per page with findings."""
    findings = scan_page(page)
    if not findings:
        return ()
    response_evidence = capture_response_evidence(
        page.response,
        requested_target=page.target,
    )
    return tuple(
        FindingEvidence(finding=finding, response=response_evidence)
        for finding in findings
    )


async def _compose_stream(
    pages: AsyncIterable[DiscoveredPage],
) -> AsyncIterator[FindingEvidence]:
    async for page in pages:
        for record in _compose_page(page):
            yield record


async def _agen_pages(pages: Sequence[DiscoveredPage]) -> AsyncIterator[DiscoveredPage]:
    for page in pages:
        yield page


def _run_compose(pages: Sequence[DiscoveredPage]) -> list[FindingEvidence]:
    async def collect() -> list[FindingEvidence]:
        return [record async for record in _compose_stream(_agen_pages(pages))]

    return asyncio.run(collect())


def _take_first_record(pages: AsyncIterable[DiscoveredPage]) -> FindingEvidence:
    collected: list[FindingEvidence] = []

    async def take_one() -> None:
        stream = _compose_stream(pages)
        try:
            collected.append(await stream.__anext__())
        finally:
            await cast(AsyncGenerator[FindingEvidence], stream).aclose()

    asyncio.run(take_one())
    assert collected
    return collected[0]


def _rule_ids(records: Sequence[FindingEvidence]) -> tuple[str, ...]:
    return tuple(record.finding.rule_id for record in records)


def _record_surface(record: FindingEvidence) -> str:
    finding = record.finding
    response = record.response
    parts = [
        repr(record),
        repr(finding),
        repr(response),
        record.evidence_id,
        finding.fingerprint,
        finding.rule_id,
        str(finding.kind),
        finding.observation,
        finding.rationale,
        finding.target.url,
        finding.requested_target.url,
        str(response.status),
        response.final_target.url,
        response.requested_target.url,
        str(response.body_length),
        response.body_sha256,
    ]
    for key, value in finding.evidence:
        parts.append(key)
        parts.append(value)
    for model in (record, finding, response):
        for field in fields(model):
            value = getattr(model, field.name)
            parts.append(str(value))
            parts.append(repr(value))
    return "\n".join(parts)


def test_scan_page_findings_compose_with_one_shared_response_evidence() -> None:
    page = _insecure_html()
    findings = scan_page(page)
    assert len(findings) > 1
    assert (
        tuple(finding.rule_id for finding in findings)
        == _HTTPS_HTML_INSECURE_COOKIE_ORDER
    )

    response_evidence = capture_response_evidence(
        page.response,
        requested_target=page.target,
    )
    records = tuple(
        FindingEvidence(finding=finding, response=response_evidence)
        for finding in findings
    )

    assert len(records) == len(findings)
    assert type(response_evidence) is ResponseEvidence
    assert all(type(record) is FindingEvidence for record in records)
    assert all(
        record.finding is finding
        for record, finding in zip(records, findings, strict=True)
    )
    assert all(record.response is response_evidence for record in records)
    assert response_evidence.status == page.response.status
    assert response_evidence.final_target is page.response.final_target
    assert response_evidence.requested_target is page.target
    assert response_evidence.body_length == len(page.response.body)


def test_one_capture_per_page_is_shared_by_every_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[TransportResponse] = []
    original = capture_response_evidence

    def wrapped(
        response: TransportResponse,
        *,
        requested_target: TargetUrl,
    ) -> ResponseEvidence:
        calls.append(response)
        return original(response, requested_target=requested_target)

    monkeypatch.setattr(f"{__name__}.capture_response_evidence", wrapped)

    page = _insecure_html()
    records = _compose_page(page)

    assert len(records) == len(_HTTPS_HTML_INSECURE_COOKIE_ORDER)
    assert len(calls) == 1
    assert calls[0] is page.response
    assert all(record.response is records[0].response for record in records)
    assert records[0].response.body_length == len(page.response.body)


def test_redirect_provenance_is_preserved() -> None:
    page = _insecure_html(
        url="https://app.test/final",
        requested="https://app.test/start",
    )
    assert page.target != page.response.final_target

    records = _compose_page(page)

    assert records
    for record in records:
        assert record.finding.target is page.response.final_target
        assert record.finding.requested_target is page.target
        assert record.response.final_target is page.response.final_target
        assert record.response.requested_target is page.target
        assert record.response.final_target.url == "https://app.test/final"
        assert record.response.requested_target.url == "https://app.test/start"
        assert record.finding.target == record.response.final_target
        assert record.finding.requested_target == record.response.requested_target


def test_distinct_findings_from_one_page_have_distinct_evidence_ids() -> None:
    records = _compose_page(_insecure_html())
    evidence_ids = [record.evidence_id for record in records]

    assert len(records) > 1
    assert len(set(evidence_ids)) == len(evidence_ids)
    assert all(record.response == records[0].response for record in records)
    assert all(record.response is records[0].response for record in records)


def test_same_fingerprint_with_different_status_changes_evidence_id() -> None:
    page = _page(headers=_json(), body=b"same-body")
    finding = scan_page(page)[0]
    first = capture_response_evidence(
        page.response,
        requested_target=page.target,
    )
    altered = TransportResponse(
        status=404,
        headers=page.response.headers,
        body=page.response.body,
        final_target=page.response.final_target,
    )
    second = capture_response_evidence(altered, requested_target=page.target)

    left = FindingEvidence(finding=finding, response=first)
    right = FindingEvidence(finding=finding, response=second)

    assert left.finding.fingerprint == right.finding.fingerprint
    assert left.finding is right.finding
    assert first.status != second.status
    assert left.evidence_id != right.evidence_id


def test_same_fingerprint_with_different_body_length_changes_evidence_id() -> None:
    first_page = _page(headers=_json(), body=b"short")
    second_page = _page(headers=_json(), body=b"longer-body")
    first_finding = scan_page(first_page)[0]
    second_finding = scan_page(second_page)[0]

    assert first_finding.fingerprint == second_finding.fingerprint
    assert len(first_page.response.body) != len(second_page.response.body)

    records = _run_compose((first_page, second_page))

    assert len(records) == 2
    assert records[0].finding.fingerprint == records[1].finding.fingerprint
    assert records[0].response.body_length != records[1].response.body_length
    assert records[0].evidence_id != records[1].evidence_id


def test_same_fingerprint_with_different_body_bytes_changes_evidence_id() -> None:
    first_page = _page(headers=_json(), body=b"one-body")
    second_page = _page(headers=_json(), body=b"two-body")
    first_finding = scan_page(first_page)[0]
    second_finding = scan_page(second_page)[0]

    assert first_finding.fingerprint == second_finding.fingerprint
    assert len(first_page.response.body) == len(second_page.response.body)
    assert first_page.response.body != second_page.response.body

    records = _run_compose((first_page, second_page))

    assert len(records) == 2
    assert records[0].finding.fingerprint == records[1].finding.fingerprint
    assert records[0].response.body_length == records[1].response.body_length
    assert records[0].response.body_sha256 != records[1].response.body_sha256
    assert records[0].evidence_id != records[1].evidence_id


def test_redirect_alias_pages_with_equal_projection_share_evidence_id() -> None:
    """Equal evidence_id values for redirect aliases are genuine duplicates."""
    body = b'{"ok":true}'
    first = _page(
        url="https://app.test/final",
        requested="https://app.test/a",
        headers=_json(),
        body=body,
    )
    second = _page(
        url="https://app.test/final",
        requested="https://app.test/b",
        headers=_json(),
        body=body,
    )
    first_finding = scan_page(first)[0]
    second_finding = scan_page(second)[0]

    assert first.target.url != second.target.url
    assert first.response.final_target.url == second.response.final_target.url
    assert first_finding.fingerprint == second_finding.fingerprint

    records = _run_compose((first, second))

    assert len(records) == 2
    assert records[0].response.status == records[1].response.status
    assert records[0].response.body_length == records[1].response.body_length
    assert records[0].response.body_sha256 == records[1].response.body_sha256
    assert records[0].response.requested_target is first.target
    assert records[1].response.requested_target is second.target
    assert records[0].evidence_id == records[1].evidence_id


def test_zero_finding_page_produces_no_evidence_and_performs_no_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[TransportResponse] = []
    original = capture_response_evidence

    def wrapped(
        response: TransportResponse,
        *,
        requested_target: TargetUrl,
    ) -> ResponseEvidence:
        calls.append(response)
        return original(response, requested_target=requested_target)

    monkeypatch.setattr(f"{__name__}.capture_response_evidence", wrapped)

    page = _page(headers=_protected_html(), body=b"<html>protected</html>")

    assert scan_page(page) == ()
    records = _compose_page(page)

    assert records == ()
    assert calls == []


def test_async_composition_is_lazy_and_does_not_pull_the_next_page() -> None:
    first = _insecure_html()
    second = _page(url="https://app.test/api", headers=_json())
    source = _ObservingPages((first, second))

    record = _take_first_record(source)

    assert source.requested == 1
    assert record.finding.rule_id == _HSTS_ID
    assert record.finding.target is first.response.final_target


def test_async_composition_does_not_pull_ahead_after_a_full_page() -> None:
    first = _insecure_html()
    second = _page(url="https://app.test/api", headers=_json())
    source = _ObservingPages((first, second))
    first_count = len(scan_page(first))

    async def walk() -> tuple[list[FindingEvidence], int, FindingEvidence]:
        stream = _compose_stream(source)
        try:
            first_page_records = [await stream.__anext__() for _ in range(first_count)]
            requested_after_first_page = source.requested
            next_record = await stream.__anext__()
            return first_page_records, requested_after_first_page, next_record
        finally:
            await cast(AsyncGenerator[FindingEvidence], stream).aclose()

    first_page_records, requested_after_first_page, next_record = asyncio.run(walk())

    assert requested_after_first_page == 1
    assert source.requested == 2
    assert _rule_ids(first_page_records) == _HTTPS_HTML_INSECURE_COOKIE_ORDER
    assert next_record.finding.rule_id == _HSTS_ID
    assert next_record.finding.target is second.response.final_target


def test_async_composition_preserves_page_and_scan_page_finding_order() -> None:
    first = _insecure_html()
    second = _page(url="https://app.test/api", headers=_json())
    expected = scan_page(first) + scan_page(second)

    records = _run_compose((first, second))

    assert [record.finding for record in records] == list(expected)
    assert _rule_ids(records) == _HTTPS_HTML_INSECURE_COOKIE_ORDER + (_HSTS_ID,)
    assert records[0].finding.target is first.response.final_target
    assert records[-1].finding.target is second.response.final_target
    assert records[-1].finding.target.url == "https://app.test/api"


def test_async_composition_does_not_accumulate_pages_or_records() -> None:
    empty = _page(headers=_protected_html())
    second = _insecure_html()
    third = _page(url="https://app.test/api", headers=_json())
    source = _ObservingPages((empty, second, third))

    record = _take_first_record(source)

    assert source.requested == 2
    assert record.finding.rule_id == _HSTS_ID
    assert record.finding.target is second.response.final_target
    assert "body" not in {field.name for field in fields(record.response)}


def test_async_composition_propagates_upstream_errors_before_any_page() -> None:
    class UpstreamError(RuntimeError):
        pass

    class Boom:
        def __aiter__(self) -> Boom:
            return self

        async def __anext__(self) -> DiscoveredPage:
            raise UpstreamError("discovery failed")

    async def collect() -> list[FindingEvidence]:
        return [record async for record in _compose_stream(Boom())]

    with pytest.raises(UpstreamError, match="discovery failed"):
        asyncio.run(collect())


def test_async_composition_propagates_upstream_errors_after_yielding() -> None:
    class UpstreamError(RuntimeError):
        pass

    page = _page(headers=_json())
    source = _BoomAfterFirst(page, UpstreamError("discovery failed"))

    async def collect() -> list[FindingEvidence]:
        seen: list[FindingEvidence] = []
        try:
            async for record in _compose_stream(source):
                seen.append(record)
        except UpstreamError:
            return seen
        raise AssertionError("expected UpstreamError")

    seen = asyncio.run(collect())

    assert _rule_ids(seen) == (_HSTS_ID,)
    assert source.requested == 2
    assert seen[0].finding.target is page.response.final_target


def test_response_content_secrets_never_appear() -> None:
    headers = _html(
        (b"authorization", _AUTH_VALUE.encode("ascii")),
        (b"set-cookie", _SET_COOKIE_VALUE.encode("ascii")),
    )
    page = _page(
        url="https://app.test/final",
        requested="https://app.test/start",
        headers=headers,
        body=_BODY_SECRET,
    )
    records = _compose_page(page)
    other = capture_response_evidence(
        TransportResponse(
            status=200,
            headers=(),
            body=b"ok",
            final_target=parse_target_url("https://app.test/other"),
        ),
        requested_target=parse_target_url("https://app.test/other"),
    )

    assert records
    secrets = (
        _AUTH_VALUE,
        _SET_COOKIE_VALUE,
        _BODY_TOKEN,
        "secret-authorization-token-7f3a",
        "secret-set-cookie-value-4d88",
        _BODY_SECRET.decode("ascii"),
    )
    for record in records:
        surface = _record_surface(record)
        lowered = surface.lower()
        for secret in secrets:
            assert secret not in surface
            assert secret.lower() not in lowered
        field_names = {field.name for field in fields(record.response)}
        assert "headers" not in field_names
        assert "body" not in field_names
        assert "raw" not in field_names
        assert "excerpt" not in field_names

    with pytest.raises(ValueError) as caught:
        FindingEvidence(finding=records[0].finding, response=other)

    message = str(caught.value)
    for secret in secrets:
        assert secret not in message
        assert secret.lower() not in message.lower()


def test_composition_does_not_mutate_the_discovered_page() -> None:
    headers = _html((b"set-cookie", b"session=ok; SameSite=None"))
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

    records = _compose_page(page)

    assert records
    assert page.target is target
    assert page.depth == 2
    assert page.response.headers is headers
    assert page.response.body is body
    assert page.response.final_target is final_target
    assert page.response.status == 200
    assert page.response.headers == (
        (b"content-type", b"text/html"),
        (b"set-cookie", b"session=ok; SameSite=None"),
    )
    assert page.response.body == b"<html>unchanged</html>"
    assert target.url == "https://app.test/start"
    assert final_target.url == "https://app.test/final"


def test_composition_completes_under_fail_fast_network_guards() -> None:
    first = _insecure_html(
        url="https://app.test/final",
        requested="https://app.test/start",
    )
    empty = _page(headers=_protected_html())
    later = _page(url="https://app.test/api", headers=_json(), body=b"one-body")

    records = _run_compose((first, empty, later))

    assert _rule_ids(records)[:6] == _HTTPS_HTML_INSECURE_COOKIE_ORDER
    assert records[-1].finding.rule_id == _HSTS_ID
    assert records[0].response.requested_target is first.target
    assert records[-1].finding.target is later.response.final_target


def test_evidence_module_binds_no_network_callables() -> None:
    import boundary.evidence as evidence

    bound = vars(evidence)
    for name in _NETWORK_BOUND_NAMES:
        assert name not in bound

    records = _compose_page(_insecure_html())

    assert records
    assert all(isinstance(record, FindingEvidence) for record in records)


def test_passive_does_not_import_evidence() -> None:
    import boundary.evidence as evidence
    import boundary.passive as passive

    bound = vars(passive)
    assert "evidence" not in bound
    assert evidence not in bound.values()
    for name in ("ResponseEvidence", "FindingEvidence", "capture_response_evidence"):
        assert name not in bound
        assert getattr(passive, name, None) is None
