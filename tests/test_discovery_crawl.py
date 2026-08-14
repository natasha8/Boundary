"""Offline tests for deterministic breadth-first discovery orchestration (Slice D2)."""

from __future__ import annotations

import asyncio
import inspect
import socket
from collections.abc import AsyncIterator, Collection, Mapping, Sequence
from dataclasses import FrozenInstanceError, dataclass
from typing import Protocol
from urllib.parse import urljoin

import anyio
import pytest

from boundary.discovery import (
    DiscoveredPage,
    DiscoveryLimits,
    crawl,
    extract_html_references,
    is_html_response,
    resolve_candidate,
)
from boundary.scope import (
    AddressPolicy,
    Origin,
    ScopeErrorCode,
    ScopeValidationError,
    TargetUrl,
    parse_target_url,
)
from boundary.transport import (
    RequestLimits,
    TransportError,
    TransportErrorCode,
    TransportResponse,
)

_APP_IP = "93.184.216.34"
_API_IP = "93.184.216.35"
_PRIVATE_IP = "192.168.1.10"


@dataclass(frozen=True, slots=True)
class RequestOnceCall:
    """One recorded request_once invocation."""

    target: TargetUrl
    pinned_ip: str
    method: str
    headers: tuple[tuple[bytes, bytes], ...]
    limits: RequestLimits


@dataclass(frozen=True, slots=True)
class _ScriptedResponse:
    """Scripted hop body; RecordingRequestOnce attaches the requested target."""

    status: int
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes


class RecordingResolver:
    """Minimal AddressResolver that records calls and returns scripted addresses."""

    def __init__(
        self,
        addresses_by_host: Mapping[str, Sequence[str]] | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self._addresses_by_host = {
            host: tuple(addresses)
            for host, addresses in (addresses_by_host or {}).items()
        }
        self._error = error
        self.calls: list[tuple[str, int]] = []

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.calls.append((host, port))
        if self._error is not None:
            raise self._error
        if host not in self._addresses_by_host:
            raise AssertionError(f"unexpected resolver host: {host!r}")
        return self._addresses_by_host[host]


class RecordingRequestOnce:
    """Scripted request_once double keyed by the hop URL being requested."""

    def __init__(
        self,
        responses_by_url: Mapping[str, _ScriptedResponse | BaseException],
    ) -> None:
        self._responses_by_url = dict(responses_by_url)
        self.calls: list[RequestOnceCall] = []

    async def __call__(
        self,
        target: TargetUrl,
        pinned_ip: str,
        *,
        method: str = "GET",
        headers: Collection[tuple[bytes, bytes]] = (),
        limits: RequestLimits,
    ) -> TransportResponse:
        self.calls.append(
            RequestOnceCall(
                target=target,
                pinned_ip=pinned_ip,
                method=method,
                headers=tuple(headers),
                limits=limits,
            )
        )
        if target.url not in self._responses_by_url:
            raise AssertionError(f"unexpected request_once target: {target.url!r}")
        item = self._responses_by_url[target.url]
        if isinstance(item, BaseException):
            raise item
        return TransportResponse(
            status=item.status,
            headers=item.headers,
            body=item.body,
            final_target=target,
        )


class PatchRequestOnce(Protocol):
    def __call__(
        self,
        responses_by_url: Mapping[str, _ScriptedResponse | BaseException],
    ) -> RecordingRequestOnce: ...


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if discovery crawl performs DNS or real TCP I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)


@pytest.fixture
def patch_request_once(monkeypatch: pytest.MonkeyPatch) -> PatchRequestOnce:
    """Install a RecordingRequestOnce in place of the real request_once."""

    def install(
        responses_by_url: Mapping[str, _ScriptedResponse | BaseException],
    ) -> RecordingRequestOnce:
        recorded = RecordingRequestOnce(responses_by_url)
        monkeypatch.setattr("boundary.transport.request_once", recorded)
        return recorded

    return install


def _limits() -> RequestLimits:
    return RequestLimits(
        max_body_bytes=65536,
        connect_timeout=1.0,
        read_timeout=2.0,
        write_timeout=3.0,
        pool_timeout=4.0,
    )


def _origins(*raw_urls: str) -> frozenset[Origin]:
    return frozenset(parse_target_url(raw).origin for raw in raw_urls)


def _html(*hrefs: str) -> bytes:
    anchors = "".join(f'<a href="{href}">x</a>' for href in hrefs)
    return f"<html><body>{anchors}</body></html>".encode()


def _html_headers() -> tuple[tuple[bytes, bytes], ...]:
    return ((b"content-type", b"text/html"),)


def _page(
    body: bytes = b"",
    *,
    status: int = 200,
    headers: tuple[tuple[bytes, bytes], ...] | None = None,
) -> _ScriptedResponse:
    return _ScriptedResponse(
        status=status,
        headers=_html_headers() if headers is None else headers,
        body=body,
    )


def _redirect(location: bytes, *, status: int = 302) -> _ScriptedResponse:
    return _ScriptedResponse(
        status=status,
        headers=((b"location", location),),
        body=b"",
    )


def _json(body: bytes = b'{"ok":true}') -> _ScriptedResponse:
    return _ScriptedResponse(
        status=200,
        headers=((b"content-type", b"application/json"),),
        body=body,
    )


def _app_resolver(*hosts: str) -> RecordingResolver:
    mapping = {host: (_APP_IP,) for host in hosts}
    if "app.test" not in mapping:
        mapping["app.test"] = (_APP_IP,)
    return RecordingResolver(mapping)


async def _collect(
    seed: TargetUrl,
    *,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: RecordingResolver,
    request_limits: RequestLimits,
    max_redirects: int,
    limits: DiscoveryLimits,
) -> list[DiscoveredPage]:
    pages: list[DiscoveredPage] = []
    stream: AsyncIterator[DiscoveredPage] = crawl(
        seed,
        allowed_origins=allowed_origins,
        policy=policy,
        resolver=resolver,
        request_limits=request_limits,
        max_redirects=max_redirects,
        limits=limits,
    )
    async for page in stream:
        pages.append(page)
    return pages


def _run(
    seed: TargetUrl,
    *,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: RecordingResolver,
    request_limits: RequestLimits,
    max_redirects: int,
    limits: DiscoveryLimits,
) -> list[DiscoveredPage]:
    return asyncio.run(
        _collect(
            seed,
            allowed_origins=allowed_origins,
            policy=policy,
            resolver=resolver,
            request_limits=request_limits,
            max_redirects=max_redirects,
            limits=limits,
        )
    )


def _discovery_targets(recorded: RecordingRequestOnce) -> list[str]:
    """Return hop URLs in request_once order (includes transport redirect hops)."""
    return [call.target.url for call in recorded.calls]


def test_crawl_is_an_async_generator_function() -> None:
    assert inspect.isasyncgenfunction(crawl)


def test_discovered_page_is_immutable_and_slotted() -> None:
    seed = parse_target_url("https://app.test/")
    response = TransportResponse(
        status=200,
        headers=_html_headers(),
        body=b"",
        final_target=seed,
    )
    page = DiscoveredPage(target=seed, depth=0, response=response)

    with pytest.raises(FrozenInstanceError):
        page.depth = 1  # type: ignore[misc]

    assert set(DiscoveredPage.__slots__) == {"target", "depth", "response"}


def test_seed_only_crawl_requests_and_yields_depth_zero(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    limits = _limits()
    recorded = patch_request_once({seed.url: _page(b"<html></html>")})

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=limits,
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=3),
    )

    assert len(pages) == 1
    assert pages[0].target == seed
    assert pages[0].target.url == seed.url
    assert pages[0].depth == 0
    assert pages[0].response.final_target.url == seed.url
    assert pages[0].response.final_target == seed
    assert _discovery_targets(recorded) == [seed.url]
    assert all(call.method == "GET" for call in recorded.calls)
    assert all(call.headers == () for call in recorded.calls)
    assert all(call.limits is limits for call in recorded.calls)
    assert resolver.calls == [("app.test", 443)]


def test_traversal_is_strict_breadth_first_not_depth_first(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    a = parse_target_url("https://app.test/a")
    b = parse_target_url("https://app.test/b")
    child = parse_target_url("https://app.test/a/child")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _page(_html("/a", "/b")),
            a.url: _page(_html("/a/child")),
            b.url: _page(b"<html></html>"),
            child.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert [page.target.url for page in pages] == [
        seed.url,
        a.url,
        b.url,
        child.url,
    ]
    assert [page.depth for page in pages] == [0, 1, 1, 2]
    assert _discovery_targets(recorded) == [seed.url, a.url, b.url, child.url]


def test_max_depth_zero_requests_seed_but_does_not_expand(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once({seed.url: _page(_html("/a", "/b", "/c"))})

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=0),
    )

    assert len(pages) == 1
    assert pages[0].target.url == seed.url
    assert pages[0].depth == 0
    assert _discovery_targets(recorded) == [seed.url]


def test_max_depth_one_requests_direct_children_but_does_not_expand_them(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    a = parse_target_url("https://app.test/a")
    b = parse_target_url("https://app.test/b")
    grandchild = parse_target_url("https://app.test/a/child")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _page(_html("/a", "/b")),
            a.url: _page(_html("/a/child")),
            b.url: _page(_html("/b/child")),
            grandchild.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=1),
    )

    assert [page.target.url for page in pages] == [seed.url, a.url, b.url]
    assert [page.depth for page in pages] == [0, 1, 1]
    assert grandchild.url not in _discovery_targets(recorded)
    assert _discovery_targets(recorded) == [seed.url, a.url, b.url]


def test_max_pages_one_requests_only_the_seed(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {seed.url: _page(_html("/a", "/b", "/c", "/d", "/e"))}
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=1, max_depth=5),
    )

    assert len(pages) == 1
    assert pages[0].target.url == seed.url
    assert _discovery_targets(recorded) == [seed.url]


def test_page_budget_admits_first_candidates_in_document_order(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    a = parse_target_url("https://app.test/a")
    b = parse_target_url("https://app.test/b")
    c = parse_target_url("https://app.test/c")
    d = parse_target_url("https://app.test/d")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _page(_html("/a", "/b", "/c", "/d")),
            a.url: _page(b"<html></html>"),
            b.url: _page(b"<html></html>"),
            c.url: _page(b"<html></html>"),
            d.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=3, max_depth=5),
    )

    assert [page.target.url for page in pages] == [seed.url, a.url, b.url]
    assert c.url not in _discovery_targets(recorded)
    assert d.url not in _discovery_targets(recorded)
    assert _discovery_targets(recorded) == [seed.url, a.url, b.url]


def test_duplicate_links_on_one_page_are_requested_once(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    a = parse_target_url("https://app.test/a")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _page(_html("/a", "/a", "/a")),
            a.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert [page.target.url for page in pages] == [seed.url, a.url]
    assert _discovery_targets(recorded) == [seed.url, a.url]


def test_same_url_discovered_from_multiple_pages_is_requested_once(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    a = parse_target_url("https://app.test/a")
    b = parse_target_url("https://app.test/b")
    shared = parse_target_url("https://app.test/shared")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _page(_html("/a", "/b")),
            a.url: _page(_html("/shared")),
            b.url: _page(_html("/shared")),
            shared.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert [page.target.url for page in pages] == [
        seed.url,
        a.url,
        b.url,
        shared.url,
    ]
    assert _discovery_targets(recorded).count(shared.url) == 1


def test_non_html_response_is_yielded_without_candidate_expansion(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/api")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    body = b'{"links":["/a","/b"]}<a href="/c"></a>'
    recorded = patch_request_once({seed.url: _json(body)})

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert len(pages) == 1
    assert pages[0].target.url == seed.url
    assert not is_html_response(pages[0].response.headers)
    assert _discovery_targets(recorded) == [seed.url]


def test_empty_html_is_yielded_without_children(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once({seed.url: _page(b"")})

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert len(pages) == 1
    assert extract_html_references(pages[0].response.body) == ()
    assert _discovery_targets(recorded) == [seed.url]


def test_rejected_candidates_are_never_requested(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    references = (
        "javascript:alert(1)",
        "mailto:admin@app.test",
        "https://evil.test/steal",
        "https://app.test:abc/bad",
        "/api/\nusers",
        "#section",
        "",
        "  ",
    )
    for reference in references:
        assert resolve_candidate(seed, reference, allowed) is None

    recorded = patch_request_once({seed.url: _page(_html(*references))})

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert len(pages) == 1
    assert _discovery_targets(recorded) == [seed.url]


def test_relative_candidate_after_redirect_resolves_against_final_target(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/start")
    final = parse_target_url("https://app.test/app/dashboard/")
    expected = parse_target_url(urljoin(final.url, "../api"))
    assert expected.url == "https://app.test/app/api"
    assert resolve_candidate(final, "../api", _origins("https://app.test/")) == expected

    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _redirect(b"/app/dashboard/"),
            final.url: _page(_html("../api")),
            expected.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert len(pages) == 2
    assert pages[0].target.url == seed.url
    assert pages[0].response.final_target.url == final.url
    assert pages[0].depth == 0
    assert pages[1].target.url == expected.url
    assert pages[1].depth == 1
    assert _discovery_targets(recorded) == [seed.url, final.url, expected.url]


def test_redirect_destination_registered_with_mark_seen_is_not_requeued(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/start")
    home = parse_target_url("https://app.test/home")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _redirect(b"/home"),
            home.url: _page(_html("/home", "/next")),
            "https://app.test/next": _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert [page.target.url for page in pages] == [
        seed.url,
        "https://app.test/next",
    ]
    # /home was fetched only as a transport redirect hop, never as its own
    # Discovery request after final_target mark_seen().
    discovery_page_targets = [page.target.url for page in pages]
    assert home.url not in discovery_page_targets
    assert _discovery_targets(recorded) == [
        seed.url,
        home.url,
        "https://app.test/next",
    ]


def test_redirects_do_not_increase_discovery_depth(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/start")
    home = parse_target_url("https://app.test/home")
    child = parse_target_url("https://app.test/child")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _redirect(b"/home"),
            home.url: _page(_html("/child")),
            child.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert pages[0].target.url == seed.url
    assert pages[0].response.final_target.url == home.url
    assert pages[0].depth == 0
    assert pages[1].target.url == child.url
    assert pages[1].depth == 1
    assert _discovery_targets(recorded) == [seed.url, home.url, child.url]


def test_allowlisted_cross_origin_candidate_may_enter_the_frontier(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    api = parse_target_url("https://api.test/v1")
    allowed = _origins("https://app.test/", "https://api.test/")
    resolver = RecordingResolver({"app.test": (_APP_IP,), "api.test": (_API_IP,)})
    patch_request_once(
        {
            seed.url: _page(_html("https://api.test/v1")),
            api.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert [page.target.url for page in pages] == [seed.url, api.url]
    assert ("api.test", 443) in resolver.calls


def test_non_allowlisted_cross_origin_candidate_never_enters_the_frontier(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    local = parse_target_url("https://app.test/local")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _page(_html("https://api.test/v1", "/local")),
            local.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert [page.target.url for page in pages] == [seed.url, local.url]
    assert all("api.test" not in url for url in _discovery_targets(recorded))
    assert ("api.test", 443) not in resolver.calls


def test_request_limits_object_is_forwarded_by_identity(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    child = parse_target_url("https://app.test/a")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    limits = _limits()
    recorded = patch_request_once(
        {
            seed.url: _page(_html("/a")),
            child.url: _page(b"<html></html>"),
        }
    )

    _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=limits,
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert recorded.calls
    assert all(call.limits is limits for call in recorded.calls)


def test_address_policy_is_forwarded_and_enforced(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = RecordingResolver({"app.test": (_PRIVATE_IP,)})
    recorded = patch_request_once({seed.url: _page(b"<html></html>")})

    with pytest.raises(ScopeValidationError) as caught:
        _run(
            seed,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            request_limits=_limits(),
            max_redirects=3,
            limits=DiscoveryLimits(max_pages=10, max_depth=5),
        )

    assert caught.value.code is ScopeErrorCode.ADDRESS_NOT_ALLOWED
    assert recorded.calls == []
    assert resolver.calls == [("app.test", 443)]


def test_local_lab_policy_allows_private_addresses_when_forwarded(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = RecordingResolver({"app.test": (_PRIVATE_IP,)})
    recorded = patch_request_once({seed.url: _page(b"<html></html>")})

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.LOCAL_LAB,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert len(pages) == 1
    assert recorded.calls[0].pinned_ip == _PRIVATE_IP


def test_supplied_resolver_is_used_by_request_with_redirects_path(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    mid = parse_target_url("https://app.test/mid")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _redirect(b"/mid"),
            mid.url: _page(b"<html></html>"),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert len(pages) == 1
    # Real request_with_redirects re-resolves every hop before request_once.
    assert resolver.calls == [("app.test", 443), ("app.test", 443)]
    assert _discovery_targets(recorded) == [seed.url, mid.url]


def test_transport_error_propagates_out_of_crawl(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    patch_request_once(
        {
            seed.url: TransportError(
                TransportErrorCode.RESPONSE_TOO_LARGE,
                "Response body exceeds the configured limit.",
            )
        }
    )

    with pytest.raises(TransportError) as caught:
        _run(
            seed,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            request_limits=_limits(),
            max_redirects=3,
            limits=DiscoveryLimits(max_pages=10, max_depth=5),
        )

    assert caught.value.code is TransportErrorCode.RESPONSE_TOO_LARGE


def test_resolver_exception_propagates_out_of_crawl(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")
    resolver = RecordingResolver(error=RuntimeError("dns unavailable"))
    patch_request_once({seed.url: _page(b"<html></html>")})

    with pytest.raises(RuntimeError, match="dns unavailable"):
        _run(
            seed,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            request_limits=_limits(),
            max_redirects=3,
            limits=DiscoveryLimits(max_pages=10, max_depth=5),
        )


def test_max_redirects_is_forwarded_to_transport(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/start")
    mid = parse_target_url("https://app.test/mid")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    patch_request_once(
        {
            seed.url: _redirect(b"/mid"),
            mid.url: _redirect(b"/end"),
        }
    )

    with pytest.raises(TransportError) as caught:
        _run(
            seed,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            request_limits=_limits(),
            max_redirects=0,
            limits=DiscoveryLimits(max_pages=10, max_depth=5),
        )

    assert caught.value.code is TransportErrorCode.TOO_MANY_REDIRECTS


def test_dequeued_url_is_never_requested_again_as_discovery_target(
    patch_request_once: PatchRequestOnce,
) -> None:
    seed = parse_target_url("https://app.test/")
    a = parse_target_url("https://app.test/a")
    allowed = _origins("https://app.test/")
    resolver = _app_resolver()
    recorded = patch_request_once(
        {
            seed.url: _page(_html("/a")),
            a.url: _page(_html("/", "/a")),
        }
    )

    pages = _run(
        seed,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=_limits(),
        max_redirects=3,
        limits=DiscoveryLimits(max_pages=10, max_depth=5),
    )

    assert [page.target.url for page in pages] == [seed.url, a.url]
    assert _discovery_targets(recorded) == [seed.url, a.url]
