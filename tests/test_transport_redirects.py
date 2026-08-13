"""Offline tests for controlled redirect orchestration (Milestone 2 Slice D)."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

import anyio
import pytest

from boundary.scope import (
    AddressPolicy,
    AddressResolver,
    Origin,
    ScopeErrorCode,
    ScopeValidationError,
    TargetUrl,
    UrlErrorCode,
    UrlValidationError,
    parse_target_url,
)
from boundary.transport import (
    RequestLimits,
    TransportError,
    TransportErrorCode,
    TransportResponse,
    request_with_redirects,
)

_EXAMPLE_IP = "93.184.216.34"
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
    """Scripted request_once double that records hop arguments."""

    def __init__(
        self,
        responses: Sequence[_ScriptedResponse | BaseException],
    ) -> None:
        self._responses = list(responses)
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
        if not self._responses:
            raise AssertionError("unexpected request_once call")
        item = self._responses.pop(0)
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
        responses: Sequence[_ScriptedResponse | BaseException],
    ) -> RecordingRequestOnce: ...


def _limits() -> RequestLimits:
    return RequestLimits(
        max_body_bytes=1024,
        connect_timeout=1.0,
        read_timeout=2.0,
        write_timeout=3.0,
        pool_timeout=4.0,
    )


def _response(
    status: int,
    *,
    location: bytes | None = None,
    location_name: bytes = b"Location",
    body: bytes = b"",
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
) -> _ScriptedResponse:
    headers: list[tuple[bytes, bytes]] = list(extra_headers)
    if location is not None:
        headers.append((location_name, location))
    return _ScriptedResponse(status=status, headers=tuple(headers), body=body)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if redirect tests perform DNS or real TCP I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)


@pytest.fixture
def patch_request_once(monkeypatch: pytest.MonkeyPatch) -> PatchRequestOnce:
    """Install a RecordingRequestOnce in place of the real request_once."""

    def install(
        responses: Sequence[_ScriptedResponse | BaseException],
    ) -> RecordingRequestOnce:
        recorded = RecordingRequestOnce(responses)
        monkeypatch.setattr(
            "boundary.transport.request_once",
            recorded,
        )
        return recorded

    return install


def _allowed(*urls: str) -> set[Origin]:
    return {parse_target_url(url).origin for url in urls}


def _run(
    target_url: str,
    *,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: AddressResolver,
    limits: RequestLimits,
    max_redirects: int,
    method: str = "GET",
    headers: Collection[tuple[bytes, bytes]] = (),
) -> TransportResponse:
    return asyncio.run(
        request_with_redirects(
            parse_target_url(target_url),
            allowed_origins=allowed_origins,
            policy=policy,
            resolver=resolver,
            limits=limits,
            max_redirects=max_redirects,
            method=method,
            headers=headers,
        )
    )


def test_redirect_transport_error_codes_are_stable() -> None:
    assert TransportErrorCode.TOO_MANY_REDIRECTS.value == "too_many_redirects"
    assert TransportErrorCode.REDIRECT_LOOP.value == "redirect_loop"
    assert TransportErrorCode.INVALID_REDIRECT.value == "invalid_redirect"


def test_non_redirect_response_returns_immediately(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(200, body=b"ok")])
    limits = _limits()

    response = _run(
        target.url,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=limits,
        max_redirects=5,
    )

    assert response.status == 200
    assert response.body == b"ok"
    assert response.final_target is recorded.calls[0].target
    assert response.final_target == target
    assert response.final_target.url == "https://example.com/start"
    assert resolver.calls == [("example.com", 443)]
    assert len(recorded.calls) == 1
    assert recorded.calls[0].target.url == "https://example.com/start"
    assert recorded.calls[0].pinned_ip == _EXAMPLE_IP
    assert recorded.calls[0].limits is limits


def test_relative_redirect_revalidates_and_resolves_again(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    nxt = parse_target_url("https://example.com/next")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/next"),
            _response(200, body=b"done"),
        ]
    )

    response = _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 200
    assert response.body == b"done"
    assert response.final_target is recorded.calls[-1].target
    assert response.final_target == nxt
    assert response.final_target.url == "https://example.com/next"
    assert response.final_target != start
    assert resolver.calls == [
        ("example.com", 443),
        ("example.com", 443),
    ]
    assert [call.target.url for call in recorded.calls] == [start.url, nxt.url]
    assert all(call.pinned_ip == _EXAMPLE_IP for call in recorded.calls)


def test_absolute_same_origin_redirect_succeeds(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(301, location=b"https://example.com/dashboard"),
            _response(200, body=b"ok"),
        ]
    )

    response = _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 200
    assert [call.target.url for call in recorded.calls] == [
        "https://example.com/start",
        "https://example.com/dashboard",
    ]
    assert response.final_target is recorded.calls[-1].target
    assert response.final_target.url == "https://example.com/dashboard"
    assert response.final_target != start
    assert resolver.calls == [("example.com", 443), ("example.com", 443)]


def test_allowlisted_cross_origin_redirect_uses_new_validated_ip(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP, "1.1.1.1"),
            "api.example.com": (_API_IP, "8.8.8.8"),
        }
    )
    recorded = patch_request_once(
        [
            _response(307, location=b"https://api.example.com/v1"),
            _response(200, body=b"api"),
        ]
    )

    response = _run(
        start.url,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 200
    assert response.final_target is recorded.calls[-1].target
    assert response.final_target.url == "https://api.example.com/v1"
    assert response.final_target.host == "api.example.com"
    assert response.final_target != start
    assert resolver.calls == [
        ("example.com", 443),
        ("api.example.com", 443),
    ]
    assert recorded.calls[0].pinned_ip == _EXAMPLE_IP
    assert recorded.calls[1].pinned_ip == _API_IP
    assert recorded.calls[1].pinned_ip != recorded.calls[0].pinned_ip
    assert recorded.calls[1].target.url == "https://api.example.com/v1"
    assert recorded.calls[1].target.host == "api.example.com"


def test_allowlisted_cross_origin_redirect_reports_destination_as_final_target(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://app.test/start")
    final = parse_target_url("https://api.test/final")
    allowed = _allowed("https://app.test/", "https://api.test/")
    resolver = RecordingResolver(
        {
            "app.test": (_EXAMPLE_IP,),
            "api.test": (_API_IP,),
        }
    )
    recorded = patch_request_once(
        [
            _response(302, location=b"https://api.test/final"),
            _response(200, body=b"ok"),
        ]
    )

    response = _run(
        start.url,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 200
    assert response.body == b"ok"
    assert response.final_target is recorded.calls[-1].target
    assert response.final_target == final
    assert response.final_target.host == "api.test"
    assert response.final_target.url == "https://api.test/final"
    assert response.final_target != start
    assert recorded.calls[0].pinned_ip == _EXAMPLE_IP
    assert recorded.calls[1].pinned_ip == _API_IP
    assert resolver.calls == [("app.test", 443), ("api.test", 443)]


def test_redirect_to_non_allowlisted_origin_fails_before_second_request(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=b"https://evil.test/phish")])

    with pytest.raises(ScopeValidationError) as caught:
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert caught.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]


def test_public_policy_rejects_private_ip_for_redirect_destination(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_PRIVATE_IP,),
        }
    )
    recorded = patch_request_once(
        [_response(302, location=b"https://api.example.com/internal")]
    )

    with pytest.raises(ScopeValidationError) as caught:
        _run(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert caught.value.code is ScopeErrorCode.ADDRESS_NOT_ALLOWED
    assert len(recorded.calls) == 1
    assert resolver.calls == [
        ("example.com", 443),
        ("api.example.com", 443),
    ]


def test_mixed_public_private_dns_for_redirect_destination_fails_closed(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_EXAMPLE_IP, _PRIVATE_IP),
        }
    )
    recorded = patch_request_once(
        [_response(308, location=b"https://api.example.com/mixed")]
    )

    with pytest.raises(ScopeValidationError) as caught:
        _run(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert caught.value.code is ScopeErrorCode.ADDRESS_NOT_ALLOWED
    assert len(recorded.calls) == 1
    assert resolver.calls == [
        ("example.com", 443),
        ("api.example.com", 443),
    ]


def test_max_redirects_zero_rejects_first_redirect(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=b"/next")])

    with pytest.raises(TransportError) as caught:
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=0,
        )

    assert caught.value.code is TransportErrorCode.TOO_MANY_REDIRECTS
    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]


def test_exactly_max_redirects_may_be_followed(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/b"),
            _response(302, location=b"/c"),
            _response(200, body=b"final"),
        ]
    )

    response = _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=2,
    )

    assert response.status == 200
    assert response.body == b"final"
    assert response.final_target is recorded.calls[-1].target
    assert response.final_target.url == "https://example.com/c"
    assert response.final_target != start
    assert [call.target.url for call in recorded.calls] == [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
    ]
    assert len(resolver.calls) == 3


def test_one_redirect_beyond_max_raises_too_many_redirects(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/b"),
            _response(302, location=b"/c"),
            _response(302, location=b"/d"),
        ]
    )

    with pytest.raises(TransportError) as caught:
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=2,
        )

    assert caught.value.code is TransportErrorCode.TOO_MANY_REDIRECTS
    assert [call.target.url for call in recorded.calls] == [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
    ]
    assert len(resolver.calls) == 3


def test_direct_redirect_loop_is_detected(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=b"/a")])

    with pytest.raises(TransportError) as caught:
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert caught.value.code is TransportErrorCode.REDIRECT_LOOP
    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]


def test_indirect_redirect_loop_is_detected(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/b"),
            _response(302, location=b"/a"),
        ]
    )

    with pytest.raises(TransportError) as caught:
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert caught.value.code is TransportErrorCode.REDIRECT_LOOP
    assert [call.target.url for call in recorded.calls] == [
        "https://example.com/a",
        "https://example.com/b",
    ]
    assert len(resolver.calls) == 2


def test_redirect_status_without_location_is_returned_normally(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, body=b"no location")])

    response = _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 302
    assert response.body == b"no location"
    assert response.final_target is recorded.calls[0].target
    assert response.final_target == start
    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]


@pytest.mark.parametrize(
    "location_name",
    [b"Location", b"location", b"LOCATION", b"LoCaTiOn"],
)
def test_location_header_name_is_matched_case_insensitively(
    patch_request_once: PatchRequestOnce,
    location_name: bytes,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(303, location=b"/next", location_name=location_name),
            _response(200, body=b"ok"),
        ]
    )

    response = _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 200
    assert [call.target.url for call in recorded.calls] == [
        "https://example.com/start",
        "https://example.com/next",
    ]


def test_multiple_location_headers_raise_invalid_redirect(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(
                302,
                extra_headers=(
                    (b"Location", b"/first"),
                    (b"LOCATION", b"/second"),
                ),
            )
        ]
    )

    with pytest.raises(TransportError) as caught:
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert caught.value.code is TransportErrorCode.INVALID_REDIRECT
    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]


def test_non_ascii_location_fails_closed(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=b"/\xc3\xa9")])

    with pytest.raises(UnicodeDecodeError):
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]


def test_url_and_scope_validation_errors_propagate_unchanged(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(
                302,
                location=b"https://user:password@example.com/creds",
            )
        ]
    )

    with pytest.raises(UrlValidationError) as caught:
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert caught.value.code is UrlErrorCode.EMBEDDED_CREDENTIALS
    assert not isinstance(caught.value, TransportError)
    assert len(recorded.calls) == 1


def test_resolver_exceptions_propagate_unchanged(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    error = RuntimeError("resolver failed")
    resolver = RecordingResolver(error=error)
    recorded = patch_request_once([])

    with pytest.raises(RuntimeError) as caught:
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert caught.value is error
    assert recorded.calls == []
    assert resolver.calls == [("example.com", 443)]


def test_each_accepted_redirect_destination_is_resolved_exactly_once(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/b"),
            _response(302, location=b"/c"),
            _response(200, body=b"ok"),
        ]
    )

    _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert resolver.calls == [
        ("example.com", 443),
        ("example.com", 443),
        ("example.com", 443),
    ]
    assert len(recorded.calls) == 3


def test_request_limits_object_is_forwarded_unchanged_every_hop(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    limits = _limits()
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/b"),
            _response(200, body=b"ok"),
        ]
    )

    _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=limits,
        max_redirects=5,
    )

    assert len(recorded.calls) == 2
    assert all(call.limits is limits for call in recorded.calls)


def test_original_method_and_headers_are_forwarded_unchanged(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    headers = ((b"X-Trace", b"abc"), (b"Accept", b"text/plain"))
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/b"),
            _response(302, location=b"/c"),
            _response(200, body=b"ok"),
        ]
    )

    _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        method="PUT",
        headers=headers,
    )

    assert [call.method for call in recorded.calls] == ["PUT", "PUT", "PUT"]
    assert [call.headers for call in recorded.calls] == [
        headers,
        headers,
        headers,
    ]


def test_negative_max_redirects_raises_before_network_io(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([])

    with pytest.raises(ValueError):
        _run(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=-1,
        )

    assert recorded.calls == []
    assert resolver.calls == []
