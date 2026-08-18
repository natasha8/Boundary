"""Offline tests for origin-bound credential containment (Milestone 6 Slice B)."""

from __future__ import annotations

import asyncio
import inspect
import socket
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, get_type_hints

import anyio
import pytest

from boundary.discovery import crawl
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
    resolve_allowed_redirect,
)
from boundary.transport import (
    OriginBoundCredentials,
    RequestLimits,
    TransportError,
    TransportErrorCode,
    TransportResponse,
    request_once,
    request_with_redirects,
)

_EXAMPLE_IP = "93.184.216.34"
_API_IP = "93.184.216.35"
_AUTH_VALUE = b"Bearer SUPERSECRET_AUTH_TOKEN_aaa"
_COOKIE_VALUE = b"session=SUPERSECRET_COOKIE_VALUE_bbb"
_GENERIC_HEADERS = ((b"X-Trace", b"abc"), (b"Accept", b"text/plain"))
_SECRET_MARKERS = (
    "SUPERSECRET_AUTH_TOKEN_aaa",
    "SUPERSECRET_COOKIE_VALUE_bbb",
    _AUTH_VALUE.decode("ascii"),
    _COOKIE_VALUE.decode("ascii"),
)
_HEADER_NAME_MARKERS = (
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
)
_REQUEST_ONCE_PARAMETERS = ("target", "pinned_ip", "method", "headers", "limits")
_REQUEST_WITH_REDIRECTS_PARAMETERS = (
    "target",
    "allowed_origins",
    "policy",
    "resolver",
    "limits",
    "max_redirects",
    "method",
    "headers",
    "credentials",
)


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
    """Fail immediately if credentialed transport tests perform DNS or real TCP I/O."""
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
        monkeypatch.setattr("boundary.transport.request_once", recorded)
        return recorded

    return install


def _allowed(*urls: str) -> set[Origin]:
    return {parse_target_url(url).origin for url in urls}


def _credentials(
    origin: Origin,
    headers: Collection[tuple[bytes, bytes]] = ((b"Authorization", _AUTH_VALUE),),
) -> OriginBoundCredentials:
    return OriginBoundCredentials(origin=origin, headers=tuple(headers))


def _hop_headers(
    generic: Collection[tuple[bytes, bytes]] = (),
    credentials: OriginBoundCredentials | None = None,
) -> tuple[tuple[bytes, bytes], ...]:
    bound = credentials.headers if credentials is not None else ()
    return tuple(generic) + bound


def _assert_no_secrets(text: str) -> None:
    lowered = text.lower()
    for marker in _SECRET_MARKERS:
        assert marker.lower() not in lowered
        assert marker not in text


def _assert_no_header_names(text: str) -> None:
    lowered = text.lower()
    for marker in _HEADER_NAME_MARKERS:
        assert marker not in lowered


def _assert_redacted(
    error: BaseException,
    *,
    location: str | None = None,
) -> None:
    text = f"{error!s}\n{error!r}"
    _assert_no_secrets(text)
    _assert_no_header_names(text)
    if location is not None:
        assert location not in text
        assert location.encode("ascii").decode("latin-1") not in text


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


def _run_with_credentials(
    target_url: str,
    *,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: AddressResolver,
    limits: RequestLimits,
    max_redirects: int,
    credentials: OriginBoundCredentials | None,
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
            credentials=credentials,
        )
    )


def test_cross_origin_credential_redirect_code_is_stable() -> None:
    assert (
        TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
        is TransportErrorCode["CROSS_ORIGIN_CREDENTIAL_REDIRECT"]
    )
    assert (
        TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT.value
        == "cross_origin_credential_redirect"
    )
    assert TransportErrorCode.TOO_MANY_REDIRECTS.value == "too_many_redirects"
    assert TransportErrorCode.REDIRECT_LOOP.value == "redirect_loop"
    assert TransportErrorCode.INVALID_REDIRECT.value == "invalid_redirect"


def test_request_with_redirects_credentials_is_keyword_only_optional_none() -> None:
    signature = inspect.signature(request_with_redirects)
    parameters = signature.parameters

    assert tuple(parameters) == _REQUEST_WITH_REDIRECTS_PARAMETERS
    credentials = parameters["credentials"]
    assert credentials.kind is inspect.Parameter.KEYWORD_ONLY
    assert credentials.default is None
    assert get_type_hints(request_with_redirects)["credentials"] == (
        OriginBoundCredentials | None
    )


def test_request_once_signature_does_not_include_credentials() -> None:
    signature = inspect.signature(request_once)
    parameters = signature.parameters

    assert tuple(parameters) == _REQUEST_ONCE_PARAMETERS
    assert "credentials" not in parameters
    assert parameters["target"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameters["pinned_ip"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameters["method"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["headers"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["limits"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["limits"].default is inspect.Parameter.empty


def test_crawl_does_not_pass_credentials() -> None:
    source = inspect.getsource(crawl)
    signature = inspect.signature(crawl)

    assert "credentials=" not in source
    assert "credentials" not in signature.parameters
    assert "request_with_redirects(" in source


def test_request_with_redirects_still_uses_request_once_and_scope_redirect() -> None:
    source = inspect.getsource(request_with_redirects)
    lowered = source.lower()

    assert "request_once(" in source
    assert "resolve_allowed_redirect(" in source
    assert "httpx" not in lowered
    assert "aiohttp" not in lowered
    assert "urllib.request" not in lowered


def test_omitted_credentials_does_not_send_authorization_or_cookie(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(200, body=b"ok")])

    response = _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        headers=_GENERIC_HEADERS,
    )

    assert response.status == 200
    assert len(recorded.calls) == 1
    assert recorded.calls[0].headers == _GENERIC_HEADERS
    assert recorded.calls[0].headers != _hop_headers(
        _GENERIC_HEADERS,
        _credentials(start.origin),
    )


def test_explicit_none_credentials_matches_omitted_uncredentialed_behavior(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_API_IP,),
        }
    )
    recorded = patch_request_once(
        [
            _response(302, location=b"https://api.example.com/v1"),
            _response(200, body=b"api"),
        ]
    )

    response = _run_with_credentials(
        start.url,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        credentials=None,
        headers=_GENERIC_HEADERS,
    )

    assert response.status == 200
    assert response.final_target.url == "https://api.example.com/v1"
    assert [call.target.url for call in recorded.calls] == [
        "https://example.com/start",
        "https://api.example.com/v1",
    ]
    assert [call.headers for call in recorded.calls] == [
        _GENERIC_HEADERS,
        _GENERIC_HEADERS,
    ]
    assert resolver.calls == [("example.com", 443), ("api.example.com", 443)]


def test_uncredentialed_allowlisted_cross_origin_redirect_still_succeeds(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_API_IP,),
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
        headers=_GENERIC_HEADERS,
    )

    assert response.status == 200
    assert response.body == b"api"
    assert response.final_target is recorded.calls[-1].target
    assert response.final_target.url == "https://api.example.com/v1"
    assert [call.headers for call in recorded.calls] == [
        _GENERIC_HEADERS,
        _GENERIC_HEADERS,
    ]
    assert recorded.calls[0].pinned_ip == _EXAMPLE_IP
    assert recorded.calls[1].pinned_ip == _API_IP
    assert resolver.calls == [("example.com", 443), ("api.example.com", 443)]


def test_discovery_shaped_call_keeps_empty_headers_and_no_credentials(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(200, body=b"ok")])

    response = _run(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 200
    assert recorded.calls[0].method == "GET"
    assert recorded.calls[0].headers == ()


def test_authorization_and_cookie_headers_are_added_only_to_credentialed_requests(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(
        start.origin,
        ((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE)),
    )
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(200, body=b"ok")])

    response = _run_with_credentials(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        credentials=credentials,
        headers=_GENERIC_HEADERS,
        method="GET",
    )

    assert response.status == 200
    assert response.final_target.url == start.url
    assert len(recorded.calls) == 1
    assert recorded.calls[0].headers == _hop_headers(_GENERIC_HEADERS, credentials)
    assert recorded.calls[0].headers[: len(_GENERIC_HEADERS)] == _GENERIC_HEADERS
    assert recorded.calls[0].headers[len(_GENERIC_HEADERS) :] == credentials.headers
    assert resolver.calls == [("example.com", 443)]


@pytest.mark.parametrize(
    ("target_url", "credential_origin_url"),
    [
        ("https://example.com/start", "https://api.example.com/"),
        ("https://example.com/start", "http://example.com/"),
        ("https://example.com/start", "https://example.com:8443/"),
    ],
    ids=("different_host", "different_scheme", "different_port"),
)
def test_initial_target_must_match_credentials_origin_before_network_io(
    patch_request_once: PatchRequestOnce,
    target_url: str,
    credential_origin_url: str,
) -> None:
    target = parse_target_url(target_url)
    credentials = _credentials(parse_target_url(credential_origin_url).origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([])

    with pytest.raises(ValueError) as caught:
        _run_with_credentials(
            target.url,
            allowed_origins={target.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert not isinstance(caught.value, TransportError)
    _assert_redacted(caught.value)
    assert "origin" in str(caught.value).lower()
    assert recorded.calls == []
    assert resolver.calls == []
    assert target.origin != credentials.origin


def test_generic_and_credential_header_bags_are_not_mutated(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    generic = [(b"X-Trace", b"abc"), (b"Accept", b"text/plain")]
    generic_snapshot = list(generic)
    credential_headers = (
        (b"Authorization", _AUTH_VALUE),
        (b"Cookie", _COOKIE_VALUE),
    )
    credentials = _credentials(start.origin, credential_headers)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/next"),
            _response(200, body=b"ok"),
        ]
    )

    _run_with_credentials(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        credentials=credentials,
        headers=generic,
    )

    assert generic == generic_snapshot
    assert credentials.headers == credential_headers
    assert [call.headers for call in recorded.calls] == [
        _hop_headers(generic_snapshot, credentials),
        _hop_headers(generic_snapshot, credentials),
    ]


@pytest.mark.parametrize(
    ("generic_name", "credential_name"),
    [
        (b"Authorization", b"Authorization"),
        (b"authorization", b"Authorization"),
        (b"COOKIE", b"Cookie"),
        (b"Cookie", b"cookie"),
    ],
    ids=(
        "authorization",
        "authorization_mixed_case",
        "cookie_upper_generic",
        "cookie_mixed_case",
    ),
)
def test_overlapping_generic_and_credential_header_names_raise_before_io(
    patch_request_once: PatchRequestOnce,
    generic_name: bytes,
    credential_name: bytes,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin, ((credential_name, _COOKIE_VALUE),))
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([])

    with pytest.raises(ValueError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
            headers=((generic_name, _AUTH_VALUE), (b"X-Trace", b"abc")),
        )

    assert not isinstance(caught.value, TransportError)
    _assert_redacted(caught.value)
    assert recorded.calls == []
    assert resolver.calls == []


def test_non_overlapping_generic_headers_are_merged_with_credential_headers(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin, ((b"Cookie", _COOKIE_VALUE),))
    generic = ((b"X-Trace", b"abc"),)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(200, body=b"ok")])

    _run_with_credentials(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        credentials=credentials,
        headers=generic,
    )

    assert recorded.calls[0].headers == _hop_headers(generic, credentials)


def test_same_origin_relative_redirect_preserves_credentials(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    nxt = parse_target_url("https://example.com/next")
    credentials = _credentials(
        start.origin,
        ((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE)),
    )
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/next"),
            _response(200, body=b"done"),
        ]
    )

    response = _run_with_credentials(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        credentials=credentials,
        headers=_GENERIC_HEADERS,
    )

    assert response.status == 200
    assert response.body == b"done"
    assert response.final_target is recorded.calls[-1].target
    assert response.final_target == nxt
    assert response.final_target != start
    assert [call.target.url for call in recorded.calls] == [start.url, nxt.url]
    assert [call.headers for call in recorded.calls] == [
        _hop_headers(_GENERIC_HEADERS, credentials),
        _hop_headers(_GENERIC_HEADERS, credentials),
    ]
    assert resolver.calls == [("example.com", 443), ("example.com", 443)]
    assert all(call.pinned_ip == _EXAMPLE_IP for call in recorded.calls)


def test_same_origin_absolute_redirect_preserves_credentials(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin, ((b"Cookie", _COOKIE_VALUE),))
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(301, location=b"https://example.com/dashboard"),
            _response(200, body=b"ok"),
        ]
    )

    response = _run_with_credentials(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        credentials=credentials,
    )

    assert response.status == 200
    assert response.final_target.url == "https://example.com/dashboard"
    assert [call.headers for call in recorded.calls] == [
        credentials.headers,
        credentials.headers,
    ]
    assert resolver.calls == [("example.com", 443), ("example.com", 443)]


def test_explicit_default_port_redirect_is_same_origin_and_keeps_credentials(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"https://example.com:443/next"),
            _response(200, body=b"ok"),
        ]
    )

    response = _run_with_credentials(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        credentials=credentials,
    )

    assert response.status == 200
    assert response.final_target.origin == start.origin
    assert response.final_target.origin == credentials.origin
    assert response.final_target.url == "https://example.com/next"
    assert [call.headers for call in recorded.calls] == [
        credentials.headers,
        credentials.headers,
    ]


def test_credentialed_same_origin_respects_max_redirects_and_final_target(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    credentials = _credentials(start.origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/b"),
            _response(302, location=b"/c"),
            _response(200, body=b"final"),
        ]
    )
    limits = _limits()

    response = _run_with_credentials(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=limits,
        max_redirects=2,
        credentials=credentials,
        method="GET",
    )

    assert response.status == 200
    assert response.final_target is recorded.calls[-1].target
    assert response.final_target.url == "https://example.com/c"
    assert [call.target.url for call in recorded.calls] == [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
    ]
    assert [call.headers for call in recorded.calls] == [
        credentials.headers,
        credentials.headers,
        credentials.headers,
    ]
    assert all(call.limits is limits for call in recorded.calls)
    assert len(resolver.calls) == 3


def test_credentialed_same_origin_max_redirects_zero_raises_too_many_redirects(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=b"/next")])

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=0,
            credentials=credentials,
        )

    assert caught.value.code is TransportErrorCode.TOO_MANY_REDIRECTS
    _assert_redacted(caught.value, location="/next")
    assert len(recorded.calls) == 1
    assert recorded.calls[0].headers == credentials.headers
    assert resolver.calls == [("example.com", 443)]


def test_credentialed_same_origin_redirect_loop_is_detected(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/a")
    credentials = _credentials(start.origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/b"),
            _response(302, location=b"/a"),
        ]
    )

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert caught.value.code is TransportErrorCode.REDIRECT_LOOP
    _assert_redacted(caught.value)
    assert [call.target.url for call in recorded.calls] == [
        "https://example.com/a",
        "https://example.com/b",
    ]
    assert [call.headers for call in recorded.calls] == [
        credentials.headers,
        credentials.headers,
    ]
    assert len(resolver.calls) == 2


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_allowlisted_cross_origin_redirect_raises_before_next_request(
    patch_request_once: PatchRequestOnce,
    status: int,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    credentials = _credentials(start.origin)
    location = b"https://api.example.com/v1"
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_API_IP,),
        }
    )
    recorded = patch_request_once([_response(status, location=location)])

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
            headers=_GENERIC_HEADERS,
        )

    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    assert not isinstance(caught.value, ScopeValidationError)
    _assert_redacted(caught.value, location=location.decode("ascii"))
    assert len(recorded.calls) == 1
    assert recorded.calls[0].target.url == start.url
    assert recorded.calls[0].headers == _hop_headers(_GENERIC_HEADERS, credentials)
    assert recorded.calls[0].pinned_ip == _EXAMPLE_IP
    assert resolver.calls == [("example.com", 443)]
    assert ("api.example.com", 443) not in resolver.calls


def test_allowlisted_scheme_change_is_a_cross_origin_credential_redirect(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "http://example.com/")
    credentials = _credentials(start.origin)
    location = b"http://example.com/next"
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
        }
    )
    recorded = patch_request_once([_response(302, location=location)])

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    _assert_redacted(caught.value, location=location.decode("ascii"))
    assert len(recorded.calls) == 1
    assert recorded.calls[0].headers == credentials.headers
    assert resolver.calls == [("example.com", 443)]


def test_allowlisted_port_change_is_a_cross_origin_credential_redirect(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://example.com:8443/")
    credentials = _credentials(start.origin)
    location = b"https://example.com:8443/next"
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=location)])

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    _assert_redacted(caught.value, location=location.decode("ascii"))
    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]
    assert ("example.com", 8443) not in resolver.calls


def test_protocol_relative_allowlisted_redirect_raises_before_next_origin(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    credentials = _credentials(start.origin)
    location = b"//api.example.com/v1"
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_API_IP,),
        }
    )
    recorded = patch_request_once([_response(302, location=location)])

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    _assert_redacted(caught.value, location="//api.example.com/v1")
    _assert_redacted(caught.value, location="https://api.example.com/v1")
    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]


def test_credentials_are_never_stripped_and_continued_cross_origin(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    credentials = _credentials(start.origin)
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_API_IP,),
        }
    )
    recorded = patch_request_once(
        [
            _response(302, location=b"https://api.example.com/v1"),
            _response(200, body=b"should-not-be-requested"),
        ]
    )

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
            headers=_GENERIC_HEADERS,
        )

    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    assert len(recorded.calls) == 1
    assert recorded.calls[0].target.host == "example.com"
    assert recorded.calls[0].headers == _hop_headers(_GENERIC_HEADERS, credentials)
    assert all(call.target.host != "api.example.com" for call in recorded.calls)
    assert all(call.headers != _GENERIC_HEADERS for call in recorded.calls)


def test_resolve_allowed_redirect_runs_before_cross_origin_credential_error(
    patch_request_once: PatchRequestOnce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    credentials = _credentials(start.origin)
    location = "https://api.example.com/v1"
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_API_IP,),
        }
    )
    recorded = patch_request_once([_response(302, location=location.encode("ascii"))])
    redirect_calls: list[tuple[str, str]] = []
    original = resolve_allowed_redirect

    def _record_resolve(
        current: TargetUrl,
        location: str,
        allowed_origins: Collection[Origin],
    ) -> TargetUrl:
        redirect_calls.append((current.url, location))
        admitted = original(
            current=current,
            location=location,
            allowed_origins=allowed_origins,
        )
        assert admitted.origin != credentials.origin
        assert admitted.origin in allowed
        return admitted

    monkeypatch.setattr("boundary.transport.resolve_allowed_redirect", _record_resolve)

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    assert redirect_calls == [(start.url, location)]
    assert len(recorded.calls) == 1
    assert resolver.calls == [("example.com", 443)]


def test_out_of_scope_redirect_keeps_origin_not_allowed(
    patch_request_once: PatchRequestOnce,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin)
    location = "https://evil.test/phish"
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=location.encode("ascii"))])
    redirect_calls: list[str] = []
    original = resolve_allowed_redirect

    def _record_resolve(
        current: TargetUrl,
        location: str,
        allowed_origins: Collection[Origin],
    ) -> TargetUrl:
        redirect_calls.append(location)
        return original(
            current=current,
            location=location,
            allowed_origins=allowed_origins,
        )

    monkeypatch.setattr("boundary.transport.resolve_allowed_redirect", _record_resolve)

    with pytest.raises(ScopeValidationError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert caught.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
    assert not isinstance(caught.value, TransportError)
    _assert_redacted(caught.value, location=location)
    assert redirect_calls == [location]
    assert len(recorded.calls) == 1
    assert recorded.calls[0].headers == credentials.headers
    assert resolver.calls == [("example.com", 443)]


@pytest.mark.parametrize(
    ("location", "error_type", "error_code"),
    [
        (
            b"https://user:password@example.com/creds",
            UrlValidationError,
            UrlErrorCode.EMBEDDED_CREDENTIALS,
        ),
        (b"", UrlValidationError, UrlErrorCode.MALFORMED_URL),
        (b"#only", UrlValidationError, UrlErrorCode.MALFORMED_URL),
        (
            b"ftp://files.example.com/x",
            UrlValidationError,
            UrlErrorCode.UNSUPPORTED_SCHEME,
        ),
        (b"/login next", UrlValidationError, UrlErrorCode.UNSAFE_CHARACTER),
    ],
    ids=(
        "embedded_credentials",
        "empty",
        "fragment_only",
        "unsupported_scheme",
        "unsafe_character",
    ),
)
def test_unsafe_or_malformed_location_keeps_existing_url_error(
    patch_request_once: PatchRequestOnce,
    location: bytes,
    error_type: type[UrlValidationError],
    error_code: UrlErrorCode,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=location)])

    with pytest.raises(error_type) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert caught.value.code is error_code
    assert not isinstance(caught.value, TransportError)
    _assert_redacted(caught.value)
    if location:
        _assert_redacted(caught.value, location=location.decode("latin-1"))
    assert len(recorded.calls) == 1
    assert recorded.calls[0].headers == credentials.headers
    assert resolver.calls == [("example.com", 443)]


def test_multiple_location_headers_still_raise_invalid_redirect(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin)
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
        _run_with_credentials(
            start.url,
            allowed_origins={start.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    assert caught.value.code is TransportErrorCode.INVALID_REDIRECT
    _assert_redacted(caught.value, location="/first")
    _assert_redacted(caught.value, location="/second")
    assert len(recorded.calls) == 1
    assert recorded.calls[0].headers == credentials.headers


def test_cross_origin_error_message_states_origin_difference_without_location(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    allowed = _allowed("https://example.com/", "https://api.example.com/")
    credentials = _credentials(start.origin)
    location = "https://api.example.com/exfiltrate"
    resolver = RecordingResolver(
        {
            "example.com": (_EXAMPLE_IP,),
            "api.example.com": (_API_IP,),
        }
    )
    patch_request_once([_response(302, location=location.encode("ascii"))])

    with pytest.raises(TransportError) as caught:
        _run_with_credentials(
            start.url,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
            credentials=credentials,
        )

    message = str(caught.value)
    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    assert "origin" in message.lower()
    _assert_redacted(caught.value, location=location)
    _assert_redacted(caught.value, location="/exfiltrate")
    _assert_no_secrets(repr(credentials))
    _assert_no_header_names(repr(credentials))
    _assert_no_secrets(str(credentials))


def test_credentialed_redirect_without_location_returns_normally(
    patch_request_once: PatchRequestOnce,
) -> None:
    start = parse_target_url("https://example.com/start")
    credentials = _credentials(start.origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, body=b"no location")])

    response = _run_with_credentials(
        start.url,
        allowed_origins={start.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
        credentials=credentials,
    )

    assert response.status == 302
    assert response.body == b"no location"
    assert response.final_target is recorded.calls[0].target
    assert response.final_target == start
    assert recorded.calls[0].headers == credentials.headers
    assert len(recorded.calls) == 1
