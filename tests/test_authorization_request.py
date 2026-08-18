"""Offline tests for request_as and caller-side response evidence capture (Slice C)."""

from __future__ import annotations

import asyncio
import inspect
import socket
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, fields
from typing import Any, Protocol, cast, get_type_hints

import anyio
import pytest

from boundary.authorization import Identity, request_as
from boundary.evidence import ResponseEvidence, capture_response_evidence
from boundary.scope import (
    AddressPolicy,
    AddressResolver,
    Origin,
    ScopeErrorCode,
    ScopeValidationError,
    TargetUrl,
    parse_target_url,
)
from boundary.transport import (
    OriginBoundCredentials,
    RequestLimits,
    TransportError,
    TransportErrorCode,
    TransportResponse,
    request_with_redirects,
)

_EXAMPLE_IP = "93.184.216.34"
_API_IP = "93.184.216.35"
_AUTH_VALUE = b"Bearer SUPERSECRET_AUTH_TOKEN_aaa"
_COOKIE_VALUE = b"session=SUPERSECRET_COOKIE_VALUE_bbb"
_ASCII_BODY = b"hello"
_ASCII_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
_SECRET_MARKERS = (
    "SUPERSECRET_AUTH_TOKEN_aaa",
    "SUPERSECRET_COOKIE_VALUE_bbb",
    _AUTH_VALUE.decode("ascii"),
    _COOKIE_VALUE.decode("ascii"),
)
_REQUEST_AS_PARAMETERS = (
    "target",
    "identity",
    "credentials",
    "allowed_origins",
    "policy",
    "resolver",
    "limits",
    "max_redirects",
)
_FORBIDDEN_REQUEST_AS_PARAMETERS = (
    "method",
    "headers",
    "header",
    "body",
    "content",
    "json",
    "data",
    "host",
    "case",
    "baseline",
    "comparison",
)
_SPECULATIVE_AUTHORIZATION_NAMES = (
    "AuthorizationEngine",
    "CredentialVault",
    "SecretManager",
    "CookieJar",
    "LoginClient",
    "SessionStore",
    "AuthorizationResponse",
    "IdentityResponse",
    "RequestAsResult",
)
_ALTERNATE_CLIENT_MARKERS = (
    "httpx",
    "aiohttp",
    "urllib.request",
    "httpcore",
    "request_once(",
    "crawl(",
)


@dataclass(frozen=True, slots=True)
class RequestWithRedirectsCall:
    """One recorded request_with_redirects invocation."""

    target: TargetUrl
    allowed_origins: Collection[Origin]
    policy: AddressPolicy
    resolver: AddressResolver
    limits: RequestLimits
    max_redirects: int
    method: str
    headers: tuple[tuple[bytes, bytes], ...]
    credentials: OriginBoundCredentials | None


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


class RequestWithRedirectsFn(Protocol):
    async def __call__(
        self,
        target: TargetUrl,
        *,
        allowed_origins: Collection[Origin],
        policy: AddressPolicy,
        resolver: AddressResolver,
        limits: RequestLimits,
        max_redirects: int,
        method: str = "GET",
        headers: Collection[tuple[bytes, bytes]] = (),
        credentials: OriginBoundCredentials | None = None,
    ) -> TransportResponse: ...


class RecordingRequestWithRedirects:
    """Spy that records request_with_redirects arguments and calls through."""

    def __init__(self, inner: RequestWithRedirectsFn) -> None:
        self._inner = inner
        self.calls: list[RequestWithRedirectsCall] = []

    async def __call__(
        self,
        target: TargetUrl,
        *,
        allowed_origins: Collection[Origin],
        policy: AddressPolicy,
        resolver: AddressResolver,
        limits: RequestLimits,
        max_redirects: int,
        method: str = "GET",
        headers: Collection[tuple[bytes, bytes]] = (),
        credentials: OriginBoundCredentials | None = None,
    ) -> TransportResponse:
        self.calls.append(
            RequestWithRedirectsCall(
                target=target,
                allowed_origins=allowed_origins,
                policy=policy,
                resolver=resolver,
                limits=limits,
                max_redirects=max_redirects,
                method=method,
                headers=tuple(headers),
                credentials=credentials,
            )
        )
        return await self._inner(
            target,
            allowed_origins=allowed_origins,
            policy=policy,
            resolver=resolver,
            limits=limits,
            max_redirects=max_redirects,
            method=method,
            headers=headers,
            credentials=credentials,
        )


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
    body: bytes = b"",
    extra_headers: tuple[tuple[bytes, bytes], ...] = (),
) -> _ScriptedResponse:
    headers: list[tuple[bytes, bytes]] = list(extra_headers)
    if location is not None:
        headers.append((b"Location", location))
    return _ScriptedResponse(status=status, headers=tuple(headers), body=body)


def _origin(url: str = "https://example.com/") -> Origin:
    return parse_target_url(url).origin


def _target(url: str = "https://example.com/resource") -> TargetUrl:
    return parse_target_url(url)


def _identity(identity_id: str = "user-a") -> Identity:
    return Identity(identity_id=identity_id)


def _credentials(
    origin: Origin | None = None,
    headers: Collection[tuple[bytes, bytes]] = ((b"Authorization", _AUTH_VALUE),),
) -> OriginBoundCredentials:
    return OriginBoundCredentials(
        origin=_origin() if origin is None else origin,
        headers=tuple(headers),
    )


def _allowed(*urls: str) -> set[Origin]:
    return {parse_target_url(url).origin for url in urls}


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("request_as must not perform network activity")


def _assert_no_secrets(text: str) -> None:
    lowered = text.lower()
    for marker in _SECRET_MARKERS:
        assert marker.lower() not in lowered
        assert marker not in text


def _capture(
    response: TransportResponse,
    *,
    requested_target: TargetUrl,
) -> ResponseEvidence:
    return capture_response_evidence(response, requested_target=requested_target)


def _request_as(
    *,
    target: TargetUrl,
    identity: Identity,
    credentials: OriginBoundCredentials | None,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: AddressResolver,
    limits: RequestLimits,
    max_redirects: int,
) -> TransportResponse:
    response: TransportResponse = asyncio.run(
        request_as(
            target,
            identity,
            credentials=credentials,
            allowed_origins=allowed_origins,
            policy=policy,
            resolver=resolver,
            limits=limits,
            max_redirects=max_redirects,
        )
    )
    return response


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if request_as tests perform DNS, TCP, or discovery I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.resolve",
        _reject_network,
    )


@pytest.fixture(autouse=True)
def crawl_guard(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Fail immediately if request_as reaches crawl."""
    calls: list[object] = []

    def _reject_crawl(*args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))
        raise AssertionError("request_as must not call crawl")

    monkeypatch.setattr("boundary.discovery.crawl", _reject_crawl)
    monkeypatch.setattr("boundary.authorization.crawl", _reject_crawl, raising=False)
    return calls


@pytest.fixture(autouse=True)
def capture_guard(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Fail if request_as itself calls capture_response_evidence."""
    calls: list[object] = []

    def _reject_capture(*args: object, **kwargs: object) -> ResponseEvidence:
        calls.append((args, kwargs))
        raise AssertionError("request_as must not capture response evidence")

    monkeypatch.setattr(
        "boundary.evidence.capture_response_evidence",
        _reject_capture,
    )
    monkeypatch.setattr(
        "boundary.authorization.capture_response_evidence",
        _reject_capture,
        raising=False,
    )
    return calls


@pytest.fixture(autouse=True)
def recorded_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> RecordingRequestWithRedirects:
    """Record request_with_redirects arguments without replacing Transport."""
    recorded = RecordingRequestWithRedirects(request_with_redirects)
    monkeypatch.setattr("boundary.transport.request_with_redirects", recorded)
    monkeypatch.setattr(
        "boundary.authorization.request_with_redirects",
        recorded,
        raising=False,
    )
    return recorded


@pytest.fixture
def patch_request_once(monkeypatch: pytest.MonkeyPatch) -> PatchRequestOnce:
    """Install a RecordingRequestOnce in place of the real request_once."""

    def install(
        responses: Sequence[_ScriptedResponse | BaseException],
    ) -> RecordingRequestOnce:
        recorded = RecordingRequestOnce(responses)
        monkeypatch.setattr("boundary.transport.request_once", recorded)
        monkeypatch.setattr(
            "boundary.authorization.request_once",
            recorded,
            raising=False,
        )
        return recorded

    return install


def test_request_as_lives_on_the_authorization_module() -> None:
    import boundary.authorization as authorization

    assert authorization.request_as is request_as
    module = inspect.getmodule(request_as)
    assert module is not None
    assert module.__name__ == "boundary.authorization"
    for name in _SPECULATIVE_AUTHORIZATION_NAMES:
        assert not hasattr(authorization, name)


def test_request_as_signature_matches_the_approved_contract() -> None:
    signature = inspect.signature(request_as)
    parameters = signature.parameters

    assert tuple(parameters) == _REQUEST_AS_PARAMETERS
    assert parameters["target"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameters["identity"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    for name in _REQUEST_AS_PARAMETERS[2:]:
        assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
    for parameter in parameters.values():
        assert parameter.default is inspect.Parameter.empty
    for forbidden in _FORBIDDEN_REQUEST_AS_PARAMETERS:
        assert forbidden not in parameters


def test_request_as_type_hints_resolve() -> None:
    hints = get_type_hints(request_as)

    assert hints["target"] is TargetUrl
    assert hints["identity"] is Identity
    assert hints["credentials"] == OriginBoundCredentials | None
    assert hints["policy"] is AddressPolicy
    assert hints["resolver"] is AddressResolver
    assert hints["limits"] is RequestLimits
    assert hints["max_redirects"] is int
    assert hints["return"] is TransportResponse


def test_request_as_is_async() -> None:
    assert inspect.iscoroutinefunction(request_as)
    assert inspect.isfunction(request_as)


def test_authorization_module_does_not_import_discovery_or_passive() -> None:
    import boundary.authorization as authorization

    source = inspect.getsource(authorization)
    lowered = source.lower()
    assert "boundary.discovery" not in source
    assert "boundary.passive" not in source
    assert "httpx" not in lowered
    assert "aiohttp" not in lowered
    assert "httpcore" not in lowered
    assert "urllib.request" not in lowered


def test_request_as_uses_request_with_redirects_not_alternate_clients() -> None:
    source = inspect.getsource(request_as)
    lowered = source.lower()

    assert "request_with_redirects(" in source
    for marker in _ALTERNATE_CLIENT_MARKERS:
        assert marker not in source
        assert marker not in lowered


def test_credentials_argument_is_required(
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    request = cast(Any, request_as)

    with pytest.raises(TypeError):
        asyncio.run(
            request(
                _target(),
                _identity(),
                allowed_origins=_allowed("https://example.com/"),
                policy=AddressPolicy.PUBLIC,
                resolver=RecordingResolver({"example.com": (_EXAMPLE_IP,)}),
                limits=_limits(),
                max_redirects=5,
            )
        )

    assert recorded_redirects.calls == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD"])
def test_non_get_method_argument_is_rejected_before_io(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
    method: str,
) -> None:
    recorded = patch_request_once([])
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    request = cast(Any, request_as)

    with pytest.raises(TypeError):
        asyncio.run(
            request(
                _target(),
                _identity(),
                credentials=None,
                allowed_origins=_allowed("https://example.com/"),
                policy=AddressPolicy.PUBLIC,
                resolver=resolver,
                limits=_limits(),
                max_redirects=5,
                method=method,
            )
        )

    assert recorded.calls == []
    assert recorded_redirects.calls == []
    assert resolver.calls == []


def test_anonymous_request_as_delegates_one_get_without_credentials(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
    crawl_guard: list[object],
    capture_guard: list[object],
) -> None:
    target = _target()
    identity = _identity("anonymous")
    allowed = {target.origin}
    policy = AddressPolicy.PUBLIC
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    limits = _limits()
    recorded = patch_request_once([_response(200, body=_ASCII_BODY)])

    response = _request_as(
        target=target,
        identity=identity,
        credentials=None,
        allowed_origins=allowed,
        policy=policy,
        resolver=resolver,
        limits=limits,
        max_redirects=5,
    )

    assert type(response) is TransportResponse
    assert response.status == 200
    assert response.body == _ASCII_BODY
    assert len(recorded_redirects.calls) == 1
    call = recorded_redirects.calls[0]
    assert call.target is target
    assert call.allowed_origins is allowed
    assert call.policy is policy
    assert call.resolver is resolver
    assert call.limits is limits
    assert call.max_redirects == 5
    assert call.method == "GET"
    assert call.headers == ()
    assert call.credentials is None
    assert len(recorded.calls) == 1
    assert recorded.calls[0].method == "GET"
    assert crawl_guard == []
    assert capture_guard == []


def test_credentialed_request_as_forwards_origin_bound_credentials(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target()
    identity = _identity("user-a")
    credentials = _credentials(
        target.origin,
        ((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE)),
    )
    allowed = {target.origin}
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    limits = _limits()
    recorded = patch_request_once([_response(200, body=_ASCII_BODY)])

    response = _request_as(
        target=target,
        identity=identity,
        credentials=credentials,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=limits,
        max_redirects=2,
    )

    assert type(response) is TransportResponse
    assert len(recorded_redirects.calls) == 1
    call = recorded_redirects.calls[0]
    assert call.target is target
    assert call.credentials is credentials
    assert call.method == "GET"
    assert call.headers == ()
    assert call.max_redirects == 2
    assert call.limits is limits
    assert len(recorded.calls) == 1
    assert recorded.calls[0].method == "GET"


def test_request_as_does_not_require_anonymous_identity_id(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target()
    identity = _identity("user-b")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    patch_request_once([_response(200, body=b"ok")])

    response = _request_as(
        target=target,
        identity=identity,
        credentials=None,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 200
    assert recorded_redirects.calls[0].credentials is None
    assert identity.identity_id == "user-b"


def test_identity_is_not_serialized_onto_the_wire(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target()
    identity = _identity("user-a")
    credentials = _credentials(target.origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(200, body=b"ok")])

    _request_as(
        target=target,
        identity=identity,
        credentials=credentials,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    call = recorded_redirects.calls[0]
    assert not hasattr(call, "identity")
    assert "identity" not in inspect.signature(request_with_redirects).parameters
    wire = b"".join(name + value for name, value in recorded.calls[0].headers)
    assert identity.identity_id.encode("ascii") not in wire
    assert b"user-a" not in wire


def test_request_as_does_not_call_crawl_or_perform_extra_requests(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
    crawl_guard: list[object],
) -> None:
    target = _target()
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(200, body=b"ok"),
            _response(200, body=b"should-not-be-requested"),
        ]
    )

    response = _request_as(
        target=target,
        identity=_identity("anonymous"),
        credentials=None,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert response.status == 200
    assert len(recorded_redirects.calls) == 1
    assert [call.target.url for call in recorded.calls] == [target.url]
    assert crawl_guard == []


def test_request_as_does_not_expand_the_requested_target(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target("https://example.com/resource?id=1")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(200, body=b"ok")])

    _request_as(
        target=target,
        identity=_identity(),
        credentials=None,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert recorded_redirects.calls[0].target is target
    assert recorded_redirects.calls[0].target.url == "https://example.com/resource?id=1"
    assert [call.target.url for call in recorded.calls] == [target.url]


def test_request_as_does_not_mutate_inputs(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = _target()
    identity = _identity("user-a")
    credential_headers = (
        (b"Authorization", _AUTH_VALUE),
        (b"Cookie", _COOKIE_VALUE),
    )
    credentials = _credentials(target.origin, credential_headers)
    allowed = {target.origin}
    allowed_snapshot = set(allowed)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    limits = _limits()
    patch_request_once([_response(200, body=b"ok")])

    _request_as(
        target=target,
        identity=identity,
        credentials=credentials,
        allowed_origins=allowed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=limits,
        max_redirects=5,
    )

    assert identity.identity_id == "user-a"
    assert credentials.headers == credential_headers
    assert allowed == allowed_snapshot
    assert target.url == "https://example.com/resource"
    assert limits.max_body_bytes == 1024


def test_request_as_does_not_capture_evidence_itself(
    patch_request_once: PatchRequestOnce,
    capture_guard: list[object],
) -> None:
    target = _target()
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    patch_request_once([_response(200, body=_ASCII_BODY)])

    response = _request_as(
        target=target,
        identity=_identity(),
        credentials=None,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )

    assert type(response) is TransportResponse
    assert response.body == _ASCII_BODY
    assert response.headers == ()
    assert capture_guard == []


def test_caller_captures_response_evidence_from_returned_transport_response(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = _target()
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    patch_request_once(
        [
            _response(
                200,
                body=_ASCII_BODY,
                extra_headers=((b"Set-Cookie", _COOKIE_VALUE),),
            )
        ]
    )

    response = _request_as(
        target=target,
        identity=_identity(),
        credentials=None,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )
    evidence = _capture(response, requested_target=target)

    assert type(evidence) is ResponseEvidence
    assert evidence.requested_target is target
    assert evidence.final_target is response.final_target
    assert evidence.status == response.status
    assert evidence.body_length == len(response.body)
    assert evidence.body_sha256 == _ASCII_SHA256
    assert evidence == capture_response_evidence(
        response,
        requested_target=target,
    )


def test_requested_target_stays_the_original_target_after_same_origin_redirect(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = _target("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once(
        [
            _response(302, location=b"/final", body=b"redirect"),
            _response(200, body=_ASCII_BODY),
        ]
    )

    response = _request_as(
        target=target,
        identity=_identity(),
        credentials=None,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )
    evidence = _capture(response, requested_target=target)

    assert response.final_target is recorded.calls[-1].target
    assert response.final_target.url == "https://example.com/final"
    assert evidence.requested_target is target
    assert evidence.requested_target.url == "https://example.com/start"
    assert evidence.final_target is response.final_target
    assert evidence.final_target.url == "https://example.com/final"
    assert evidence.final_target is not target


def test_status_length_and_digest_come_only_from_response_evidence_capture(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = _target()
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    body = _ASCII_BODY
    patch_request_once(
        [
            _response(
                404,
                body=body,
                extra_headers=((b"content-length", b"9999"),),
            )
        ]
    )

    response = _request_as(
        target=target,
        identity=_identity(),
        credentials=None,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )
    evidence = _capture(response, requested_target=target)

    assert evidence.status == 404
    assert evidence.status == response.status
    assert evidence.body_length == len(body)
    assert evidence.body_length != 9999
    assert evidence.body_sha256 == _ASCII_SHA256
    assert tuple(field.name for field in fields(evidence)) == (
        "status",
        "final_target",
        "requested_target",
        "body_length",
        "body_sha256",
    )


def test_captured_authorization_result_does_not_retain_body_or_headers(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = _target()
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    headers = (
        (b"Set-Cookie", _COOKIE_VALUE),
        (b"X-Trace", b"abc"),
    )
    patch_request_once([_response(200, body=_ASCII_BODY, extra_headers=headers)])

    response = _request_as(
        target=target,
        identity=_identity(),
        credentials=None,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )
    evidence = _capture(response, requested_target=target)
    field_names = {field.name for field in fields(evidence)}
    public_names = {name for name in dir(evidence) if not name.startswith("_")}

    assert response.body == _ASCII_BODY
    assert (b"Set-Cookie", _COOKIE_VALUE) in response.headers
    assert "headers" not in field_names
    assert "body" not in field_names
    assert "raw" not in field_names
    assert "excerpt" not in field_names
    assert "headers" not in public_names
    assert "body" not in public_names
    _assert_no_secrets(repr(evidence))
    _assert_no_secrets(str(evidence))


def test_credentials_do_not_enter_response_evidence_or_identity(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = _target()
    identity = _identity("user-a")
    credentials = _credentials(
        target.origin,
        ((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE)),
    )
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    patch_request_once(
        [
            _response(
                200,
                body=b"password=supersecret-body-token",
                extra_headers=((b"Set-Cookie", _COOKIE_VALUE),),
            )
        ]
    )

    response = _request_as(
        target=target,
        identity=identity,
        credentials=credentials,
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )
    evidence = _capture(response, requested_target=target)
    surface = "\n".join(
        (
            repr(evidence),
            str(evidence),
            repr(identity),
            str(identity),
            identity.identity_id,
        )
    )

    assert "headers" not in {field.name for field in fields(evidence)}
    assert "credentials" not in {field.name for field in fields(identity)}
    _assert_no_secrets(surface)
    _assert_no_secrets(repr(credentials))


def test_identity_metadata_remains_available_for_later_comparison(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = _target()
    identity = _identity("user-a")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    patch_request_once([_response(200, body=_ASCII_BODY)])

    response = _request_as(
        target=target,
        identity=identity,
        credentials=_credentials(target.origin),
        allowed_origins={target.origin},
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        limits=_limits(),
        max_redirects=5,
    )
    evidence = _capture(response, requested_target=target)

    assert identity.identity_id == "user-a"
    assert identity == Identity(identity_id="user-a")
    assert evidence.requested_target is target
    assert {field.name for field in fields(identity)} == {"identity_id"}


def test_scope_origin_not_allowed_propagates_without_synthetic_response(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target("https://example.com/private")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(200, body=b"should-not-be-requested")])
    result: TransportResponse | None = None

    with pytest.raises(ScopeValidationError) as caught:
        result = _request_as(
            target=target,
            identity=_identity(),
            credentials=None,
            allowed_origins=_allowed("https://other.test/"),
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert result is None
    assert caught.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
    assert not isinstance(caught.value, TransportError)
    assert recorded.calls == []
    assert resolver.calls == []
    assert len(recorded_redirects.calls) <= 1


def test_transport_error_propagates_without_retry_or_fallback(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target()
    credentials = _credentials(target.origin)
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    error = TransportError(
        TransportErrorCode.RESPONSE_TOO_LARGE,
        "Response body exceeds the configured limit.",
    )
    recorded = patch_request_once(
        [
            error,
            _response(200, body=b"should-not-be-requested"),
        ]
    )
    result: TransportResponse | None = None

    with pytest.raises(TransportError) as caught:
        result = _request_as(
            target=target,
            identity=_identity(),
            credentials=credentials,
            allowed_origins={target.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert result is None
    assert caught.value is error
    assert caught.value.code is TransportErrorCode.RESPONSE_TOO_LARGE
    assert len(recorded.calls) == 1
    assert len(recorded_redirects.calls) == 1
    assert recorded_redirects.calls[0].credentials is credentials
    _assert_no_secrets(str(caught.value))


def test_resolver_exception_propagates_without_benign_response(
    patch_request_once: PatchRequestOnce,
) -> None:
    target = _target()
    resolver = RecordingResolver(error=RuntimeError("dns unavailable"))
    recorded = patch_request_once([_response(200, body=b"should-not-be-requested")])
    result: TransportResponse | None = None

    with pytest.raises(RuntimeError, match="dns unavailable") as caught:
        result = _request_as(
            target=target,
            identity=_identity(),
            credentials=None,
            allowed_origins={target.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert result is None
    assert str(caught.value) == "dns unavailable"
    assert recorded.calls == []
    assert resolver.calls == [("example.com", 443)]


def test_credential_origin_mismatch_propagates_before_network_io(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target("https://example.com/start")
    credentials = _credentials(_origin("https://api.example.com/"))
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([])
    result: TransportResponse | None = None

    with pytest.raises(ValueError) as caught:
        result = _request_as(
            target=target,
            identity=_identity(),
            credentials=credentials,
            allowed_origins={target.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert result is None
    assert not isinstance(caught.value, TransportError)
    assert "origin" in str(caught.value).lower()
    _assert_no_secrets(str(caught.value))
    _assert_no_secrets(repr(caught.value))
    assert recorded.calls == []
    assert resolver.calls == []
    assert len(recorded_redirects.calls) <= 1
    if recorded_redirects.calls:
        assert recorded_redirects.calls[0].credentials is credentials


def test_cross_origin_credential_redirect_propagates_as_transport_failure(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target("https://example.com/start")
    credentials = _credentials(target.origin)
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
            _response(200, body=b"should-not-be-requested"),
        ]
    )
    result: TransportResponse | None = None

    with pytest.raises(TransportError) as caught:
        result = _request_as(
            target=target,
            identity=_identity(),
            credentials=credentials,
            allowed_origins=allowed,
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=5,
        )

    assert result is None
    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    assert len(recorded.calls) == 1
    assert recorded.calls[0].target.url == target.url
    assert len(recorded_redirects.calls) == 1
    assert recorded_redirects.calls[0].credentials is credentials
    assert ("api.example.com", 443) not in resolver.calls
    _assert_no_secrets(str(caught.value))


def test_max_redirects_is_forwarded_and_not_swallowed(
    patch_request_once: PatchRequestOnce,
    recorded_redirects: RecordingRequestWithRedirects,
) -> None:
    target = _target("https://example.com/start")
    resolver = RecordingResolver({"example.com": (_EXAMPLE_IP,)})
    recorded = patch_request_once([_response(302, location=b"/next")])
    result: TransportResponse | None = None

    with pytest.raises(TransportError) as caught:
        result = _request_as(
            target=target,
            identity=_identity(),
            credentials=None,
            allowed_origins={target.origin},
            policy=AddressPolicy.PUBLIC,
            resolver=resolver,
            limits=_limits(),
            max_redirects=0,
        )

    assert result is None
    assert caught.value.code is TransportErrorCode.TOO_MANY_REDIRECTS
    assert recorded_redirects.calls[0].max_redirects == 0
    assert len(recorded.calls) == 1
