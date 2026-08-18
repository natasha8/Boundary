"""Offline tests for passive scan orchestration (Slice B)."""

from __future__ import annotations

import asyncio
import inspect
import socket
from collections.abc import AsyncIterator, Callable, Collection, Mapping, Sequence
from dataclasses import MISSING, FrozenInstanceError, dataclass, fields
from typing import Any, Protocol, get_type_hints

import anyio
import pytest

from boundary.discovery import DiscoveredPage, DiscoveryLimits
from boundary.discovery import crawl as real_crawl
from boundary.evidence import FindingEvidence, ResponseEvidence
from boundary.evidence import capture_response_evidence as real_capture
from boundary.passive import PassiveFinding
from boundary.passive import scan_page as real_scan_page
from boundary.scan import ScanConfig, ScanResult, run_passive_scan
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
    RequestLimits,
    TransportError,
    TransportErrorCode,
    TransportResponse,
)

_APP_IP = "93.184.216.34"
_PRIVATE_IP = "192.168.1.10"
_PROTECTED_CSP = b"default-src 'self'; frame-ancestors 'none'"
_SCAN_RESULT_FIELDS = ("findings",)
_SPECULATIVE_SCAN_NAMES = (
    "ScanEngine",
    "Orchestrator",
    "ScanProfile",
    "CredentialVault",
    "SecretManager",
    "CookieJar",
    "ReportSerializer",
    "ResultStore",
)
_FORBIDDEN_RESULT_FIELDS = (
    "pages",
    "page",
    "pages_visited",
    "body",
    "headers",
    "response",
    "config",
    "run_id",
    "timestamp",
    "duration",
    "report",
    "sarif",
    "json",
    "markdown",
    "credentials",
    "identity",
    "authorization",
    "observations",
    "severity",
    "cvss",
    "confidence",
)
_FORBIDDEN_RESULT_KWARGS = (
    "pages",
    "body",
    "headers",
    "config",
    "run_id",
    "report",
    "credentials",
)
_SECRET_MARKERS = (
    "SUPERSECRET_AUTH_TOKEN_aaa",
    "SUPERSECRET_COOKIE_VALUE_bbb",
    "SUPERSECRET_BODY",
)
_SECRET_HEADERS = (
    (b"set-cookie", b"session=SUPERSECRET_COOKIE_VALUE_bbb; Secure; SameSite=Lax"),
    (b"www-authenticate", b"Bearer SUPERSECRET_AUTH_TOKEN_aaa"),
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


class Recorders:
    """Thin wrappers that call real crawl, scan_page, capture, and FindingEvidence."""

    def __init__(self) -> None:
        self.crawl_calls: list[dict[str, object]] = []
        self.events: list[tuple[object, ...]] = []
        self.yielded_pages: list[DiscoveredPage] = []
        self.scan_page_calls: list[DiscoveredPage] = []
        self.scan_page_returns: list[tuple[PassiveFinding, ...]] = []
        self.capture_calls: list[tuple[TransportResponse, TargetUrl]] = []
        self.capture_returned: list[ResponseEvidence] = []
        self.finding_evidence_calls: list[tuple[PassiveFinding, ResponseEvidence]] = []
        self.scan_pages_calls = 0

    async def crawl(
        self,
        seed: TargetUrl,
        *,
        allowed_origins: Collection[Origin],
        policy: AddressPolicy,
        resolver: AddressResolver,
        request_limits: RequestLimits,
        max_redirects: int,
        limits: DiscoveryLimits,
    ) -> AsyncIterator[DiscoveredPage]:
        self.crawl_calls.append(
            {
                "seed": seed,
                "allowed_origins": allowed_origins,
                "policy": policy,
                "resolver": resolver,
                "request_limits": request_limits,
                "max_redirects": max_redirects,
                "limits": limits,
            }
        )
        async for page in real_crawl(
            seed,
            allowed_origins=allowed_origins,
            policy=policy,
            resolver=resolver,
            request_limits=request_limits,
            max_redirects=max_redirects,
            limits=limits,
        ):
            self.yielded_pages.append(page)
            self.events.append(("yield", page))
            yield page

    def scan_page(self, page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
        self.scan_page_calls.append(page)
        self.events.append(("scan_page", page))
        findings = real_scan_page(page)
        self.scan_page_returns.append(findings)
        return findings

    def capture_response_evidence(
        self,
        response: TransportResponse,
        *,
        requested_target: TargetUrl,
    ) -> ResponseEvidence:
        self.capture_calls.append((response, requested_target))
        self.events.append(("capture", response, requested_target))
        evidence = real_capture(response, requested_target=requested_target)
        self.capture_returned.append(evidence)
        return evidence

    def finding_evidence(self, *args: object, **kwargs: object) -> FindingEvidence:
        bound = inspect.signature(FindingEvidence).bind(*args, **kwargs)
        finding = bound.arguments["finding"]
        response = bound.arguments["response"]
        assert isinstance(finding, PassiveFinding)
        assert isinstance(response, ResponseEvidence)
        self.events.append(("FindingEvidence", finding, response))
        paired = FindingEvidence(finding, response)
        self.finding_evidence_calls.append((finding, response))
        return paired

    def scan_pages(self, *args: object, **kwargs: object) -> None:
        self.scan_pages_calls += 1
        raise AssertionError("run_passive_scan must not call scan_pages")

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        replacements = {
            "crawl": self.crawl,
            "scan_page": self.scan_page,
            "scan_pages": self.scan_pages,
            "capture_response_evidence": self.capture_response_evidence,
            "FindingEvidence": self.finding_evidence,
        }
        origins = {
            "crawl": "boundary.discovery.crawl",
            "scan_page": "boundary.passive.scan_page",
            "scan_pages": "boundary.passive.scan_pages",
            "capture_response_evidence": "boundary.evidence.capture_response_evidence",
            "FindingEvidence": "boundary.evidence.FindingEvidence",
        }
        scan = inspect.getmodule(ScanConfig)
        assert scan is not None
        for name, value in replacements.items():
            monkeypatch.setattr(origins[name], value)
            if hasattr(scan, name):
                monkeypatch.setattr(scan, name, value)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_request_as(*args: object, **kwargs: object) -> None:
    raise AssertionError("run_passive_scan must not call request_as")


def _reject_system_resolver_init(self: object, *args: object, **kwargs: object) -> None:
    raise AssertionError("run_passive_scan must not construct SystemAddressResolver")


@pytest.fixture(autouse=True)
def _reject_dns_and_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if a test reaches DNS, sockets, or authorization."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)
    monkeypatch.setattr("boundary.authorization.request_as", _reject_request_as)
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.resolve",
        _reject_socket_getaddrinfo,
    )
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.__init__",
        _reject_system_resolver_init,
    )


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


@pytest.fixture
def recorders(monkeypatch: pytest.MonkeyPatch) -> Recorders:
    installed = Recorders()
    installed.install(monkeypatch)
    return installed


def _assert_no_secrets(text: str) -> None:
    lowered = text.lower()
    for marker in _SECRET_MARKERS:
        assert marker.lower() not in lowered
        assert marker not in text


def _target(url: str = "https://app.test/") -> TargetUrl:
    return parse_target_url(url)


def _request_limits() -> RequestLimits:
    return RequestLimits(
        max_body_bytes=65536,
        connect_timeout=1.0,
        read_timeout=2.0,
        write_timeout=3.0,
        pool_timeout=4.0,
    )


def _discovery_limits(
    *,
    max_pages: int = 8,
    max_depth: int = 2,
) -> DiscoveryLimits:
    return DiscoveryLimits(max_pages=max_pages, max_depth=max_depth)


def _app_resolver(*hosts: str) -> RecordingResolver:
    mapping = {host: (_APP_IP,) for host in hosts}
    mapping.setdefault("app.test", (_APP_IP,))
    return RecordingResolver(mapping)


def _config(
    *,
    target: TargetUrl | None = None,
    allowed_origins: tuple[Origin, ...] | None = None,
    policy: AddressPolicy = AddressPolicy.PUBLIC,
    resolver: RecordingResolver | None = None,
    request_limits: RequestLimits | None = None,
    max_redirects: int = 3,
    discovery_limits: DiscoveryLimits | None = None,
) -> ScanConfig:
    resolved_target = _target() if target is None else target
    return ScanConfig(
        target=resolved_target,
        allowed_origins=(
            (resolved_target.origin,) if allowed_origins is None else allowed_origins
        ),
        policy=policy,
        resolver=_app_resolver() if resolver is None else resolver,
        request_limits=_request_limits() if request_limits is None else request_limits,
        max_redirects=max_redirects,
        discovery_limits=(
            _discovery_limits() if discovery_limits is None else discovery_limits
        ),
    )


def _html(*hrefs: str) -> bytes:
    anchors = "".join(f'<a href="{href}">x</a>' for href in hrefs)
    return (f"<html>password=SUPERSECRET_BODY<body>{anchors}</body></html>").encode()


def _with_secrets(
    headers: tuple[tuple[bytes, bytes], ...],
) -> tuple[tuple[bytes, bytes], ...]:
    return headers + _SECRET_HEADERS


def _insecure_html_headers() -> tuple[tuple[bytes, bytes], ...]:
    return _with_secrets(((b"content-type", b"text/html"),))


def _protected_html_headers() -> tuple[tuple[bytes, bytes], ...]:
    return _with_secrets(
        (
            (b"content-type", b"text/html"),
            (b"strict-transport-security", b"max-age=31536000"),
            (b"x-content-type-options", b"nosniff"),
            (b"content-security-policy", _PROTECTED_CSP),
        )
    )


def _json_headers() -> tuple[tuple[bytes, bytes], ...]:
    return _with_secrets(((b"content-type", b"application/json"),))


def _scripted(
    body: bytes = b"",
    *,
    status: int = 200,
    headers: tuple[tuple[bytes, bytes], ...] | None = None,
) -> _ScriptedResponse:
    return _ScriptedResponse(
        status=status,
        headers=_insecure_html_headers() if headers is None else headers,
        body=body if body else _html(),
    )


def _redirect(location: bytes, *, status: int = 302) -> _ScriptedResponse:
    return _ScriptedResponse(
        status=status,
        headers=((b"location", location),),
        body=b"",
    )


def _discovered_page(
    *,
    url: str = "https://app.test/",
    requested: str | None = None,
    headers: tuple[tuple[bytes, bytes], ...] | None = None,
    body: bytes | None = None,
) -> DiscoveredPage:
    final_target = parse_target_url(url)
    requested_target = (
        parse_target_url(requested) if requested is not None else final_target
    )
    return DiscoveredPage(
        target=requested_target,
        depth=0,
        response=TransportResponse(
            status=200,
            headers=_insecure_html_headers() if headers is None else headers,
            body=_html() if body is None else body,
            final_target=final_target,
        ),
    )


def _expected_finding_evidence(
    pages: Sequence[DiscoveredPage],
) -> tuple[FindingEvidence, ...]:
    items: list[FindingEvidence] = []
    for page in pages:
        findings = real_scan_page(page)
        if not findings:
            continue
        response = real_capture(page.response, requested_target=page.target)
        for finding in findings:
            items.append(FindingEvidence(finding, response))
    return tuple(items)


def _run(config: ScanConfig) -> ScanResult:
    return asyncio.run(run_passive_scan(config))


def _construct_result(*args: object, **kwargs: object) -> ScanResult:
    construct: Callable[..., ScanResult] = ScanResult
    return construct(*args, **kwargs)


def test_scan_result_and_run_passive_scan_live_on_the_scan_module() -> None:
    import boundary.scan as scan

    assert scan.ScanResult is ScanResult
    assert scan.run_passive_scan is run_passive_scan
    module = inspect.getmodule(ScanResult)
    assert module is not None
    assert module.__name__ == "boundary.scan"
    assert inspect.getmodule(run_passive_scan) is module
    for name in _SPECULATIVE_SCAN_NAMES:
        assert not hasattr(scan, name)
    source = inspect.getsource(scan)
    assert "boundary.authorization" not in source
    assert "scan_pages" not in source
    assert "request_as" not in source
    assert "request_once" not in source
    assert "request_with_redirects" not in source
    assert "sarif" not in source.lower()
    assert "markdown" not in source.lower()


def test_scan_result_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(ScanResult))

    assert names == _SCAN_RESULT_FIELDS
    for forbidden in _FORBIDDEN_RESULT_FIELDS:
        assert forbidden not in names


def test_scan_result_constructor_accepts_the_documented_field() -> None:
    parameters = list(inspect.signature(ScanResult).parameters)

    assert parameters == list(_SCAN_RESULT_FIELDS)
    parameter = inspect.signature(ScanResult).parameters["findings"]
    assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameter.default is inspect.Parameter.empty


def test_scan_result_has_no_hidden_field_defaults() -> None:
    for field in fields(ScanResult):
        assert field.default is MISSING
        assert field.default_factory is MISSING


def test_scan_result_type_hints_match_the_approved_contract() -> None:
    hints = get_type_hints(ScanResult)

    assert hints["findings"] == tuple[FindingEvidence, ...]


def test_scan_result_is_frozen_and_slotted() -> None:
    page = _discovered_page()
    findings = real_scan_page(page)
    assert findings
    response = real_capture(page.response, requested_target=page.target)
    result = ScanResult(findings=(FindingEvidence(findings[0], response),))
    frozen: Any = result

    with pytest.raises(FrozenInstanceError):
        frozen.findings = ()

    scan_result_type: Any = ScanResult
    dataclass_params = scan_result_type.__dataclass_params__
    assert dataclass_params.frozen is True
    assert dataclass_params.slots is True
    assert set(scan_result_type.__slots__) == set(_SCAN_RESULT_FIELDS)
    assert not hasattr(result, "__dict__")


def test_scan_result_accepts_positional_findings() -> None:
    result = ScanResult(())

    assert type(result.findings) is tuple
    assert result.findings == ()


def test_omitting_findings_raises_type_error() -> None:
    with pytest.raises(TypeError):
        _construct_result()


@pytest.mark.parametrize("extra", _FORBIDDEN_RESULT_KWARGS)
def test_forbidden_scan_result_constructor_keyword_is_rejected(extra: str) -> None:
    with pytest.raises(TypeError):
        _construct_result(findings=(), **{extra: None})


def test_scan_result_holds_no_page_body_header_or_runtime_fields() -> None:
    result = ScanResult(findings=())
    field_names = {field.name for field in fields(ScanResult)}
    public_names = {name for name in dir(result) if not name.startswith("_")}

    for forbidden in _FORBIDDEN_RESULT_FIELDS:
        assert forbidden not in field_names
        assert forbidden not in public_names

    assert not hasattr(ScanResult, "to_json")
    assert not hasattr(ScanResult, "to_sarif")
    assert not hasattr(ScanResult, "to_markdown")
    assert not hasattr(result, "pages")
    assert not hasattr(result, "body")
    assert not hasattr(result, "headers")


def test_run_passive_scan_signature_matches_the_approved_contract() -> None:
    parameters = list(inspect.signature(run_passive_scan).parameters)

    assert parameters == ["config"]
    parameter = inspect.signature(run_passive_scan).parameters["config"]
    assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameter.default is inspect.Parameter.empty
    assert inspect.iscoroutinefunction(run_passive_scan)
    assert not inspect.isasyncgenfunction(run_passive_scan)
    hints = get_type_hints(run_passive_scan)
    assert hints["config"] is ScanConfig
    assert hints["return"] is ScanResult
    names = run_passive_scan.__code__.co_names
    assert "scan_pages" not in names
    assert "request_as" not in names
    assert "request_once" not in names
    assert "request_with_redirects" not in names
    source = inspect.getsource(run_passive_scan)
    assert "except Exception" not in source


def test_run_passive_scan_calls_crawl_once_with_scan_config_fields(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    resolver = _app_resolver()
    target = _target("https://app.test/seed")
    allowed_origins = (target.origin, _target("https://other.test/").origin)
    request_limits = _request_limits()
    discovery_limits = _discovery_limits(max_pages=4, max_depth=0)
    config = _config(
        target=target,
        allowed_origins=allowed_origins,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=request_limits,
        max_redirects=7,
        discovery_limits=discovery_limits,
    )
    recorded_http = patch_request_once(
        {target.url: _scripted(headers=_protected_html_headers(), body=_html())}
    )

    result = _run(config)

    assert recorders.crawl_calls == [
        {
            "seed": target,
            "allowed_origins": allowed_origins,
            "policy": AddressPolicy.PUBLIC,
            "resolver": resolver,
            "request_limits": request_limits,
            "max_redirects": 7,
            "limits": discovery_limits,
        }
    ]
    assert recorders.crawl_calls[0]["seed"] is config.target
    assert recorders.crawl_calls[0]["allowed_origins"] is config.allowed_origins
    assert recorders.crawl_calls[0]["policy"] is config.policy
    assert recorders.crawl_calls[0]["resolver"] is config.resolver
    assert recorders.crawl_calls[0]["request_limits"] is config.request_limits
    assert recorders.crawl_calls[0]["limits"] is config.discovery_limits
    assert len(recorders.crawl_calls) == 1
    assert recorded_http.calls
    assert all(call.method == "GET" for call in recorded_http.calls)
    assert all(call.headers == () for call in recorded_http.calls)
    assert all(call.limits is request_limits for call in recorded_http.calls)
    assert type(result) is ScanResult
    assert result.findings == ()


def test_discovery_hops_are_uncredentialed_gets(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    child = _target("https://app.test/a")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    recorded_http = patch_request_once(
        {
            seed.url: _scripted(
                headers=_protected_html_headers(),
                body=_html("/a"),
            ),
            child.url: _scripted(headers=_json_headers(), body=b'{"ok":true}'),
        }
    )

    _run(config)

    assert [call.target.url for call in recorded_http.calls] == [seed.url, child.url]
    assert all(call.method == "GET" for call in recorded_http.calls)
    assert all(call.headers == () for call in recorded_http.calls)
    assert recorders.scan_pages_calls == 0


def test_pages_are_consumed_sequentially_in_crawl_order(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    child = _target("https://app.test/api")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    patch_request_once(
        {
            seed.url: _scripted(body=_html("/api")),
            child.url: _scripted(headers=_json_headers(), body=b'{"ok":true}'),
        }
    )

    result = _run(config)

    pages = tuple(recorders.yielded_pages)
    assert [page.target.url for page in pages] == [seed.url, child.url]
    assert recorders.scan_page_calls == list(pages)
    names = tuple(event[0] for event in recorders.events)
    first_yield = names.index("yield")
    first_scan = names.index("scan_page")
    second_yield = names.index("yield", first_yield + 1)
    second_scan = names.index("scan_page", first_scan + 1)
    assert first_yield < first_scan < second_yield < second_scan
    seed_findings = recorders.scan_page_returns[0]
    child_findings = recorders.scan_page_returns[1]
    assert seed_findings
    assert child_findings
    assert names.count("capture") == 2
    assert names.count("FindingEvidence") == len(seed_findings) + len(child_findings)
    assert [item.finding for item in result.findings] == [
        *seed_findings,
        *child_findings,
    ]


def test_scan_page_is_called_once_per_yielded_page(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    child = _target("https://app.test/a")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    patch_request_once(
        {
            seed.url: _scripted(
                headers=_protected_html_headers(),
                body=_html("/a"),
            ),
            child.url: _scripted(
                headers=_protected_html_headers(),
                body=_html(),
            ),
        }
    )

    _run(config)

    pages = recorders.yielded_pages
    assert len(pages) == 2
    assert recorders.scan_page_calls == pages
    assert all(
        call is page
        for call, page in zip(recorders.scan_page_calls, pages, strict=True)
    )
    assert recorders.scan_page_returns == [(), ()]
    assert recorders.capture_calls == []
    assert recorders.finding_evidence_calls == []


def test_clean_completed_crawl_returns_empty_findings_tuple(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once(
        {seed.url: _scripted(headers=_protected_html_headers(), body=_html("/a"))}
    )

    result = _run(config)

    assert type(result) is ScanResult
    assert type(result.findings) is tuple
    assert result.findings == ()
    assert recorders.yielded_pages
    assert real_scan_page(recorders.yielded_pages[0]) == ()
    assert recorders.capture_calls == []
    assert recorders.finding_evidence_calls == []
    assert recorders.scan_pages_calls == 0


def test_clean_pages_do_not_capture_evidence_and_scanning_continues(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    child = _target("https://app.test/api")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    patch_request_once(
        {
            seed.url: _scripted(
                headers=_protected_html_headers(),
                body=_html("/api"),
            ),
            child.url: _scripted(headers=_json_headers(), body=b'{"ok":true}'),
        }
    )

    result = _run(config)

    pages = recorders.yielded_pages
    assert [page.target.url for page in pages] == [seed.url, child.url]
    assert recorders.scan_page_calls == pages
    assert recorders.scan_page_returns[0] == ()
    assert recorders.scan_page_returns[1]
    assert recorders.capture_calls == [(pages[1].response, pages[1].target)]
    assert len(result.findings) == len(recorders.scan_page_returns[1])
    assert all(
        item.finding in recorders.scan_page_returns[1] for item in result.findings
    )
    assert all(
        item.response is recorders.capture_returned[0] for item in result.findings
    )


def test_page_with_findings_captures_evidence_once_using_page_target(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/start")
    final = _target("https://app.test/final")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once(
        {
            seed.url: _redirect(b"/final"),
            final.url: _scripted(headers=_json_headers(), body=b'{"ok":true}'),
        }
    )

    result = _run(config)

    page = recorders.yielded_pages[0]
    assert page.target is not page.response.final_target
    assert page.target.url == seed.url
    assert page.response.final_target.url == final.url
    findings = recorders.scan_page_returns[0]
    assert findings
    assert recorders.capture_calls == [(page.response, page.target)]
    assert recorders.capture_calls[0][1] is page.target
    captured = recorders.capture_returned[0]
    assert captured.requested_target.url == seed.url
    assert captured.final_target.url == final.url
    assert all(
        item.finding.requested_target.url == seed.url for item in result.findings
    )
    assert all(item.finding.target.url == final.url for item in result.findings)
    assert all(item.response is captured for item in result.findings)
    assert len(result.findings) == len(findings)


def test_one_response_evidence_is_reused_for_every_finding_from_the_page(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once({seed.url: _scripted(body=_html())})

    result = _run(config)

    findings = recorders.scan_page_returns[0]
    assert len(findings) > 1
    assert len(recorders.capture_returned) == 1
    shared = recorders.capture_returned[0]
    assert [item.response for item in result.findings] == [shared] * len(findings)
    assert result.findings[0].response is shared
    assert result.findings[1].response is shared
    assert [pair[1] for pair in recorders.finding_evidence_calls] == [shared] * len(
        findings
    )


def test_finding_evidence_pairs_each_scan_page_finding_with_the_captured_response(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once({seed.url: _scripted(body=_html())})

    result = _run(config)

    findings = recorders.scan_page_returns[0]
    shared = recorders.capture_returned[0]
    assert recorders.finding_evidence_calls == [
        (finding, shared) for finding in findings
    ]
    assert [item.finding for item in result.findings] == list(findings)
    assert type(result.findings[0]) is FindingEvidence
    assert type(result.findings) is tuple
    expected = _expected_finding_evidence(recorders.yielded_pages)
    assert result.findings == expected


def test_findings_preserve_crawl_order_then_scan_page_order(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    child = _target("https://app.test/api")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    patch_request_once(
        {
            seed.url: _scripted(body=_html("/api")),
            child.url: _scripted(headers=_json_headers(), body=b'{"ok":true}'),
        }
    )

    result = _run(config)

    expected_findings = [
        finding for findings in recorders.scan_page_returns for finding in findings
    ]
    assert [item.finding for item in result.findings] == expected_findings
    assert tuple(item.finding.rule_id for item in result.findings) == tuple(
        finding.rule_id for finding in expected_findings
    )
    assert result.findings == _expected_finding_evidence(recorders.yielded_pages)


def test_duplicate_finding_and_evidence_ids_are_retained_without_cross_page_dedup(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    alias_a = _target("https://app.test/alias-a")
    alias_b = _target("https://app.test/alias-b")
    final = _target("https://app.test/resource")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    final_body = b'{"ok":true}'
    patch_request_once(
        {
            seed.url: _scripted(
                headers=_protected_html_headers(),
                body=_html("/alias-a", "/alias-b"),
            ),
            alias_a.url: _redirect(b"/resource"),
            alias_b.url: _redirect(b"/resource"),
            final.url: _scripted(headers=_json_headers(), body=final_body),
        }
    )

    result = _run(config)

    assert [page.target.url for page in recorders.yielded_pages] == [
        seed.url,
        alias_a.url,
        alias_b.url,
    ]
    assert recorders.scan_page_returns[0] == ()
    first = result.findings[0]
    second = result.findings[1]
    assert len(result.findings) == 2
    assert first.finding.fingerprint == second.finding.fingerprint
    assert first.evidence_id == second.evidence_id
    assert first is not second
    assert first.finding.requested_target.url == alias_a.url
    assert second.finding.requested_target.url == alias_b.url
    assert first.finding.target.url == final.url
    assert second.finding.target.url == final.url
    assert recorders.scan_pages_calls == 0


def test_scan_pages_is_not_used(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once({seed.url: _scripted(body=_html())})

    _run(config)

    assert recorders.scan_pages_calls == 0
    source = inspect.getsource(run_passive_scan)
    assert "scan_pages" not in source


def test_authorization_and_direct_transport_entry_points_are_not_used(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once({seed.url: _scripted(body=_html())})
    scan = inspect.getmodule(ScanConfig)
    assert scan is not None
    if hasattr(scan, "request_as"):
        monkeypatch.setattr(scan, "request_as", _reject_request_as)

    result = _run(config)

    assert result.findings
    assert recorders.crawl_calls
    source = inspect.getsource(run_passive_scan)
    assert "request_as" not in source
    assert "request_once" not in source
    assert "request_with_redirects" not in source


def test_run_passive_scan_does_not_mutate_caller_inputs(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/resource?id=1")
    request_limits = _request_limits()
    discovery_limits = _discovery_limits(max_pages=1, max_depth=0)
    allowed_origins = (seed.origin,)
    config = _config(
        target=seed,
        allowed_origins=allowed_origins,
        request_limits=request_limits,
        discovery_limits=discovery_limits,
    )
    body = _html()
    headers = _insecure_html_headers()
    patch_request_once({seed.url: _scripted(body=body, headers=headers)})
    target_url = config.target.url
    max_redirects = config.max_redirects

    result = _run(config)

    assert config.target.url == target_url
    assert config.allowed_origins is allowed_origins
    assert config.max_redirects == max_redirects
    assert config.request_limits is request_limits
    assert config.discovery_limits is discovery_limits
    assert body == _html()
    assert headers == _insecure_html_headers()
    assert result.findings
    page = recorders.yielded_pages[0]
    assert page.response.body == body
    assert page.response.headers == headers


def test_query_string_tokens_remain_visible_on_returned_findings(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/resource?token=visible-query")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once(
        {seed.url: _scripted(headers=_json_headers(), body=b'{"ok":true}')}
    )

    result = _run(config)

    assert result.findings
    assert result.findings[0].finding.target.url == (
        "https://app.test/resource?token=visible-query"
    )
    assert "token=visible-query" in result.findings[0].finding.target.url
    assert "token=visible-query" in result.findings[0].finding.requested_target.url
    assert recorders.yielded_pages[0].target.url.endswith("token=visible-query")


def test_response_secrets_do_not_appear_in_scan_result(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once({seed.url: _scripted(body=_html())})

    result = _run(config)

    _assert_no_secrets(repr(result))
    _assert_no_secrets(str(result))
    _assert_no_secrets(repr(result.findings))
    assert b"SUPERSECRET_BODY" in recorders.yielded_pages[0].response.body
    assert not hasattr(result, "body")
    assert not hasattr(result, "headers")
    assert not hasattr(result, "pages")


def test_scan_result_does_not_retain_pages_bodies_or_headers(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once({seed.url: _scripted(body=_html())})

    result = _run(config)
    page = recorders.yielded_pages[0]
    item = result.findings[0]

    assert fields(type(result))[0].name == "findings"
    assert not any(hasattr(result, name) for name in ("pages", "body", "headers"))
    assert not hasattr(item.response, "body")
    assert not hasattr(item.response, "headers")
    assert page not in result.findings
    assert page.response not in result.findings


def test_transport_error_from_crawl_propagates_without_scan_result(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    error = TransportError(
        TransportErrorCode.RESPONSE_TOO_LARGE,
        "Response body exceeds the configured limit.",
    )
    patch_request_once({seed.url: error})
    returned: object = None

    with pytest.raises(TransportError) as caught:
        returned = asyncio.run(run_passive_scan(config))

    assert caught.value is error
    assert caught.value.code is TransportErrorCode.RESPONSE_TOO_LARGE
    assert returned is None
    assert recorders.yielded_pages == []
    assert recorders.scan_page_calls == []
    assert recorders.capture_calls == []
    assert len(recorders.crawl_calls) == 1
    _assert_no_secrets(str(caught.value))


def test_transport_error_after_a_finding_does_not_return_a_partial_scan_result(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    child = _target("https://app.test/a")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    error = TransportError(
        TransportErrorCode.RESPONSE_TOO_LARGE,
        "Response body exceeds the configured limit.",
    )
    patch_request_once(
        {
            seed.url: _scripted(body=_html("/a")),
            child.url: error,
        }
    )
    returned: object = None

    with pytest.raises(TransportError) as caught:
        returned = asyncio.run(run_passive_scan(config))

    assert caught.value is error
    assert returned is None
    assert len(recorders.yielded_pages) == 1
    assert recorders.scan_page_calls == recorders.yielded_pages
    assert recorders.finding_evidence_calls
    assert len(recorders.crawl_calls) == 1
    assert recorders.scan_pages_calls == 0
    _assert_no_secrets(str(caught.value))


def test_scope_validation_error_from_crawl_propagates_without_scan_result(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    resolver = RecordingResolver({"app.test": (_PRIVATE_IP,)})
    config = _config(
        target=seed,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    recorded_http = patch_request_once({seed.url: _scripted(body=_html())})
    returned: object = None

    with pytest.raises(ScopeValidationError) as caught:
        returned = asyncio.run(run_passive_scan(config))

    assert caught.value.code is ScopeErrorCode.ADDRESS_NOT_ALLOWED
    assert returned is None
    assert recorded_http.calls == []
    assert recorders.yielded_pages == []
    assert recorders.scan_page_calls == []
    assert recorders.finding_evidence_calls == []
    assert len(recorders.crawl_calls) == 1


def test_resolver_error_from_crawl_propagates_without_scan_result(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    error = OSError("resolution failed")
    resolver = RecordingResolver(error=error)
    config = _config(
        target=seed,
        resolver=resolver,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once({seed.url: _scripted(body=_html())})
    returned: object = None

    with pytest.raises(OSError) as caught:
        returned = asyncio.run(run_passive_scan(config))

    assert caught.value is error
    assert returned is None
    assert recorders.yielded_pages == []
    assert recorders.scan_page_calls == []
    assert len(recorders.crawl_calls) == 1


def test_unicode_decode_error_after_a_page_does_not_return_a_partial_scan_result(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    patch_request_once({seed.url: _scripted(body=b"<html>\xff</html>")})
    returned: object = None

    with pytest.raises(UnicodeDecodeError) as caught:
        returned = asyncio.run(run_passive_scan(config))

    assert type(caught.value) is UnicodeDecodeError
    assert returned is None
    assert len(recorders.yielded_pages) == 1
    assert recorders.scan_page_calls == recorders.yielded_pages
    assert recorders.finding_evidence_calls
    assert len(recorders.crawl_calls) == 1
    assert recorders.scan_pages_calls == 0


def test_failures_are_not_converted_into_synthetic_findings(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    error = TransportError(TransportErrorCode.REDIRECT_LOOP, "redirect loop")
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=1, max_depth=0),
    )
    patch_request_once({seed.url: error})
    returned: object = None

    with pytest.raises(TransportError) as caught:
        returned = asyncio.run(run_passive_scan(config))

    assert caught.value is error
    assert returned is None
    assert type(caught.value) is TransportError
    assert recorders.finding_evidence_calls == []
    assert recorders.scan_page_calls == []
    assert "scan_failed" not in str(caught.value)


def test_failed_scan_does_not_retry_crawl_or_fall_back_to_scan_pages(
    patch_request_once: PatchRequestOnce,
    recorders: Recorders,
) -> None:
    seed = _target("https://app.test/")
    child = _target("https://app.test/a")
    error = TransportError(
        TransportErrorCode.TOO_MANY_REDIRECTS,
        "Too many redirects.",
    )
    config = _config(
        target=seed,
        discovery_limits=_discovery_limits(max_pages=4, max_depth=1),
    )
    recorded_http = patch_request_once(
        {
            seed.url: _scripted(body=_html("/a")),
            child.url: error,
        }
    )

    with pytest.raises(TransportError) as caught:
        asyncio.run(run_passive_scan(config))

    assert caught.value is error
    assert len(recorders.crawl_calls) == 1
    assert recorders.scan_pages_calls == 0
    assert [call.target.url for call in recorded_http.calls] == [seed.url, child.url]
    assert [call.target.url for call in recorded_http.calls].count(child.url) == 1
