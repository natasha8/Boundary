"""Offline tests for the ScanConfig value model (Slice A)."""

from __future__ import annotations

import inspect
import socket
from collections.abc import Callable, Collection
from dataclasses import MISSING, FrozenInstanceError, fields
from typing import Any, get_type_hints

import anyio
import pytest

from boundary.discovery import DiscoveryLimits
from boundary.scan import ScanConfig
from boundary.scope import (
    AddressPolicy,
    AddressResolver,
    Origin,
    ScopeErrorCode,
    ScopeValidationError,
    TargetUrl,
    parse_target_url,
    require_allowed_origin,
)
from boundary.transport import RequestLimits

_SCAN_CONFIG_FIELDS = (
    "target",
    "allowed_origins",
    "policy",
    "resolver",
    "request_limits",
    "max_redirects",
    "discovery_limits",
)
_FORBIDDEN_FIELDS = (
    "credentials",
    "identity",
    "identities",
    "headers",
    "authorization",
    "cookie",
    "cookies",
    "token",
    "password",
    "secret",
    "session",
    "method",
    "body",
    "user_agent",
    "output",
    "report",
    "profile",
    "run_id",
    "timestamp",
    "pages_visited",
    "findings",
    "concurrency",
    "plugin",
    "url",
)
_FORBIDDEN_CONSTRUCTOR_KWARGS = (
    "credentials",
    "identity",
    "identities",
    "headers",
    "method",
    "output",
    "report",
    "profile",
    "run_id",
    "timestamp",
)
_SPECULATIVE_SCAN_NAMES = (
    "ScanEngine",
    "Orchestrator",
    "ScanProfile",
    "CredentialVault",
    "SecretManager",
    "CookieJar",
)
_SECRET_MARKERS = (
    "SUPERSECRET_AUTH_TOKEN_aaa",
    "SUPERSECRET_COOKIE_VALUE_bbb",
    "<html>response-body",
)
_DUPLICATED_POLICY_MARKERS = (
    "parse_target_url",
    "urlsplit",
    "urlunsplit",
    "urljoin",
    "require_allowed_address",
    "resolve_allowed_addresses",
    "resolve_allowed_redirect",
    "ip_address",
    "getaddrinfo",
    "crawl",
    "request_once",
    "request_with_redirects",
    "request_as",
    "SystemAddressResolver",
    "max_pages",
    "max_body_bytes",
    "max_depth",
    "connect_timeout",
)


class RecordingResolver:
    """AddressResolver double that records resolve attempts and never does I/O."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.calls.append((host, port))
        raise AssertionError("ScanConfig must not invoke the resolver")


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("ScanConfig construction must not perform network activity")


def _reject_system_resolver_init(self: object, *args: object, **kwargs: object) -> None:
    raise AssertionError("ScanConfig must not construct SystemAddressResolver")


@pytest.fixture(autouse=True)
def _reject_dns_transport_discovery_and_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if ScanConfig construction reaches DNS, HTTP, or crawl."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)
    monkeypatch.setattr("boundary.discovery.crawl", _reject_network)
    monkeypatch.setattr("boundary.transport.request_once", _reject_network)
    monkeypatch.setattr("boundary.transport.request_with_redirects", _reject_network)
    monkeypatch.setattr("boundary.authorization.request_as", _reject_network)
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.resolve",
        _reject_network,
    )
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.__init__",
        _reject_system_resolver_init,
    )


def _assert_no_secrets(text: str) -> None:
    lowered = text.lower()
    for marker in _SECRET_MARKERS:
        assert marker.lower() not in lowered
        assert marker not in text


def _target(url: str = "https://app.test/") -> TargetUrl:
    return parse_target_url(url)


def _origin(url: str = "https://app.test/") -> Origin:
    return parse_target_url(url).origin


def _request_limits(
    *,
    max_body_bytes: int = 65536,
    connect_timeout: float | None = 1.0,
    read_timeout: float | None = 2.0,
    write_timeout: float | None = 3.0,
    pool_timeout: float | None = 4.0,
) -> RequestLimits:
    return RequestLimits(
        max_body_bytes=max_body_bytes,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        write_timeout=write_timeout,
        pool_timeout=pool_timeout,
    )


def _discovery_limits(
    *,
    max_pages: int = 1,
    max_depth: int = 0,
) -> DiscoveryLimits:
    return DiscoveryLimits(max_pages=max_pages, max_depth=max_depth)


def _valid_kwargs(
    *,
    target: TargetUrl | None = None,
    allowed_origins: tuple[Origin, ...] | None = None,
    policy: AddressPolicy = AddressPolicy.PUBLIC,
    resolver: RecordingResolver | None = None,
    request_limits: RequestLimits | None = None,
    max_redirects: int = 0,
    discovery_limits: DiscoveryLimits | None = None,
) -> dict[str, object]:
    resolved_target = _target() if target is None else target
    return {
        "target": resolved_target,
        "allowed_origins": (
            (resolved_target.origin,) if allowed_origins is None else allowed_origins
        ),
        "policy": policy,
        "resolver": RecordingResolver() if resolver is None else resolver,
        "request_limits": (
            _request_limits() if request_limits is None else request_limits
        ),
        "max_redirects": max_redirects,
        "discovery_limits": (
            _discovery_limits() if discovery_limits is None else discovery_limits
        ),
    }


def _config(
    *,
    target: TargetUrl | None = None,
    allowed_origins: tuple[Origin, ...] | None = None,
    policy: AddressPolicy = AddressPolicy.PUBLIC,
    resolver: RecordingResolver | None = None,
    request_limits: RequestLimits | None = None,
    max_redirects: int = 0,
    discovery_limits: DiscoveryLimits | None = None,
) -> ScanConfig:
    resolved_target = _target() if target is None else target
    return ScanConfig(
        target=resolved_target,
        allowed_origins=(
            (resolved_target.origin,) if allowed_origins is None else allowed_origins
        ),
        policy=policy,
        resolver=RecordingResolver() if resolver is None else resolver,
        request_limits=_request_limits() if request_limits is None else request_limits,
        max_redirects=max_redirects,
        discovery_limits=(
            _discovery_limits() if discovery_limits is None else discovery_limits
        ),
    )


def _construct(**kwargs: object) -> ScanConfig:
    construct: Callable[..., ScanConfig] = ScanConfig
    return construct(**kwargs)


def _patch_scope_and_scan(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    wrapper: object,
) -> None:
    scan = inspect.getmodule(ScanConfig)
    assert scan is not None
    monkeypatch.setattr(f"boundary.scope.{name}", wrapper)
    if hasattr(scan, name):
        monkeypatch.setattr(scan, name, wrapper)


def test_scan_config_lives_on_the_scan_module() -> None:
    import boundary.scan as scan

    assert scan.ScanConfig is ScanConfig
    module = inspect.getmodule(ScanConfig)
    assert module is not None
    assert module.__name__ == "boundary.scan"
    for name in _SPECULATIVE_SCAN_NAMES:
        assert not hasattr(scan, name)
    source = inspect.getsource(scan)
    assert "boundary.authorization" not in source
    assert "SystemAddressResolver" not in source


def test_scan_config_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(ScanConfig))

    assert names == _SCAN_CONFIG_FIELDS
    for forbidden in _FORBIDDEN_FIELDS:
        assert forbidden not in names


def test_scan_config_constructor_accepts_the_seven_documented_fields() -> None:
    parameters = list(inspect.signature(ScanConfig).parameters)

    assert parameters == list(_SCAN_CONFIG_FIELDS)
    for parameter in inspect.signature(ScanConfig).parameters.values():
        assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert parameter.default is inspect.Parameter.empty


def test_scan_config_has_no_hidden_field_defaults() -> None:
    for field in fields(ScanConfig):
        assert field.default is MISSING
        assert field.default_factory is MISSING


def test_scan_config_type_hints_match_the_approved_contract() -> None:
    hints = get_type_hints(ScanConfig)

    assert hints["target"] is TargetUrl
    assert hints["allowed_origins"] == tuple[Origin, ...]
    assert hints["policy"] is AddressPolicy
    assert hints["resolver"] is AddressResolver
    assert hints["request_limits"] is RequestLimits
    assert hints["max_redirects"] is int
    assert hints["discovery_limits"] is DiscoveryLimits


def test_scan_config_is_frozen_and_slotted() -> None:
    config = _config()
    other_target = _target("https://app.test/other")
    frozen: Any = config

    with pytest.raises(FrozenInstanceError):
        frozen.target = other_target

    with pytest.raises(FrozenInstanceError):
        frozen.allowed_origins = (other_target.origin,)

    with pytest.raises(FrozenInstanceError):
        frozen.policy = AddressPolicy.LOCAL_LAB

    with pytest.raises(FrozenInstanceError):
        frozen.max_redirects = 1

    dataclass_params = ScanConfig.__dataclass_params__  # type: ignore[attr-defined]
    assert dataclass_params.frozen is True
    assert dataclass_params.slots is True
    assert set(ScanConfig.__slots__) == set(_SCAN_CONFIG_FIELDS)
    assert not hasattr(config, "__dict__")


def test_scan_config_preserves_supplied_objects_and_tuple() -> None:
    target = _target("https://app.test/resource?id=1")
    allowed_origins = (target.origin, _origin("https://other.test/"))
    policy = AddressPolicy.LOCAL_LAB
    resolver = RecordingResolver()
    request_limits = _request_limits(max_body_bytes=32)
    discovery_limits = _discovery_limits(max_pages=4, max_depth=2)

    config = ScanConfig(
        target=target,
        allowed_origins=allowed_origins,
        policy=policy,
        resolver=resolver,
        request_limits=request_limits,
        max_redirects=3,
        discovery_limits=discovery_limits,
    )

    assert config.target is target
    assert config.allowed_origins is allowed_origins
    assert type(config.allowed_origins) is tuple
    assert config.policy is policy
    assert config.resolver is resolver
    assert config.request_limits is request_limits
    assert config.max_redirects == 3
    assert config.discovery_limits is discovery_limits
    assert config.target.url == "https://app.test/resource?id=1"
    assert config.target.query == "id=1"


def test_scan_config_accepts_positional_arguments_in_documented_order() -> None:
    target = _target()
    allowed_origins = (target.origin,)
    resolver = RecordingResolver()
    request_limits = _request_limits()
    discovery_limits = _discovery_limits()

    config = ScanConfig(
        target,
        allowed_origins,
        AddressPolicy.PUBLIC,
        resolver,
        request_limits,
        0,
        discovery_limits,
    )

    assert config.target is target
    assert config.allowed_origins is allowed_origins
    assert config.policy is AddressPolicy.PUBLIC
    assert config.resolver is resolver
    assert config.request_limits is request_limits
    assert config.max_redirects == 0
    assert config.discovery_limits is discovery_limits


@pytest.mark.parametrize("missing", _SCAN_CONFIG_FIELDS)
def test_omitting_any_field_raises_type_error(missing: str) -> None:
    kwargs = _valid_kwargs()
    del kwargs[missing]

    with pytest.raises(TypeError):
        _construct(**kwargs)


@pytest.mark.parametrize("extra", _FORBIDDEN_CONSTRUCTOR_KWARGS)
def test_forbidden_constructor_keyword_is_rejected(extra: str) -> None:
    kwargs = _valid_kwargs()
    kwargs[extra] = None

    with pytest.raises(TypeError):
        _construct(**kwargs)


def test_allowed_target_origin_constructs_without_invoking_the_resolver() -> None:
    resolver = RecordingResolver()
    target = _target("https://app.test/path")

    config = _config(target=target, resolver=resolver)

    assert config.target is target
    assert config.allowed_origins == (target.origin,)
    assert resolver.calls == []


def test_empty_allowlist_raises_existing_origin_not_allowed_error() -> None:
    target = _target()
    allowed_origins: tuple[Origin, ...] = ()

    with pytest.raises(ScopeValidationError) as expected:
        require_allowed_origin(target, allowed_origins)
    with pytest.raises(ScopeValidationError) as actual:
        _config(target=target, allowed_origins=allowed_origins)

    assert type(actual.value) is ScopeValidationError
    assert actual.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
    assert actual.value.code is expected.value.code
    assert str(actual.value) == str(expected.value)
    assert str(actual.value) == "Target origin is not allowed."
    _assert_no_secrets(str(actual.value))
    assert allowed_origins == ()


def test_missing_seed_origin_is_not_auto_inserted() -> None:
    target = _target("https://app.test/")
    other = _origin("https://other.test/")
    allowed_origins = (other,)

    with pytest.raises(ScopeValidationError) as caught:
        _config(target=target, allowed_origins=allowed_origins)

    assert caught.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
    assert allowed_origins == (other,)
    assert target.origin not in allowed_origins


def test_seed_origin_is_not_prepended_when_already_present() -> None:
    target = _target()
    other = _origin("https://other.test/")
    allowed_origins = (other, target.origin)

    config = _config(target=target, allowed_origins=allowed_origins)

    assert config.allowed_origins is allowed_origins
    assert config.allowed_origins == (other, target.origin)
    assert config.allowed_origins[0] is other
    assert config.allowed_origins.count(target.origin) == 1


def test_equivalent_separately_built_origin_satisfies_the_allowlist() -> None:
    target = _target("https://app.test/resource?q=1")
    origin = Origin(scheme="https", host="app.test", port=443)
    allowed_origins = (origin,)

    assert origin == target.origin
    assert origin is not target.origin

    config = _config(target=target, allowed_origins=allowed_origins)

    assert config.allowed_origins is allowed_origins
    assert config.target is target


@pytest.mark.parametrize(
    "disallowed_url",
    [
        "http://app.test/",
        "https://api.app.test/",
        "https://app.test:8443/",
    ],
)
def test_disallowed_scheme_host_or_port_propagates_origin_not_allowed(
    disallowed_url: str,
) -> None:
    target = _target("https://app.test/")
    allowed_origins = (_origin(disallowed_url),)

    with pytest.raises(ScopeValidationError) as caught:
        _config(target=target, allowed_origins=allowed_origins)

    assert caught.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
    assert str(caught.value) == "Target origin is not allowed."
    _assert_no_secrets(str(caught.value))


def test_construction_calls_existing_require_allowed_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[tuple[TargetUrl, Collection[Origin]]] = []
    original = require_allowed_origin

    def wrapper(
        target: TargetUrl,
        allowed_origins: Collection[Origin],
    ) -> None:
        recorded.append((target, allowed_origins))
        original(target, allowed_origins)

    _patch_scope_and_scan(monkeypatch, "require_allowed_origin", wrapper)

    target = _target("https://app.test/admin")
    allowed_origins = (target.origin, _origin("https://other.test/"))
    config = _config(target=target, allowed_origins=allowed_origins)

    assert recorded == [(target, allowed_origins)]
    assert config.allowed_origins is allowed_origins


def test_empty_allowlist_still_calls_require_allowed_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: list[tuple[TargetUrl, Collection[Origin]]] = []
    original = require_allowed_origin

    def wrapper(
        target: TargetUrl,
        allowed_origins: Collection[Origin],
    ) -> None:
        recorded.append((target, allowed_origins))
        original(target, allowed_origins)

    _patch_scope_and_scan(monkeypatch, "require_allowed_origin", wrapper)

    target = _target()
    allowed_origins: tuple[Origin, ...] = ()

    with pytest.raises(ScopeValidationError) as caught:
        _config(target=target, allowed_origins=allowed_origins)

    assert recorded == [(target, allowed_origins)]
    assert caught.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED


def test_max_redirects_zero_is_accepted() -> None:
    config = _config(max_redirects=0)

    assert config.max_redirects == 0


@pytest.mark.parametrize("max_redirects", [1, 10, 1000])
def test_positive_max_redirects_is_stored(max_redirects: int) -> None:
    config = _config(max_redirects=max_redirects)

    assert config.max_redirects == max_redirects


@pytest.mark.parametrize("max_redirects", [-1, -2, -1000])
def test_negative_max_redirects_raises_value_error_before_resolver_call(
    max_redirects: int,
) -> None:
    resolver = RecordingResolver()

    with pytest.raises(ValueError) as caught:
        _config(resolver=resolver, max_redirects=max_redirects)

    assert type(caught.value) is ValueError
    assert not isinstance(caught.value, ScopeValidationError)
    _assert_no_secrets(str(caught.value))
    assert resolver.calls == []


@pytest.mark.parametrize("policy", [AddressPolicy.PUBLIC, AddressPolicy.LOCAL_LAB])
def test_explicit_address_policy_is_stored_without_defaulting(
    policy: AddressPolicy,
) -> None:
    config = _config(policy=policy)

    assert config.policy is policy


def test_construction_does_not_apply_address_policy_or_dns() -> None:
    resolver = RecordingResolver()
    target = _target("http://127.0.0.1:3000/health")

    config = _config(
        target=target,
        allowed_origins=(target.origin,),
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
    )

    assert config.target is target
    assert config.policy is AddressPolicy.PUBLIC
    assert resolver.calls == []


def test_none_transport_timeouts_are_stored_on_the_supplied_limits() -> None:
    request_limits = _request_limits(
        connect_timeout=None,
        read_timeout=None,
        write_timeout=None,
        pool_timeout=None,
    )

    config = _config(request_limits=request_limits)

    assert config.request_limits is request_limits
    assert config.request_limits.connect_timeout is None
    assert config.request_limits.read_timeout is None
    assert config.request_limits.write_timeout is None
    assert config.request_limits.pool_timeout is None


def test_construction_does_not_reparse_the_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> TargetUrl:
        raise AssertionError("ScanConfig must not reparse the target URL")

    _patch_scope_and_scan(monkeypatch, "parse_target_url", boom)

    target = _target("https://app.test/already-parsed?q=1")
    config = _config(target=target, allowed_origins=(target.origin,))

    assert config.target is target
    assert config.target.url == "https://app.test/already-parsed?q=1"


def test_construction_does_not_revalidate_ip_or_dns_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("ScanConfig must not copy IP or DNS admission")

    _patch_scope_and_scan(monkeypatch, "require_allowed_address", boom)
    _patch_scope_and_scan(monkeypatch, "resolve_allowed_addresses", boom)
    _patch_scope_and_scan(monkeypatch, "resolve_allowed_redirect", boom)

    target = _target("http://192.168.1.10/lab")
    config = _config(
        target=target,
        allowed_origins=(target.origin,),
        policy=AddressPolicy.PUBLIC,
    )

    assert config.target is target


def test_scan_config_does_not_duplicate_url_ip_or_nested_limit_logic() -> None:
    source = inspect.getsource(ScanConfig)

    assert "require_allowed_origin" in source
    assert "max_redirects" in source
    for marker in _DUPLICATED_POLICY_MARKERS:
        assert marker not in source


def test_scan_config_holds_no_credentials_identities_or_runtime_fields() -> None:
    config = _config()
    field_names = {field.name for field in fields(ScanConfig)}
    public_names = {name for name in dir(config) if not name.startswith("_")}

    for forbidden in _FORBIDDEN_FIELDS:
        assert forbidden not in field_names
        assert forbidden not in public_names

    assert not hasattr(ScanConfig, "run")
    assert not hasattr(ScanConfig, "run_passive_scan")
    assert not hasattr(config, "credentials")


def test_construction_does_not_mutate_caller_inputs() -> None:
    target = _target("https://app.test/resource?id=1")
    seed_origin = target.origin
    other_origin = _origin("https://other.test/")
    allowed_origins = (seed_origin, other_origin)
    origins_snapshot = (seed_origin, other_origin)
    request_limits = _request_limits(max_body_bytes=8)
    discovery_limits = _discovery_limits(max_pages=2, max_depth=1)
    resolver = RecordingResolver()
    target_url = target.url
    body_budget = request_limits.max_body_bytes
    page_budget = discovery_limits.max_pages

    config = ScanConfig(
        target=target,
        allowed_origins=allowed_origins,
        policy=AddressPolicy.PUBLIC,
        resolver=resolver,
        request_limits=request_limits,
        max_redirects=0,
        discovery_limits=discovery_limits,
    )

    assert allowed_origins == origins_snapshot
    assert allowed_origins[0] is seed_origin
    assert target.url == target_url
    assert request_limits.max_body_bytes == body_budget
    assert discovery_limits.max_pages == page_budget
    assert config.allowed_origins is allowed_origins
    assert resolver.calls == []


def test_failed_origin_check_does_not_mutate_caller_allowlist() -> None:
    target = _target()
    other = _origin("https://other.test/")
    allowed_origins = (other,)
    snapshot = (other,)

    with pytest.raises(ScopeValidationError):
        _config(target=target, allowed_origins=allowed_origins)

    assert allowed_origins == snapshot
    assert allowed_origins == (other,)
