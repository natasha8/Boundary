"""Offline tests for identity metadata and ephemeral origin-bound credentials (Slice A)."""

from __future__ import annotations

import inspect
import socket
from collections.abc import Collection
from dataclasses import FrozenInstanceError, fields
from enum import Enum

import anyio
import pytest

from boundary.authorization import AuthorizationCase, Identity
from boundary.scope import Origin, TargetUrl, parse_target_url
from boundary.transport import OriginBoundCredentials

_AUTH_VALUE = b"Bearer SUPERSECRET_AUTH_TOKEN_aaa"
_COOKIE_VALUE = b"session=SUPERSECRET_COOKIE_VALUE_bbb"
_PASTED_SECRET = "Authorization: Bearer pasted-secret-token-xyz"
_SECRET_MARKERS = (
    "SUPERSECRET_AUTH_TOKEN_aaa",
    "SUPERSECRET_COOKIE_VALUE_bbb",
    "pasted-secret-token-xyz",
    _AUTH_VALUE.decode("ascii"),
    _COOKIE_VALUE.decode("ascii"),
    _PASTED_SECRET,
)
_HEADER_NAME_MARKERS = (
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
)
_FORBIDDEN_IDENTITY_FIELDS = (
    "headers",
    "credentials",
    "authorization",
    "cookie",
    "cookies",
    "token",
    "tokens",
    "password",
    "secret",
    "session",
    "origin",
    "fingerprint",
)
_SPECULATIVE_AUTHORIZATION_NAMES = (
    "AuthorizationEngine",
    "CredentialVault",
    "SecretManager",
    "CookieJar",
    "LoginClient",
    "SessionStore",
    "UserDirectory",
    "WellKnownIdentity",
    "AnonymousIdentity",
)
_SPECULATIVE_CREDENTIAL_NAMES = (
    "fingerprint",
    "evidence_id",
    "dumps",
    "dump",
    "serialize",
    "to_json",
    "from_json",
    "persist",
    "save",
    "store",
    "load",
)
_ALLOWED_HEADER_NAMES = (
    b"Authorization",
    b"authorization",
    b"AUTHORIZATION",
    b"AuThOrIzAtIoN",
    b"Cookie",
    b"cookie",
    b"COOKIE",
    b"cOoKiE",
)
_REJECTED_HEADER_NAMES = (
    b"X-Api-Key",
    b"X-Auth-Token",
    b"Api-Key",
    b"host",
    b"Host",
    b"Set-Cookie",
    b"Proxy-Authorization",
    b"",
)
_VALID_IDENTITY_IDS = (
    "anonymous",
    "user-a",
    "user-b",
    "user.a",
    "user_a",
    "User-A",
    "a",
    "0",
    "A.Z_9-z",
)
_INVALID_IDENTITY_IDS = (
    "",
    " ",
    "user a",
    "user/a",
    "user:a",
    "user@a",
    "user\na",
    "\tuser-a",
    "user-a ",
    " user-a",
    "üser",
    _PASTED_SECRET,
    "Cookie: session=SUPERSECRET_COOKIE_VALUE_bbb",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("identity construction must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if identity or credential construction reaches the network."""
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


def _origin(url: str = "https://app.test/") -> Origin:
    return parse_target_url(url).origin


def _target(url: str = "https://app.test/") -> TargetUrl:
    return parse_target_url(url)


def _case(
    *,
    target: TargetUrl | None = None,
    baseline: Identity | None = None,
    comparison: Identity | None = None,
) -> AuthorizationCase:
    return AuthorizationCase(
        target=_target() if target is None else target,
        baseline=Identity(identity_id="anonymous") if baseline is None else baseline,
        comparison=Identity(identity_id="user-a") if comparison is None else comparison,
    )


def _credentials(
    *,
    origin: Origin | None = None,
    headers: Collection[tuple[bytes, bytes]] = ((b"Authorization", _AUTH_VALUE),),
) -> OriginBoundCredentials:
    return OriginBoundCredentials(
        origin=_origin() if origin is None else origin,
        headers=tuple(headers),
    )


def _assert_no_secrets(text: str) -> None:
    lowered = text.lower()
    for marker in _SECRET_MARKERS:
        assert marker.lower() not in lowered
        assert marker not in text


def _assert_no_header_names(text: str) -> None:
    lowered = text.lower()
    for marker in _HEADER_NAME_MARKERS:
        assert marker not in lowered


def test_identity_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(Identity))

    assert names == ("identity_id",)
    for forbidden in _FORBIDDEN_IDENTITY_FIELDS:
        assert forbidden not in names


def test_identity_constructor_accepts_only_identity_id() -> None:
    parameters = list(inspect.signature(Identity).parameters)

    assert parameters == ["identity_id"]


def test_identity_is_frozen_and_slotted() -> None:
    identity = Identity(identity_id="user-a")

    with pytest.raises(FrozenInstanceError):
        identity.identity_id = "user-b"  # type: ignore[misc]

    assert set(Identity.__slots__) == {"identity_id"}
    assert not hasattr(identity, "__dict__")


def test_identity_stores_identity_id_without_normalization() -> None:
    identity = Identity(identity_id="User-A")

    assert identity.identity_id == "User-A"
    assert identity.identity_id != "user-a"


@pytest.mark.parametrize("identity_id", _VALID_IDENTITY_IDS)
def test_identity_accepts_canonical_ascii_tokens(identity_id: str) -> None:
    identity = Identity(identity_id=identity_id)

    assert identity.identity_id == identity_id


def test_header_word_identity_ids_are_valid_public_labels() -> None:
    """ADR 0006 validates identity_id with the token regex only; it is not a header."""
    assert Identity(identity_id="Authorization").identity_id == "Authorization"
    assert Identity(identity_id="Cookie").identity_id == "Cookie"


@pytest.mark.parametrize("identity_id", _INVALID_IDENTITY_IDS)
def test_invalid_identity_id_raises_value_error_without_echoing_the_value(
    identity_id: str,
) -> None:
    with pytest.raises(ValueError) as caught:
        Identity(identity_id=identity_id)

    message = str(caught.value)
    if identity_id.strip():
        assert identity_id not in message
    _assert_no_secrets(message)


def test_identity_equality_is_identity_id_equality() -> None:
    left = Identity(identity_id="user-a")
    right = Identity(identity_id="user-a")
    other = Identity(identity_id="user-b")

    assert left == right
    assert left is not right
    assert left != other
    assert Identity(identity_id="User-a") != Identity(identity_id="user-a")


def test_identity_repr_and_str_are_deterministic_and_non_secret() -> None:
    identity = Identity(identity_id="user-a")
    other = Identity(identity_id="user-a")

    assert "user-a" in repr(identity)
    assert "user-a" in str(identity)
    assert repr(identity) == repr(other)
    assert str(identity) == str(other)
    _assert_no_secrets(repr(identity))
    _assert_no_secrets(str(identity))


def test_identity_holds_no_credentials_or_runtime_secrets() -> None:
    identity = Identity(identity_id="anonymous")
    field_names = {field.name for field in fields(Identity)}
    public_names = {name for name in dir(identity) if not name.startswith("_")}

    for forbidden in _FORBIDDEN_IDENTITY_FIELDS:
        assert forbidden not in field_names
        assert forbidden not in public_names

    with pytest.raises(TypeError):
        Identity(identity_id="user-a", headers=((b"Authorization", _AUTH_VALUE),))  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        Identity(identity_id="user-a", credentials=None)  # type: ignore[call-arg]


def test_identity_is_not_an_enum_and_has_no_well_known_special_type() -> None:
    assert not issubclass(Identity, Enum)
    assert Identity(identity_id="anonymous").identity_id == "anonymous"


def test_identity_lives_on_the_authorization_module() -> None:
    import boundary.authorization as authorization

    assert authorization.Identity is Identity
    module = inspect.getmodule(Identity)
    assert module is not None
    assert module.__name__ == "boundary.authorization"
    for name in _SPECULATIVE_AUTHORIZATION_NAMES:
        assert not hasattr(authorization, name)


def test_authorization_case_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(AuthorizationCase))

    assert names == ("target", "baseline", "comparison")


def test_authorization_case_constructor_accepts_target_baseline_comparison() -> None:
    parameters = list(inspect.signature(AuthorizationCase).parameters)

    assert parameters == ["target", "baseline", "comparison"]


def test_authorization_case_is_frozen_and_slotted() -> None:
    case = _case()
    other_target = _target("https://app.test/other")
    other_identity = Identity(identity_id="user-b")

    with pytest.raises(FrozenInstanceError):
        case.target = other_target  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        case.baseline = other_identity  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        case.comparison = other_identity  # type: ignore[misc]

    assert set(AuthorizationCase.__slots__) == {"target", "baseline", "comparison"}
    assert not hasattr(case, "__dict__")


def test_authorization_case_preserves_supplied_target_and_identities() -> None:
    target = _target("https://app.test/resource?id=1")
    baseline = Identity(identity_id="anonymous")
    comparison = Identity(identity_id="user-a")

    case = AuthorizationCase(
        target=target,
        baseline=baseline,
        comparison=comparison,
    )

    assert case.target is target
    assert case.baseline is baseline
    assert case.comparison is comparison
    assert case.target.url == "https://app.test/resource?id=1"


@pytest.mark.parametrize(
    ("baseline_id", "comparison_id"),
    [
        ("anonymous", "user-a"),
        ("user-a", "user-b"),
        ("User-A", "user-a"),
    ],
)
def test_authorization_case_accepts_distinct_identity_ids(
    baseline_id: str,
    comparison_id: str,
) -> None:
    case = _case(
        baseline=Identity(identity_id=baseline_id),
        comparison=Identity(identity_id=comparison_id),
    )

    assert case.baseline.identity_id == baseline_id
    assert case.comparison.identity_id == comparison_id


def test_authorization_case_pair_is_ordered_and_directional() -> None:
    target = _target()
    user_a = Identity(identity_id="user-a")
    user_b = Identity(identity_id="user-b")

    forward = AuthorizationCase(
        target=target,
        baseline=user_a,
        comparison=user_b,
    )
    swapped = AuthorizationCase(
        target=target,
        baseline=user_b,
        comparison=user_a,
    )

    assert forward != swapped
    assert forward.baseline is user_a
    assert forward.comparison is user_b
    assert swapped.baseline is user_b
    assert swapped.comparison is user_a


def test_identical_identity_ids_raise_value_error() -> None:
    target = _target()
    left = Identity(identity_id="user-a")
    right = Identity(identity_id="user-a")

    assert left is not right
    assert left == right

    with pytest.raises(ValueError):
        AuthorizationCase(target=target, baseline=left, comparison=right)

    with pytest.raises(ValueError):
        AuthorizationCase(target=target, baseline=left, comparison=left)


def test_authorization_case_stores_no_credentials_or_secrets() -> None:
    case = _case()
    field_names = {field.name for field in fields(AuthorizationCase)}
    public_names = {name for name in dir(case) if not name.startswith("_")}

    for forbidden in (
        "headers",
        "credentials",
        "authorization",
        "cookie",
        "cookies",
        "token",
        "password",
        "secret",
        "session",
        "origin",
        "fingerprint",
        "allowed_origins",
    ):
        assert forbidden not in field_names
        assert forbidden not in public_names

    with pytest.raises(TypeError):
        AuthorizationCase(  # type: ignore[call-arg]
            target=_target(),
            baseline=Identity(identity_id="anonymous"),
            comparison=Identity(identity_id="user-a"),
            credentials=None,
        )


def test_authorization_case_construction_does_not_validate_scope_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _target("https://app.test/private")
    baseline = Identity(identity_id="anonymous")
    comparison = Identity(identity_id="user-a")

    def _boom(*args: object, **kwargs: object) -> None:
        raise AssertionError(
            "AuthorizationCase must not revalidate scope or parse URLs"
        )

    monkeypatch.setattr("boundary.scope.parse_target_url", _boom)
    monkeypatch.setattr("boundary.scope.require_allowed_origin", _boom)
    monkeypatch.setattr("boundary.scope.require_allowed_address", _boom)
    monkeypatch.setattr("boundary.scope.resolve_allowed_redirect", _boom)

    case = AuthorizationCase(
        target=target,
        baseline=baseline,
        comparison=comparison,
    )

    assert case.target is target
    assert case.baseline is baseline
    assert case.comparison is comparison


def test_authorization_case_lives_on_the_authorization_module() -> None:
    import boundary.authorization as authorization

    assert authorization.AuthorizationCase is AuthorizationCase
    module = inspect.getmodule(AuthorizationCase)
    assert module is not None
    assert module.__name__ == "boundary.authorization"


def test_origin_bound_credentials_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(OriginBoundCredentials))

    assert names == ("origin", "headers")
    assert "fingerprint" not in names
    assert "identity" not in names
    assert "identity_id" not in names


def test_origin_bound_credentials_constructor_accepts_origin_and_headers() -> None:
    parameters = list(inspect.signature(OriginBoundCredentials).parameters)

    assert parameters == ["origin", "headers"]


def test_origin_bound_credentials_is_frozen_and_slotted() -> None:
    credentials = _credentials()

    with pytest.raises(FrozenInstanceError):
        credentials.origin = _origin("https://other.test/")  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        credentials.headers = ((b"Cookie", _COOKIE_VALUE),)  # type: ignore[misc]

    assert set(OriginBoundCredentials.__slots__) == {"origin", "headers"}
    assert not hasattr(credentials, "__dict__")


def test_origin_bound_credentials_is_bound_to_one_exact_origin() -> None:
    origin = _origin("https://app.test/")
    credentials = _credentials(origin=origin)

    assert credentials.origin is origin
    assert credentials.origin == Origin(scheme="https", host="app.test", port=443)
    assert credentials.origin != Origin(scheme="http", host="app.test", port=80)
    assert credentials.origin != Origin(scheme="https", host="app.test", port=8443)
    assert credentials.origin != Origin(scheme="https", host="api.app.test", port=443)


def test_origin_bound_credentials_preserves_caller_header_bytes_and_order() -> None:
    headers = (
        (b"COOKIE", _COOKIE_VALUE),
        (b"authorization", _AUTH_VALUE),
    )
    credentials = _credentials(headers=headers)

    assert credentials.headers == headers
    assert isinstance(credentials.headers, tuple)
    assert all(isinstance(pair, tuple) for pair in credentials.headers)
    assert type(credentials.headers[0][0]) is bytes
    assert type(credentials.headers[0][1]) is bytes
    assert type(credentials.headers[1][0]) is bytes
    assert type(credentials.headers[1][1]) is bytes
    assert credentials.headers[0][1] == _COOKIE_VALUE
    assert credentials.headers[1][1] == _AUTH_VALUE


def test_origin_bound_credentials_does_not_decode_or_normalize_values() -> None:
    value = b"session=\xff\xfe; id=SUPERSECRET_COOKIE_VALUE_bbb"
    credentials = _credentials(headers=((b"Cookie", value),))

    assert credentials.headers == ((b"Cookie", value),)
    assert type(credentials.headers[0][1]) is bytes
    assert credentials.headers[0][1] == value


@pytest.mark.parametrize("name", _ALLOWED_HEADER_NAMES)
def test_origin_bound_credentials_accepts_authorization_and_cookie_case_insensitively(
    name: bytes,
) -> None:
    credentials = _credentials(
        headers=((name, _AUTH_VALUE if b"auth" in name.lower() else _COOKIE_VALUE),)
    )

    assert credentials.headers[0][0] == name
    assert len(credentials.headers) == 1


@pytest.mark.parametrize(
    "headers",
    [
        ((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE)),
        ((b"Cookie", _COOKIE_VALUE), (b"Authorization", _AUTH_VALUE)),
        ((b"AUTHORIZATION", _AUTH_VALUE), (b"cookie", _COOKIE_VALUE)),
        ((b"cookie", _COOKIE_VALUE), (b"authorization", _AUTH_VALUE)),
    ],
    ids=(
        "authorization_then_cookie",
        "cookie_then_authorization",
        "upper_authorization_lower_cookie",
        "lower_cookie_lower_authorization",
    ),
)
def test_origin_bound_credentials_accepts_both_allowed_names_in_caller_order(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    credentials = _credentials(headers=headers)

    assert credentials.headers == headers
    assert tuple(name for name, _value in credentials.headers) == tuple(
        name for name, _value in headers
    )


@pytest.mark.parametrize("name", _REJECTED_HEADER_NAMES)
def test_disallowed_credential_header_names_raise_value_error(name: bytes) -> None:
    with pytest.raises(ValueError) as caught:
        _credentials(headers=((name, _AUTH_VALUE),))

    message = str(caught.value)
    _assert_no_secrets(message)
    _assert_no_header_names(message)
    if name:
        assert name.decode("latin-1") not in message
    assert "allowlist" in message.lower()


@pytest.mark.parametrize(
    "headers",
    [
        ((b"Authorization", _AUTH_VALUE), (b"Authorization", _COOKIE_VALUE)),
        ((b"Authorization", _AUTH_VALUE), (b"authorization", _COOKIE_VALUE)),
        ((b"Cookie", _COOKIE_VALUE), (b"COOKIE", _AUTH_VALUE)),
        (
            (b"Authorization", _AUTH_VALUE),
            (b"Cookie", _COOKIE_VALUE),
            (b"authorization", _AUTH_VALUE),
        ),
    ],
    ids=(
        "authorization_twice",
        "authorization_mixed_case",
        "cookie_mixed_case",
        "third_header_duplicates_authorization",
    ),
)
def test_duplicate_credential_header_names_raise_value_error(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    with pytest.raises(ValueError) as caught:
        _credentials(headers=headers)

    message = str(caught.value)
    _assert_no_secrets(message)
    _assert_no_header_names(message)
    assert "duplicate" in message.lower()


def test_empty_credentials_raise_value_error() -> None:
    with pytest.raises(ValueError) as caught:
        _credentials(headers=())

    message = str(caught.value)
    _assert_no_secrets(message)
    _assert_no_header_names(message)


def test_origin_bound_credentials_repr_is_redacted() -> None:
    credentials = _credentials(
        headers=((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE)),
    )
    text = repr(credentials)

    assert "https" in text
    assert "app.test" in text
    assert "443" in text
    assert "2" in text
    _assert_no_secrets(text)
    _assert_no_header_names(text)


def test_origin_bound_credentials_str_is_redacted() -> None:
    credentials = _credentials(headers=((b"Cookie", _COOKIE_VALUE),))
    text = str(credentials)

    assert "https" in text
    assert "app.test" in text
    assert "443" in text
    assert "1" in text
    _assert_no_secrets(text)
    _assert_no_header_names(text)


def test_origin_bound_credentials_repr_count_matches_header_count() -> None:
    one = repr(_credentials(headers=((b"Authorization", _AUTH_VALUE),)))
    two = repr(
        _credentials(
            headers=((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE))
        ),
    )

    assert "1" in one
    assert "2" in two
    assert "2" not in one


def test_origin_bound_credentials_has_no_fingerprint_or_persistence_surface() -> None:
    credentials = _credentials()
    field_names = {field.name for field in fields(OriginBoundCredentials)}
    public_names = {name for name in dir(credentials) if not name.startswith("_")}

    for forbidden in _SPECULATIVE_CREDENTIAL_NAMES:
        assert forbidden not in field_names
        assert forbidden not in public_names

    with pytest.raises(TypeError):
        OriginBoundCredentials(  # type: ignore[call-arg]
            origin=_origin(),
            headers=((b"Authorization", _AUTH_VALUE),),
            fingerprint="abc",
        )


def test_origin_bound_credentials_does_not_mutate_caller_input() -> None:
    origin = _origin()
    supplied = ((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE))
    snapshot = (
        (b"Authorization", _AUTH_VALUE),
        (b"Cookie", _COOKIE_VALUE),
    )

    credentials = OriginBoundCredentials(origin=origin, headers=supplied)

    assert supplied == snapshot
    assert credentials.headers == snapshot
    assert credentials.origin is origin


def test_origin_bound_credentials_lives_on_the_transport_module() -> None:
    import boundary.transport as transport

    assert transport.OriginBoundCredentials is OriginBoundCredentials
    module = inspect.getmodule(OriginBoundCredentials)
    assert module is not None
    assert module.__name__ == "boundary.transport"
    assert not hasattr(transport, "CookieJar")
    assert not hasattr(transport, "CredentialVault")
    assert not hasattr(transport, "LoginClient")
    assert not hasattr(transport, "AuthorizationEngine")
