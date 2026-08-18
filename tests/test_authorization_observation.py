"""Offline tests for AuthorizationObservation (Slice E)."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import socket
from collections.abc import Collection
from dataclasses import FrozenInstanceError, fields
from enum import StrEnum
from typing import Any, get_type_hints

import anyio
import pytest

from boundary.authorization import (
    AuthorizationCase,
    AuthorizationObservation,
    AuthorizationObservationKind,
    Identity,
    ResponseComparison,
    compare_response_evidence,
)
from boundary.evidence import (
    FindingEvidence,
    ResponseEvidence,
    capture_response_evidence,
)
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
    OriginBoundCredentials,
    RequestLimits,
    TransportError,
    TransportErrorCode,
    TransportResponse,
)

_RULE_ID = "authorization.pair.projection.v1"
_DIGEST_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_DIGEST_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_AUTH_VALUE = b"Bearer SUPERSECRET_AUTH_TOKEN_aaa"
_COOKIE_VALUE = b"session=SUPERSECRET_COOKIE_VALUE_bbb"
_BODY_SECRET = b"<html>password=SUPERSECRET_BODY</html>"
_SECRET_MARKERS = (
    "SUPERSECRET_AUTH_TOKEN_aaa",
    "SUPERSECRET_COOKIE_VALUE_bbb",
    "SUPERSECRET_BODY",
    _AUTH_VALUE.decode("ascii"),
    _COOKIE_VALUE.decode("ascii"),
)
_EQUIVALENT_OBSERVATION = (
    "Baseline and comparison identities produced equivalent captured "
    "response projections."
)
_EQUIVALENT_RATIONALE = (
    "Equivalent projections are an authorization anomaly requiring human "
    "review, not a confirmed IDOR/BOLA."
)
_DISTINCT_OBSERVATION = (
    "Baseline and comparison identities produced distinct captured "
    "response projections."
)
_DISTINCT_RATIONALE = (
    "Distinct projections are not a demonstration that access control worked."
)
_OBSERVATION_FIELDS = (
    "rule_id",
    "kind",
    "target",
    "baseline_identity",
    "comparison_identity",
    "baseline_response",
    "comparison_response",
    "comparison",
    "observation",
    "rationale",
)
_CANONICAL_IDENTITY_JSON = (
    '{"baseline_identity":"user-a",'
    '"baseline_response":{"body_length":5,'
    '"body_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"final_target":"https://app.test/resource","status":200},'
    '"comparison_identity":"user-b",'
    '"comparison_response":{"body_length":5,'
    '"body_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    '"final_target":"https://app.test/resource","status":200},'
    '"rule_id":"authorization.pair.projection.v1",'
    '"schema":1,'
    '"target":"https://app.test/resource"}'
)
_LOCKED_FINGERPRINT = "a51821e9c299d6b6ecaa21914312fc4643902ea366e426c19ac62b6132bb64bc"
_FORBIDDEN_KIND_NAMES = (
    "confirmed",
    "validated",
    "rejected",
    "vulnerable",
    "safe",
    "idor",
    "bola",
    "error",
    "incomplete",
    "severity",
    "cvss",
    "confidence",
    "verdict",
)
_FORBIDDEN_OBSERVATION_FIELDS = (
    "confidence",
    "severity",
    "cvss",
    "vulnerability",
    "verdict",
    "idor",
    "bola",
    "headers",
    "body",
    "raw",
    "excerpt",
    "score",
    "similarity",
    "heuristic",
    "credentials",
    "fingerprint",
    "evidence_id",
    "uuid",
    "timestamp",
    "ai",
    "llm",
    "embedding",
    "remediation",
)
_SPECULATIVE_AUTHORIZATION_NAMES = (
    "AuthorizationEngine",
    "observe_pair",
    "observe_case",
    "run_authorization_case",
    "compare_and_observe",
    "observe_from_error",
    "AuthorizationPlanner",
    "Flow",
    "Task",
    "Subtask",
    "CookieJar",
    "LoginClient",
    "compare_responses",
)
_FORBIDDEN_FINGERPRINT_SOURCE = (
    "requested_target",
    "uuid",
    "uuid4",
    "datetime",
    "time.time",
    "monotonic",
    "random.",
    "secrets.",
    "os.urandom",
    "json.loads",
    "json.load",
    "html.parser",
    "BeautifulSoup",
    "lxml",
    "difflib",
    "SequenceMatcher",
    ".headers",
    ".body",
    "openai",
    "anthropic",
    "llm",
    "embedding",
    "heuristic",
    "confidence",
    "severity",
    "cvss",
    "idor",
    "bola",
    "vulnerable",
    "confirmed",
    "crawl(",
    "request_once(",
    "request_with_redirects(",
    "socket.",
    "getaddrinfo",
    "connect_tcp",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("authorization observation must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if observation construction reaches the network."""
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


def _assert_no_secrets(text: str) -> None:
    lowered = text.lower()
    for marker in _SECRET_MARKERS:
        assert marker.lower() not in lowered
        assert marker not in text


def _target(url: str = "https://app.test/resource") -> TargetUrl:
    return parse_target_url(url)


def _identity(identity_id: str = "user-a") -> Identity:
    return Identity(identity_id=identity_id)


def _case(
    *,
    target: TargetUrl | None = None,
    baseline: Identity | None = None,
    comparison: Identity | None = None,
) -> AuthorizationCase:
    return AuthorizationCase(
        target=_target() if target is None else target,
        baseline=_identity("user-a") if baseline is None else baseline,
        comparison=_identity("user-b") if comparison is None else comparison,
    )


def _evidence(
    *,
    status: int = 200,
    final_target: TargetUrl | None = None,
    requested_target: TargetUrl | None = None,
    body_length: int = 5,
    body_sha256: str = _DIGEST_A,
) -> ResponseEvidence:
    requested = _target() if requested_target is None else requested_target
    return ResponseEvidence(
        status=status,
        final_target=requested if final_target is None else final_target,
        requested_target=requested,
        body_length=body_length,
        body_sha256=body_sha256,
    )


def _all_flags_true(result: ResponseComparison) -> bool:
    return (
        result.status_equal
        and result.body_length_equal
        and result.body_sha256_equal
        and result.final_target_equal
    )


def _kind_for(comparison: ResponseComparison) -> AuthorizationObservationKind:
    if _all_flags_true(comparison):
        return AuthorizationObservationKind.EQUIVALENT_PROJECTION
    return AuthorizationObservationKind.DISTINCT_PROJECTION


def _observation(
    *,
    rule_id: str = _RULE_ID,
    kind: AuthorizationObservationKind | None = None,
    target: TargetUrl | None = None,
    baseline_identity: Identity | None = None,
    comparison_identity: Identity | None = None,
    baseline_response: ResponseEvidence | None = None,
    comparison_response: ResponseEvidence | None = None,
    comparison: ResponseComparison | None = None,
    observation: str | None = None,
    rationale: str | None = None,
) -> AuthorizationObservation:
    resolved_target = _target() if target is None else target
    resolved_baseline_identity = (
        _identity("user-a") if baseline_identity is None else baseline_identity
    )
    resolved_comparison_identity = (
        _identity("user-b") if comparison_identity is None else comparison_identity
    )
    resolved_baseline_response = (
        _evidence(requested_target=resolved_target)
        if baseline_response is None
        else baseline_response
    )
    resolved_comparison_response = (
        _evidence(requested_target=resolved_target)
        if comparison_response is None
        else comparison_response
    )
    resolved_comparison = (
        compare_response_evidence(
            resolved_baseline_response,
            resolved_comparison_response,
        )
        if comparison is None
        else comparison
    )
    resolved_kind = _kind_for(resolved_comparison) if kind is None else kind
    equivalent = resolved_kind is AuthorizationObservationKind.EQUIVALENT_PROJECTION
    return AuthorizationObservation(
        rule_id=rule_id,
        kind=resolved_kind,
        target=resolved_target,
        baseline_identity=resolved_baseline_identity,
        comparison_identity=resolved_comparison_identity,
        baseline_response=resolved_baseline_response,
        comparison_response=resolved_comparison_response,
        comparison=resolved_comparison,
        observation=(
            _EQUIVALENT_OBSERVATION
            if observation is None and equivalent
            else _DISTINCT_OBSERVATION
            if observation is None
            else observation
        ),
        rationale=(
            _EQUIVALENT_RATIONALE
            if rationale is None and equivalent
            else _DISTINCT_RATIONALE
            if rationale is None
            else rationale
        ),
    )


def _limits() -> RequestLimits:
    return RequestLimits(
        max_body_bytes=1024,
        connect_timeout=1.0,
        read_timeout=2.0,
        write_timeout=3.0,
        pool_timeout=4.0,
    )


class _UnusedResolver:
    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        raise AssertionError("authorization observation must not resolve DNS")


def _resolver() -> AddressResolver:
    return _UnusedResolver()


def _credentials(origin: Origin) -> OriginBoundCredentials:
    return OriginBoundCredentials(
        origin=origin,
        headers=((b"Authorization", _AUTH_VALUE), (b"Cookie", _COOKIE_VALUE)),
    )


async def _observe_completed_pair(
    case: AuthorizationCase,
    *,
    baseline_credentials: OriginBoundCredentials | None,
    comparison_credentials: OriginBoundCredentials | None,
) -> AuthorizationObservation:
    import boundary.authorization as authorization

    allowed_origins: Collection[Origin] = frozenset({case.target.origin})
    policy = AddressPolicy.PUBLIC
    resolver = _resolver()
    limits = _limits()
    baseline_transport = await authorization.request_as(
        case.target,
        case.baseline,
        credentials=baseline_credentials,
        allowed_origins=allowed_origins,
        policy=policy,
        resolver=resolver,
        limits=limits,
        max_redirects=5,
    )
    baseline_response = capture_response_evidence(
        baseline_transport,
        requested_target=case.target,
    )
    comparison_transport = await authorization.request_as(
        case.target,
        case.comparison,
        credentials=comparison_credentials,
        allowed_origins=allowed_origins,
        policy=policy,
        resolver=resolver,
        limits=limits,
        max_redirects=5,
    )
    comparison_response = capture_response_evidence(
        comparison_transport,
        requested_target=case.target,
    )
    comparison = compare_response_evidence(baseline_response, comparison_response)
    kind = _kind_for(comparison)
    equivalent = kind is AuthorizationObservationKind.EQUIVALENT_PROJECTION
    return AuthorizationObservation(
        rule_id=_RULE_ID,
        kind=kind,
        target=case.target,
        baseline_identity=case.baseline,
        comparison_identity=case.comparison,
        baseline_response=baseline_response,
        comparison_response=comparison_response,
        comparison=comparison,
        observation=(_EQUIVALENT_OBSERVATION if equivalent else _DISTINCT_OBSERVATION),
        rationale=_EQUIVALENT_RATIONALE if equivalent else _DISTINCT_RATIONALE,
    )


def _canonical_material(
    *,
    rule_id: str = _RULE_ID,
    target: str = "https://app.test/resource",
    baseline_identity: str = "user-a",
    comparison_identity: str = "user-b",
    baseline_status: int = 200,
    baseline_body_length: int = 5,
    baseline_body_sha256: str = _DIGEST_A,
    baseline_final_target: str = "https://app.test/resource",
    comparison_status: int = 200,
    comparison_body_length: int = 5,
    comparison_body_sha256: str = _DIGEST_A,
    comparison_final_target: str = "https://app.test/resource",
) -> dict[str, object]:
    return {
        "schema": 1,
        "rule_id": rule_id,
        "target": target,
        "baseline_identity": baseline_identity,
        "comparison_identity": comparison_identity,
        "baseline_response": {
            "status": baseline_status,
            "body_length": baseline_body_length,
            "body_sha256": baseline_body_sha256,
            "final_target": baseline_final_target,
        },
        "comparison_response": {
            "status": comparison_status,
            "body_length": comparison_body_length,
            "body_sha256": comparison_body_sha256,
            "final_target": comparison_final_target,
        },
    }


def test_authorization_observation_kind_lives_on_the_authorization_module() -> None:
    import boundary.authorization as authorization

    assert authorization.AuthorizationObservationKind is AuthorizationObservationKind
    module = inspect.getmodule(AuthorizationObservationKind)
    assert module is not None
    assert module.__name__ == "boundary.authorization"


def test_authorization_observation_kind_is_a_strenum() -> None:
    assert issubclass(AuthorizationObservationKind, StrEnum)


def test_authorization_observation_kind_has_exactly_the_approved_values() -> None:
    assert (
        AuthorizationObservationKind.EQUIVALENT_PROJECTION.value
        == "equivalent_projection"
    )
    assert (
        AuthorizationObservationKind.DISTINCT_PROJECTION.value == "distinct_projection"
    )
    assert list(AuthorizationObservationKind) == [
        AuthorizationObservationKind.EQUIVALENT_PROJECTION,
        AuthorizationObservationKind.DISTINCT_PROJECTION,
    ]
    assert set(AuthorizationObservationKind) == {
        AuthorizationObservationKind.EQUIVALENT_PROJECTION,
        AuthorizationObservationKind.DISTINCT_PROJECTION,
    }


def test_authorization_observation_kind_has_no_vulnerability_or_safe_verdict() -> None:
    names = {member.name.lower() for member in AuthorizationObservationKind}
    values = {member.value.lower() for member in AuthorizationObservationKind}

    for forbidden in _FORBIDDEN_KIND_NAMES:
        assert forbidden not in names
        assert forbidden not in values
    assert "confirmed" not in names
    assert "validated" not in names
    assert "rejected" not in names


def test_all_four_flags_true_maps_to_equivalent_projection() -> None:
    record = _observation()

    assert _all_flags_true(record.comparison) is True
    assert record.kind is AuthorizationObservationKind.EQUIVALENT_PROJECTION
    assert record.kind == "equivalent_projection"  # type: ignore[comparison-overlap]


@pytest.mark.parametrize(
    ("field", "raw"),
    [
        ("status", 403),
        ("body_length", 9),
        ("body_sha256", _DIGEST_B),
        ("final_target", "https://app.test/other"),
    ],
    ids=("status", "body_length", "body_sha256", "final_target"),
)
def test_any_false_flag_maps_to_distinct_projection(field: str, raw: object) -> None:
    target = _target()
    value: object = parse_target_url(str(raw)) if field == "final_target" else raw
    comparison_response = _evidence(
        requested_target=target,
        status=403 if field == "status" else 200,
        body_length=9 if field == "body_length" else 5,
        body_sha256=_DIGEST_B if field == "body_sha256" else _DIGEST_A,
        final_target=(
            parse_target_url("https://app.test/other")
            if field == "final_target"
            else target
        ),
    )

    record = _observation(target=target, comparison_response=comparison_response)

    assert value is not None
    assert _all_flags_true(record.comparison) is False
    assert record.kind is AuthorizationObservationKind.DISTINCT_PROJECTION
    assert record.kind == "distinct_projection"  # type: ignore[comparison-overlap]


def test_multiple_false_flags_map_to_distinct_projection() -> None:
    target = _target()
    record = _observation(
        target=target,
        comparison_response=_evidence(
            requested_target=target,
            status=404,
            body_length=0,
            body_sha256=_DIGEST_B,
            final_target=_target("https://app.test/other"),
        ),
    )

    assert record.comparison == ResponseComparison(
        status_equal=False,
        body_length_equal=False,
        body_sha256_equal=False,
        final_target_equal=False,
    )
    assert record.kind is AuthorizationObservationKind.DISTINCT_PROJECTION


def test_distinct_kind_is_rejected_when_all_four_flags_are_true() -> None:
    with pytest.raises(ValueError, match="kind") as caught:
        _observation(kind=AuthorizationObservationKind.DISTINCT_PROJECTION)

    _assert_no_secrets(str(caught.value))
    assert "<html" not in str(caught.value).lower()


def test_equivalent_kind_is_rejected_when_any_flag_is_false() -> None:
    target = _target()
    with pytest.raises(ValueError, match="kind") as caught:
        _observation(
            target=target,
            comparison_response=_evidence(requested_target=target, status=403),
            kind=AuthorizationObservationKind.EQUIVALENT_PROJECTION,
        )

    _assert_no_secrets(str(caught.value))


def test_authorization_observation_lives_on_the_authorization_module() -> None:
    import boundary.authorization as authorization
    import boundary.evidence as evidence

    assert authorization.AuthorizationObservation is AuthorizationObservation
    module = inspect.getmodule(AuthorizationObservation)
    assert module is not None
    assert module.__name__ == "boundary.authorization"
    assert not hasattr(evidence, "AuthorizationObservation")
    assert not hasattr(evidence, "AuthorizationObservationKind")
    for name in _SPECULATIVE_AUTHORIZATION_NAMES:
        assert not hasattr(authorization, name)


def test_authorization_observation_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(AuthorizationObservation))

    assert names == _OBSERVATION_FIELDS
    assert "fingerprint" not in names
    for forbidden in _FORBIDDEN_OBSERVATION_FIELDS:
        assert forbidden not in names


def test_authorization_observation_constructor_accepts_the_approved_fields() -> None:
    parameters = list(inspect.signature(AuthorizationObservation).parameters)

    assert parameters == list(_OBSERVATION_FIELDS)
    assert "fingerprint" not in parameters


def test_authorization_observation_is_frozen_and_slotted() -> None:
    record = _observation()

    for name in _OBSERVATION_FIELDS:
        with pytest.raises(FrozenInstanceError):
            setattr(record, name, getattr(record, name))

    assert set(AuthorizationObservation.__slots__) == set(_OBSERVATION_FIELDS)
    assert "fingerprint" not in AuthorizationObservation.__slots__
    assert not hasattr(record, "__dict__")


def test_authorization_observation_type_hints_resolve() -> None:
    hints = get_type_hints(AuthorizationObservation)

    assert hints["rule_id"] is str
    assert hints["kind"] is AuthorizationObservationKind
    assert hints["target"] is TargetUrl
    assert hints["baseline_identity"] is Identity
    assert hints["comparison_identity"] is Identity
    assert hints["baseline_response"] is ResponseEvidence
    assert hints["comparison_response"] is ResponseEvidence
    assert hints["comparison"] is ResponseComparison
    assert hints["observation"] is str
    assert hints["rationale"] is str


def test_fingerprint_is_a_computed_property_not_a_stored_field() -> None:
    record = _observation()

    assert "fingerprint" not in {
        field.name for field in fields(AuthorizationObservation)
    }
    assert isinstance(AuthorizationObservation.fingerprint, property)
    assert record.fingerprint == _LOCKED_FINGERPRINT


def test_fingerprint_cannot_be_supplied_to_the_constructor() -> None:
    target = _target()
    baseline_response = _evidence(requested_target=target)
    comparison_response = _evidence(requested_target=target)
    comparison = compare_response_evidence(baseline_response, comparison_response)

    constructor: Any = AuthorizationObservation
    with pytest.raises(TypeError):
        constructor(
            rule_id=_RULE_ID,
            kind=AuthorizationObservationKind.EQUIVALENT_PROJECTION,
            target=target,
            baseline_identity=_identity("user-a"),
            comparison_identity=_identity("user-b"),
            baseline_response=baseline_response,
            comparison_response=comparison_response,
            comparison=comparison,
            observation=_EQUIVALENT_OBSERVATION,
            rationale=_EQUIVALENT_RATIONALE,
            fingerprint=_LOCKED_FINGERPRINT,
        )


def test_observation_target_is_the_authorization_case_target() -> None:
    case = _case()
    record = _observation(
        target=case.target,
        baseline_identity=case.baseline,
        comparison_identity=case.comparison,
    )

    assert record.target is case.target
    assert record.baseline_identity is case.baseline
    assert record.comparison_identity is case.comparison


def test_baseline_and_comparison_identities_remain_ordered_and_directional() -> None:
    user_a = _identity("user-a")
    user_b = _identity("user-b")
    target = _target()
    forward = _observation(
        target=target,
        baseline_identity=user_a,
        comparison_identity=user_b,
    )
    swapped = _observation(
        target=target,
        baseline_identity=user_b,
        comparison_identity=user_a,
    )

    assert forward.baseline_identity is user_a
    assert forward.comparison_identity is user_b
    assert swapped.baseline_identity is user_b
    assert swapped.comparison_identity is user_a
    assert forward != swapped
    assert forward.fingerprint != swapped.fingerprint


def test_observation_preserves_response_projections_and_comparison() -> None:
    target = _target()
    baseline_response = _evidence(requested_target=target, status=200)
    comparison_response = _evidence(requested_target=target, status=403)
    comparison = compare_response_evidence(baseline_response, comparison_response)

    record = _observation(
        target=target,
        baseline_response=baseline_response,
        comparison_response=comparison_response,
        comparison=comparison,
    )

    assert record.baseline_response is baseline_response
    assert record.comparison_response is comparison_response
    assert record.comparison is comparison
    assert record.kind is AuthorizationObservationKind.DISTINCT_PROJECTION


def test_completed_pair_yields_exactly_one_observation() -> None:
    record = _observation()

    assert type(record) is AuthorizationObservation
    assert record.rule_id == _RULE_ID


def test_observation_stores_no_credentials_or_raw_response_data() -> None:
    credentials = _credentials(_target().origin)
    record = _observation()
    field_names = {field.name for field in fields(AuthorizationObservation)}
    public_names = {name for name in dir(record) if not name.startswith("_")}

    assert credentials.headers[0][1] == _AUTH_VALUE
    for forbidden in (
        "credentials",
        "headers",
        "body",
        "raw",
        "excerpt",
        "authorization",
        "cookie",
    ):
        assert forbidden not in field_names
        assert forbidden not in public_names
    _assert_no_secrets(repr(record))
    _assert_no_secrets(str(record))
    _assert_no_secrets(record.observation)
    _assert_no_secrets(record.rationale)
    _assert_no_secrets(record.fingerprint)


def test_query_string_on_the_case_target_remains_visible() -> None:
    target = _target("https://app.test/resource?token=visible-query-token")
    record = _observation(target=target)
    canonical = json.dumps(
        _canonical_material(
            target=target.url,
            baseline_final_target=target.url,
            comparison_final_target=target.url,
        ),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )

    assert "token=visible-query-token" in record.target.url
    assert "token=visible-query-token" in canonical
    assert record.fingerprint == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert record.fingerprint != _LOCKED_FINGERPRINT


def test_finding_evidence_is_not_reused_for_authorization_observation() -> None:
    record = _observation()
    public_names = {name for name in dir(record) if not name.startswith("_")}

    assert not isinstance(record, FindingEvidence)
    assert "evidence_id" not in {
        field.name for field in fields(AuthorizationObservation)
    }
    assert "evidence_id" not in public_names
    assert "finding" not in {field.name for field in fields(AuthorizationObservation)}


def test_authorization_module_does_not_import_discovery_or_passive() -> None:
    import boundary.authorization as authorization

    source = inspect.getsource(authorization)
    assert "boundary.discovery" not in source
    assert "boundary.passive" not in source


def test_fingerprint_is_a_64_character_lowercase_sha256_hex_string() -> None:
    fingerprint = _observation().fingerprint

    assert len(fingerprint) == 64
    assert fingerprint == fingerprint.lower()
    assert all(character in "0123456789abcdef" for character in fingerprint)


def test_canonical_fingerprint_matches_the_locked_test_vector() -> None:
    record = _observation()
    canonical = json.dumps(
        _canonical_material(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    assert canonical == _CANONICAL_IDENTITY_JSON
    assert digest == _LOCKED_FINGERPRINT
    assert record.fingerprint == _LOCKED_FINGERPRINT
    assert "requested_target" not in canonical
    assert "status_equal" not in canonical
    assert "body_length_equal" not in canonical
    assert "body_sha256_equal" not in canonical
    assert "final_target_equal" not in canonical
    assert "equivalent_projection" not in canonical
    assert "distinct_projection" not in canonical
    assert "kind" not in canonical
    assert "observation" not in canonical
    assert "rationale" not in canonical
    _assert_no_secrets(canonical)


def test_canonical_serialization_is_independent_of_insertion_order() -> None:
    unordered = {
        "target": "https://app.test/resource",
        "schema": 1,
        "comparison_identity": "user-b",
        "rule_id": _RULE_ID,
        "baseline_identity": "user-a",
        "comparison_response": {
            "final_target": "https://app.test/resource",
            "status": 200,
            "body_sha256": _DIGEST_A,
            "body_length": 5,
        },
        "baseline_response": {
            "status": 200,
            "final_target": "https://app.test/resource",
            "body_length": 5,
            "body_sha256": _DIGEST_A,
        },
    }
    canonical = json.dumps(
        unordered,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )

    assert canonical == _CANONICAL_IDENTITY_JSON
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == _LOCKED_FINGERPRINT
    assert _observation().fingerprint == _LOCKED_FINGERPRINT


def test_repeated_construction_produces_the_same_fingerprint() -> None:
    first = _observation()
    second = _observation()

    assert first.fingerprint == second.fingerprint
    assert first.fingerprint == _LOCKED_FINGERPRINT


def test_separately_created_equal_inputs_produce_the_same_fingerprint() -> None:
    left = _observation(
        target=_target("https://app.test/resource"),
        baseline_identity=_identity("user-a"),
        comparison_identity=_identity("user-b"),
        baseline_response=_evidence(
            requested_target=_target("https://app.test/resource")
        ),
        comparison_response=_evidence(
            requested_target=_target("https://app.test/resource")
        ),
    )
    right = _observation(
        target=_target("https://app.test/resource"),
        baseline_identity=_identity("user-a"),
        comparison_identity=_identity("user-b"),
        baseline_response=_evidence(
            requested_target=_target("https://app.test/resource")
        ),
        comparison_response=_evidence(
            requested_target=_target("https://app.test/resource")
        ),
    )

    assert left.target is not right.target
    assert left.baseline_identity is not right.baseline_identity
    assert left.baseline_response is not right.baseline_response
    assert left.fingerprint == right.fingerprint
    assert left.fingerprint == _LOCKED_FINGERPRINT


def test_object_identity_of_equal_targets_does_not_change_fingerprint() -> None:
    left_target = _target("https://app.test/resource")
    right_target = _target("https://app.test/resource")

    assert left_target is not right_target
    assert left_target == right_target
    assert (
        _observation(target=left_target).fingerprint
        == _observation(target=right_target).fingerprint
        == _LOCKED_FINGERPRINT
    )


def test_changing_rule_id_changes_fingerprint() -> None:
    other = _observation(rule_id="authorization.pair.projection.v2")

    assert other.rule_id == "authorization.pair.projection.v2"
    assert other.fingerprint != _LOCKED_FINGERPRINT


def test_changing_case_target_changes_fingerprint() -> None:
    target = _target("https://app.test/other")
    other = _observation(target=target)

    assert other.target.url == "https://app.test/other"
    assert other.fingerprint != _LOCKED_FINGERPRINT


def test_changing_baseline_identity_changes_fingerprint() -> None:
    other = _observation(baseline_identity=_identity("anonymous"))

    assert other.baseline_identity.identity_id == "anonymous"
    assert other.fingerprint != _LOCKED_FINGERPRINT


def test_changing_comparison_identity_changes_fingerprint() -> None:
    other = _observation(comparison_identity=_identity("user-c"))

    assert other.comparison_identity.identity_id == "user-c"
    assert other.fingerprint != _LOCKED_FINGERPRINT


@pytest.mark.parametrize("which", ("baseline", "comparison"))
@pytest.mark.parametrize(
    "field",
    ("status", "body_length", "body_sha256", "final_target"),
)
def test_changing_either_response_projection_changes_fingerprint(
    which: str,
    field: str,
) -> None:
    target = _target()
    mutated = _evidence(
        requested_target=target,
        status=403 if field == "status" else 200,
        body_length=9 if field == "body_length" else 5,
        body_sha256=_DIGEST_B if field == "body_sha256" else _DIGEST_A,
        final_target=(
            _target("https://app.test/other") if field == "final_target" else target
        ),
    )
    other = (
        _observation(target=target, baseline_response=mutated)
        if which == "baseline"
        else _observation(target=target, comparison_response=mutated)
    )

    assert other.fingerprint != _LOCKED_FINGERPRINT
    assert other.kind is AuthorizationObservationKind.DISTINCT_PROJECTION


def test_changing_only_observation_wording_does_not_change_fingerprint() -> None:
    other = _observation(observation="Different wording of the same captured fact.")

    assert other.observation != _EQUIVALENT_OBSERVATION
    assert other.fingerprint == _LOCKED_FINGERPRINT


def test_changing_only_rationale_wording_does_not_change_fingerprint() -> None:
    other = _observation(rationale="Different wording of the documented limit.")

    assert other.rationale != _EQUIVALENT_RATIONALE
    assert other.fingerprint == _LOCKED_FINGERPRINT


def test_fingerprint_source_excludes_nondeterministic_and_secret_inputs() -> None:
    descriptor = AuthorizationObservation.__dict__["fingerprint"]
    assert isinstance(descriptor, property)
    getter = descriptor.fget
    assert getter is not None
    source = inspect.getsource(getter)

    for marker in _FORBIDDEN_FINGERPRINT_SOURCE:
        assert marker not in source


def test_identical_identities_raise_value_error_before_observation_creation() -> None:
    user_a = _identity("user-a")
    result: AuthorizationObservation | None = None

    with pytest.raises(ValueError, match="identit") as caught:
        result = _observation(
            baseline_identity=user_a,
            comparison_identity=_identity("user-a"),
        )

    assert result is None
    _assert_no_secrets(str(caught.value))
    assert _BODY_SECRET.decode("ascii") not in str(caught.value)


def test_baseline_requested_target_mismatch_raises_value_error() -> None:
    target = _target()
    result: AuthorizationObservation | None = None

    with pytest.raises(ValueError, match="requested_target") as caught:
        result = _observation(
            target=target,
            baseline_response=_evidence(
                requested_target=_target("https://app.test/other-start"),
                final_target=target,
            ),
            comparison_response=_evidence(requested_target=target),
        )

    assert result is None
    _assert_no_secrets(str(caught.value))
    assert "<html" not in str(caught.value).lower()


def test_comparison_requested_target_mismatch_raises_value_error() -> None:
    target = _target()
    result: AuthorizationObservation | None = None

    with pytest.raises(ValueError, match="requested_target") as caught:
        result = _observation(
            target=target,
            baseline_response=_evidence(requested_target=target),
            comparison_response=_evidence(
                requested_target=_target("https://app.test/other-start"),
                final_target=target,
            ),
        )

    assert result is None
    _assert_no_secrets(str(caught.value))


def test_redirect_final_targets_are_allowed_when_requested_targets_match_case() -> None:
    target = _target("https://app.test/start")
    baseline_final = _target("https://app.test/resource")
    comparison_final = _target("https://app.test/other")
    record = _observation(
        target=target,
        baseline_response=_evidence(
            requested_target=target,
            final_target=baseline_final,
        ),
        comparison_response=_evidence(
            requested_target=target,
            final_target=comparison_final,
        ),
    )

    assert record.target is target
    assert record.baseline_response.requested_target == target
    assert record.comparison_response.requested_target == target
    assert record.baseline_response.final_target is baseline_final
    assert record.comparison_response.final_target is comparison_final
    assert record.comparison.final_target_equal is False
    assert record.kind is AuthorizationObservationKind.DISTINCT_PROJECTION


def test_supplied_comparison_must_equal_compare_response_evidence() -> None:
    target = _target()
    baseline_response = _evidence(requested_target=target)
    comparison_response = _evidence(requested_target=target)
    wrong_comparison = ResponseComparison(
        status_equal=False,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=True,
    )
    result: AuthorizationObservation | None = None

    with pytest.raises(ValueError, match="comparison") as caught:
        result = _observation(
            target=target,
            baseline_response=baseline_response,
            comparison_response=comparison_response,
            comparison=wrong_comparison,
            kind=AuthorizationObservationKind.DISTINCT_PROJECTION,
        )

    assert result is None
    _assert_no_secrets(str(caught.value))
    assert "set-cookie" not in str(caught.value).lower()


def test_observation_cannot_be_constructed_from_an_incomplete_pair() -> None:
    target = _target()
    baseline_response = _evidence(requested_target=target)
    comparison = compare_response_evidence(baseline_response, baseline_response)
    result: AuthorizationObservation | None = None

    constructor: Any = AuthorizationObservation
    with pytest.raises(TypeError):
        result = constructor(
            rule_id=_RULE_ID,
            kind=AuthorizationObservationKind.EQUIVALENT_PROJECTION,
            target=target,
            baseline_identity=_identity("user-a"),
            comparison_identity=_identity("user-b"),
            baseline_response=baseline_response,
            comparison=comparison,
            observation=_EQUIVALENT_OBSERVATION,
            rationale=_EQUIVALENT_RATIONALE,
        )

    assert result is None


def test_baseline_request_failure_skips_comparison_and_emits_no_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boundary.authorization as authorization

    calls: list[str] = []
    error = TransportError(
        TransportErrorCode.RESPONSE_TOO_LARGE,
        "Response body exceeds the configured limit.",
    )

    async def fail_as(
        target: TargetUrl,
        identity: Identity,
        *,
        credentials: OriginBoundCredentials | None,
        allowed_origins: Collection[Origin],
        policy: AddressPolicy,
        resolver: AddressResolver,
        limits: RequestLimits,
        max_redirects: int,
    ) -> TransportResponse:
        calls.append(identity.identity_id)
        raise error

    monkeypatch.setattr(authorization, "request_as", fail_as)
    case = _case()
    result: AuthorizationObservation | None = None

    with pytest.raises(TransportError) as caught:
        result = asyncio.run(
            _observe_completed_pair(
                case,
                baseline_credentials=_credentials(case.target.origin),
                comparison_credentials=None,
            )
        )

    assert result is None
    assert caught.value is error
    assert caught.value.code is TransportErrorCode.RESPONSE_TOO_LARGE
    assert calls == ["user-a"]
    assert not isinstance(caught.value, AuthorizationObservation)
    _assert_no_secrets(str(caught.value))


def test_comparison_request_failure_emits_no_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boundary.authorization as authorization

    calls: list[str] = []
    error = TransportError(
        TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT,
        "Redirect destination origin differs from the bound origin.",
    )
    case = _case()

    async def scripted_as(
        target: TargetUrl,
        identity: Identity,
        *,
        credentials: OriginBoundCredentials | None,
        allowed_origins: Collection[Origin],
        policy: AddressPolicy,
        resolver: AddressResolver,
        limits: RequestLimits,
        max_redirects: int,
    ) -> TransportResponse:
        calls.append(identity.identity_id)
        if identity.identity_id == case.baseline.identity_id:
            return TransportResponse(
                status=200,
                headers=((b"Set-Cookie", _COOKIE_VALUE),),
                body=_BODY_SECRET,
                final_target=target,
            )
        raise error

    monkeypatch.setattr(authorization, "request_as", scripted_as)
    result: AuthorizationObservation | None = None

    with pytest.raises(TransportError) as caught:
        result = asyncio.run(
            _observe_completed_pair(
                case,
                baseline_credentials=None,
                comparison_credentials=_credentials(case.target.origin),
            )
        )

    assert result is None
    assert caught.value is error
    assert caught.value.code is TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT
    assert calls == ["user-a", "user-b"]
    assert caught.value.code.value != AuthorizationObservationKind.DISTINCT_PROJECTION
    _assert_no_secrets(str(caught.value))


def test_scope_failure_is_not_rewritten_as_a_benign_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boundary.authorization as authorization

    error = ScopeValidationError(
        ScopeErrorCode.ORIGIN_NOT_ALLOWED,
        "Origin is not in the allowlist.",
    )

    async def fail_as(
        target: TargetUrl,
        identity: Identity,
        *,
        credentials: OriginBoundCredentials | None,
        allowed_origins: Collection[Origin],
        policy: AddressPolicy,
        resolver: AddressResolver,
        limits: RequestLimits,
        max_redirects: int,
    ) -> TransportResponse:
        raise error

    monkeypatch.setattr(authorization, "request_as", fail_as)
    result: AuthorizationObservation | None = None

    with pytest.raises(ScopeValidationError) as caught:
        result = asyncio.run(
            _observe_completed_pair(
                _case(),
                baseline_credentials=None,
                comparison_credentials=None,
            )
        )

    assert result is None
    assert caught.value is error
    assert caught.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
    assert not isinstance(caught.value, AuthorizationObservation)


def test_url_validation_failure_is_not_rewritten_as_distinct_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boundary.authorization as authorization

    error = UrlValidationError(
        UrlErrorCode.EMBEDDED_CREDENTIALS,
        "Target URL must not contain embedded credentials.",
    )

    async def fail_as(
        target: TargetUrl,
        identity: Identity,
        *,
        credentials: OriginBoundCredentials | None,
        allowed_origins: Collection[Origin],
        policy: AddressPolicy,
        resolver: AddressResolver,
        limits: RequestLimits,
        max_redirects: int,
    ) -> TransportResponse:
        raise error

    monkeypatch.setattr(authorization, "request_as", fail_as)
    result: AuthorizationObservation | None = None

    with pytest.raises(UrlValidationError) as caught:
        result = asyncio.run(
            _observe_completed_pair(
                _case(),
                baseline_credentials=None,
                comparison_credentials=None,
            )
        )

    assert result is None
    assert caught.value is error
    assert caught.value.code is UrlErrorCode.EMBEDDED_CREDENTIALS
    assert caught.value.code.value != AuthorizationObservationKind.DISTINCT_PROJECTION


def test_documented_loop_emits_one_observation_for_a_completed_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import boundary.authorization as authorization

    case = _case()
    credentials = _credentials(case.target.origin)
    calls: list[str] = []

    async def scripted_as(
        target: TargetUrl,
        identity: Identity,
        *,
        credentials: OriginBoundCredentials | None,
        allowed_origins: Collection[Origin],
        policy: AddressPolicy,
        resolver: AddressResolver,
        limits: RequestLimits,
        max_redirects: int,
    ) -> TransportResponse:
        calls.append(identity.identity_id)
        body = b"same-body" if identity.identity_id == "user-a" else b"other-body"
        return TransportResponse(
            status=200,
            headers=((b"Authorization", _AUTH_VALUE),),
            body=body,
            final_target=target,
        )

    monkeypatch.setattr(authorization, "request_as", scripted_as)

    record = asyncio.run(
        _observe_completed_pair(
            case,
            baseline_credentials=credentials,
            comparison_credentials=credentials,
        )
    )

    assert calls == ["user-a", "user-b"]
    assert type(record) is AuthorizationObservation
    assert record.target is case.target
    assert record.baseline_identity is case.baseline
    assert record.comparison_identity is case.comparison
    assert record.kind is AuthorizationObservationKind.DISTINCT_PROJECTION
    _assert_no_secrets(repr(record))
    _assert_no_secrets(record.fingerprint)
    assert not hasattr(record, "headers")
    assert not hasattr(record, "body")


def test_observation_construction_performs_no_network_activity() -> None:
    record = _observation()

    assert record.fingerprint == _LOCKED_FINGERPRINT


def test_observation_has_no_raw_body_header_access_or_semantic_parsing() -> None:
    record = _observation()
    field_names = {field.name for field in fields(AuthorizationObservation)}
    public_names = {name for name in dir(record) if not name.startswith("_")}
    init_source = inspect.getsource(AuthorizationObservation.__post_init__)

    for forbidden in ("headers", "body", "raw", "excerpt"):
        assert forbidden not in field_names
        assert forbidden not in public_names
    for marker in (
        "difflib",
        "SequenceMatcher",
        "BeautifulSoup",
        "html.parser",
        "openai",
        "anthropic",
        "embedding",
    ):
        assert marker not in init_source


def test_observation_carries_no_severity_confidence_cvss_or_ai_claim() -> None:
    record = _observation()
    field_names = {field.name for field in fields(AuthorizationObservation)}
    public_names = {name for name in dir(record) if not name.startswith("_")}
    type_name = AuthorizationObservation.__name__.lower()

    for forbidden in (
        "confidence",
        "severity",
        "cvss",
        "vulnerability",
        "verdict",
        "idor",
        "bola",
        "score",
        "similarity",
        "heuristic",
        "ai",
        "llm",
        "remediation",
    ):
        assert forbidden not in field_names
        assert forbidden not in public_names
    assert "idor" not in type_name
    assert "bola" not in type_name
    assert "vulnerab" not in type_name
    assert record.kind in AuthorizationObservationKind
