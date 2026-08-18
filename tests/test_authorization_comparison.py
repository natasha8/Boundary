"""Offline tests for deterministic ResponseEvidence comparison (Slice D)."""

from __future__ import annotations

import inspect
import socket
from dataclasses import FrozenInstanceError, fields
from typing import get_type_hints

import anyio
import pytest

from boundary.authorization import ResponseComparison, compare_response_evidence
from boundary.evidence import ResponseEvidence
from boundary.scope import TargetUrl, parse_target_url

_DIGEST_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_DIGEST_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_COMPARISON_FIELDS = (
    "status_equal",
    "body_length_equal",
    "body_sha256_equal",
    "final_target_equal",
)
_FORBIDDEN_COMPARISON_NAMES = (
    "confidence",
    "severity",
    "cvss",
    "vulnerability",
    "verdict",
    "idor",
    "bola",
    "kind",
    "observation",
    "rationale",
    "headers",
    "body",
    "raw",
    "excerpt",
    "score",
    "similarity",
    "heuristic",
    "equivalent",
    "distinct",
    "equivalent_projection",
    "distinct_projection",
    "requested_target",
    "requested_target_equal",
    "credentials",
    "identity",
    "ai",
    "llm",
    "embedding",
)
_FORBIDDEN_SOURCE_MARKERS = (
    "json.loads",
    "json.load",
    "html.parser",
    "BeautifulSoup",
    "lxml",
    "xml.etree",
    "difflib",
    "SequenceMatcher",
    ".headers",
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
    "requested_target",
)
_SPECULATIVE_AUTHORIZATION_NAMES = (
    "AuthorizationEngine",
    "compare_responses",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("response comparison must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if comparison reaches the network or HTTP stack."""
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


def _target(url: str = "https://app.test/resource") -> TargetUrl:
    return parse_target_url(url)


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


def _flags(result: ResponseComparison) -> tuple[bool, bool, bool, bool]:
    return (
        result.status_equal,
        result.body_length_equal,
        result.body_sha256_equal,
        result.final_target_equal,
    )


def test_response_comparison_lives_on_the_authorization_module() -> None:
    import boundary.authorization as authorization

    assert authorization.ResponseComparison is ResponseComparison
    module = inspect.getmodule(ResponseComparison)
    assert module is not None
    assert module.__name__ == "boundary.authorization"
    for name in _SPECULATIVE_AUTHORIZATION_NAMES:
        assert not hasattr(authorization, name)


def test_compare_response_evidence_lives_on_the_authorization_module() -> None:
    import boundary.authorization as authorization
    import boundary.evidence as evidence

    assert authorization.compare_response_evidence is compare_response_evidence
    module = inspect.getmodule(compare_response_evidence)
    assert module is not None
    assert module.__name__ == "boundary.authorization"
    assert not hasattr(ResponseEvidence, "compare")
    assert not hasattr(ResponseEvidence, "compare_response_evidence")
    assert not hasattr(evidence, "compare_responses")
    assert not hasattr(evidence, "compare_response_evidence")
    assert not hasattr(evidence, "ResponseComparison")


def test_response_comparison_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(ResponseComparison))

    assert names == _COMPARISON_FIELDS
    for forbidden in _FORBIDDEN_COMPARISON_NAMES:
        assert forbidden not in names


def test_response_comparison_constructor_accepts_the_four_booleans() -> None:
    parameters = list(inspect.signature(ResponseComparison).parameters)

    assert parameters == list(_COMPARISON_FIELDS)


def test_response_comparison_is_frozen_and_slotted() -> None:
    result = ResponseComparison(
        status_equal=True,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=True,
    )

    for name in _COMPARISON_FIELDS:
        with pytest.raises(FrozenInstanceError):
            setattr(result, name, False)

    assert set(ResponseComparison.__slots__) == set(_COMPARISON_FIELDS)
    assert not hasattr(result, "__dict__")


def test_compare_response_evidence_signature_matches_the_approved_contract() -> None:
    signature = inspect.signature(compare_response_evidence)
    parameters = signature.parameters

    assert tuple(parameters) == ("baseline", "comparison")
    assert parameters["baseline"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameters["comparison"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    for parameter in parameters.values():
        assert parameter.default is inspect.Parameter.empty


def test_compare_response_evidence_type_hints_resolve() -> None:
    hints = get_type_hints(compare_response_evidence)

    assert hints["baseline"] is ResponseEvidence
    assert hints["comparison"] is ResponseEvidence
    assert hints["return"] is ResponseComparison


def test_compare_response_evidence_is_a_pure_sync_function() -> None:
    assert inspect.isfunction(compare_response_evidence)
    assert inspect.iscoroutinefunction(compare_response_evidence) is False


def test_equal_projections_set_all_four_flags_true() -> None:
    baseline = _evidence()
    comparison = _evidence()

    result = compare_response_evidence(baseline, comparison)

    assert baseline is not comparison
    assert baseline == comparison
    assert type(result) is ResponseComparison
    assert result == ResponseComparison(
        status_equal=True,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=True,
    )
    assert _flags(result) == (True, True, True, True)
    assert all(type(flag) is bool for flag in _flags(result))


def test_status_only_difference_flips_only_status_equal() -> None:
    result = compare_response_evidence(_evidence(), _evidence(status=403))

    assert result == ResponseComparison(
        status_equal=False,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=True,
    )


def test_body_length_only_difference_flips_only_body_length_equal() -> None:
    result = compare_response_evidence(_evidence(), _evidence(body_length=9))

    assert result == ResponseComparison(
        status_equal=True,
        body_length_equal=False,
        body_sha256_equal=True,
        final_target_equal=True,
    )


def test_body_sha256_only_difference_flips_only_body_sha256_equal() -> None:
    result = compare_response_evidence(
        _evidence(),
        _evidence(body_sha256=_DIGEST_B),
    )

    assert result == ResponseComparison(
        status_equal=True,
        body_length_equal=True,
        body_sha256_equal=False,
        final_target_equal=True,
    )


def test_final_target_only_difference_flips_only_final_target_equal() -> None:
    result = compare_response_evidence(
        _evidence(),
        _evidence(final_target=_target("https://app.test/other")),
    )

    assert result == ResponseComparison(
        status_equal=True,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=False,
    )


def test_multiple_dimensions_differ_flip_only_those_flags() -> None:
    baseline = _evidence()
    two_dimensions = _evidence(status=403, body_length=9)
    all_four = _evidence(
        status=404,
        final_target=_target("https://app.test/other"),
        body_length=0,
        body_sha256=_DIGEST_B,
    )

    two_result = compare_response_evidence(baseline, two_dimensions)
    all_result = compare_response_evidence(baseline, all_four)

    assert two_result == ResponseComparison(
        status_equal=False,
        body_length_equal=False,
        body_sha256_equal=True,
        final_target_equal=True,
    )
    assert all_result == ResponseComparison(
        status_equal=False,
        body_length_equal=False,
        body_sha256_equal=False,
        final_target_equal=False,
    )


def test_response_comparison_equality_is_the_four_boolean_values() -> None:
    left = ResponseComparison(
        status_equal=True,
        body_length_equal=False,
        body_sha256_equal=True,
        final_target_equal=False,
    )
    right = ResponseComparison(
        status_equal=True,
        body_length_equal=False,
        body_sha256_equal=True,
        final_target_equal=False,
    )
    other = ResponseComparison(
        status_equal=False,
        body_length_equal=False,
        body_sha256_equal=True,
        final_target_equal=False,
    )

    assert left == right
    assert left is not right
    assert left != other


def test_repeated_comparison_is_deterministic() -> None:
    baseline = _evidence(status=403, body_sha256=_DIGEST_B)
    comparison = _evidence(status=200, body_sha256=_DIGEST_B)

    first = compare_response_evidence(baseline, comparison)
    second = compare_response_evidence(baseline, comparison)
    third = compare_response_evidence(
        _evidence(status=403, body_sha256=_DIGEST_B),
        _evidence(status=200, body_sha256=_DIGEST_B),
    )

    assert first == second == third
    assert first == ResponseComparison(
        status_equal=False,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=True,
    )


def test_swapped_baseline_and_comparison_yield_the_same_equality_flags() -> None:
    baseline = _evidence(status=200, body_length=5)
    comparison = _evidence(status=403, body_length=9)

    forward = compare_response_evidence(baseline, comparison)
    swapped = compare_response_evidence(comparison, baseline)

    assert forward == swapped
    assert forward == ResponseComparison(
        status_equal=False,
        body_length_equal=False,
        body_sha256_equal=True,
        final_target_equal=True,
    )


def test_final_target_equal_uses_target_url_equality_not_object_identity() -> None:
    left_final = _target("https://app.test/resource")
    right_final = _target("https://app.test/resource")
    baseline = _evidence(final_target=left_final)
    comparison = _evidence(final_target=right_final)

    result = compare_response_evidence(baseline, comparison)

    assert left_final is not right_final
    assert left_final == right_final
    assert result.final_target_equal is True


def test_requested_target_does_not_substitute_for_final_target_comparison() -> None:
    requested = _target("https://app.test/start")
    final_a = _target("https://app.test/resource")
    final_b = _target("https://app.test/other")
    same_requested_different_final = compare_response_evidence(
        _evidence(final_target=final_a, requested_target=requested),
        _evidence(final_target=final_b, requested_target=requested),
    )
    same_final_different_requested = compare_response_evidence(
        _evidence(final_target=final_a, requested_target=requested),
        _evidence(
            final_target=final_a,
            requested_target=_target("https://app.test/other-start"),
        ),
    )

    assert same_requested_different_final.final_target_equal is False
    assert same_requested_different_final == ResponseComparison(
        status_equal=True,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=False,
    )
    assert same_final_different_requested.final_target_equal is True
    assert same_final_different_requested == ResponseComparison(
        status_equal=True,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=True,
    )


def test_requested_target_is_not_a_comparison_flag() -> None:
    names = tuple(field.name for field in fields(ResponseComparison))
    public_names = {
        name
        for name in dir(
            ResponseComparison(
                status_equal=True,
                body_length_equal=True,
                body_sha256_equal=True,
                final_target_equal=True,
            )
        )
        if not name.startswith("_")
    }

    assert "requested_target_equal" not in names
    assert "requested_target" not in names
    assert "requested_target_equal" not in public_names
    assert "requested_target" not in public_names


def test_compare_response_evidence_does_not_mutate_inputs() -> None:
    baseline_final = _target("https://app.test/resource")
    comparison_final = _target("https://app.test/other")
    baseline = _evidence(
        status=200,
        final_target=baseline_final,
        requested_target=_target("https://app.test/start"),
        body_length=5,
        body_sha256=_DIGEST_A,
    )
    comparison = _evidence(
        status=403,
        final_target=comparison_final,
        requested_target=_target("https://app.test/start"),
        body_length=9,
        body_sha256=_DIGEST_B,
    )
    baseline_snapshot = (
        baseline.status,
        baseline.final_target,
        baseline.requested_target,
        baseline.body_length,
        baseline.body_sha256,
    )
    comparison_snapshot = (
        comparison.status,
        comparison.final_target,
        comparison.requested_target,
        comparison.body_length,
        comparison.body_sha256,
    )

    result = compare_response_evidence(baseline, comparison)

    assert (
        baseline.status,
        baseline.final_target,
        baseline.requested_target,
        baseline.body_length,
        baseline.body_sha256,
    ) == baseline_snapshot
    assert (
        comparison.status,
        comparison.final_target,
        comparison.requested_target,
        comparison.body_length,
        comparison.body_sha256,
    ) == comparison_snapshot
    assert baseline.final_target is baseline_final
    assert comparison.final_target is comparison_final
    assert result == ResponseComparison(
        status_equal=False,
        body_length_equal=False,
        body_sha256_equal=False,
        final_target_equal=False,
    )


def test_comparison_performs_no_network_activity() -> None:
    result = compare_response_evidence(_evidence(), _evidence(status=404))

    assert result.status_equal is False
    assert result.body_length_equal is True
    assert result.body_sha256_equal is True
    assert result.final_target_equal is True


def test_comparison_has_no_raw_body_header_access_or_semantic_parsing() -> None:
    result = compare_response_evidence(_evidence(), _evidence())
    field_names = {field.name for field in fields(ResponseComparison)}
    public_names = {name for name in dir(result) if not name.startswith("_")}
    source = inspect.getsource(compare_response_evidence)

    for forbidden in ("headers", "body", "raw", "excerpt"):
        assert forbidden not in field_names
        assert forbidden not in public_names
    for marker in _FORBIDDEN_SOURCE_MARKERS:
        assert marker not in source


def test_comparison_carries_no_verdict_confidence_or_authorization_claim() -> None:
    result = compare_response_evidence(_evidence(), _evidence())
    field_names = {field.name for field in fields(ResponseComparison)}
    public_names = {name for name in dir(result) if not name.startswith("_")}
    type_name = ResponseComparison.__name__.lower()

    for forbidden in (
        "confidence",
        "severity",
        "cvss",
        "vulnerability",
        "verdict",
        "idor",
        "bola",
        "kind",
        "equivalent",
        "distinct",
        "score",
        "similarity",
        "heuristic",
        "ai",
        "llm",
    ):
        assert forbidden not in field_names
        assert forbidden not in public_names
    assert "idor" not in type_name
    assert "bola" not in type_name
    assert "vulnerab" not in type_name
    assert result == ResponseComparison(
        status_equal=True,
        body_length_equal=True,
        body_sha256_equal=True,
        final_target_equal=True,
    )
