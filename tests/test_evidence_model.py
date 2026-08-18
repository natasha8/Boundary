"""Offline tests for the evidence model and deterministic identity (Slice A)."""

from __future__ import annotations

import hashlib
import json
import socket
from collections.abc import Collection
from dataclasses import FrozenInstanceError, fields

import anyio
import pytest

from boundary.evidence import FindingEvidence, ResponseEvidence
from boundary.passive import (
    PassiveFinding,
    PassiveFindingKind,
    build_passive_finding,
)
from boundary.scope import TargetUrl, parse_target_url

_RULE_ID = "passive.hsts.not_enforced.v1"
_OBSERVATION = "HTTPS response did not enforce Strict-Transport-Security."
_RATIONALE = (
    "Missing HSTS is a transport-hardening observation, not proof of exploitability."
)
_UNSORTED_EVIDENCE: tuple[tuple[str, str], ...] = (
    ("status", "200"),
    ("state", "missing"),
)
_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_OTHER_BODY_SHA256 = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
_LOCKED_FINDING_FINGERPRINT = (
    "ac661e0391660b0790cfa46f51c189d30afb408b5d8232eee7e8bd72a6018628"
)
_CANONICAL_IDENTITY_JSON = (
    '{"body_length":123,'
    '"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",'
    '"finding":"ac661e0391660b0790cfa46f51c189d30afb408b5d8232eee7e8bd72a6018628",'
    '"schema":1,'
    '"status":200}'
)
_LOCKED_EVIDENCE_ID = "c4c4af338f8df7e692ebfe4125ba217cdb10c2a50845a079a34f245cb3dd7d17"
_FORBIDDEN_MODEL_FIELDS = (
    "severity",
    "cvss",
    "confidence",
    "state",
    "status_state",
    "id",
    "uuid",
    "created_at",
    "timestamp",
    "time",
    "random",
    "nonce",
    "headers",
    "body",
    "raw",
    "excerpt",
    "verdict",
    "validated",
    "confirmation",
)
_SPECULATIVE_PUBLIC_NAMES = (
    "EvidenceEngine",
    "EvidenceStore",
    "EvidenceRepository",
    "EvidenceRecord",
    "Evidence",
    "build_finding_evidence",
    "compare_responses",
    "compare_evidence",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("evidence model must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if evidence construction reaches network entry points."""
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


def _finding(
    *,
    rule_id: str = _RULE_ID,
    kind: PassiveFindingKind = PassiveFindingKind.HARDENING,
    target: TargetUrl | None = None,
    requested_target: TargetUrl | None = None,
    observation: str = _OBSERVATION,
    rationale: str = _RATIONALE,
    evidence: Collection[tuple[str, str]] = _UNSORTED_EVIDENCE,
) -> PassiveFinding:
    return build_passive_finding(
        rule_id=rule_id,
        kind=kind,
        target=parse_target_url("https://app.test/") if target is None else target,
        requested_target=(
            parse_target_url("https://app.test/start")
            if requested_target is None
            else requested_target
        ),
        observation=observation,
        rationale=rationale,
        evidence=evidence,
    )


def _response_evidence(
    *,
    status: int = 200,
    final_target: TargetUrl | None = None,
    requested_target: TargetUrl | None = None,
    body_length: int = 123,
    body_sha256: str = _BODY_SHA256,
) -> ResponseEvidence:
    return ResponseEvidence(
        status=status,
        final_target=(
            parse_target_url("https://app.test/")
            if final_target is None
            else final_target
        ),
        requested_target=(
            parse_target_url("https://app.test/start")
            if requested_target is None
            else requested_target
        ),
        body_length=body_length,
        body_sha256=body_sha256,
    )


def _finding_evidence(
    *,
    finding: PassiveFinding | None = None,
    response: ResponseEvidence | None = None,
) -> FindingEvidence:
    resolved_finding = _finding() if finding is None else finding
    resolved_response = (
        _response_evidence(
            final_target=resolved_finding.target,
            requested_target=resolved_finding.requested_target,
        )
        if response is None
        else response
    )
    return FindingEvidence(finding=resolved_finding, response=resolved_response)


def test_response_evidence_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(ResponseEvidence))

    assert names == (
        "status",
        "final_target",
        "requested_target",
        "body_length",
        "body_sha256",
    )
    for forbidden in _FORBIDDEN_MODEL_FIELDS:
        assert forbidden not in names


def test_response_evidence_is_frozen_and_slotted() -> None:
    evidence = _response_evidence()

    with pytest.raises(FrozenInstanceError):
        evidence.status = 500  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        evidence.body_sha256 = _OTHER_BODY_SHA256  # type: ignore[misc]

    assert set(ResponseEvidence.__slots__) == {
        "status",
        "final_target",
        "requested_target",
        "body_length",
        "body_sha256",
    }
    assert not hasattr(evidence, "__dict__")


def test_response_evidence_preserves_supplied_values_and_target_objects() -> None:
    final_target = parse_target_url("https://app.test/final")
    requested_target = parse_target_url("https://app.test/start")

    evidence = ResponseEvidence(
        status=302,
        final_target=final_target,
        requested_target=requested_target,
        body_length=7,
        body_sha256=_BODY_SHA256,
    )

    assert evidence.status == 302
    assert evidence.final_target is final_target
    assert evidence.requested_target is requested_target
    assert evidence.body_length == 7
    assert evidence.body_sha256 == _BODY_SHA256


def test_response_evidence_accepts_zero_body_length() -> None:
    evidence = _response_evidence(body_length=0)

    assert evidence.body_length == 0
    assert evidence.body_sha256 == _BODY_SHA256


@pytest.mark.parametrize("body_length", [-1, -1000])
def test_negative_body_length_is_rejected(body_length: int) -> None:
    with pytest.raises(ValueError, match="body_length") as caught:
        _response_evidence(body_length=body_length)

    assert "password=" not in str(caught.value)
    assert "<html" not in str(caught.value).lower()


@pytest.mark.parametrize(
    "body_sha256",
    [
        _BODY_SHA256[:63],
        _BODY_SHA256 + "a",
        _BODY_SHA256.upper(),
        _BODY_SHA256[:63] + "g",
        "",
        f"sha256:{_BODY_SHA256}",
    ],
    ids=(
        "shorter_than_64",
        "longer_than_64",
        "uppercase_hex",
        "non_hex_character",
        "empty",
        "sha256_prefix",
    ),
)
def test_non_canonical_body_sha256_is_rejected(body_sha256: str) -> None:
    with pytest.raises(ValueError, match="body_sha256") as caught:
        _response_evidence(body_sha256=body_sha256)

    message = str(caught.value)
    assert "password=" not in message
    assert "set-cookie" not in message.lower()
    assert "authorization" not in message.lower()


def test_finding_evidence_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(FindingEvidence))

    assert names == ("finding", "response")
    assert "evidence_id" not in names
    for forbidden in _FORBIDDEN_MODEL_FIELDS:
        assert forbidden not in names


def test_finding_evidence_is_frozen_and_slotted() -> None:
    record = _finding_evidence()

    with pytest.raises(FrozenInstanceError):
        record.finding = _finding()  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        record.response = _response_evidence()  # type: ignore[misc]

    assert set(FindingEvidence.__slots__) == {"finding", "response"}
    assert "evidence_id" not in FindingEvidence.__slots__
    assert not hasattr(record, "__dict__")


def test_finding_evidence_preserves_finding_and_response_by_reference() -> None:
    finding = _finding()
    response = _response_evidence(
        final_target=finding.target,
        requested_target=finding.requested_target,
    )

    record = FindingEvidence(finding=finding, response=response)

    assert record.finding is finding
    assert record.response is response


def test_finding_evidence_accepts_equivalent_separately_constructed_targets() -> None:
    finding = _finding(
        target=parse_target_url("https://app.test/"),
        requested_target=parse_target_url("https://app.test/start"),
    )
    response = _response_evidence(
        final_target=parse_target_url("https://app.test/"),
        requested_target=parse_target_url("https://app.test/start"),
    )

    assert finding.target is not response.final_target
    assert finding.requested_target is not response.requested_target
    assert finding.target == response.final_target
    assert finding.requested_target == response.requested_target

    record = FindingEvidence(finding=finding, response=response)

    assert record.evidence_id == _LOCKED_EVIDENCE_ID


def test_mismatched_final_target_raises_value_error() -> None:
    finding = _finding()
    response = _response_evidence(
        final_target=parse_target_url("https://app.test/other"),
        requested_target=finding.requested_target,
    )

    with pytest.raises(ValueError, match="final_target") as caught:
        FindingEvidence(finding=finding, response=response)

    message = str(caught.value)
    assert "password=" not in message
    assert "<html" not in message.lower()
    assert "set-cookie" not in message.lower()


def test_mismatched_requested_target_raises_value_error() -> None:
    finding = _finding()
    response = _response_evidence(
        final_target=finding.target,
        requested_target=parse_target_url("https://app.test/other"),
    )

    with pytest.raises(ValueError, match="requested_target") as caught:
        FindingEvidence(finding=finding, response=response)

    message = str(caught.value)
    assert "password=" not in message
    assert "<html" not in message.lower()
    assert "authorization" not in message.lower()


def test_evidence_id_is_a_computed_property_not_a_stored_field() -> None:
    record = _finding_evidence()

    assert "evidence_id" not in {field.name for field in fields(FindingEvidence)}
    assert isinstance(FindingEvidence.evidence_id, property)
    assert record.evidence_id == _LOCKED_EVIDENCE_ID


def test_evidence_id_cannot_be_supplied_to_the_constructor() -> None:
    finding = _finding()
    response = _response_evidence(
        final_target=finding.target,
        requested_target=finding.requested_target,
    )

    with pytest.raises(TypeError):
        FindingEvidence(
            finding=finding,
            response=response,
            evidence_id=_LOCKED_EVIDENCE_ID,  # type: ignore[call-arg]
        )


def test_evidence_id_is_a_64_character_lowercase_sha256_hex_string() -> None:
    evidence_id = _finding_evidence().evidence_id

    assert len(evidence_id) == 64
    assert evidence_id == evidence_id.lower()
    assert all(character in "0123456789abcdef" for character in evidence_id)


def test_canonical_evidence_id_matches_the_locked_test_vector() -> None:
    record = _finding_evidence()
    canonical = json.dumps(
        {
            "schema": 1,
            "finding": record.finding.fingerprint,
            "status": record.response.status,
            "body_length": record.response.body_length,
            "body_sha256": record.response.body_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    assert record.finding.fingerprint == _LOCKED_FINDING_FINGERPRINT
    assert canonical == _CANONICAL_IDENTITY_JSON
    assert digest == _LOCKED_EVIDENCE_ID
    assert record.evidence_id == _LOCKED_EVIDENCE_ID
    assert "requested_target" not in canonical
    assert "rule_id" not in canonical
    assert "https://app.test/" not in canonical
    assert "missing" not in canonical


def test_repeated_construction_produces_the_same_evidence_id() -> None:
    first = _finding_evidence()
    second = _finding_evidence()

    assert first.evidence_id == second.evidence_id
    assert first.evidence_id == _LOCKED_EVIDENCE_ID


def test_separately_created_target_instances_produce_the_same_evidence_id() -> None:
    left = FindingEvidence(
        finding=_finding(
            target=parse_target_url("https://app.test/"),
            requested_target=parse_target_url("https://app.test/start"),
        ),
        response=_response_evidence(
            final_target=parse_target_url("https://app.test/"),
            requested_target=parse_target_url("https://app.test/start"),
        ),
    )
    right = FindingEvidence(
        finding=_finding(
            target=parse_target_url("https://app.test/"),
            requested_target=parse_target_url("https://app.test/start"),
        ),
        response=_response_evidence(
            final_target=parse_target_url("https://app.test/"),
            requested_target=parse_target_url("https://app.test/start"),
        ),
    )

    assert left.finding.target is not right.finding.target
    assert left.response.final_target is not right.response.final_target
    assert left.finding.target == right.finding.target
    assert left.evidence_id == right.evidence_id
    assert left.evidence_id == _LOCKED_EVIDENCE_ID


def test_separately_created_finding_instances_produce_the_same_evidence_id() -> None:
    left_finding = _finding()
    right_finding = _finding()

    assert left_finding is not right_finding
    assert left_finding.fingerprint == right_finding.fingerprint

    left = _finding_evidence(finding=left_finding)
    right = _finding_evidence(finding=right_finding)

    assert left.finding is not right.finding
    assert left.evidence_id == right.evidence_id
    assert left.evidence_id == _LOCKED_EVIDENCE_ID


def test_different_finding_fingerprint_changes_evidence_id() -> None:
    other = _finding_evidence(
        finding=_finding(rule_id="passive.csp.missing_enforced_policy.v1"),
    )

    assert other.finding.fingerprint != _LOCKED_FINDING_FINGERPRINT
    assert other.evidence_id != _LOCKED_EVIDENCE_ID


def test_different_status_changes_evidence_id() -> None:
    other = _finding_evidence(response=_response_evidence(status=404))

    assert other.response.status == 404
    assert other.evidence_id != _LOCKED_EVIDENCE_ID


def test_different_body_length_changes_evidence_id() -> None:
    other = _finding_evidence(response=_response_evidence(body_length=0))

    assert other.response.body_length == 0
    assert other.response.body_sha256 == _BODY_SHA256
    assert other.evidence_id != _LOCKED_EVIDENCE_ID


def test_different_body_sha256_changes_evidence_id() -> None:
    other = _finding_evidence(
        response=_response_evidence(body_sha256=_OTHER_BODY_SHA256),
    )

    assert other.response.body_length == 123
    assert other.response.body_sha256 == _OTHER_BODY_SHA256
    assert other.evidence_id != _LOCKED_EVIDENCE_ID


def test_changing_final_target_changes_identity_through_finding_fingerprint() -> None:
    final_target = parse_target_url("https://app.test/other")
    finding = _finding(target=final_target)
    record = _finding_evidence(
        finding=finding,
        response=_response_evidence(
            final_target=final_target,
            requested_target=finding.requested_target,
        ),
    )

    assert finding.fingerprint != _LOCKED_FINDING_FINGERPRINT
    assert record.evidence_id != _LOCKED_EVIDENCE_ID


def test_changing_only_requested_target_does_not_change_evidence_id() -> None:
    """ADR 0005 excludes requested_target from identity; it is provenance only."""
    requested_target = parse_target_url("https://app.test/alias")
    finding = _finding(requested_target=requested_target)
    record = _finding_evidence(
        finding=finding,
        response=_response_evidence(
            final_target=finding.target,
            requested_target=requested_target,
        ),
    )

    assert finding.requested_target.url == "https://app.test/alias"
    assert finding.fingerprint == _LOCKED_FINDING_FINGERPRINT
    assert record.evidence_id == _LOCKED_EVIDENCE_ID


def test_changing_only_observation_does_not_change_evidence_id() -> None:
    record = _finding_evidence(
        finding=_finding(observation="A different observation."),
    )

    assert record.finding.observation != _OBSERVATION
    assert record.finding.fingerprint == _LOCKED_FINDING_FINGERPRINT
    assert record.evidence_id == _LOCKED_EVIDENCE_ID


def test_changing_only_rationale_does_not_change_evidence_id() -> None:
    record = _finding_evidence(finding=_finding(rationale="A different rationale."))

    assert record.finding.rationale != _RATIONALE
    assert record.finding.fingerprint == _LOCKED_FINDING_FINGERPRINT
    assert record.evidence_id == _LOCKED_EVIDENCE_ID


def test_changing_only_kind_does_not_change_evidence_id() -> None:
    """Kind is outside PassiveFinding.fingerprint, so it cannot affect evidence_id."""
    hardening = _finding_evidence(
        finding=_finding(kind=PassiveFindingKind.HARDENING),
    )
    misconfiguration = _finding_evidence(
        finding=_finding(kind=PassiveFindingKind.MISCONFIGURATION),
    )

    assert hardening.finding.kind is not misconfiguration.finding.kind
    assert hardening.finding.fingerprint == misconfiguration.finding.fingerprint
    assert hardening.evidence_id == misconfiguration.evidence_id
    assert hardening.evidence_id == _LOCKED_EVIDENCE_ID


def test_evidence_models_have_no_time_random_uuid_or_verdict_fields() -> None:
    response = _response_evidence()
    record = _finding_evidence()
    response_fields = {field.name for field in fields(ResponseEvidence)}
    finding_fields = {field.name for field in fields(FindingEvidence)}
    response_public = {name for name in dir(response) if not name.startswith("_")}
    record_public = {name for name in dir(record) if not name.startswith("_")}

    for forbidden in _FORBIDDEN_MODEL_FIELDS:
        assert forbidden not in response_fields
        assert forbidden not in finding_fields
        assert forbidden not in response_public
        assert forbidden not in record_public


def test_evidence_models_cannot_store_raw_response_content() -> None:
    response_fields = {field.name for field in fields(ResponseEvidence)}
    finding_fields = {field.name for field in fields(FindingEvidence)}

    for forbidden in ("headers", "body", "raw", "excerpt", "content"):
        assert forbidden not in response_fields
        assert forbidden not in finding_fields


def test_query_string_in_target_is_preserved_as_inherited_boundary() -> None:
    """Query parameters on TargetUrl are inherited from Scope and are not redacted."""
    target = parse_target_url("https://app.test/reset?token=secret-query-token")
    evidence = _response_evidence(final_target=target, requested_target=target)

    assert evidence.final_target is target
    assert evidence.requested_target is target
    assert evidence.final_target.query == "token=secret-query-token"
    assert "secret-query-token" in evidence.final_target.url


def test_slice_a_public_surface_exposes_the_evidence_models() -> None:
    import boundary.evidence as evidence

    assert hasattr(evidence, "ResponseEvidence")
    assert hasattr(evidence, "FindingEvidence")
    assert evidence.ResponseEvidence is ResponseEvidence
    assert evidence.FindingEvidence is FindingEvidence
    for name in _SPECULATIVE_PUBLIC_NAMES:
        assert not hasattr(evidence, name)
