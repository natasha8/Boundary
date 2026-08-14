"""Offline tests for the PassiveFinding model and deterministic identity (Slice A)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection
from dataclasses import FrozenInstanceError, fields
from enum import StrEnum

import pytest
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
_SORTED_EVIDENCE: tuple[tuple[str, str], ...] = (
    ("state", "missing"),
    ("status", "200"),
)
_CANONICAL_IDENTITY_JSON = (
    '{"evidence":[["state","missing"],["status","200"]],'
    '"rule_id":"passive.hsts.not_enforced.v1",'
    '"schema":1,'
    '"target":"https://app.test/"}'
)
_LOCKED_FINGERPRINT = "ac661e0391660b0790cfa46f51c189d30afb408b5d8232eee7e8bd72a6018628"


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


def test_passive_finding_kind_is_a_strenum() -> None:
    assert issubclass(PassiveFindingKind, StrEnum)


def test_passive_finding_kind_has_exactly_the_approved_values() -> None:
    assert PassiveFindingKind.MISCONFIGURATION.value == "misconfiguration"
    assert PassiveFindingKind.HARDENING.value == "hardening"
    assert set(PassiveFindingKind) == {
        PassiveFindingKind.MISCONFIGURATION,
        PassiveFindingKind.HARDENING,
    }


def test_passive_finding_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(PassiveFinding))

    assert names == (
        "rule_id",
        "kind",
        "target",
        "requested_target",
        "observation",
        "rationale",
        "evidence",
    )
    assert "fingerprint" not in names
    assert "severity" not in names
    assert "cvss" not in names
    assert "confidence" not in names
    assert "uuid" not in names
    assert "id" not in names
    assert "created_at" not in names
    assert "timestamp" not in names


def test_fingerprint_is_a_computed_property_not_a_stored_field() -> None:
    finding = _finding()

    assert "fingerprint" not in {field.name for field in fields(PassiveFinding)}
    assert finding.fingerprint == _LOCKED_FINGERPRINT


def test_passive_finding_is_frozen_and_slotted() -> None:
    finding = _finding()

    with pytest.raises(FrozenInstanceError):
        finding.rule_id = "passive.other.v1"  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        finding.evidence = ()  # type: ignore[misc]

    assert set(PassiveFinding.__slots__) == {
        "rule_id",
        "kind",
        "target",
        "requested_target",
        "observation",
        "rationale",
        "evidence",
    }
    assert not hasattr(finding, "__dict__")


def test_build_passive_finding_preserves_supplied_normalized_targets() -> None:
    target = parse_target_url("https://app.test/final")
    requested_target = parse_target_url("https://app.test/start")

    finding = _finding(target=target, requested_target=requested_target)

    assert finding.target is target
    assert finding.requested_target is requested_target
    assert finding.target.url == "https://app.test/final"
    assert finding.requested_target.url == "https://app.test/start"


def test_build_passive_finding_stores_exactly_the_supplied_sanitized_evidence() -> None:
    supplied = (("status", "200"), ("cookie_name", "sessionid"), ("state", "missing"))

    finding = _finding(evidence=supplied)

    assert finding.evidence == (
        ("cookie_name", "sessionid"),
        ("state", "missing"),
        ("status", "200"),
    )
    assert finding.evidence != supplied


def test_evidence_is_stored_as_a_tuple_sorted_by_key() -> None:
    finding = _finding(
        evidence=[("status", "200"), ("header", "strict-transport-security")],
    )

    assert finding.evidence == (
        ("header", "strict-transport-security"),
        ("status", "200"),
    )
    assert isinstance(finding.evidence, tuple)
    assert all(isinstance(pair, tuple) for pair in finding.evidence)


def test_evidence_order_does_not_change_stored_evidence_or_fingerprint() -> None:
    left = _finding(evidence=(("status", "200"), ("state", "missing")))
    right = _finding(evidence=(("state", "missing"), ("status", "200")))

    assert left.evidence == _SORTED_EVIDENCE
    assert right.evidence == _SORTED_EVIDENCE
    assert left.evidence == right.evidence
    assert left.fingerprint == right.fingerprint
    assert left.fingerprint == _LOCKED_FINGERPRINT


def test_canonical_fingerprint_matches_the_locked_test_vector() -> None:
    finding = _finding()
    canonical = json.dumps(
        {
            "schema": 1,
            "rule_id": _RULE_ID,
            "target": "https://app.test/",
            "evidence": [list(pair) for pair in _SORTED_EVIDENCE],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    assert canonical == _CANONICAL_IDENTITY_JSON
    assert digest == _LOCKED_FINGERPRINT
    assert finding.fingerprint == _LOCKED_FINGERPRINT


def test_fingerprint_is_a_64_character_lowercase_sha256_hex_string() -> None:
    fingerprint = _finding().fingerprint

    assert len(fingerprint) == 64
    assert fingerprint == fingerprint.lower()
    assert all(character in "0123456789abcdef" for character in fingerprint)


def test_repeated_construction_produces_the_same_fingerprint() -> None:
    first = _finding()
    second = _finding()

    assert first.fingerprint == second.fingerprint
    assert first.fingerprint == _LOCKED_FINGERPRINT


def test_separately_created_target_instances_produce_the_same_fingerprint() -> None:
    left = _finding(
        target=parse_target_url("https://app.test/"),
        requested_target=parse_target_url("https://app.test/start"),
    )
    right = _finding(
        target=parse_target_url("https://app.test/"),
        requested_target=parse_target_url("https://app.test/start"),
    )

    assert left.target is not right.target
    assert left.requested_target is not right.requested_target
    assert left.target == right.target
    assert left.fingerprint == right.fingerprint


def test_different_rule_id_changes_fingerprint() -> None:
    other = _finding(rule_id="passive.csp.missing_enforced_policy.v1")

    assert other.fingerprint != _LOCKED_FINGERPRINT


def test_different_final_target_changes_fingerprint() -> None:
    other = _finding(target=parse_target_url("https://app.test/other"))

    assert other.fingerprint != _LOCKED_FINGERPRINT


def test_different_evidence_changes_fingerprint() -> None:
    other = _finding(evidence=(("state", "disabled"), ("status", "200")))

    assert other.fingerprint != _LOCKED_FINGERPRINT


def test_empty_evidence_is_stored_and_has_a_distinct_fingerprint() -> None:
    finding = _finding(evidence=())

    assert finding.evidence == ()
    assert finding.fingerprint != _LOCKED_FINGERPRINT
    assert len(finding.fingerprint) == 64


def test_changing_only_observation_does_not_change_fingerprint() -> None:
    other = _finding(observation="A different observation.")

    assert other.observation != _OBSERVATION
    assert other.fingerprint == _LOCKED_FINGERPRINT


def test_changing_only_rationale_does_not_change_fingerprint() -> None:
    other = _finding(rationale="A different rationale.")

    assert other.rationale != _RATIONALE
    assert other.fingerprint == _LOCKED_FINGERPRINT


def test_changing_only_requested_target_does_not_change_fingerprint() -> None:
    """ADR 0004 keeps requested_target as provenance, not finding identity."""
    other = _finding(requested_target=parse_target_url("https://app.test/alias"))

    assert other.requested_target.url == "https://app.test/alias"
    assert other.fingerprint == _LOCKED_FINGERPRINT


def test_kind_does_not_change_fingerprint() -> None:
    """ADR 0004 excludes kind from identity; classification is versioned by rule_id."""
    hardening = _finding(kind=PassiveFindingKind.HARDENING)
    misconfiguration = _finding(kind=PassiveFindingKind.MISCONFIGURATION)

    assert hardening.kind is not misconfiguration.kind
    assert hardening.fingerprint == misconfiguration.fingerprint
    assert hardening.fingerprint == _LOCKED_FINGERPRINT


def test_duplicate_evidence_keys_are_rejected() -> None:
    with pytest.raises(ValueError):
        _finding(evidence=(("state", "missing"), ("state", "invalid")))

    with pytest.raises(ValueError):
        _finding(evidence=(("state", "missing"), ("state", "missing")))


def test_identical_values_with_distinct_keys_are_preserved() -> None:
    finding = _finding(evidence=(("header", "missing"), ("state", "missing")))

    assert finding.evidence == (("header", "missing"), ("state", "missing"))


def test_passive_finding_has_no_time_random_or_uuid_fields() -> None:
    finding = _finding()
    field_names = {field.name for field in fields(PassiveFinding)}
    public_names = {name for name in dir(finding) if not name.startswith("_")}

    for forbidden in (
        "uuid",
        "id",
        "created_at",
        "timestamp",
        "time",
        "random",
        "nonce",
        "severity",
        "cvss",
        "confidence",
    ):
        assert forbidden not in field_names
        assert forbidden not in public_names


def test_passive_module_public_surface_is_minimal() -> None:
    import boundary.passive as passive

    assert hasattr(passive, "PassiveFinding")
    assert hasattr(passive, "PassiveFindingKind")
    assert hasattr(passive, "build_passive_finding")
    assert not hasattr(passive, "scan_page")
    assert not hasattr(passive, "scan_pages")
    assert not hasattr(passive, "Rule")
    assert not hasattr(passive, "RuleEngine")
    assert not hasattr(passive, "RuleProtocol")
    assert not hasattr(passive, "register_rule")
