"""Deterministic passive findings derived from already-fetched evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boundary.scope import TargetUrl


class PassiveFindingKind(StrEnum):
    """Classification of a passive observation, not a risk score."""

    MISCONFIGURATION = "misconfiguration"
    HARDENING = "hardening"


@dataclass(frozen=True, slots=True)
class PassiveFinding:
    """Immutable sanitized finding attached to a final response target."""

    rule_id: str
    kind: PassiveFindingKind
    target: TargetUrl
    requested_target: TargetUrl
    observation: str
    rationale: str
    evidence: tuple[tuple[str, str], ...]

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "schema": 1,
                "rule_id": self.rule_id,
                "target": self.target.url,
                "evidence": [list(pair) for pair in self.evidence],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonicalize_evidence(
    evidence: Collection[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    pairs = tuple((key, value) for key, value in evidence)
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ValueError("Evidence keys must be unique.")
        seen.add(key)
    return tuple(sorted(pairs, key=lambda pair: pair[0]))


def build_passive_finding(
    *,
    rule_id: str,
    kind: PassiveFindingKind,
    target: TargetUrl,
    requested_target: TargetUrl,
    observation: str,
    rationale: str,
    evidence: Collection[tuple[str, str]] = (),
) -> PassiveFinding:
    return PassiveFinding(
        rule_id=rule_id,
        kind=kind,
        target=target,
        requested_target=requested_target,
        observation=observation,
        rationale=rationale,
        evidence=_canonicalize_evidence(evidence),
    )
