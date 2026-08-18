"""Deterministic captured-response facts and finding-to-response pairing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from boundary.passive import PassiveFinding
    from boundary.scope import TargetUrl


@dataclass(frozen=True, slots=True)
class ResponseEvidence:
    """Immutable captured response projection: status, targets, length, digest."""

    status: int
    final_target: TargetUrl
    requested_target: TargetUrl
    body_length: int
    body_sha256: str

    def __post_init__(self) -> None:
        if self.body_length < 0:
            raise ValueError("body_length must be greater than or equal to zero.")
        if len(self.body_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.body_sha256
        ):
            raise ValueError("body_sha256 must be 64 lowercase hexadecimal characters.")


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    """Immutable pairing of one passive finding with the response that produced it."""

    finding: PassiveFinding
    response: ResponseEvidence

    def __post_init__(self) -> None:
        if self.finding.target != self.response.final_target:
            raise ValueError("finding.target must equal response.final_target.")
        if self.finding.requested_target != self.response.requested_target:
            raise ValueError(
                "finding.requested_target must equal response.requested_target."
            )

    @property
    def evidence_id(self) -> str:
        material = {
            "schema": 1,
            "finding": self.finding.fingerprint,
            "status": self.response.status,
            "body_length": self.response.body_length,
            "body_sha256": self.response.body_sha256,
        }
        canonical = json.dumps(
            material,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
