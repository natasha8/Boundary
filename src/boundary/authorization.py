"""Explicit identity labels, comparison cases, identity-scoped GET requests, and pair observations."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum

from boundary.evidence import ResponseEvidence
from boundary.scope import AddressPolicy, AddressResolver, Origin, TargetUrl
from boundary.transport import (
    OriginBoundCredentials,
    RequestLimits,
    TransportResponse,
    request_with_redirects,
)

_IDENTITY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True, slots=True)
class Identity:
    """Public identity label that is safe to store in findings."""

    identity_id: str

    def __post_init__(self) -> None:
        if _IDENTITY_ID_PATTERN.fullmatch(self.identity_id) is None:
            raise ValueError(
                "identity_id must be a non-empty ASCII token of letters, "
                "digits, dots, underscores and hyphens."
            )


@dataclass(frozen=True, slots=True)
class AuthorizationCase:
    """One explicit target plus two ordered, distinct identities."""

    target: TargetUrl
    baseline: Identity
    comparison: Identity

    def __post_init__(self) -> None:
        if self.baseline.identity_id == self.comparison.identity_id:
            raise ValueError("baseline and comparison identities must be distinct.")


async def request_as(
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
    """Execute one GET for a named identity through the controlled transport path."""
    return await request_with_redirects(
        target,
        allowed_origins=allowed_origins,
        policy=policy,
        resolver=resolver,
        limits=limits,
        max_redirects=max_redirects,
        method="GET",
        headers=(),
        credentials=credentials,
    )


@dataclass(frozen=True, slots=True)
class ResponseComparison:
    """Independent equality flags for two captured response projections."""

    status_equal: bool
    body_length_equal: bool
    body_sha256_equal: bool
    final_target_equal: bool


def compare_response_evidence(
    baseline: ResponseEvidence,
    comparison: ResponseEvidence,
) -> ResponseComparison:
    """Compare two captured projections on status, length, digest and final target."""
    return ResponseComparison(
        status_equal=baseline.status == comparison.status,
        body_length_equal=baseline.body_length == comparison.body_length,
        body_sha256_equal=baseline.body_sha256 == comparison.body_sha256,
        final_target_equal=baseline.final_target == comparison.final_target,
    )


def _response_projection(response: ResponseEvidence) -> dict[str, int | str]:
    return {
        "status": response.status,
        "body_length": response.body_length,
        "body_sha256": response.body_sha256,
        "final_target": response.final_target.url,
    }


class AuthorizationObservationKind(StrEnum):
    """Classification of one completed pair, not a risk score or verdict."""

    EQUIVALENT_PROJECTION = "equivalent_projection"
    DISTINCT_PROJECTION = "distinct_projection"


@dataclass(frozen=True, slots=True)
class AuthorizationObservation:
    """Deterministic record of one ordered identity pair comparison."""

    rule_id: str
    kind: AuthorizationObservationKind
    target: TargetUrl
    baseline_identity: Identity
    comparison_identity: Identity
    baseline_response: ResponseEvidence
    comparison_response: ResponseEvidence
    comparison: ResponseComparison
    observation: str
    rationale: str

    def __post_init__(self) -> None:
        if self.baseline_identity.identity_id == self.comparison_identity.identity_id:
            raise ValueError("baseline and comparison identities must be distinct.")
        if self.baseline_response.requested_target != self.target:
            raise ValueError("baseline_response.requested_target must equal target.")
        if self.comparison_response.requested_target != self.target:
            raise ValueError("comparison_response.requested_target must equal target.")
        if self.comparison != compare_response_evidence(
            self.baseline_response,
            self.comparison_response,
        ):
            raise ValueError(
                "comparison must equal compare_response_evidence of the two projections."
            )
        all_equal = (
            self.comparison.status_equal
            and self.comparison.body_length_equal
            and self.comparison.body_sha256_equal
            and self.comparison.final_target_equal
        )
        expected_kind = (
            AuthorizationObservationKind.EQUIVALENT_PROJECTION
            if all_equal
            else AuthorizationObservationKind.DISTINCT_PROJECTION
        )
        if self.kind != expected_kind:
            raise ValueError("kind must match the four comparison flags.")

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "schema": 1,
                "rule_id": self.rule_id,
                "target": self.target.url,
                "baseline_identity": self.baseline_identity.identity_id,
                "comparison_identity": self.comparison_identity.identity_id,
                "baseline_response": _response_projection(self.baseline_response),
                "comparison_response": _response_projection(self.comparison_response),
            },
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
