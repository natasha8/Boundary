"""Explicit identity labels, comparison cases, identity-scoped GET requests, and response comparison."""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass

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
