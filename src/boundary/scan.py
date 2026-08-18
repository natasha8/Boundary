"""Immutable configuration for one uncredentialed passive scan."""

from __future__ import annotations

from dataclasses import dataclass

from boundary.discovery import DiscoveryLimits
from boundary.scope import (
    AddressPolicy,
    AddressResolver,
    Origin,
    TargetUrl,
    require_allowed_origin,
)
from boundary.transport import RequestLimits


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Complete explicit input of one uncredentialed passive scan."""

    target: TargetUrl
    allowed_origins: tuple[Origin, ...]
    policy: AddressPolicy
    resolver: AddressResolver
    request_limits: RequestLimits
    max_redirects: int
    discovery_limits: DiscoveryLimits

    def __post_init__(self) -> None:
        require_allowed_origin(
            self.target,
            self.allowed_origins,
        )
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be non-negative")
