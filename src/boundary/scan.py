"""Immutable configuration, result, and uncredentialed passive scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from boundary.discovery import DiscoveryLimits, crawl
from boundary.evidence import FindingEvidence, capture_response_evidence
from boundary.passive import scan_page
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


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Ordered FindingEvidence values from one completed uncredentialed passive scan."""

    findings: tuple[FindingEvidence, ...]


async def run_passive_scan(config: ScanConfig) -> ScanResult:
    """Crawl in config order, scan each page, and pair findings with captured evidence."""
    collected_findings: list[FindingEvidence] = []
    async for page in crawl(
        seed=config.target,
        allowed_origins=config.allowed_origins,
        policy=config.policy,
        resolver=config.resolver,
        request_limits=config.request_limits,
        max_redirects=config.max_redirects,
        limits=config.discovery_limits,
    ):
        findings = scan_page(page)
        if not findings:
            continue
        response = capture_response_evidence(
            page.response,
            requested_target=page.target,
        )
        for finding in findings:
            collected_findings.append(
                FindingEvidence(finding=finding, response=response)
            )
    return ScanResult(findings=tuple(collected_findings))
