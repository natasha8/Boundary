"""Safe report URL and ScanResult projection with fail-closed query redaction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlunsplit

from boundary.passive import PassiveFindingKind
from boundary.scan import ScanResult
from boundary.scope import TargetUrl

QUERY_REDACTION_MARKER = "REDACTED"
REPORT_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ReportUrl:
    """Query-safe URL string allowed to appear on a report."""

    url: str

    def __post_init__(self) -> None:
        if self.url == "":
            raise ValueError("url must be non-empty")
        if "#" in self.url:
            raise ValueError("fragments are forbidden")
        if "?" in self.url and self.url.split("?", 1)[1] != QUERY_REDACTION_MARKER:
            raise ValueError(
                "query after the first '?' must be exactly the redaction marker"
            )


def _require_evidence_pairs(evidence: object) -> None:
    if type(evidence) is not tuple:
        raise ValueError("evidence must be a tuple of string pairs")
    for item in evidence:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError("evidence items must be length-2 tuples")
        key, value = item
        if type(key) is not str or type(value) is not str:
            raise ValueError("evidence keys and values must be str")


def project_report_target(target: TargetUrl) -> ReportUrl:
    """Project a TargetUrl into a query-safe ReportUrl without reading target.url."""
    defaults = {"http": 80, "https": 443}
    if target.scheme not in defaults:
        raise ValueError("unsupported URL scheme")
    if target.host == "" or target.path == "":
        raise ValueError("host and path are required")
    display_host = f"[{target.host}]" if ":" in target.host else target.host
    default_port = defaults[target.scheme]
    netloc = (
        display_host if target.port == default_port else f"{display_host}:{target.port}"
    )
    query_component = QUERY_REDACTION_MARKER if target.query != "" else ""
    rendered = urlunsplit((target.scheme, netloc, target.path, query_component, ""))
    return ReportUrl(url=rendered)


@dataclass(frozen=True, slots=True)
class ReportFinding:
    """Allowlisted passive finding projection for a query-safe report."""

    rule_id: str
    kind: PassiveFindingKind
    target: ReportUrl
    requested_target: ReportUrl
    observation: str
    rationale: str
    evidence: tuple[tuple[str, str], ...]
    status: int
    body_length: int
    body_sha256: str

    def __post_init__(self) -> None:
        if (
            self.kind is not PassiveFindingKind.MISCONFIGURATION
            and self.kind is not PassiveFindingKind.HARDENING
        ):
            raise ValueError("kind must be a supported PassiveFindingKind")
        if type(self.rule_id) is not str:
            raise ValueError("rule_id must be str")
        if type(self.observation) is not str:
            raise ValueError("observation must be str")
        if type(self.rationale) is not str:
            raise ValueError("rationale must be str")
        if type(self.body_sha256) is not str:
            raise ValueError("body_sha256 must be str")
        if type(self.status) is not int:
            raise ValueError("status must be int")
        if type(self.body_length) is not int:
            raise ValueError("body_length must be int")
        if type(self.target) is not ReportUrl:
            raise ValueError("target must be ReportUrl")
        if type(self.requested_target) is not ReportUrl:
            raise ValueError("requested_target must be ReportUrl")
        _require_evidence_pairs(self.evidence)


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Query-safe seed target plus ordered allowlisted findings."""

    schema: int
    target: ReportUrl
    findings: tuple[ReportFinding, ...]

    def __post_init__(self) -> None:
        if self.schema != REPORT_SCHEMA_VERSION:
            raise ValueError("schema must equal REPORT_SCHEMA_VERSION")
        if type(self.findings) is not tuple:
            raise ValueError("findings must be a tuple")


def build_scan_report(*, target: TargetUrl, result: ScanResult) -> ScanReport:
    """Project a seed TargetUrl and ScanResult into a query-safe ScanReport."""
    projected_seed = project_report_target(target)
    findings = tuple(
        ReportFinding(
            rule_id=record.finding.rule_id,
            kind=record.finding.kind,
            target=project_report_target(record.finding.target),
            requested_target=project_report_target(record.finding.requested_target),
            observation=record.finding.observation,
            rationale=record.finding.rationale,
            evidence=record.finding.evidence,
            status=record.response.status,
            body_length=record.response.body_length,
            body_sha256=record.response.body_sha256,
        )
        for record in result.findings
    )
    return ScanReport(
        schema=REPORT_SCHEMA_VERSION,
        target=projected_seed,
        findings=findings,
    )


def render_scan_report_json(report: ScanReport) -> str:
    """Render ScanReport as compact deterministic JSON."""
    if report.schema != REPORT_SCHEMA_VERSION:
        raise ValueError("schema must equal REPORT_SCHEMA_VERSION")
    payload = {
        "schema": report.schema,
        "target": report.target.url,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "kind": finding.kind.value,
                "target": finding.target.url,
                "requested_target": finding.requested_target.url,
                "observation": finding.observation,
                "rationale": finding.rationale,
                "evidence": [[key, value] for key, value in finding.evidence],
                "status": finding.status,
                "body_length": finding.body_length,
                "body_sha256": finding.body_sha256,
            }
            for finding in report.findings
        ],
    }
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=False,
    )
