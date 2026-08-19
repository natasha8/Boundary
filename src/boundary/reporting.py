"""Safe report URL projection with fail-closed query redaction."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlunsplit

from boundary.scope import TargetUrl

QUERY_REDACTION_MARKER = "REDACTED"


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
