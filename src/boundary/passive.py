"""Deterministic passive findings derived from already-fetched evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterable, AsyncIterator, Collection
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from boundary.discovery import DiscoveredPage, is_html_response

if TYPE_CHECKING:
    from boundary.scope import TargetUrl

_OWS = " \t"
_HSTS_ID = "passive.hsts.not_enforced.v1"
_NOSNIFF_ID = "passive.nosniff.missing_or_invalid.v1"
_CSP_ID = "passive.csp.missing_enforced_policy.v1"
_FRAME_ID = "passive.framing.missing_protection.v1"
_COOKIE_SECURE_ID = "passive.cookie.secure_missing_https.v1"
_COOKIE_SAMESITE_ID = "passive.cookie.samesite_none_without_secure.v1"
_COOKIE_TOKEN = (
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_RECOGNIZED_SAMESITE = frozenset({"none", "lax", "strict"})


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


def _header_values(
    headers: Collection[tuple[bytes, bytes]],
    name: bytes,
) -> tuple[bytes, ...]:
    needle = name.lower()
    return tuple(value for raw_name, value in headers if raw_name.lower() == needle)


def _decode_ascii(value: bytes) -> str | None:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        return None


def _strip_ows(value: str) -> str:
    return value.strip(_OWS)


def _status(page: DiscoveredPage) -> str:
    return str(page.response.status)


def _hardening_finding(
    page: DiscoveredPage,
    *,
    rule_id: str,
    observation: str,
    rationale: str,
    evidence: Collection[tuple[str, str]],
) -> tuple[PassiveFinding, ...]:
    return (
        build_passive_finding(
            rule_id=rule_id,
            kind=PassiveFindingKind.HARDENING,
            target=page.response.final_target,
            requested_target=page.target,
            observation=observation,
            rationale=rationale,
            evidence=evidence,
        ),
    )


def _hsts_field_state(value: str) -> str:
    max_ages: list[int | None] = []
    for segment in value.split(";"):
        directive = _strip_ows(segment)
        if not directive:
            continue
        if "=" in directive:
            raw_name, raw_value = directive.split("=", 1)
            name = _strip_ows(raw_name)
            parsed_value: str | None = _strip_ows(raw_value)
        else:
            name = directive
            parsed_value = None
        if name.lower() != "max-age":
            continue
        if parsed_value is None or not parsed_value.isdigit():
            max_ages.append(None)
        else:
            max_ages.append(int(parsed_value))
    if len(max_ages) > 1:
        return "ambiguous"
    if not max_ages:
        return "invalid"
    age = max_ages[0]
    if age is None:
        return "invalid"
    if age == 0:
        return "disabled"
    return "protected"


def _split_directive(directive: str) -> tuple[str, str]:
    for index, character in enumerate(directive):
        if character in _OWS:
            return directive[:index], _strip_ows(directive[index:])
    return directive, ""


def _has_frame_ancestors(value: str) -> bool:
    for segment in value.split(";"):
        directive = _strip_ows(segment)
        if not directive:
            continue
        name, rest = _split_directive(directive)
        if name.lower() == "frame-ancestors" and rest != "":
            return True
    return False


def _xfo_protects(headers: Collection[tuple[bytes, bytes]]) -> bool:
    values = _header_values(headers, b"x-frame-options")
    if len(values) != 1:
        return False
    text = _decode_ascii(values[0])
    if text is None:
        return False
    return _strip_ows(text).lower() in {"deny", "sameorigin"}


def _csp_frame_ancestors_protects(headers: Collection[tuple[bytes, bytes]]) -> bool:
    for raw in _header_values(headers, b"content-security-policy"):
        text = _decode_ascii(raw)
        if text is None:
            continue
        if _has_frame_ancestors(text):
            return True
    return False


def _check_hsts(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
    if page.response.final_target.scheme != "https":
        return ()

    values = _header_values(page.response.headers, b"strict-transport-security")
    count = str(len(values))
    if not values:
        state = "missing"
    elif len(values) > 1:
        state = "ambiguous"
    else:
        text = _decode_ascii(values[0])
        state = "invalid" if text is None else _hsts_field_state(text)
        if state == "protected":
            return ()

    return _hardening_finding(
        page,
        rule_id=_HSTS_ID,
        observation="HTTPS response did not enforce Strict-Transport-Security.",
        rationale=(
            "Missing or ineffective HSTS is a transport-hardening observation, "
            "not a confirmed attack."
        ),
        evidence=(
            ("header", "strict-transport-security"),
            ("state", state),
            ("count", count),
            ("status", _status(page)),
        ),
    )


def _check_nosniff(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
    if not is_html_response(page.response.headers):
        return ()

    values = _header_values(page.response.headers, b"x-content-type-options")
    count = str(len(values))
    if not values:
        state = "missing"
    elif len(values) > 1:
        state = "ambiguous"
    else:
        text = _decode_ascii(values[0])
        if text is not None and _strip_ows(text).lower() == "nosniff":
            return ()
        state = "invalid"

    return _hardening_finding(
        page,
        rule_id=_NOSNIFF_ID,
        observation="HTML response did not send X-Content-Type-Options nosniff.",
        rationale=(
            "Missing or invalid MIME sniffing protection is a hardening "
            "observation, not proof of exploitability."
        ),
        evidence=(
            ("header", "x-content-type-options"),
            ("state", state),
            ("count", count),
            ("status", _status(page)),
        ),
    )


def _check_enforced_csp(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
    if not is_html_response(page.response.headers):
        return ()

    enforced = _header_values(page.response.headers, b"content-security-policy")
    report_only = _header_values(
        page.response.headers,
        b"content-security-policy-report-only",
    )
    for raw in enforced:
        text = _decode_ascii(raw)
        if text is not None and _strip_ows(text) != "":
            return ()

    if enforced:
        state = "invalid"
    elif report_only:
        state = "report_only"
    else:
        state = "missing"

    return _hardening_finding(
        page,
        rule_id=_CSP_ID,
        observation="HTML response did not send an enforced Content-Security-Policy.",
        rationale=(
            "Missing enforced CSP is a hardening observation, not proof that "
            "a cross-site scripting flaw exists."
        ),
        evidence=(
            ("header", "content-security-policy"),
            ("state", state),
            ("count", str(len(enforced))),
            ("status", _status(page)),
        ),
    )


def _check_frame_protection(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
    if not is_html_response(page.response.headers):
        return ()

    headers = page.response.headers
    if _xfo_protects(headers) or _csp_frame_ancestors_protects(headers):
        return ()

    return _hardening_finding(
        page,
        rule_id=_FRAME_ID,
        observation="HTML response did not provide recognized frame protection.",
        rationale=(
            "Missing X-Frame-Options and CSP frame-ancestors is a hardening "
            "observation, not proof of a successful framing attack."
        ),
        evidence=(
            ("state", "missing"),
            ("status", _status(page)),
        ),
    )


@dataclass(frozen=True, slots=True)
class _CookieMeta:
    name: str
    secure_present: bool
    same_sites: tuple[str | None, ...]


def _is_cookie_name(name: str) -> bool:
    return bool(name) and all(character in _COOKIE_TOKEN for character in name)


def _parse_cookie_field(field: bytes) -> _CookieMeta | None:
    segments = field.split(b";")
    pair = segments[0]
    separator = pair.find(b"=")
    if separator < 0:
        return None
    raw_name = pair[:separator]
    try:
        name = raw_name.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not _is_cookie_name(name):
        return None

    secure_present = False
    same_sites: list[str | None] = []
    for raw_attribute in segments[1:]:
        text = _decode_ascii(raw_attribute)
        if text is None:
            continue
        attribute = _strip_ows(text)
        if not attribute:
            continue
        if "=" in attribute:
            raw_attr_name, raw_attr_value = attribute.split("=", 1)
            attr_name = _strip_ows(raw_attr_name)
            attr_value: str | None = _strip_ows(raw_attr_value)
        else:
            attr_name = attribute
            attr_value = None
        lowered = attr_name.lower()
        if lowered == "secure":
            secure_present = True
        elif lowered == "samesite":
            if attr_value is not None and attr_value.lower() in _RECOGNIZED_SAMESITE:
                same_sites.append(attr_value.lower())
            else:
                same_sites.append(None)

    return _CookieMeta(
        name=name,
        secure_present=secure_present,
        same_sites=tuple(same_sites),
    )


def _misconfiguration_finding(
    page: DiscoveredPage,
    *,
    rule_id: str,
    observation: str,
    rationale: str,
    evidence: Collection[tuple[str, str]],
) -> PassiveFinding:
    return build_passive_finding(
        rule_id=rule_id,
        kind=PassiveFindingKind.MISCONFIGURATION,
        target=page.response.final_target,
        requested_target=page.target,
        observation=observation,
        rationale=rationale,
        evidence=evidence,
    )


def _check_cookie_secure(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
    if page.response.final_target.scheme != "https":
        return ()

    findings: list[PassiveFinding] = []
    for field in _header_values(page.response.headers, b"set-cookie"):
        cookie = _parse_cookie_field(field)
        if cookie is None or cookie.secure_present:
            continue
        findings.append(
            _misconfiguration_finding(
                page,
                rule_id=_COOKIE_SECURE_ID,
                observation="HTTPS Set-Cookie did not include the Secure attribute.",
                rationale=(
                    "A cookie set over HTTPS without Secure is a configuration "
                    "observation, not a confirmed attack."
                ),
                evidence=(
                    ("cookie", cookie.name),
                    ("secure", "missing"),
                    ("status", _status(page)),
                ),
            )
        )
    return tuple(findings)


def _check_samesite_none_secure(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
    findings: list[PassiveFinding] = []
    for field in _header_values(page.response.headers, b"set-cookie"):
        cookie = _parse_cookie_field(field)
        if cookie is None:
            continue
        if (
            len(cookie.same_sites) != 1
            or cookie.same_sites[0] != "none"
            or cookie.secure_present
        ):
            continue
        findings.append(
            _misconfiguration_finding(
                page,
                rule_id=_COOKIE_SAMESITE_ID,
                observation=(
                    "Set-Cookie used SameSite=None without the Secure attribute."
                ),
                rationale=(
                    "SameSite=None without Secure is a configuration observation, "
                    "not a confirmed attack."
                ),
                evidence=(
                    ("cookie", cookie.name),
                    ("same_site", "none"),
                    ("secure", "missing"),
                    ("status", _status(page)),
                ),
            )
        )
    return tuple(findings)


def scan_page(page: DiscoveredPage) -> tuple[PassiveFinding, ...]:
    """Analyze one already-fetched page without additional network activity."""
    seen: set[str] = set()
    findings: list[PassiveFinding] = []
    for rule in (
        _check_hsts,
        _check_nosniff,
        _check_enforced_csp,
        _check_frame_protection,
        _check_cookie_secure,
        _check_samesite_none_secure,
    ):
        for finding in rule(page):
            fingerprint = finding.fingerprint
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            findings.append(finding)
    return tuple(findings)


async def scan_pages(
    pages: AsyncIterable[DiscoveredPage],
) -> AsyncIterator[PassiveFinding]:
    """Yield page findings in stream order, suppressing duplicate fingerprints."""
    emitted: set[str] = set()
    async for page in pages:
        for finding in scan_page(page):
            fingerprint = finding.fingerprint
            if fingerprint in emitted:
                continue
            emitted.add(fingerprint)
            yield finding
