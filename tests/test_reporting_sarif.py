"""Offline tests for deterministic SARIF 2.1.0 scan-report rendering (Milestone 8, Slice D)."""

from __future__ import annotations

import inspect
import json
import socket
import urllib.request
from typing import get_type_hints

import anyio
import pytest

import boundary.reporting as reporting
from boundary.evidence import FindingEvidence, ResponseEvidence
from boundary.passive import PassiveFindingKind, build_passive_finding
from boundary.reporting import (
    ReportFinding,
    ReportUrl,
    ScanReport,
    build_scan_report,
    render_scan_report_sarif,
)
from boundary.scan import ScanResult
from boundary.scope import parse_target_url

_RULE_ID = "passive.hsts.not_enforced.v1"
_OTHER_RULE_ID = "passive.csp.missing_enforced_policy.v1"
_OBSERVATION = "HTTPS response did not enforce Strict-Transport-Security."
_RATIONALE = (
    "Missing or ineffective HSTS is a transport-hardening observation, "
    "not proof of exploitability."
)
_OTHER_OBSERVATION = "Response did not enforce Content-Security-Policy."
_OTHER_RATIONALE = (
    "Missing CSP is a markup-hardening observation, not proof of exploitability."
)
_NON_ASCII_OBSERVATION = (
    "Observation with caf\u00e9 and \u0441\u0435\u043a\u0440\u0435\u0442"
)
_NON_ASCII_RATIONALE = "Rationale with na\u00efve"
_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_OTHER_BODY_SHA256 = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
_TOKEN_KEY = "token"
_TOKEN_VALUE = "reset-token-7f3a9c21"
_SESSION_KEY = "session"
_SESSION_VALUE = "session-id-9c21aabb"
_API_KEY_VALUE = "sk_live_51NotARealKey"
_SECRET_VALUE = "supersecret-query-value"
_UNSORTED_EVIDENCE: tuple[tuple[str, str], ...] = (
    ("status", "200"),
    ("header", "strict-transport-security"),
)
_DUPLICATE_EVIDENCE: tuple[tuple[str, str], ...] = (
    ("status", "200"),
    ("status", "500"),
)
_SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
    "schemas/sarif-schema-2.1.0.json"
)
_TOP_LEVEL_KEYS = ("$schema", "version", "runs")
_RUN_KEYS = ("tool", "results", "properties")
_DRIVER_KEYS = ("name", "rules")
_RULE_KEYS = ("id", "name")
_RESULT_KEYS = (
    "ruleId",
    "ruleIndex",
    "level",
    "message",
    "locations",
    "relatedLocations",
    "properties",
)
_RESULT_KEYS_WITHOUT_RELATED = (
    "ruleId",
    "ruleIndex",
    "level",
    "message",
    "locations",
    "properties",
)
_LOCATION_KEYS = ("physicalLocation",)
_PHYSICAL_LOCATION_KEYS = ("artifactLocation",)
_ARTIFACT_LOCATION_KEYS = ("uri",)
_RELATED_LOCATION_KEYS = ("physicalLocation", "message")
_MESSAGE_KEYS = ("text",)
_RESULT_PROPERTY_KEYS = (
    "kind",
    "rationale",
    "evidence",
    "status",
    "body_length",
    "body_sha256",
)
_RUN_PROPERTY_KEYS = ("scan_target",)
_ALLOWED_OBJECT_KEYS = frozenset(
    (
        *_TOP_LEVEL_KEYS,
        *_RUN_KEYS,
        "driver",
        *_DRIVER_KEYS,
        *_RULE_KEYS,
        *_RESULT_KEYS,
        *_LOCATION_KEYS,
        *_PHYSICAL_LOCATION_KEYS,
        *_ARTIFACT_LOCATION_KEYS,
        *_RELATED_LOCATION_KEYS,
        *_MESSAGE_KEYS,
        *_RESULT_PROPERTY_KEYS,
        *_RUN_PROPERTY_KEYS,
    )
)
_EMPTY_REPORT_SARIF = (
    '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
    'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"BOUNDARY","rules":[]}},"results":[],"properties":{"scan_target":'
    '"https://example.com/"}}]}'
)
_EMPTY_REDACTED_SARIF = (
    '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
    'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"BOUNDARY","rules":[]}},"results":[],"properties":{"scan_target":'
    '"https://example.com/?REDACTED"}}]}'
)
_ONE_FINDING_RELATED_SARIF = (
    '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
    'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"BOUNDARY","rules":[{"id":"passive.hsts.not_enforced.v1","name":'
    '"passive.hsts.not_enforced.v1"}]}},"results":[{"ruleId":'
    '"passive.hsts.not_enforced.v1","ruleIndex":0,"level":"note","message":{"text":'
    '"HTTPS response did not enforce Strict-Transport-Security."},"locations":'
    '[{"physicalLocation":{"artifactLocation":{"uri":'
    '"https://app.test/reset?REDACTED"}}}],"relatedLocations":[{"physicalLocation":'
    '{"artifactLocation":{"uri":"https://app.test/start?REDACTED"}},"message":'
    '{"text":"requested target"}}],"properties":{"kind":"hardening","rationale":'
    '"Missing or ineffective HSTS is a transport-hardening observation, not proof '
    'of exploitability.","evidence":[["status","200"],["header",'
    '"strict-transport-security"]],"status":200,"body_length":123,"body_sha256":'
    '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],'
    '"properties":{"scan_target":"https://example.com/?REDACTED"}}]}'
)
_ONE_FINDING_EQUAL_SARIF = (
    '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
    'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"BOUNDARY","rules":[{"id":"passive.hsts.not_enforced.v1","name":'
    '"passive.hsts.not_enforced.v1"}]}},"results":[{"ruleId":'
    '"passive.hsts.not_enforced.v1","ruleIndex":0,"level":"note","message":{"text":'
    '"HTTPS response did not enforce Strict-Transport-Security."},"locations":'
    '[{"physicalLocation":{"artifactLocation":{"uri":"https://app.test/"}}}],'
    '"properties":{"kind":"hardening","rationale":"Missing or ineffective HSTS is a '
    'transport-hardening observation, not proof of exploitability.","evidence":[],'
    '"status":200,"body_length":123,"body_sha256":'
    '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],'
    '"properties":{"scan_target":"https://example.com/"}}]}'
)
_MULTIPLE_FINDINGS_SARIF = (
    '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
    'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"BOUNDARY","rules":[{"id":"passive.hsts.not_enforced.v1","name":'
    '"passive.hsts.not_enforced.v1"},{"id":"passive.csp.missing_enforced_policy.v1"'
    ',"name":"passive.csp.missing_enforced_policy.v1"}]}},"results":[{"ruleId":'
    '"passive.hsts.not_enforced.v1","ruleIndex":0,"level":"note","message":{"text":'
    '"HTTPS response did not enforce Strict-Transport-Security."},"locations":'
    '[{"physicalLocation":{"artifactLocation":{"uri":"https://app.test/final"}}}],'
    '"relatedLocations":[{"physicalLocation":{"artifactLocation":{"uri":'
    '"https://app.test/start"}},"message":{"text":"requested target"}}],'
    '"properties":{"kind":"hardening","rationale":"Missing or ineffective HSTS is a '
    'transport-hardening observation, not proof of exploitability.","evidence":'
    '[["state","missing"]],"status":200,"body_length":123,"body_sha256":'
    '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},{"ruleId":'
    '"passive.csp.missing_enforced_policy.v1","ruleIndex":1,"level":"note",'
    '"message":{"text":"Response did not enforce Content-Security-Policy."},'
    '"locations":[{"physicalLocation":{"artifactLocation":{"uri":'
    '"https://app.test/final"}}}],"relatedLocations":[{"physicalLocation":'
    '{"artifactLocation":{"uri":"https://app.test/start"}},"message":{"text":'
    '"requested target"}}],"properties":{"kind":"misconfiguration","rationale":'
    '"Missing CSP is a markup-hardening observation, not proof of exploitability.",'
    '"evidence":[["header","content-security-policy"]],"status":500,"body_length":4,'
    '"body_sha256":'
    '"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}}],'
    '"properties":{"scan_target":"https://example.com/"}}]}'
)
_DUPLICATE_RULE_SARIF = (
    '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
    'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"BOUNDARY","rules":[{"id":"passive.hsts.not_enforced.v1","name":'
    '"passive.hsts.not_enforced.v1"}]}},"results":[{"ruleId":'
    '"passive.hsts.not_enforced.v1","ruleIndex":0,"level":"note","message":{"text":'
    '"HTTPS response did not enforce Strict-Transport-Security."},"locations":'
    '[{"physicalLocation":{"artifactLocation":{"uri":"https://app.test/final"}}}],'
    '"relatedLocations":[{"physicalLocation":{"artifactLocation":{"uri":'
    '"https://app.test/start"}},"message":{"text":"requested target"}}],'
    '"properties":{"kind":"hardening","rationale":"Missing or ineffective HSTS is a '
    'transport-hardening observation, not proof of exploitability.","evidence":'
    '[["state","missing"]],"status":200,"body_length":123,"body_sha256":'
    '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},{"ruleId":'
    '"passive.hsts.not_enforced.v1","ruleIndex":0,"level":"note","message":{"text":'
    '"HTTPS response did not enforce Strict-Transport-Security."},"locations":'
    '[{"physicalLocation":{"artifactLocation":{"uri":"https://app.test/other"}}}],'
    '"properties":{"kind":"hardening","rationale":"Missing or ineffective HSTS is a '
    'transport-hardening observation, not proof of exploitability.","evidence":'
    '[["state","missing"]],"status":404,"body_length":9,"body_sha256":'
    '"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}}],'
    '"properties":{"scan_target":"https://example.com/"}}]}'
)
_DUPLICATE_EVIDENCE_SARIF = (
    '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
    'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"BOUNDARY","rules":[{"id":"passive.hsts.not_enforced.v1","name":'
    '"passive.hsts.not_enforced.v1"}]}},"results":[{"ruleId":'
    '"passive.hsts.not_enforced.v1","ruleIndex":0,"level":"note","message":{"text":'
    '"HTTPS response did not enforce Strict-Transport-Security."},"locations":'
    '[{"physicalLocation":{"artifactLocation":{"uri":"https://app.test/"}}}],'
    '"properties":{"kind":"hardening","rationale":"Missing or ineffective HSTS is a '
    'transport-hardening observation, not proof of exploitability.","evidence":'
    '[["status","200"],["status","500"]],"status":200,"body_length":123,'
    '"body_sha256":'
    '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],'
    '"properties":{"scan_target":"https://example.com/"}}]}'
)
_NON_ASCII_SARIF = (
    '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
    'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":'
    '{"name":"BOUNDARY","rules":[{"id":"passive.hsts.not_enforced.v1","name":'
    '"passive.hsts.not_enforced.v1"}]}},"results":[{"ruleId":'
    '"passive.hsts.not_enforced.v1","ruleIndex":0,"level":"note","message":{"text":'
    '"Observation with caf\\u00e9 and \\u0441\\u0435\\u043a\\u0440\\u0435\\u0442"},'
    '"locations":[{"physicalLocation":{"artifactLocation":{"uri":'
    '"https://app.test/"}}}],"properties":{"kind":"hardening","rationale":'
    '"Rationale with na\\u00efve","evidence":[],"status":200,"body_length":0,'
    '"body_sha256":'
    '"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],'
    '"properties":{"scan_target":"https://example.com/"}}]}'
)
_FORBIDDEN_REPR = (
    "ReportUrl(",
    "ReportFinding(",
    "ScanReport(",
    "ScanResult",
    "FindingEvidence",
    "PassiveFinding",
    "ResponseEvidence",
    "TargetUrl",
    "ScanConfig",
    "PassiveFindingKind",
    "object at 0x",
)
_FORBIDDEN_OBJECT_KEYS = (
    "fingerprint",
    "evidence_id",
    "url",
    "headers",
    "header",
    "body",
    "raw",
    "query",
    "credentials",
    "authorization",
    "cookie",
    "cookies",
    "token",
    "run_id",
    "timestamp",
    "time",
    "duration",
    "pages_visited",
    "config",
    "severity",
    "cvss",
    "confidence",
    "confirmation",
    "remediation",
    "uuid",
    "schema",
    "schema_version",
    "rule_id",
    "observation",
    "requested_target",
    "target",
    "webRequest",
    "webResponse",
    "uriBaseId",
    "region",
    "startLine",
    "endLine",
    "byteOffset",
    "invocations",
    "semanticVersion",
    "informationUri",
    "originalUriBaseIds",
    "automationDetails",
    "commandLine",
    "argv",
    "environment",
    "checkout_uri",
    "github",
    "partialFingerprints",
    "fingerprints",
    "rank",
    "baselineState",
    "suppressions",
    "fixes",
    "codeFlows",
    "help",
    "helpUri",
    "shortDescription",
    "fullDescription",
    "defaultConfiguration",
    "hostedViewerUri",
    "downloadUri",
    "logicalLocations",
)
_DOMAIN_TYPE_NAMES = (
    "ScanResult",
    "FindingEvidence",
    "PassiveFinding",
    "ResponseEvidence",
    "TargetUrl",
    "ScanConfig",
)
_GENERIC_SERIALIZATION_MARKERS = (
    "asdict(",
    ".__dict__",
    "__dict__",
    "vars(",
    "getattr(",
    "setattr(",
    "dir(",
    "default=",
    "JSONEncoder",
    "object_hook",
)
_GITHUB_MARKERS = (
    "github",
    "GitHub",
    "upload-sarif",
    "code scanning",
    "Code Scanning",
    "checkout_uri",
    "partialFingerprints",
    "file://",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("SARIF rendering must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if rendering reaches network, GitHub, or scan entry points."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)
    monkeypatch.setattr(urllib.request, "urlopen", _reject_network)
    monkeypatch.setattr("boundary.discovery.crawl", _reject_network)
    monkeypatch.setattr("boundary.transport.request_once", _reject_network)
    monkeypatch.setattr("boundary.transport.request_with_redirects", _reject_network)
    monkeypatch.setattr("boundary.scan.run_passive_scan", _reject_network)
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.resolve",
        _reject_network,
    )


def _report_finding(
    *,
    rule_id: str = _RULE_ID,
    kind: PassiveFindingKind = PassiveFindingKind.HARDENING,
    target: str = "https://app.test/",
    requested_target: str = "https://app.test/",
    observation: str = _OBSERVATION,
    rationale: str = _RATIONALE,
    evidence: tuple[tuple[str, str], ...] = (),
    status: int = 200,
    body_length: int = 123,
    body_sha256: str = _BODY_SHA256,
) -> ReportFinding:
    return ReportFinding(
        rule_id=rule_id,
        kind=kind,
        target=ReportUrl(url=target),
        requested_target=ReportUrl(url=requested_target),
        observation=observation,
        rationale=rationale,
        evidence=evidence,
        status=status,
        body_length=body_length,
        body_sha256=body_sha256,
    )


def _report(
    *,
    target: str = "https://example.com/",
    findings: tuple[ReportFinding, ...] = (),
) -> ScanReport:
    return ScanReport(schema=1, target=ReportUrl(url=target), findings=findings)


def _one_finding_related_report() -> ScanReport:
    return _report(
        target="https://example.com/?REDACTED",
        findings=(
            _report_finding(
                target="https://app.test/reset?REDACTED",
                requested_target="https://app.test/start?REDACTED",
                evidence=_UNSORTED_EVIDENCE,
            ),
        ),
    )


def _one_finding_equal_report() -> ScanReport:
    return _report(findings=(_report_finding(evidence=()),))


def _multiple_findings_report() -> ScanReport:
    return _report(
        findings=(
            _report_finding(
                target="https://app.test/final",
                requested_target="https://app.test/start",
                evidence=(("state", "missing"),),
            ),
            _report_finding(
                rule_id=_OTHER_RULE_ID,
                kind=PassiveFindingKind.MISCONFIGURATION,
                target="https://app.test/final",
                requested_target="https://app.test/start",
                observation=_OTHER_OBSERVATION,
                rationale=_OTHER_RATIONALE,
                evidence=(("header", "content-security-policy"),),
                status=500,
                body_length=4,
                body_sha256=_OTHER_BODY_SHA256,
            ),
        )
    )


def _duplicate_rule_report() -> ScanReport:
    return _report(
        findings=(
            _report_finding(
                target="https://app.test/final",
                requested_target="https://app.test/start",
                evidence=(("state", "missing"),),
            ),
            _report_finding(
                target="https://app.test/other",
                requested_target="https://app.test/other",
                evidence=(("state", "missing"),),
                status=404,
                body_length=9,
                body_sha256=_OTHER_BODY_SHA256,
            ),
        )
    )


def _as_pairs(pairs: list[tuple[str, object]]) -> tuple[tuple[str, object], ...]:
    return tuple(pairs)


def _object_pairs(text: str) -> tuple[tuple[str, object], ...]:
    loaded = json.loads(text, object_pairs_hook=_as_pairs)
    assert isinstance(loaded, tuple)
    return loaded


def _keys(pairs: tuple[tuple[str, object], ...]) -> tuple[str, ...]:
    return tuple(key for key, _value in pairs)


def _require_pairs(value: object) -> tuple[tuple[str, object], ...]:
    assert isinstance(value, tuple)
    pairs: list[tuple[str, object]] = []
    for item in value:
        assert isinstance(item, tuple)
        assert len(item) == 2
        key, nested = item
        assert isinstance(key, str)
        pairs.append((key, nested))
    return tuple(pairs)


def _pair_value(
    pairs: tuple[tuple[str, object], ...],
    key: str,
) -> object:
    for name, value in pairs:
        if name == key:
            return value
    raise AssertionError(f"missing key {key!r}")


def _json_object_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        keys.update(value)
        for nested in value.values():
            keys.update(_json_object_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            keys.update(_json_object_keys(nested))
    return keys


def _run_pairs(text: str) -> tuple[tuple[str, object], ...]:
    runs = _pair_value(_object_pairs(text), "runs")
    assert isinstance(runs, list)
    assert len(runs) == 1
    return _require_pairs(runs[0])


def _driver_pairs(text: str) -> tuple[tuple[str, object], ...]:
    tool = _require_pairs(_pair_value(_run_pairs(text), "tool"))
    assert _keys(tool) == ("driver",)
    return _require_pairs(_pair_value(tool, "driver"))


def _result_pair_list(text: str) -> list[tuple[tuple[str, object], ...]]:
    results = _pair_value(_run_pairs(text), "results")
    assert isinstance(results, list)
    return [_require_pairs(item) for item in results]


def _record(
    *,
    target: str,
    requested_target: str | None = None,
    rule_id: str = _RULE_ID,
    kind: PassiveFindingKind = PassiveFindingKind.HARDENING,
    observation: str = _OBSERVATION,
    rationale: str = _RATIONALE,
    evidence: tuple[tuple[str, str], ...] = (("state", "missing"), ("status", "200")),
    status: int = 200,
    body_length: int = 123,
    body_sha256: str = _BODY_SHA256,
) -> FindingEvidence:
    final = parse_target_url(target)
    requested = parse_target_url(
        target if requested_target is None else requested_target
    )
    finding = build_passive_finding(
        rule_id=rule_id,
        kind=kind,
        target=final,
        requested_target=requested,
        observation=observation,
        rationale=rationale,
        evidence=evidence,
    )
    response = ResponseEvidence(
        status=status,
        final_target=final,
        requested_target=requested,
        body_length=body_length,
        body_sha256=body_sha256,
    )
    return FindingEvidence(finding=finding, response=response)


def _record_with_query_secrets() -> FindingEvidence:
    return _record(
        target=(
            "https://app.test/reset?"
            f"{_TOKEN_KEY}={_TOKEN_VALUE}&"
            f"{_SESSION_KEY}={_SESSION_VALUE}&"
            f"api_key={_API_KEY_VALUE}&"
            f"password={_SECRET_VALUE}"
        )
    )


def test_render_scan_report_sarif_signature_matches_the_approved_contract() -> None:
    signature = inspect.signature(render_scan_report_sarif)
    hints = get_type_hints(render_scan_report_sarif)
    report_parameter = signature.parameters["report"]

    assert tuple(signature.parameters) == ("report",)
    assert report_parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert report_parameter.default is inspect.Parameter.empty
    assert hints["report"] is ScanReport
    assert hints["return"] is str
    assert ScanResult not in hints.values()
    assert "render_scan_report_sarif" in {
        name for name in dir(reporting) if not name.startswith("_")
    }


def test_empty_report_golden_string() -> None:
    rendered = render_scan_report_sarif(_report())

    assert rendered == _EMPTY_REPORT_SARIF
    assert rendered == (
        '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/'
        'schemas/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":'
        '{"driver":{"name":"BOUNDARY","rules":[]}},"results":[],"properties":'
        '{"scan_target":"https://example.com/"}}]}'
    )


def test_empty_report_from_seed_matches_the_adr_golden_string() -> None:
    report = build_scan_report(
        target=parse_target_url("https://example.com/"),
        result=ScanResult(findings=()),
    )

    assert render_scan_report_sarif(report) == _EMPTY_REPORT_SARIF


def test_empty_query_bearing_seed_golden_string() -> None:
    report = build_scan_report(
        target=parse_target_url(f"https://example.com/?{_TOKEN_KEY}={_TOKEN_VALUE}"),
        result=ScanResult(findings=()),
    )
    rendered = render_scan_report_sarif(report)

    assert rendered == _EMPTY_REDACTED_SARIF
    assert _TOKEN_KEY not in rendered
    assert _TOKEN_VALUE not in rendered
    assert '"rules":[]' in rendered
    assert '"results":[]' in rendered


def test_one_finding_with_related_locations_golden_string() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())

    assert rendered == _ONE_FINDING_RELATED_SARIF


def test_one_finding_without_related_locations_golden_string() -> None:
    rendered = render_scan_report_sarif(_one_finding_equal_report())

    assert rendered == _ONE_FINDING_EQUAL_SARIF
    assert "relatedLocations" not in rendered


def test_multiple_findings_golden_string_preserves_report_order() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    payload = json.loads(rendered)
    results = payload["runs"][0]["results"]
    rules = payload["runs"][0]["tool"]["driver"]["rules"]

    assert rendered == _MULTIPLE_FINDINGS_SARIF
    assert [item["ruleId"] for item in results] == [_RULE_ID, _OTHER_RULE_ID]
    assert [item["id"] for item in rules] == [_RULE_ID, _OTHER_RULE_ID]
    assert [item["ruleIndex"] for item in results] == [0, 1]


def test_duplicate_rule_id_golden_string() -> None:
    rendered = render_scan_report_sarif(_duplicate_rule_report())
    payload = json.loads(rendered)
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    results = payload["runs"][0]["results"]

    assert rendered == _DUPLICATE_RULE_SARIF
    assert len(rules) == 1
    assert len(results) == 2
    assert rules[0] == {"id": _RULE_ID, "name": _RULE_ID}
    assert [item["ruleId"] for item in results] == [_RULE_ID, _RULE_ID]
    assert [item["ruleIndex"] for item in results] == [0, 0]


def test_duplicate_evidence_keys_golden_string() -> None:
    report = _report(findings=(_report_finding(evidence=_DUPLICATE_EVIDENCE),))
    rendered = render_scan_report_sarif(report)
    evidence = json.loads(rendered)["runs"][0]["results"][0]["properties"]["evidence"]

    assert rendered == _DUPLICATE_EVIDENCE_SARIF
    assert evidence == [["status", "200"], ["status", "500"]]
    assert type(evidence) is list
    assert type(evidence[0]) is list


def test_non_ascii_observation_and_rationale_are_escaped_ascii() -> None:
    report = _report(
        findings=(
            _report_finding(
                observation=_NON_ASCII_OBSERVATION,
                rationale=_NON_ASCII_RATIONALE,
                evidence=(),
                body_length=0,
            ),
        )
    )
    rendered = render_scan_report_sarif(report)

    assert rendered == _NON_ASCII_SARIF
    rendered.encode("ascii")
    assert "\u00e9" not in rendered
    assert "\u00ef" not in rendered
    assert "\u0441" not in rendered
    assert "\\u00e9" in rendered
    assert "\\u00ef" in rendered
    assert "\\u0441\\u0435\\u043a\\u0440\\u0435\\u0442" in rendered


def test_top_level_sarif_key_order() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())

    assert _keys(_object_pairs(rendered)) == _TOP_LEVEL_KEYS
    assert _TOP_LEVEL_KEYS != tuple(sorted(_TOP_LEVEL_KEYS))


def test_schema_uri_is_the_locked_sarif_210_uri() -> None:
    rendered = render_scan_report_sarif(_report())
    payload = json.loads(rendered)

    assert payload["$schema"] == _SARIF_SCHEMA_URI
    assert payload["$schema"] == (
        "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
        "schemas/sarif-schema-2.1.0.json"
    )
    assert payload["version"] == "2.1.0"
    assert type(payload["$schema"]) is str
    assert type(payload["version"]) is str


def test_runs_contains_exactly_one_run() -> None:
    empty = json.loads(render_scan_report_sarif(_report()))
    populated = json.loads(render_scan_report_sarif(_multiple_findings_report()))

    assert type(empty["runs"]) is list
    assert len(empty["runs"]) == 1
    assert len(populated["runs"]) == 1
    assert '"runs":[' in render_scan_report_sarif(_report())


def test_run_key_order() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())

    assert _keys(_run_pairs(rendered)) == _RUN_KEYS
    assert _RUN_KEYS != tuple(sorted(_RUN_KEYS))


def test_tool_and_driver_shape() -> None:
    rendered = render_scan_report_sarif(_one_finding_equal_report())
    driver = json.loads(rendered)["runs"][0]["tool"]["driver"]
    driver_pairs = _driver_pairs(rendered)

    assert _keys(driver_pairs) == _DRIVER_KEYS
    assert driver["name"] == "BOUNDARY"
    assert type(driver["rules"]) is list
    assert driver["rules"][0] == {"id": _RULE_ID, "name": _RULE_ID}


def test_driver_omits_version_invocations_and_help_metadata() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    driver = json.loads(rendered)["runs"][0]["tool"]["driver"]
    run = json.loads(rendered)["runs"][0]

    assert "version" not in driver
    assert "semanticVersion" not in driver
    assert "informationUri" not in driver
    assert "invocations" not in run
    assert "originalUriBaseIds" not in run
    assert "automationDetails" not in run
    assert "commandLine" not in driver
    assert "help" not in driver
    assert "helpUri" not in driver


def test_run_properties_is_exactly_scan_target_for_empty_and_populated() -> None:
    empty = render_scan_report_sarif(_report())
    populated = render_scan_report_sarif(_one_finding_related_report())
    empty_properties = _require_pairs(_pair_value(_run_pairs(empty), "properties"))
    populated_properties = _require_pairs(
        _pair_value(_run_pairs(populated), "properties")
    )

    assert _keys(empty_properties) == _RUN_PROPERTY_KEYS
    assert _keys(populated_properties) == _RUN_PROPERTY_KEYS
    assert json.loads(empty)["runs"][0]["properties"] == {
        "scan_target": "https://example.com/"
    }
    assert json.loads(populated)["runs"][0]["properties"] == {
        "scan_target": "https://example.com/?REDACTED"
    }


def test_empty_report_rules_and_results_are_empty_arrays() -> None:
    rendered = render_scan_report_sarif(_report())
    payload = json.loads(rendered)
    driver = payload["runs"][0]["tool"]["driver"]

    assert driver["rules"] == []
    assert payload["runs"][0]["results"] == []
    assert '"rules":[]' in rendered
    assert '"results":[]' in rendered
    assert '"rules":null' not in rendered
    assert '"results":null' not in rendered
    assert '"rules":{}' not in rendered


def test_result_key_order_without_related_locations() -> None:
    rendered = render_scan_report_sarif(_one_finding_equal_report())
    result_pairs = _result_pair_list(rendered)[0]

    assert _keys(result_pairs) == _RESULT_KEYS_WITHOUT_RELATED
    assert "relatedLocations" not in _keys(result_pairs)


def test_result_key_order_with_related_locations() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    result_pairs = _result_pair_list(rendered)[0]

    assert _keys(result_pairs) == _RESULT_KEYS
    assert _RESULT_KEYS != tuple(sorted(_RESULT_KEYS))


def test_location_and_artifact_key_order() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    result_pairs = _result_pair_list(rendered)[0]
    locations = _pair_value(result_pairs, "locations")
    assert isinstance(locations, list)
    assert len(locations) == 1
    location = _require_pairs(locations[0])
    physical = _require_pairs(_pair_value(location, "physicalLocation"))
    artifact = _require_pairs(_pair_value(physical, "artifactLocation"))

    assert _keys(location) == _LOCATION_KEYS
    assert _keys(physical) == _PHYSICAL_LOCATION_KEYS
    assert _keys(artifact) == _ARTIFACT_LOCATION_KEYS
    assert _pair_value(artifact, "uri") == "https://app.test/reset?REDACTED"


def test_related_location_key_order() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    result_pairs = _result_pair_list(rendered)[0]
    related = _pair_value(result_pairs, "relatedLocations")
    assert isinstance(related, list)
    assert len(related) == 1
    related_location = _require_pairs(related[0])
    message = _require_pairs(_pair_value(related_location, "message"))

    assert _keys(related_location) == _RELATED_LOCATION_KEYS
    assert _RELATED_LOCATION_KEYS != tuple(sorted(_RELATED_LOCATION_KEYS))
    assert _keys(message) == _MESSAGE_KEYS
    assert _pair_value(message, "text") == "requested target"


def test_exactly_one_location_per_result() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    results = json.loads(rendered)["runs"][0]["results"]

    assert len(results) == 2
    for result in results:
        assert type(result["locations"]) is list
        assert len(result["locations"]) == 1
        assert type(result["relatedLocations"]) is list
        assert len(result["relatedLocations"]) == 1


def test_result_properties_key_order() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    properties = _require_pairs(
        _pair_value(_result_pair_list(rendered)[0], "properties")
    )

    assert _keys(properties) == _RESULT_PROPERTY_KEYS
    assert _RESULT_PROPERTY_KEYS != tuple(sorted(_RESULT_PROPERTY_KEYS))


def test_message_text_is_exactly_the_observation() -> None:
    finding = _report_finding(observation=_OTHER_OBSERVATION)
    rendered = render_scan_report_sarif(_report(findings=(finding,)))
    result = json.loads(rendered)["runs"][0]["results"][0]
    message = _require_pairs(_pair_value(_result_pair_list(rendered)[0], "message"))

    assert _keys(message) == _MESSAGE_KEYS
    assert result["message"] == {"text": _OTHER_OBSERVATION}
    assert result["message"]["text"] == finding.observation
    assert finding.target.url not in result["message"]["text"]
    assert finding.requested_target.url not in result["message"]["text"]


def test_rules_are_deduplicated_by_rule_id_in_first_seen_order() -> None:
    report = _report(
        findings=(
            _report_finding(rule_id=_OTHER_RULE_ID),
            _report_finding(rule_id=_RULE_ID),
            _report_finding(rule_id=_OTHER_RULE_ID),
            _report_finding(rule_id=_RULE_ID),
        )
    )
    payload = json.loads(render_scan_report_sarif(report))
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    results = payload["runs"][0]["results"]

    assert [item["id"] for item in rules] == [_OTHER_RULE_ID, _RULE_ID]
    assert [item["name"] for item in rules] == [_OTHER_RULE_ID, _RULE_ID]
    assert [item["ruleId"] for item in results] == [
        _OTHER_RULE_ID,
        _RULE_ID,
        _OTHER_RULE_ID,
        _RULE_ID,
    ]
    assert [item["ruleIndex"] for item in results] == [0, 1, 0, 1]
    assert len(rules) == 2
    assert len(results) == 4


def test_rules_are_not_sorted_alphabetically() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    rule_ids = [
        item["id"]
        for item in json.loads(rendered)["runs"][0]["tool"]["driver"]["rules"]
    ]

    assert rule_ids == [_RULE_ID, _OTHER_RULE_ID]
    assert rule_ids != sorted(rule_ids)


def test_rule_descriptors_are_exactly_id_and_name() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    rules = _pair_value(_driver_pairs(rendered), "rules")
    assert isinstance(rules, list)

    for item in rules:
        pairs = _require_pairs(item)
        assert _keys(pairs) == _RULE_KEYS
        rule_id = _pair_value(pairs, "id")
        assert _pair_value(pairs, "name") == rule_id
        assert type(rule_id) is str


def test_rule_index_agrees_with_driver_rules() -> None:
    rendered = render_scan_report_sarif(_duplicate_rule_report())
    payload = json.loads(rendered)
    rules = payload["runs"][0]["tool"]["driver"]["rules"]
    results = payload["runs"][0]["results"]

    for result in results:
        assert type(result["ruleIndex"]) is int
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert '"ruleIndex":"0"' not in rendered


def test_same_rule_id_different_kind_raises_value_error() -> None:
    report = _report(
        findings=(
            _report_finding(kind=PassiveFindingKind.HARDENING),
            _report_finding(kind=PassiveFindingKind.MISCONFIGURATION),
        )
    )

    with pytest.raises(ValueError) as caught:
        render_scan_report_sarif(report)

    message = str(caught.value)
    assert _TOKEN_VALUE not in message
    assert "token=" not in message


def test_kind_mismatch_produces_no_partial_document() -> None:
    report = _report(
        findings=(
            _report_finding(rule_id=_RULE_ID, kind=PassiveFindingKind.HARDENING),
            _report_finding(
                rule_id=_OTHER_RULE_ID,
                kind=PassiveFindingKind.MISCONFIGURATION,
            ),
            _report_finding(rule_id=_RULE_ID, kind=PassiveFindingKind.MISCONFIGURATION),
        )
    )

    with pytest.raises(ValueError):
        render_scan_report_sarif(report)


def test_level_is_note_for_every_kind() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    results = json.loads(rendered)["runs"][0]["results"]

    assert [item["level"] for item in results] == ["note", "note"]
    assert results[0]["properties"]["kind"] == "hardening"
    assert results[1]["properties"]["kind"] == "misconfiguration"
    assert "warning" not in rendered
    assert "error" not in rendered
    assert '"level":"none"' not in rendered


def test_kind_is_only_emitted_on_result_properties() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    payload = json.loads(rendered)
    driver = payload["runs"][0]["tool"]["driver"]
    results = payload["runs"][0]["results"]

    assert "kind" not in driver
    for rule in driver["rules"]:
        assert "kind" not in rule
        assert "defaultConfiguration" not in rule
        assert "properties" not in rule
    for result in results:
        assert "kind" not in result
        assert result["properties"]["kind"] in {"hardening", "misconfiguration"}


def test_related_locations_omitted_when_safe_urls_equal() -> None:
    rendered = render_scan_report_sarif(_one_finding_equal_report())
    result = json.loads(rendered)["runs"][0]["results"][0]

    assert "relatedLocations" not in result
    assert '"relatedLocations":[]' not in rendered
    assert '"relatedLocations":null' not in rendered


def test_related_locations_omitted_when_raw_urls_differ_only_in_query() -> None:
    record = _record(
        target=f"https://app.test/reset?{_TOKEN_KEY}={_TOKEN_VALUE}",
        requested_target=f"https://app.test/reset?{_SESSION_KEY}={_SESSION_VALUE}",
    )
    report = build_scan_report(
        target=parse_target_url("https://example.com/"),
        result=ScanResult(findings=(record,)),
    )
    rendered = render_scan_report_sarif(report)
    result = json.loads(rendered)["runs"][0]["results"][0]

    assert report.findings[0].target.url == report.findings[0].requested_target.url
    assert report.findings[0].target.url == "https://app.test/reset?REDACTED"
    assert "relatedLocations" not in result
    assert record.finding.target.url not in rendered
    assert record.finding.requested_target.url not in rendered
    assert _TOKEN_VALUE not in rendered
    assert _SESSION_VALUE not in rendered


def test_related_locations_present_when_safe_urls_differ() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    result = json.loads(rendered)["runs"][0]["results"][0]
    related = result["relatedLocations"][0]

    assert len(result["relatedLocations"]) == 1
    assert related["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://app.test/start?REDACTED"
    )
    assert related["message"]["text"] == "requested target"


def test_location_uri_uses_only_safe_report_url_values() -> None:
    finding = _one_finding_related_report().findings[0]
    rendered = render_scan_report_sarif(_one_finding_related_report())
    result = json.loads(rendered)["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    related_uri = result["relatedLocations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]

    assert uri == finding.target.url == "https://app.test/reset?REDACTED"
    assert related_uri == finding.requested_target.url
    assert type(uri) is str
    assert uri.startswith("https://")
    assert related_uri.startswith("https://")


def test_ipv6_and_non_default_port_uris_are_safe_report_urls() -> None:
    report = _report(
        target="http://[::1]:8080/health?REDACTED",
        findings=(
            _report_finding(
                target="http://127.0.0.1:3000/health",
                requested_target="http://[::1]:8080/health?REDACTED",
            ),
        ),
    )
    rendered = render_scan_report_sarif(report)
    payload = json.loads(rendered)
    result = payload["runs"][0]["results"][0]

    assert payload["runs"][0]["properties"]["scan_target"] == (
        "http://[::1]:8080/health?REDACTED"
    )
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "http://127.0.0.1:3000/health"
    )
    assert (
        result["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "http://[::1]:8080/health?REDACTED"
    )


def test_path_tokens_are_preserved_in_location_uri() -> None:
    record = _record(target="https://app.test/reset/SECRET?x=1")
    report = build_scan_report(
        target=parse_target_url("https://example.com/"),
        result=ScanResult(findings=(record,)),
    )
    rendered = render_scan_report_sarif(report)
    uri = json.loads(rendered)["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["artifactLocation"]["uri"]

    assert uri == "https://app.test/reset/SECRET?REDACTED"
    assert "/reset/SECRET" in uri
    assert "x=1" not in rendered


def test_findings_are_not_sorted_by_rule_id() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    rule_ids = [item["ruleId"] for item in json.loads(rendered)["runs"][0]["results"]]

    assert rule_ids == [_RULE_ID, _OTHER_RULE_ID]
    assert rule_ids != sorted(rule_ids)


def test_duplicate_findings_are_both_emitted_as_results() -> None:
    finding = _report_finding(evidence=_UNSORTED_EVIDENCE)
    rendered = render_scan_report_sarif(_report(findings=(finding, finding)))
    payload = json.loads(rendered)
    results = payload["runs"][0]["results"]
    rules = payload["runs"][0]["tool"]["driver"]["rules"]

    assert len(results) == 2
    assert results[0] == results[1]
    assert len(rules) == 1
    assert rules[0] == {"id": _RULE_ID, "name": _RULE_ID}


def test_renderer_copies_scalar_fields_exactly() -> None:
    finding = _report_finding(
        rule_id=_OTHER_RULE_ID,
        kind=PassiveFindingKind.MISCONFIGURATION,
        observation=_OTHER_OBSERVATION,
        rationale=_OTHER_RATIONALE,
        evidence=(("header", "content-security-policy"),),
        status=404,
        body_length=9,
        body_sha256=_OTHER_BODY_SHA256,
    )
    result = json.loads(render_scan_report_sarif(_report(findings=(finding,))))["runs"][
        0
    ]["results"][0]
    properties = result["properties"]

    assert result["ruleId"] == finding.rule_id == _OTHER_RULE_ID
    assert result["message"]["text"] == finding.observation == _OTHER_OBSERVATION
    assert properties["kind"] == finding.kind.value
    assert properties["rationale"] == finding.rationale == _OTHER_RATIONALE
    assert properties["status"] == finding.status == 404
    assert properties["body_length"] == finding.body_length == 9
    assert properties["body_sha256"] == finding.body_sha256 == _OTHER_BODY_SHA256


def test_renderer_does_not_repair_evidence_owned_body_fields() -> None:
    finding = _report_finding(body_length=-1, body_sha256="not-a-digest")
    properties = json.loads(render_scan_report_sarif(_report(findings=(finding,))))[
        "runs"
    ][0]["results"][0]["properties"]

    assert properties["body_length"] == -1
    assert properties["body_sha256"] == "not-a-digest"


def test_empty_evidence_is_an_empty_json_array() -> None:
    rendered = render_scan_report_sarif(
        _report(findings=(_report_finding(evidence=()),))
    )
    evidence = json.loads(rendered)["runs"][0]["results"][0]["properties"]["evidence"]

    assert evidence == []
    assert type(evidence) is list
    assert '"evidence":[]' in rendered
    assert '"evidence":{}' not in rendered
    assert '"evidence":null' not in rendered


def test_schema_status_and_body_length_are_json_numbers() -> None:
    rendered = render_scan_report_sarif(_multiple_findings_report())
    first = json.loads(rendered)["runs"][0]["results"][0]["properties"]
    second = json.loads(rendered)["runs"][0]["results"][1]["properties"]

    assert type(first["status"]) is int
    assert type(first["body_length"]) is int
    assert type(first["body_sha256"]) is str
    assert first["status"] == 200
    assert second["status"] == 500
    assert first["body_length"] == 123
    assert second["body_length"] == 4
    assert '"status":"200"' not in rendered
    assert '"ruleIndex":0' in rendered


def test_http_findings_do_not_use_repository_file_paths() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    payload = json.loads(rendered)
    result = payload["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    related_uri = result["relatedLocations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    location = result["locations"][0]["physicalLocation"]

    assert uri == "https://app.test/reset?REDACTED"
    assert related_uri == "https://app.test/start?REDACTED"
    assert not uri.startswith("src/")
    assert not uri.startswith("file:")
    assert not uri.startswith("./")
    assert (
        "uriBaseId"
        not in result["locations"][0]["physicalLocation"]["artifactLocation"]
    )
    assert "region" not in location
    assert "startLine" not in location
    assert "file://" not in rendered
    assert "src/main.py" not in rendered
    assert "src/index.ts" not in rendered
    assert '"uri":"src/' not in rendered


def test_renderer_does_not_emit_github_code_scanning_fields() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    keys = _json_object_keys(json.loads(rendered))
    source = inspect.getsource(render_scan_report_sarif)

    assert "partialFingerprints" not in keys
    assert "fingerprints" not in keys
    assert "checkout_uri" not in keys
    assert "github" not in keys
    for marker in _GITHUB_MARKERS:
        assert marker not in rendered
        assert marker not in source
    assert "upload-sarif" not in source
    assert "Code Scanning" not in source


def test_object_keys_are_exactly_the_allowlisted_set() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    keys = _json_object_keys(json.loads(rendered))

    assert keys <= _ALLOWED_OBJECT_KEYS
    for forbidden in _FORBIDDEN_OBJECT_KEYS:
        assert forbidden not in keys
    assert "relatedLocations" in keys
    assert "scan_target" in keys
    assert "ruleId" in keys
    assert "rule_id" not in keys


def test_query_secrets_never_appear_in_rendered_sarif() -> None:
    seed = parse_target_url(
        "https://example.com/scan?"
        f"{_TOKEN_KEY}={_TOKEN_VALUE}&"
        f"{_SESSION_KEY}={_SESSION_VALUE}"
    )
    record = _record_with_query_secrets()
    report = build_scan_report(target=seed, result=ScanResult(findings=(record,)))
    rendered = render_scan_report_sarif(report)
    markers = (
        seed.query,
        seed.url,
        record.finding.target.url,
        record.finding.target.query,
        record.finding.requested_target.url,
        _TOKEN_KEY,
        _TOKEN_VALUE,
        _SESSION_KEY,
        _SESSION_VALUE,
        _API_KEY_VALUE,
        _SECRET_VALUE,
        "api_key",
        "password",
        "token=",
        "session=",
    )

    assert "?REDACTED" in rendered
    for marker in markers:
        assert marker not in rendered


def test_requested_raw_target_url_never_appears() -> None:
    record = _record(
        target=f"https://app.test/final?{_TOKEN_KEY}={_TOKEN_VALUE}",
        requested_target=f"https://app.test/start?{_SESSION_KEY}={_SESSION_VALUE}",
    )
    report = build_scan_report(
        target=parse_target_url("https://example.com/"),
        result=ScanResult(findings=(record,)),
    )
    rendered = render_scan_report_sarif(report)
    result = json.loads(rendered)["runs"][0]["results"][0]

    assert record.finding.requested_target.url not in rendered
    assert record.finding.target.url not in rendered
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://app.test/final?REDACTED"
    )
    assert (
        result["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "https://app.test/start?REDACTED"
    )


def test_fingerprint_and_evidence_id_never_appear_in_rendered_sarif() -> None:
    record = _record_with_query_secrets()
    report = build_scan_report(
        target=parse_target_url("https://example.com/"),
        result=ScanResult(findings=(record,)),
    )
    rendered = render_scan_report_sarif(report)

    assert "fingerprint" not in rendered
    assert "evidence_id" not in rendered
    assert record.finding.fingerprint not in rendered
    assert record.evidence_id not in rendered


def test_body_header_and_credential_fields_never_appear() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    keys = _json_object_keys(json.loads(rendered))

    assert "body" not in keys
    assert "headers" not in keys
    assert "authorization" not in keys
    assert "cookie" not in keys
    assert "cookies" not in keys
    assert "credentials" not in keys
    assert '"headers"' not in rendered
    assert '"Authorization"' not in rendered
    assert '"Cookie"' not in rendered
    assert '"Set-Cookie"' not in rendered


def test_web_request_and_hidden_domain_material_never_appear() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    keys = _json_object_keys(json.loads(rendered))
    source = inspect.getsource(render_scan_report_sarif)

    assert "webRequest" not in keys
    assert "webResponse" not in keys
    assert "webRequest" not in source
    assert "webResponse" not in source
    assert "fingerprint" not in source
    assert "evidence_id" not in source
    assert '"query"' not in rendered


def test_argv_environment_and_timestamps_never_appear() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())
    keys = _json_object_keys(json.loads(rendered))

    assert "argv" not in keys
    assert "environment" not in keys
    assert "timestamp" not in keys
    assert "time" not in keys
    assert "invocations" not in keys
    assert "commandLine" not in keys
    assert "run_id" not in keys
    assert "pages_visited" not in keys


def test_hidden_object_and_enum_repr_never_appear() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())

    for marker in _FORBIDDEN_REPR:
        assert marker not in rendered
    assert "<boundary." not in rendered
    assert "enum" not in rendered.lower()


def test_redacted_query_urls_stay_exactly_redacted() -> None:
    report = _one_finding_related_report()
    rendered = render_scan_report_sarif(report)
    payload = json.loads(rendered)
    result = payload["runs"][0]["results"][0]

    assert payload["runs"][0]["properties"]["scan_target"] == (
        "https://example.com/?REDACTED"
    )
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://app.test/reset?REDACTED"
    )
    assert (
        result["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "https://app.test/start?REDACTED"
    )
    assert rendered.count("?REDACTED") == 3
    assert "?REDACTED&" not in rendered
    assert "REDACTED=" not in rendered
    assert "token=" not in rendered


def test_renderer_returns_compact_json_without_trailing_newline() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())

    assert type(rendered) is str
    assert not rendered.endswith("\n")
    assert not rendered.endswith("\r\n")
    assert "\n" not in rendered
    assert "\r" not in rendered


def test_repeated_render_of_the_same_report_is_identical() -> None:
    report = _one_finding_related_report()

    first = render_scan_report_sarif(report)
    second = render_scan_report_sarif(report)

    assert first == second == _ONE_FINDING_RELATED_SARIF


def test_identical_scan_report_values_render_identically() -> None:
    first = render_scan_report_sarif(_one_finding_related_report())
    second = render_scan_report_sarif(_one_finding_related_report())

    assert first == second == _ONE_FINDING_RELATED_SARIF


def test_first_seen_rule_order_is_stable_across_repeated_renders() -> None:
    report = _multiple_findings_report()

    first = json.loads(render_scan_report_sarif(report))["runs"][0]["tool"]["driver"][
        "rules"
    ]
    second = json.loads(render_scan_report_sarif(report))["runs"][0]["tool"]["driver"][
        "rules"
    ]

    assert first == second
    assert [item["id"] for item in first] == [_RULE_ID, _OTHER_RULE_ID]


def test_rendered_sarif_is_ascii() -> None:
    rendered = render_scan_report_sarif(_one_finding_related_report())

    assert rendered.encode("ascii") == rendered.encode("utf-8")
    assert rendered.isascii()


def test_renderer_source_uses_locked_json_dumps_arguments() -> None:
    source = inspect.getsource(render_scan_report_sarif)

    assert "json.dumps" in source
    assert "ensure_ascii=True" in source
    assert "sort_keys=False" in source
    assert 'separators=(",", ":")' in source or "separators=(',', ':')" in source
    assert "indent" not in source
    assert "default=" not in source


def test_renderer_does_not_use_generic_or_reflective_serialization() -> None:
    source = inspect.getsource(render_scan_report_sarif)

    for marker in _GENERIC_SERIALIZATION_MARKERS:
        assert marker not in source
    assert "asdict" not in source


def test_renderer_does_not_inspect_or_serialize_domain_types() -> None:
    source = inspect.getsource(render_scan_report_sarif)

    for name in _DOMAIN_TYPE_NAMES:
        assert name not in source
    assert "project_report_target" not in source
    assert "build_scan_report" not in source
    assert "fingerprint" not in source
    assert "evidence_id" not in source
    assert "plugin" not in source.lower()
    assert "registry" not in source.lower()


def test_renderer_source_serializes_report_url_via_url_field() -> None:
    source = inspect.getsource(render_scan_report_sarif)

    assert ".url" in source
    assert ".value" in source
    assert "str(report" not in source
    assert "repr(" not in source


def test_reporting_uses_stdlib_json_only() -> None:
    source = inspect.getsource(render_scan_report_sarif)
    module_source = inspect.getsource(reporting)

    assert "json.dumps" in source
    for forbidden in ("orjson", "ujson", "simplejson", "rapidjson"):
        assert forbidden not in source
        assert forbidden not in module_source


def test_renderer_does_not_mutate_the_scan_report() -> None:
    report = _one_finding_related_report()
    before = (report.schema, report.target.url, report.findings)

    rendered = render_scan_report_sarif(report)

    assert (report.schema, report.target.url, report.findings) == before
    assert rendered == _ONE_FINDING_RELATED_SARIF


def test_renderer_has_no_fallback_or_partial_output_path() -> None:
    source = inspect.getsource(render_scan_report_sarif)

    assert "except Exception" not in source
    assert "except:" not in source
    assert "default=" not in source


def test_renderer_fail_closes_on_schema_before_emitting_a_document() -> None:
    source = inspect.getsource(render_scan_report_sarif)

    assert "report.schema" in source
    assert "ValueError" in source
    assert "!= 1" in source or "!= REPORT_SCHEMA_VERSION" in source


def test_invalid_schema_fails_before_rendering() -> None:
    with pytest.raises(ValueError):
        ScanReport(schema=2, target=ReportUrl(url="https://example.com/"), findings=())


def test_invalid_report_url_fails_before_rendering() -> None:
    with pytest.raises(ValueError) as caught:
        _report_finding(target=f"https://app.test/reset?{_TOKEN_KEY}={_TOKEN_VALUE}")

    message = str(caught.value)
    assert _TOKEN_VALUE not in message
    assert f"{_TOKEN_KEY}=" not in message


def test_no_plugin_registry_in_renderer_source() -> None:
    source = inspect.getsource(render_scan_report_sarif)

    assert "entry_points" not in source
    assert "importlib" not in source
    assert "plugins" not in source
    assert "RULES =" not in source
    assert "rule_registry" not in source
