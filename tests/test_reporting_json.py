"""Offline tests for deterministic JSON scan-report rendering (Milestone 8, Slice C)."""

from __future__ import annotations

import inspect
import json
import socket
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
    render_scan_report_json,
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
_TOP_LEVEL_KEYS = ("schema", "target", "findings")
_FINDING_KEYS = (
    "rule_id",
    "kind",
    "target",
    "requested_target",
    "observation",
    "rationale",
    "evidence",
    "status",
    "body_length",
    "body_sha256",
)
_ALLOWED_OBJECT_KEYS = frozenset(_TOP_LEVEL_KEYS) | frozenset(_FINDING_KEYS)
_EMPTY_REPORT_JSON = '{"schema":1,"target":"https://example.com/","findings":[]}'
_EMPTY_REDACTED_JSON = (
    '{"schema":1,"target":"https://example.com/?REDACTED","findings":[]}'
)
_ONE_FINDING_JSON = (
    '{"schema":1,"target":"https://example.com/?REDACTED","findings":['
    '{"rule_id":"passive.hsts.not_enforced.v1","kind":"hardening",'
    '"target":"https://app.test/reset?REDACTED",'
    '"requested_target":"https://app.test/start?REDACTED",'
    '"observation":"HTTPS response did not enforce Strict-Transport-Security.",'
    '"rationale":"Missing or ineffective HSTS is a transport-hardening observation, '
    'not proof of exploitability.",'
    '"evidence":[["status","200"],["header","strict-transport-security"]],'
    '"status":200,"body_length":123,'
    '"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}'
)
_MULTIPLE_FINDINGS_JSON = (
    '{"schema":1,"target":"https://example.com/","findings":['
    '{"rule_id":"passive.hsts.not_enforced.v1","kind":"hardening",'
    '"target":"https://app.test/final","requested_target":"https://app.test/start",'
    '"observation":"HTTPS response did not enforce Strict-Transport-Security.",'
    '"rationale":"Missing or ineffective HSTS is a transport-hardening observation, '
    'not proof of exploitability.",'
    '"evidence":[["state","missing"]],"status":200,"body_length":123,'
    '"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},'
    '{"rule_id":"passive.csp.missing_enforced_policy.v1","kind":"misconfiguration",'
    '"target":"https://app.test/final","requested_target":"https://app.test/start",'
    '"observation":"Response did not enforce Content-Security-Policy.",'
    '"rationale":"Missing CSP is a markup-hardening observation, '
    'not proof of exploitability.",'
    '"evidence":[["header","content-security-policy"]],"status":500,"body_length":4,'
    '"body_sha256":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"}]}'
)
_DUPLICATE_EVIDENCE_JSON = (
    '{"schema":1,"target":"https://example.com/","findings":['
    '{"rule_id":"passive.hsts.not_enforced.v1","kind":"hardening",'
    '"target":"https://app.test/","requested_target":"https://app.test/",'
    '"observation":"HTTPS response did not enforce Strict-Transport-Security.",'
    '"rationale":"Missing or ineffective HSTS is a transport-hardening observation, '
    'not proof of exploitability.",'
    '"evidence":[["status","200"],["status","500"]],"status":200,"body_length":123,'
    '"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}'
)
_NON_ASCII_JSON = (
    '{"schema":1,"target":"https://example.com/","findings":['
    '{"rule_id":"passive.hsts.not_enforced.v1","kind":"hardening",'
    '"target":"https://app.test/","requested_target":"https://app.test/",'
    '"observation":"Observation with caf\\u00e9 and '
    '\\u0441\\u0435\\u043a\\u0440\\u0435\\u0442",'
    '"rationale":"Rationale with na\\u00efve",'
    '"evidence":[],"status":200,"body_length":0,'
    '"body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}'
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
    "id",
    "schema_version",
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


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("JSON rendering must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if rendering reaches network or scan entry points."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)
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


def _one_finding_report() -> ScanReport:
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


def _record_with_query_secrets() -> FindingEvidence:
    target = parse_target_url(
        "https://app.test/reset?"
        f"{_TOKEN_KEY}={_TOKEN_VALUE}&"
        f"{_SESSION_KEY}={_SESSION_VALUE}&"
        f"api_key={_API_KEY_VALUE}&"
        f"password={_SECRET_VALUE}"
    )
    finding = build_passive_finding(
        rule_id=_RULE_ID,
        kind=PassiveFindingKind.HARDENING,
        target=target,
        requested_target=target,
        observation=_OBSERVATION,
        rationale=_RATIONALE,
        evidence=(("state", "missing"), ("status", "200")),
    )
    response = ResponseEvidence(
        status=200,
        final_target=target,
        requested_target=target,
        body_length=123,
        body_sha256=_BODY_SHA256,
    )
    return FindingEvidence(finding=finding, response=response)


def test_render_scan_report_json_signature_matches_the_approved_contract() -> None:
    signature = inspect.signature(render_scan_report_json)
    hints = get_type_hints(render_scan_report_json)
    report_parameter = signature.parameters["report"]

    assert tuple(signature.parameters) == ("report",)
    assert report_parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert report_parameter.default is inspect.Parameter.empty
    assert hints["report"] is ScanReport
    assert hints["return"] is str
    assert ScanResult not in hints.values()
    assert "render_scan_report_json" in {
        name for name in dir(reporting) if not name.startswith("_")
    }


def test_empty_report_golden_string() -> None:
    rendered = render_scan_report_json(_report())

    assert rendered == _EMPTY_REPORT_JSON
    assert rendered == '{"schema":1,"target":"https://example.com/","findings":[]}'


def test_empty_report_from_seed_matches_the_adr_golden_string() -> None:
    report = build_scan_report(
        target=parse_target_url("https://example.com/"),
        result=ScanResult(findings=()),
    )

    assert render_scan_report_json(report) == _EMPTY_REPORT_JSON


def test_empty_query_bearing_seed_golden_string() -> None:
    report = build_scan_report(
        target=parse_target_url(f"https://example.com/?{_TOKEN_KEY}={_TOKEN_VALUE}"),
        result=ScanResult(findings=()),
    )
    rendered = render_scan_report_json(report)

    assert rendered == _EMPTY_REDACTED_JSON
    assert (
        rendered
        == '{"schema":1,"target":"https://example.com/?REDACTED","findings":[]}'
    )
    assert _TOKEN_KEY not in rendered
    assert _TOKEN_VALUE not in rendered


def test_one_finding_golden_string() -> None:
    rendered = render_scan_report_json(_one_finding_report())

    assert rendered == _ONE_FINDING_JSON


def test_multiple_findings_golden_string_preserves_report_order() -> None:
    rendered = render_scan_report_json(_multiple_findings_report())
    payload = json.loads(rendered)

    assert rendered == _MULTIPLE_FINDINGS_JSON
    assert [finding["rule_id"] for finding in payload["findings"]] == [
        _RULE_ID,
        _OTHER_RULE_ID,
    ]
    assert [finding["kind"] for finding in payload["findings"]] == [
        "hardening",
        "misconfiguration",
    ]


def test_duplicate_evidence_keys_golden_string() -> None:
    report = _report(
        findings=(_report_finding(evidence=_DUPLICATE_EVIDENCE),),
    )
    rendered = render_scan_report_json(report)
    evidence = json.loads(rendered)["findings"][0]["evidence"]

    assert rendered == _DUPLICATE_EVIDENCE_JSON
    assert evidence == [["status", "200"], ["status", "500"]]
    assert type(evidence) is list
    assert type(evidence[0]) is list
    assert len(evidence) == 2


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
    rendered = render_scan_report_json(report)

    assert rendered == _NON_ASCII_JSON
    rendered.encode("ascii")
    assert "\u00e9" not in rendered
    assert "\u00ef" not in rendered
    assert "\u0441" not in rendered
    assert "\\u00e9" in rendered
    assert "\\u00ef" in rendered
    assert "\\u0441\\u0435\\u043a\\u0440\\u0435\\u0442" in rendered


def test_redacted_query_urls_stay_exactly_redacted() -> None:
    report = _one_finding_report()
    rendered = render_scan_report_json(report)
    payload = json.loads(rendered)

    assert payload["target"] == "https://example.com/?REDACTED"
    assert payload["findings"][0]["target"] == "https://app.test/reset?REDACTED"
    assert (
        payload["findings"][0]["requested_target"] == "https://app.test/start?REDACTED"
    )
    assert rendered.count("?REDACTED") == 3
    assert "?REDACTED&" not in rendered
    assert "REDACTED=" not in rendered
    assert "token=" not in rendered


def test_top_level_json_key_order() -> None:
    rendered = render_scan_report_json(_one_finding_report())

    assert _keys(_object_pairs(rendered)) == _TOP_LEVEL_KEYS


def test_finding_json_key_order() -> None:
    rendered = render_scan_report_json(_one_finding_report())
    findings: object | None = None
    for key, value in _object_pairs(rendered):
        if key == "findings":
            findings = value
            break

    assert isinstance(findings, list)
    assert findings
    assert _keys(_require_pairs(findings[0])) == _FINDING_KEYS


def test_report_url_is_serialized_as_url_string_only() -> None:
    rendered = render_scan_report_json(_one_finding_report())
    payload = json.loads(rendered)
    finding = payload["findings"][0]

    assert type(payload["target"]) is str
    assert type(finding["target"]) is str
    assert type(finding["requested_target"]) is str
    assert payload["target"] == "https://example.com/?REDACTED"
    assert finding["target"] == "https://app.test/reset?REDACTED"
    assert "url" not in payload
    assert "url" not in finding


def test_kind_is_serialized_as_enum_value() -> None:
    report = _multiple_findings_report()
    rendered = render_scan_report_json(report)
    kinds = [finding["kind"] for finding in json.loads(rendered)["findings"]]

    assert kinds == [
        PassiveFindingKind.HARDENING.value,
        PassiveFindingKind.MISCONFIGURATION.value,
    ]
    assert kinds == ["hardening", "misconfiguration"]
    assert "HARDENING" not in rendered
    assert "MISCONFIGURATION" not in rendered
    assert "PassiveFindingKind" not in rendered


def test_schema_status_and_body_length_are_json_numbers() -> None:
    rendered = render_scan_report_json(_multiple_findings_report())
    payload = json.loads(rendered)
    first = payload["findings"][0]
    second = payload["findings"][1]

    assert type(payload["schema"]) is int
    assert payload["schema"] == 1
    assert type(first["status"]) is int
    assert type(first["body_length"]) is int
    assert type(first["body_sha256"]) is str
    assert first["status"] == 200
    assert second["status"] == 500
    assert first["body_length"] == 123
    assert second["body_length"] == 4
    assert '"schema":"1"' not in rendered
    assert '"status":"200"' not in rendered


def test_evidence_is_array_of_two_item_string_arrays_in_stored_order() -> None:
    rendered = render_scan_report_json(_one_finding_report())
    evidence = json.loads(rendered)["findings"][0]["evidence"]

    assert evidence == [["status", "200"], ["header", "strict-transport-security"]]
    assert type(evidence) is list
    assert type(evidence[0]) is list
    assert type(evidence[0][0]) is str
    assert type(evidence[0][1]) is str
    assert len(evidence[0]) == 2
    assert evidence[0][0] == "status"
    assert not isinstance(evidence, dict)


def test_empty_evidence_is_an_empty_json_array() -> None:
    rendered = render_scan_report_json(
        _report(findings=(_report_finding(evidence=()),))
    )
    evidence = json.loads(rendered)["findings"][0]["evidence"]

    assert evidence == []
    assert type(evidence) is list
    assert '"evidence":[]' in rendered
    assert '"evidence":{}' not in rendered
    assert '"evidence":null' not in rendered


def test_renderer_returns_compact_json_without_trailing_newline() -> None:
    rendered = render_scan_report_json(_one_finding_report())

    assert type(rendered) is str
    assert not rendered.endswith("\n")
    assert not rendered.endswith("\r\n")
    assert "\n" not in rendered
    assert "\r" not in rendered


def test_repeated_render_of_the_same_report_is_identical() -> None:
    report = _one_finding_report()

    first = render_scan_report_json(report)
    second = render_scan_report_json(report)

    assert first == second == _ONE_FINDING_JSON


def test_identical_scan_report_values_render_identically() -> None:
    first = render_scan_report_json(_one_finding_report())
    second = render_scan_report_json(_one_finding_report())

    assert first == second == _ONE_FINDING_JSON


def test_duplicate_findings_are_both_emitted() -> None:
    finding = _report_finding(evidence=_UNSORTED_EVIDENCE)
    rendered = render_scan_report_json(_report(findings=(finding, finding)))
    payload = json.loads(rendered)

    assert len(payload["findings"]) == 2
    assert payload["findings"][0] == payload["findings"][1]
    assert payload["findings"][0]["rule_id"] == _RULE_ID


def test_findings_are_not_sorted_by_rule_id() -> None:
    rendered = render_scan_report_json(_multiple_findings_report())
    rule_ids = [finding["rule_id"] for finding in json.loads(rendered)["findings"]]

    assert rule_ids == [_RULE_ID, _OTHER_RULE_ID]
    assert rule_ids != sorted(rule_ids)


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
    rendered = json.loads(render_scan_report_json(_report(findings=(finding,))))
    payload = rendered["findings"][0]

    assert payload["rule_id"] == finding.rule_id == _OTHER_RULE_ID
    assert payload["kind"] == finding.kind.value
    assert payload["observation"] == finding.observation == _OTHER_OBSERVATION
    assert payload["rationale"] == finding.rationale == _OTHER_RATIONALE
    assert payload["status"] == finding.status == 404
    assert payload["body_length"] == finding.body_length == 9
    assert payload["body_sha256"] == finding.body_sha256 == _OTHER_BODY_SHA256


def test_renderer_does_not_repair_evidence_owned_body_fields() -> None:
    finding = _report_finding(body_length=-1, body_sha256="not-a-digest")
    payload = json.loads(render_scan_report_json(_report(findings=(finding,))))[
        "findings"
    ][0]

    assert payload["body_length"] == -1
    assert payload["body_sha256"] == "not-a-digest"


def test_json_object_keys_are_exactly_the_allowlisted_set() -> None:
    rendered = render_scan_report_json(_one_finding_report())
    keys = _json_object_keys(json.loads(rendered))

    assert keys == _ALLOWED_OBJECT_KEYS
    for forbidden in _FORBIDDEN_OBJECT_KEYS:
        assert forbidden not in keys


def test_renderer_source_uses_locked_json_dumps_arguments() -> None:
    source = inspect.getsource(render_scan_report_json)

    assert "json.dumps" in source
    assert "ensure_ascii=True" in source
    assert "sort_keys=False" in source
    assert 'separators=(",", ":")' in source or "separators=(',', ':')" in source
    assert "indent" not in source
    assert "default=" not in source


def test_renderer_does_not_use_generic_or_reflective_serialization() -> None:
    source = inspect.getsource(render_scan_report_json)

    for marker in _GENERIC_SERIALIZATION_MARKERS:
        assert marker not in source
    assert "asdict" not in source


def test_renderer_does_not_inspect_or_serialize_domain_types() -> None:
    source = inspect.getsource(render_scan_report_json)

    for name in _DOMAIN_TYPE_NAMES:
        assert name not in source
    assert "project_report_target" not in source
    assert "build_scan_report" not in source
    assert "fingerprint" not in source
    assert "evidence_id" not in source


def test_renderer_source_serializes_report_url_via_url_field() -> None:
    source = inspect.getsource(render_scan_report_json)

    assert ".url" in source
    assert ".value" in source
    assert "str(report" not in source
    assert "repr(" not in source


def test_query_secrets_never_appear_in_rendered_json() -> None:
    seed = parse_target_url(
        "https://example.com/scan?"
        f"{_TOKEN_KEY}={_TOKEN_VALUE}&"
        f"{_SESSION_KEY}={_SESSION_VALUE}"
    )
    record = _record_with_query_secrets()
    report = build_scan_report(target=seed, result=ScanResult(findings=(record,)))
    rendered = render_scan_report_json(report)
    markers = (
        seed.query,
        seed.url,
        record.finding.target.url,
        record.finding.target.query,
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


def test_fingerprint_and_evidence_id_never_appear_in_rendered_json() -> None:
    record = _record_with_query_secrets()
    report = build_scan_report(
        target=parse_target_url("https://example.com/"),
        result=ScanResult(findings=(record,)),
    )
    rendered = render_scan_report_json(report)

    assert "fingerprint" not in rendered
    assert "evidence_id" not in rendered
    assert record.finding.fingerprint not in rendered
    assert record.evidence_id not in rendered


def test_body_header_and_credential_fields_never_appear() -> None:
    rendered = render_scan_report_json(_one_finding_report())
    keys = _json_object_keys(json.loads(rendered))

    assert "body" not in keys
    assert "headers" not in keys
    assert "header" not in keys
    assert "authorization" not in keys
    assert "cookie" not in keys
    assert "cookies" not in keys
    assert "credentials" not in keys
    assert '"headers"' not in rendered
    assert '"Authorization"' not in rendered
    assert '"Cookie"' not in rendered
    assert '"Set-Cookie"' not in rendered


def test_hidden_object_and_enum_repr_never_appear() -> None:
    rendered = render_scan_report_json(_one_finding_report())

    for marker in _FORBIDDEN_REPR:
        assert marker not in rendered
    assert "<boundary." not in rendered
    assert "enum" not in rendered.lower()


def test_renderer_has_no_fallback_or_partial_output_path() -> None:
    source = inspect.getsource(render_scan_report_json)

    assert "except Exception" not in source
    assert "except:" not in source
    assert "default=" not in source


def test_renderer_fail_closes_on_schema_before_emitting_a_document() -> None:
    source = inspect.getsource(render_scan_report_json)

    assert "report.schema" in source
    assert "ValueError" in source
    assert "!= 1" in source or "!= REPORT_SCHEMA_VERSION" in source


def test_reporting_uses_stdlib_json_only() -> None:
    source = inspect.getsource(render_scan_report_json)
    module_source = inspect.getsource(reporting)

    assert "json.dumps" in source
    for forbidden in ("orjson", "ujson", "simplejson", "rapidjson"):
        assert forbidden not in source
        assert forbidden not in module_source


def test_renderer_does_not_mutate_the_scan_report() -> None:
    report = _one_finding_report()
    before = (report.schema, report.target.url, report.findings)

    rendered = render_scan_report_json(report)

    assert (report.schema, report.target.url, report.findings) == before
    assert rendered == _ONE_FINDING_JSON


def test_rendered_json_is_ascii() -> None:
    rendered = render_scan_report_json(_one_finding_report())

    assert rendered.encode("ascii") == rendered.encode("utf-8")
    assert rendered.isascii()
