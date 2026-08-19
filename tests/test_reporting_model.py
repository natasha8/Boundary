"""Offline tests for safe passive report projection (Milestone 8, Slice B)."""

from __future__ import annotations

import gc
import inspect
import socket
from collections.abc import Callable
from dataclasses import MISSING, FrozenInstanceError, fields, is_dataclass
from typing import Any, cast, get_type_hints

import anyio
import pytest

import boundary.reporting as reporting
import boundary.scan as scan
from boundary.evidence import FindingEvidence, ResponseEvidence
from boundary.passive import PassiveFinding, PassiveFindingKind, build_passive_finding
from boundary.reporting import (
    REPORT_SCHEMA_VERSION,
    ReportFinding,
    ReportUrl,
    ScanReport,
    build_scan_report,
    project_report_target,
)
from boundary.scan import ScanResult
from boundary.scope import TargetUrl, parse_target_url

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
_SAFE_SEED = "https://example.com/"
_SAFE_HTTPS = "https://app.test/"
_SAFE_REQUESTED = "https://app.test/start"
_SAFE_FINAL = "https://app.test/final"
_TOKEN_KEY = "token"
_TOKEN_VALUE = "reset-token-7f3a9c21"
_SESSION_KEY = "session"
_SESSION_VALUE = "session-id-9c21aabb"
_API_KEY_VALUE = "sk_live_51NotARealKey"
_SECRET_VALUE = "supersecret-query-value"
_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_OTHER_BODY_SHA256 = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
_UNSORTED_EVIDENCE: tuple[tuple[str, str], ...] = (
    ("status", "200"),
    ("state", "missing"),
)
_REPORT_FINDING_FIELDS = (
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
_SCAN_REPORT_FIELDS = ("schema", "target", "findings")
_FORBIDDEN_REPORT_FIELDS = (
    "fingerprint",
    "evidence_id",
    "run_id",
    "timestamp",
    "time",
    "duration",
    "pages_visited",
    "config",
    "headers",
    "body",
    "raw",
    "query",
    "severity",
    "cvss",
    "confidence",
    "confirmation",
    "remediation",
    "credentials",
    "resolver",
    "authorization",
    "cookie",
    "cookies",
    "token",
    "identity",
)
_FORBIDDEN_REPORTING_IMPORTS = (
    "boundary.authorization",
    "boundary.discovery",
    "boundary.transport",
    "boundary.resolver",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("report projection must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if reporting reaches network or scan entry points."""
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


def _target(raw: str) -> TargetUrl:
    return parse_target_url(raw)


def _component_target(
    *,
    scheme: str,
    host: str,
    port: int,
    path: str,
    query: str,
    url: str,
) -> TargetUrl:
    return TargetUrl(
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        url=url,
    )


def _report_url(raw: str = _SAFE_HTTPS) -> ReportUrl:
    return ReportUrl(url=raw)


def _passive_finding(
    *,
    rule_id: str = _RULE_ID,
    kind: PassiveFindingKind = PassiveFindingKind.HARDENING,
    target: TargetUrl | None = None,
    requested_target: TargetUrl | None = None,
    observation: str = _OBSERVATION,
    rationale: str = _RATIONALE,
    evidence: tuple[tuple[str, str], ...] = _UNSORTED_EVIDENCE,
) -> PassiveFinding:
    return build_passive_finding(
        rule_id=rule_id,
        kind=kind,
        target=_target(_SAFE_HTTPS) if target is None else target,
        requested_target=(
            _target(_SAFE_REQUESTED) if requested_target is None else requested_target
        ),
        observation=observation,
        rationale=rationale,
        evidence=evidence,
    )


def _direct_passive_finding(
    *,
    rule_id: str = _RULE_ID,
    kind: object = PassiveFindingKind.HARDENING,
    target: TargetUrl | None = None,
    requested_target: TargetUrl | None = None,
    observation: object = _OBSERVATION,
    rationale: object = _RATIONALE,
    evidence: object = _UNSORTED_EVIDENCE,
) -> PassiveFinding:
    construct: Callable[..., PassiveFinding] = PassiveFinding
    return construct(
        rule_id=rule_id,
        kind=kind,
        target=_target(_SAFE_HTTPS) if target is None else target,
        requested_target=(
            _target(_SAFE_REQUESTED) if requested_target is None else requested_target
        ),
        observation=observation,
        rationale=rationale,
        evidence=evidence,
    )


def _response_evidence(
    *,
    status: int = 200,
    final_target: TargetUrl | None = None,
    requested_target: TargetUrl | None = None,
    body_length: int = 123,
    body_sha256: str = _BODY_SHA256,
) -> ResponseEvidence:
    return ResponseEvidence(
        status=status,
        final_target=_target(_SAFE_HTTPS) if final_target is None else final_target,
        requested_target=(
            _target(_SAFE_REQUESTED) if requested_target is None else requested_target
        ),
        body_length=body_length,
        body_sha256=body_sha256,
    )


def _record(
    *,
    finding: PassiveFinding | None = None,
    response: ResponseEvidence | None = None,
    status: int = 200,
    body_length: int = 123,
    body_sha256: str = _BODY_SHA256,
) -> FindingEvidence:
    resolved_finding = _passive_finding() if finding is None else finding
    resolved_response = (
        _response_evidence(
            status=status,
            final_target=resolved_finding.target,
            requested_target=resolved_finding.requested_target,
            body_length=body_length,
            body_sha256=body_sha256,
        )
        if response is None
        else response
    )
    return FindingEvidence(finding=resolved_finding, response=resolved_response)


def _result(*records: FindingEvidence) -> ScanResult:
    return ScanResult(findings=records)


def _construct_report_finding(**overrides: object) -> ReportFinding:
    construct: Callable[..., ReportFinding] = ReportFinding
    return construct(
        rule_id=overrides.get("rule_id", _RULE_ID),
        kind=overrides.get("kind", PassiveFindingKind.HARDENING),
        target=overrides.get("target", _report_url(_SAFE_HTTPS)),
        requested_target=overrides.get(
            "requested_target", _report_url("https://app.test/start")
        ),
        observation=overrides.get("observation", _OBSERVATION),
        rationale=overrides.get("rationale", _RATIONALE),
        evidence=overrides.get("evidence", _UNSORTED_EVIDENCE),
        status=overrides.get("status", 200),
        body_length=overrides.get("body_length", 123),
        body_sha256=overrides.get("body_sha256", _BODY_SHA256),
    )


def _snapshot_result(result: ScanResult) -> tuple[object, ...]:
    return tuple(
        (
            id(record),
            id(record.finding),
            id(record.response),
            record.finding.rule_id,
            record.finding.kind,
            record.finding.target,
            record.finding.requested_target,
            record.finding.observation,
            record.finding.rationale,
            record.finding.evidence,
            record.response.status,
            record.response.body_length,
            record.response.body_sha256,
        )
        for record in result.findings
    )


def _assert_no_domain_targets(*values: object) -> None:
    for value in values:
        assert not any(isinstance(item, TargetUrl) for item in gc.get_referents(value))
        assert not any(
            isinstance(item, FindingEvidence) for item in gc.get_referents(value)
        )
        assert not any(
            isinstance(item, PassiveFinding) for item in gc.get_referents(value)
        )
        assert not any(
            isinstance(item, ResponseEvidence) for item in gc.get_referents(value)
        )
        assert not any(isinstance(item, ScanResult) for item in gc.get_referents(value))


def _assert_secrets_absent(value: object, markers: tuple[str, ...]) -> None:
    rendered: tuple[str, ...] = (repr(value), str(value))
    if isinstance(value, ScanReport):
        rendered = (*rendered, value.target.url)
        for finding in value.findings:
            rendered = (
                *rendered,
                finding.target.url,
                finding.requested_target.url,
                repr(finding),
                str(finding),
            )
    for marker in markers:
        for text in rendered:
            assert marker not in text


def test_report_schema_version_is_the_locked_integer() -> None:
    assert REPORT_SCHEMA_VERSION == 1
    assert type(REPORT_SCHEMA_VERSION) is int


def test_report_finding_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(ReportFinding))

    assert is_dataclass(ReportFinding)
    assert names == _REPORT_FINDING_FIELDS
    for forbidden in _FORBIDDEN_REPORT_FIELDS:
        assert forbidden not in names


def test_scan_report_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(ScanReport))

    assert is_dataclass(ScanReport)
    assert names == _SCAN_REPORT_FIELDS
    for forbidden in _FORBIDDEN_REPORT_FIELDS:
        assert forbidden not in names
    assert "fingerprint" not in names
    assert "evidence_id" not in names
    assert "run_id" not in names
    assert "timestamp" not in names
    assert "pages_visited" not in names
    assert "config" not in names


def test_report_finding_constructor_accepts_fields_positionally_and_as_keyword() -> (
    None
):
    parameters = list(inspect.signature(ReportFinding).parameters)
    target = _report_url(_SAFE_HTTPS)
    requested_target = _report_url("https://app.test/start")
    positional = ReportFinding(
        _RULE_ID,
        PassiveFindingKind.HARDENING,
        target,
        requested_target,
        _OBSERVATION,
        _RATIONALE,
        _UNSORTED_EVIDENCE,
        200,
        123,
        _BODY_SHA256,
    )
    keyword = ReportFinding(
        rule_id=_RULE_ID,
        kind=PassiveFindingKind.HARDENING,
        target=target,
        requested_target=requested_target,
        observation=_OBSERVATION,
        rationale=_RATIONALE,
        evidence=_UNSORTED_EVIDENCE,
        status=200,
        body_length=123,
        body_sha256=_BODY_SHA256,
    )

    assert parameters == list(_REPORT_FINDING_FIELDS)
    for parameter in inspect.signature(ReportFinding).parameters.values():
        assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert parameter.default is inspect.Parameter.empty
    assert positional == keyword
    assert positional.rule_id == _RULE_ID


def test_scan_report_constructor_accepts_fields_positionally_and_as_keyword() -> None:
    parameters = list(inspect.signature(ScanReport).parameters)
    target = _report_url(_SAFE_SEED)
    findings = (_construct_report_finding(),)

    assert parameters == list(_SCAN_REPORT_FIELDS)
    for parameter in inspect.signature(ScanReport).parameters.values():
        assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert parameter.default is inspect.Parameter.empty
    assert ScanReport(1, target, findings) == ScanReport(
        schema=1,
        target=target,
        findings=findings,
    )


def test_report_finding_and_scan_report_have_no_hidden_field_defaults() -> None:
    for model in (ReportFinding, ScanReport):
        for field in fields(model):
            assert field.default is MISSING
            assert field.default_factory is MISSING


def test_report_finding_type_hints_match_the_approved_contract() -> None:
    hints = get_type_hints(ReportFinding)

    assert hints["rule_id"] is str
    assert hints["kind"] is PassiveFindingKind
    assert hints["target"] is ReportUrl
    assert hints["requested_target"] is ReportUrl
    assert hints["observation"] is str
    assert hints["rationale"] is str
    assert hints["evidence"] == tuple[tuple[str, str], ...]
    assert hints["status"] is int
    assert hints["body_length"] is int
    assert hints["body_sha256"] is str
    assert TargetUrl not in hints.values()
    assert FindingEvidence not in hints.values()
    assert PassiveFinding not in hints.values()
    assert ResponseEvidence not in hints.values()


def test_scan_report_type_hints_match_the_approved_contract() -> None:
    hints = get_type_hints(ScanReport)

    assert hints["schema"] is int
    assert hints["target"] is ReportUrl
    assert hints["findings"] == tuple[ReportFinding, ...]
    assert TargetUrl not in hints.values()
    assert ScanResult not in hints.values()
    assert FindingEvidence not in hints.values()


def test_report_finding_is_frozen_and_slotted() -> None:
    finding = _construct_report_finding()
    dataclass_params = cast(Any, ReportFinding).__dataclass_params__
    frozen: Any = finding

    with pytest.raises(FrozenInstanceError):
        frozen.rule_id = _OTHER_RULE_ID

    with pytest.raises(FrozenInstanceError):
        frozen.evidence = ()

    assert dataclass_params.frozen is True
    assert dataclass_params.slots is True
    assert set(ReportFinding.__slots__) == set(_REPORT_FINDING_FIELDS)
    assert not hasattr(finding, "__dict__")


def test_scan_report_is_frozen_and_slotted() -> None:
    report = ScanReport(schema=1, target=_report_url(), findings=())
    dataclass_params = cast(Any, ScanReport).__dataclass_params__
    frozen: Any = report

    with pytest.raises(FrozenInstanceError):
        frozen.schema = 2

    with pytest.raises(FrozenInstanceError):
        frozen.findings = ()

    assert dataclass_params.frozen is True
    assert dataclass_params.slots is True
    assert set(ScanReport.__slots__) == set(_SCAN_REPORT_FIELDS)
    assert not hasattr(report, "__dict__")


def test_report_models_have_no_custom_string_behavior() -> None:
    finding = _construct_report_finding()
    report = ScanReport(schema=1, target=_report_url(), findings=(finding,))

    for model in (ReportFinding, ScanReport):
        assert "__str__" not in model.__dict__
        assert "__format__" not in model.__dict__
    assert str(finding) != finding.target.url
    assert str(report) != report.target.url
    assert not str(report).startswith("https://")


def test_build_scan_report_signature_matches_the_approved_contract() -> None:
    signature = inspect.signature(build_scan_report)
    hints = get_type_hints(build_scan_report)

    assert tuple(signature.parameters) == ("target", "result")
    for parameter in signature.parameters.values():
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty
    assert hints["target"] is TargetUrl
    assert hints["result"] is ScanResult
    assert hints["return"] is ScanReport


def test_build_scan_report_rejects_positional_arguments() -> None:
    with pytest.raises(TypeError):
        cast(Any, build_scan_report)(_target(_SAFE_SEED), _result())


def test_zero_findings_still_projects_the_seed_target() -> None:
    seed = _target(_SAFE_SEED)
    result = _result()

    report = build_scan_report(target=seed, result=result)

    assert report.schema == REPORT_SCHEMA_VERSION == 1
    assert report.target == project_report_target(seed)
    assert report.target.url == _SAFE_SEED
    assert report.findings == ()
    assert len(report.findings) == len(result.findings) == 0
    assert isinstance(report.findings, tuple)
    assert not hasattr(report, "run_id")
    assert not hasattr(report, "timestamp")
    assert not hasattr(report, "pages_visited")
    assert not hasattr(report, "config")
    _assert_no_domain_targets(report)


def test_zero_findings_with_a_query_bearing_seed_redacts_the_query() -> None:
    seed = _target(f"https://example.com/?{_TOKEN_KEY}={_TOKEN_VALUE}")

    report = build_scan_report(target=seed, result=_result())

    assert report.findings == ()
    assert report.target == project_report_target(seed)
    assert report.target.url == "https://example.com/?REDACTED"
    _assert_secrets_absent(report, (seed.query, seed.url, _TOKEN_KEY, _TOKEN_VALUE))


def test_build_scan_report_maps_one_finding_from_the_locked_sources() -> None:
    seed = _target(_SAFE_SEED)
    finding_target = _target(_SAFE_FINAL)
    requested = _target(_SAFE_REQUESTED)
    evidence = (("header", "strict-transport-security"), ("state", "missing"))
    record = _record(
        finding=_passive_finding(
            rule_id=_RULE_ID,
            kind=PassiveFindingKind.HARDENING,
            target=finding_target,
            requested_target=requested,
            observation=_OBSERVATION,
            rationale=_RATIONALE,
            evidence=evidence,
        ),
        status=204,
        body_length=17,
        body_sha256=_OTHER_BODY_SHA256,
    )

    report = build_scan_report(target=seed, result=_result(record))
    projected = report.findings[0]

    assert len(report.findings) == 1
    assert report.schema == 1
    assert report.target == project_report_target(seed)
    assert report.target.url == _SAFE_SEED
    assert projected.rule_id is record.finding.rule_id
    assert projected.kind is record.finding.kind
    assert projected.kind is PassiveFindingKind.HARDENING
    assert type(projected.kind) is PassiveFindingKind
    assert projected.target == project_report_target(record.finding.target)
    assert projected.requested_target == project_report_target(
        record.finding.requested_target
    )
    assert projected.observation is record.finding.observation
    assert projected.rationale is record.finding.rationale
    assert projected.evidence is record.finding.evidence
    assert projected.status == record.response.status == 204
    assert type(projected.status) is int
    assert projected.body_length == record.response.body_length == 17
    assert projected.body_sha256 is record.response.body_sha256
    assert "204" not in {value for _key, value in projected.evidence}


def test_status_comes_from_the_response_not_the_evidence_key() -> None:
    record = _record(
        finding=_passive_finding(evidence=(("status", "200"), ("state", "missing"))),
        status=404,
        body_length=9,
    )

    projected = build_scan_report(
        target=_target(_SAFE_SEED),
        result=_result(record),
    ).findings[0]

    assert projected.status == 404
    assert ("status", "200") in projected.evidence
    assert projected.status != int(dict(projected.evidence)["status"])


def test_build_scan_report_does_not_read_response_url_fields() -> None:
    source = inspect.getsource(build_scan_report)

    assert "project_report_target" in source
    assert "final_target" not in source
    assert "response.requested_target" not in source
    assert "urlunsplit" not in source


def test_requested_target_is_present_even_when_equal_to_target() -> None:
    same = _target(_SAFE_HTTPS)
    record = _record(finding=_passive_finding(target=same, requested_target=same))

    projected = build_scan_report(
        target=_target(_SAFE_SEED),
        result=_result(record),
    ).findings[0]

    assert projected.requested_target == projected.target
    assert projected.requested_target.url == projected.target.url == _SAFE_HTTPS
    names = tuple(field.name for field in fields(type(projected)))
    assert "requested_target" in names


def test_distinct_raw_targets_keep_distinct_report_urls_when_safe_urls_differ() -> None:
    record = _record(
        finding=_passive_finding(
            target=_target(_SAFE_FINAL),
            requested_target=_target(_SAFE_REQUESTED),
        )
    )

    projected = build_scan_report(
        target=_target(_SAFE_SEED),
        result=_result(record),
    ).findings[0]

    assert projected.target.url == "https://app.test/final"
    assert projected.requested_target.url == "https://app.test/start"
    assert projected.target != projected.requested_target


def test_seed_target_is_independent_of_finding_targets() -> None:
    seed = _target("https://seed.test/scan")
    record = _record(
        finding=_passive_finding(
            target=_target("https://app.test/page"),
            requested_target=_target("https://app.test/start"),
        )
    )

    report = build_scan_report(target=seed, result=_result(record))

    assert report.target == project_report_target(seed)
    assert report.target.url == "https://seed.test/scan"
    assert report.findings[0].target.url == "https://app.test/page"


def test_finding_order_matches_scan_result_order() -> None:
    first = _record(
        finding=_passive_finding(
            rule_id=_RULE_ID,
            kind=PassiveFindingKind.HARDENING,
            observation=_OBSERVATION,
            rationale=_RATIONALE,
        )
    )
    second = _record(
        finding=_passive_finding(
            rule_id=_OTHER_RULE_ID,
            kind=PassiveFindingKind.MISCONFIGURATION,
            observation=_OTHER_OBSERVATION,
            rationale=_OTHER_RATIONALE,
            evidence=(("header", "content-security-policy"),),
        ),
        status=500,
        body_length=4,
        body_sha256=_OTHER_BODY_SHA256,
    )
    result = _result(first, second)

    report = build_scan_report(target=_target(_SAFE_SEED), result=result)

    assert len(report.findings) == len(result.findings) == 2
    assert tuple(item.rule_id for item in report.findings) == (_RULE_ID, _OTHER_RULE_ID)
    assert report.findings[0].kind is PassiveFindingKind.HARDENING
    assert report.findings[1].kind is PassiveFindingKind.MISCONFIGURATION
    assert report.findings[0].observation is first.finding.observation
    assert report.findings[1].observation is second.finding.observation
    assert report.findings[1].status == 500


def test_duplicate_findings_remain_duplicate_rows() -> None:
    first = _record()
    second = _record()
    result = _result(first, second)

    report = build_scan_report(target=_target(_SAFE_SEED), result=result)

    assert len(report.findings) == 2
    assert report.findings[0] == report.findings[1]
    assert first.evidence_id == second.evidence_id
    assert not hasattr(report.findings[0], "evidence_id")
    assert not hasattr(report.findings[0], "fingerprint")


def test_evidence_is_stored_unchanged_including_unsorted_order() -> None:
    unsorted = (("status", "200"), ("header", "x-content-type-options"))
    record = _record(finding=_direct_passive_finding(evidence=unsorted))

    projected = build_scan_report(
        target=_target(_SAFE_SEED),
        result=_result(record),
    ).findings[0]

    assert projected.evidence is record.finding.evidence
    assert projected.evidence == unsorted
    assert projected.evidence[0][0] == "status"


def test_duplicate_evidence_keys_are_not_rejected_by_reporting() -> None:
    duplicated = (("status", "200"), ("status", "500"))
    finding = _construct_report_finding(evidence=duplicated)
    record = _record(finding=_direct_passive_finding(evidence=duplicated))

    projected = build_scan_report(
        target=_target(_SAFE_SEED),
        result=_result(record),
    ).findings[0]

    assert finding.evidence == duplicated
    assert projected.evidence == duplicated


def test_empty_evidence_is_preserved() -> None:
    record = _record(finding=_passive_finding(evidence=()))

    projected = build_scan_report(
        target=_target(_SAFE_SEED),
        result=_result(record),
    ).findings[0]

    assert projected.evidence == ()
    assert projected.evidence is record.finding.evidence


def test_report_finding_does_not_revalidate_evidence_owned_body_fields() -> None:
    finding = _construct_report_finding(body_length=-1, body_sha256="not-a-digest")

    assert finding.body_length == -1
    assert finding.body_sha256 == "not-a-digest"


@pytest.mark.parametrize(
    "evidence",
    [
        pytest.param([("status", "200")], id="list"),
        pytest.param({"status": "200"}, id="dict"),
        pytest.param(b"status=200", id="bytes"),
        pytest.param(1, id="int"),
        pytest.param("status=200", id="bare_str"),
        pytest.param((["status", "200"],), id="list_pair"),
        pytest.param((("status",),), id="one_element_pair"),
        pytest.param((("status", "200", "extra"),), id="three_element_pair"),
        pytest.param((("status", 200),), id="non_str_value"),
        pytest.param(((1, "200"),), id="non_str_key"),
        pytest.param(({"status": "200"},), id="nested_dict_item"),
        pytest.param((_target(_SAFE_HTTPS),), id="target_url_item"),
        pytest.param(((_target(_SAFE_HTTPS), "200"),), id="target_url_key"),
    ],
)
def test_report_finding_rejects_invalid_evidence_shapes(evidence: object) -> None:
    with pytest.raises(ValueError) as caught:
        _construct_report_finding(evidence=evidence)

    message = str(caught.value)
    assert "token=" not in message
    assert _TOKEN_VALUE not in message
    assert "https://app.test/?token=" not in message


@pytest.mark.parametrize(
    "evidence",
    [
        pytest.param([("status", "200")], id="list"),
        pytest.param({"status": "200"}, id="dict"),
        pytest.param(b"status=200", id="bytes"),
        pytest.param((("status", "200", "extra"),), id="three_element_pair"),
        pytest.param((("status", 200),), id="non_str_value"),
    ],
)
def test_build_scan_report_rejects_invalid_evidence_without_omitting_rows(
    evidence: object,
) -> None:
    valid = _record()
    invalid = _record(finding=_direct_passive_finding(evidence=evidence))

    with pytest.raises(ValueError):
        build_scan_report(target=_target(_SAFE_SEED), result=_result(valid, invalid))


@pytest.mark.parametrize(
    "kind",
    [
        pytest.param("hardening", id="bare_hardening_string"),
        pytest.param("misconfiguration", id="bare_misconfiguration_string"),
        pytest.param(object(), id="arbitrary_object"),
        pytest.param(1, id="int"),
        pytest.param(None, id="none"),
    ],
)
def test_report_finding_rejects_unsupported_kind(kind: object) -> None:
    with pytest.raises(ValueError):
        _construct_report_finding(kind=kind)


def test_build_scan_report_rejects_bare_kind_string() -> None:
    record = _record(finding=_direct_passive_finding(kind="hardening"))

    with pytest.raises(ValueError):
        build_scan_report(target=_target(_SAFE_SEED), result=_result(record))


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("observation", 1),
        ("observation", None),
        ("observation", b"text"),
        ("rationale", 1),
        ("rationale", None),
        ("rule_id", 1),
        ("rule_id", None),
        ("body_sha256", 1),
        ("body_sha256", None),
        ("status", "200"),
        ("status", None),
        ("body_length", "123"),
        ("body_length", None),
        ("target", _SAFE_HTTPS),
        ("target", _target(_SAFE_HTTPS)),
        ("requested_target", _SAFE_REQUESTED),
        ("requested_target", _target(_SAFE_REQUESTED)),
    ],
)
def test_report_finding_rejects_unsupported_field_types(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(ValueError) as caught:
        _construct_report_finding(**{field_name: value})

    message = str(caught.value)
    assert "token=" not in message
    assert _TOKEN_VALUE not in message


@pytest.mark.parametrize("schema", [0, 2, "1", None])
def test_scan_report_rejects_schema_other_than_one(schema: object) -> None:
    construct: Callable[..., ScanReport] = ScanReport

    with pytest.raises(ValueError):
        construct(schema=schema, target=_report_url(), findings=())


def test_scan_report_rejects_non_tuple_findings() -> None:
    construct: Callable[..., ScanReport] = ScanReport

    with pytest.raises(ValueError):
        construct(
            schema=1,
            target=_report_url(),
            findings=[_construct_report_finding()],
        )


def test_failing_finding_projection_yields_no_scan_report() -> None:
    valid = _record()
    invalid_target = _component_target(
        scheme="ftp",
        host="app.test",
        port=21,
        path="/reset",
        query=f"{_TOKEN_KEY}={_TOKEN_VALUE}",
        url=f"ftp://app.test/reset?{_TOKEN_KEY}={_TOKEN_VALUE}",
    )
    invalid = _record(
        finding=_direct_passive_finding(
            target=invalid_target,
            requested_target=invalid_target,
        )
    )

    with pytest.raises(ValueError, match="unsupported URL scheme") as caught:
        build_scan_report(target=_target(_SAFE_SEED), result=_result(valid, invalid))

    message = str(caught.value)
    assert _TOKEN_VALUE not in message
    assert invalid_target.query not in message
    assert invalid_target.url not in message


def test_unsupported_seed_scheme_yields_no_scan_report() -> None:
    seed = _component_target(
        scheme="ftp",
        host="app.test",
        port=21,
        path="/",
        query=f"{_TOKEN_KEY}={_TOKEN_VALUE}",
        url=f"ftp://app.test/?{_TOKEN_KEY}={_TOKEN_VALUE}",
    )

    with pytest.raises(ValueError, match="unsupported URL scheme") as caught:
        build_scan_report(target=seed, result=_result())

    message = str(caught.value)
    assert seed.query not in message
    assert seed.url not in message
    assert _TOKEN_VALUE not in message


def test_observation_and_rationale_are_not_interpolated_with_urls() -> None:
    seed = _target(f"https://app.test/reset?{_TOKEN_KEY}={_TOKEN_VALUE}")
    record = _record(
        finding=_passive_finding(
            target=seed,
            requested_target=seed,
            observation=_OBSERVATION,
            rationale=_RATIONALE,
        )
    )

    report = build_scan_report(target=seed, result=_result(record))
    projected = report.findings[0]

    assert projected.observation == _OBSERVATION
    assert projected.rationale == _RATIONALE
    assert projected.observation is record.finding.observation
    assert seed.url not in projected.observation
    assert seed.query not in projected.observation
    assert seed.url not in projected.rationale
    assert report.target.url not in projected.observation


def test_query_secrets_are_absent_from_report_repr_and_str() -> None:
    seed = _target(
        "https://app.test/reset?"
        f"{_TOKEN_KEY}={_TOKEN_VALUE}&"
        f"{_SESSION_KEY}={_SESSION_VALUE}&"
        f"api_key={_API_KEY_VALUE}&"
        f"password={_SECRET_VALUE}"
    )
    record = _record(
        finding=_passive_finding(target=seed, requested_target=seed),
    )

    report = build_scan_report(target=seed, result=_result(record))

    assert report.target.url == "https://app.test/reset?REDACTED"
    assert report.findings[0].target.url == "https://app.test/reset?REDACTED"
    assert report.findings[0].requested_target.url == "https://app.test/reset?REDACTED"
    _assert_secrets_absent(
        report,
        (
            seed.query,
            seed.url,
            _TOKEN_KEY,
            _TOKEN_VALUE,
            _SESSION_KEY,
            _SESSION_VALUE,
            _API_KEY_VALUE,
            _SECRET_VALUE,
            "password",
            "api_key",
        ),
    )
    _assert_no_domain_targets(report, *report.findings)


def test_fingerprint_and_evidence_id_are_omitted_from_the_report() -> None:
    record = _record(
        finding=_passive_finding(
            target=_target(f"https://app.test/reset?{_TOKEN_KEY}={_TOKEN_VALUE}")
        )
    )
    report = build_scan_report(target=_target(_SAFE_SEED), result=_result(record))
    projected = report.findings[0]
    public_report = {name for name in dir(report) if not name.startswith("_")}
    public_finding = {name for name in dir(projected) if not name.startswith("_")}

    assert "fingerprint" not in public_report
    assert "evidence_id" not in public_report
    assert "fingerprint" not in public_finding
    assert "evidence_id" not in public_finding
    assert record.finding.fingerprint not in repr(report)
    assert record.finding.fingerprint not in str(report)
    assert record.evidence_id not in repr(report)
    assert record.evidence_id not in str(report)
    assert record.finding.fingerprint not in repr(projected)
    assert record.evidence_id not in repr(projected)


def test_build_scan_report_does_not_retain_the_source_domain_objects() -> None:
    seed = _target(f"https://app.test/reset?{_TOKEN_KEY}={_TOKEN_VALUE}")
    record = _record(finding=_passive_finding(target=seed, requested_target=seed))
    result = _result(record)

    report = build_scan_report(target=seed, result=result)

    assert isinstance(report.findings[0].target, ReportUrl)
    assert isinstance(report.findings[0].requested_target, ReportUrl)
    assert not isinstance(report.findings[0].target, TargetUrl)
    assert seed not in gc.get_referents(report)
    assert result not in gc.get_referents(report)
    assert record not in gc.get_referents(report)
    assert record.finding not in gc.get_referents(report)
    assert not any(isinstance(item, TargetUrl) for item in gc.get_referents(report))
    assert not any(item is seed.url for item in gc.get_referents(report))
    _assert_no_domain_targets(report, report.target, *report.findings)


def test_build_scan_report_does_not_mutate_inputs() -> None:
    seed = _target(f"https://app.test/reset?{_TOKEN_KEY}={_TOKEN_VALUE}")
    result = _result(
        _record(finding=_passive_finding(target=seed, requested_target=seed))
    )
    before_seed = (seed.scheme, seed.host, seed.port, seed.path, seed.query, seed.url)
    before_result = _snapshot_result(result)
    seed_id = id(seed)
    result_id = id(result)

    report = build_scan_report(target=seed, result=result)

    assert id(seed) == seed_id
    assert id(result) == result_id
    assert (seed.scheme, seed.host, seed.port, seed.path, seed.query, seed.url) == (
        before_seed
    )
    assert _snapshot_result(result) == before_result
    assert seed.query == f"{_TOKEN_KEY}={_TOKEN_VALUE}"
    assert report.target.url == "https://app.test/reset?REDACTED"


def test_path_tokens_are_preserved_and_queries_are_redacted() -> None:
    seed = _target("https://app.test/reset/SECRET?x=1")
    record = _record(finding=_passive_finding(target=seed, requested_target=seed))

    report = build_scan_report(target=seed, result=_result(record))

    assert report.target.url == "https://app.test/reset/SECRET?REDACTED"
    assert "/reset/SECRET" in report.target.url
    assert "x=1" not in report.target.url


def test_reporting_module_does_not_import_authorization_or_network_modules() -> None:
    source = inspect.getsource(reporting)

    for forbidden in _FORBIDDEN_REPORTING_IMPORTS:
        assert forbidden not in source
    assert "boundary.reporting" not in inspect.getsource(scan)
    assert not hasattr(scan, "build_scan_report")
    assert not hasattr(scan, "ScanReport")


def test_reporting_does_not_expose_authorization_report_types() -> None:
    public_names = {name for name in dir(reporting) if not name.startswith("_")}

    assert "AuthorizationObservation" not in public_names
    assert "ReportFinding" in public_names
    assert "ScanReport" in public_names
    assert "build_scan_report" in public_names
    assert "REPORT_SCHEMA_VERSION" in public_names
