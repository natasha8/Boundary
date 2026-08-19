"""Offline tests for the CLI scan subcommand and report format adapter."""

from __future__ import annotations

import inspect
import socket
from argparse import Action, ArgumentParser
from collections.abc import Callable, Sequence
from typing import TypedDict, cast

import anyio
import pytest
from pytest import CaptureFixture

import boundary.cli as cli
from boundary.cli import build_parser, main
from boundary.discovery import DiscoveryLimits
from boundary.evidence import FindingEvidence, ResponseEvidence
from boundary.passive import PassiveFindingKind, build_passive_finding
from boundary.reporting import (
    ScanReport,
    build_scan_report,
    render_scan_report_json,
    render_scan_report_sarif,
)
from boundary.resolver import SystemAddressResolver
from boundary.scan import ScanConfig, ScanResult
from boundary.scope import (
    AddressPolicy,
    Origin,
    ScopeErrorCode,
    ScopeValidationError,
    TargetUrl,
    UrlValidationError,
    parse_target_url,
    require_allowed_origin,
)
from boundary.transport import RequestLimits, TransportError, TransportErrorCode

_TARGET = "https://app.test/"
_SECRET = "SUPERSECRET_PASSWORD_cli_slice_d"
_QUERY_TOKEN = "SUPERSECRET_QUERY_TOKEN_cli"
_EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_REQUIRED_OPTIONS = (
    "--allow-origin",
    "--address-policy",
    "--max-pages",
    "--max-depth",
    "--max-redirects",
    "--max-body-bytes",
)
_OPTIONAL_TIMEOUTS = (
    "--connect-timeout",
    "--read-timeout",
    "--write-timeout",
    "--pool-timeout",
)
_FORMAT_CHOICES = ("text", "json", "sarif")
_ALL_FORMAT_ARGV: tuple[tuple[str, ...], ...] = (
    (),
    ("--format", "text"),
    ("--format", "json"),
    ("--format", "sarif"),
)
_TEXT_FORMAT_ARGV: tuple[tuple[str, ...], ...] = (
    (),
    ("--format", "text"),
)
_REPORT_FORMATS = ("json", "sarif")
_INVALID_FORMATS = (
    "xml",
    "markdown",
    "html",
    "JSON",
    "TEXT",
    "SARIF",
    "yaml",
)
_EXPECTED_SCAN_OPTION_STRINGS = {
    "-h",
    "--help",
    "--allow-origin",
    "--address-policy",
    "--max-pages",
    "--max-depth",
    "--max-redirects",
    "--max-body-bytes",
    "--connect-timeout",
    "--read-timeout",
    "--write-timeout",
    "--pool-timeout",
    "--format",
}
_FORBIDDEN_FLAGS = (
    "--json",
    "--sarif",
    "--markdown",
    "--html",
    "--output",
    "--pretty",
    "--indent",
    "--upload",
    "--github",
    "--cookie",
    "--header",
    "--identity",
    "--auth",
    "--profile",
    "--concurrency",
    "--plugin",
    "--login",
    "--session",
    "--config",
    "--ai",
    "--timeout",
    "--progress",
)
_FORBIDDEN_HELP_MARKERS = (
    "markdown",
    "html",
    "spinner",
    "github",
    "pretty",
    "indent",
    "upload",
)
_FORBIDDEN_CLI_MARKERS = (
    "crawl",
    "scan_page",
    "scan_pages",
    "capture_response_evidence",
    "request_once",
    "request_with_redirects",
    "request_as",
    "urlsplit",
    "urlunsplit",
    "urljoin",
    "boundary.authorization",
    "json.dumps",
    "import json",
    "from json import",
    "dataclasses.asdict",
    "asdict(",
    "ScanReport(",
    "ReportFinding(",
    "ReportUrl(",
    "project_report_target",
    "FindingEvidence",
    "PassiveFinding",
    "ResponseEvidence",
)


class RunRecorder:
    """Captures ScanConfig values passed to run_passive_scan without crawling."""

    def __init__(self) -> None:
        self.calls: list[ScanConfig] = []
        self.result: ScanResult = ScanResult(findings=())
        self.error: BaseException | None = None

    async def fake_run(self, config: ScanConfig) -> ScanResult:
        self.calls.append(config)
        if self.error is not None:
            raise self.error
        return self.result


class ReportingRecorder:
    """Records reporting-adapter calls while delegating to the real projection."""

    def __init__(self) -> None:
        self.build_calls: list[tuple[TargetUrl, ScanResult, ScanReport]] = []
        self.json_calls: list[tuple[ScanReport, str]] = []
        self.sarif_calls: list[tuple[ScanReport, str]] = []
        self.build_attempts = 0
        self.json_attempts = 0
        self.sarif_attempts = 0
        self.build_error: BaseException | None = None
        self.json_error: BaseException | None = None
        self.sarif_error: BaseException | None = None

    def build(self, *, target: TargetUrl, result: ScanResult) -> ScanReport:
        self.build_attempts += 1
        if self.build_error is not None:
            raise self.build_error
        report = build_scan_report(target=target, result=result)
        self.build_calls.append((target, result, report))
        return report

    def render_json(self, report: ScanReport) -> str:
        self.json_attempts += 1
        if self.json_error is not None:
            raise self.json_error
        rendered = render_scan_report_json(report)
        self.json_calls.append((report, rendered))
        return rendered

    def render_sarif(self, report: ScanReport) -> str:
        self.sarif_attempts += 1
        if self.sarif_error is not None:
            raise self.sarif_error
        rendered = render_scan_report_sarif(report)
        self.sarif_calls.append((report, rendered))
        return rendered


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_cli_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("CLI scan tests must not perform network activity")


class _ScanArgvOverrides(TypedDict, total=False):
    target: str | None
    allow_origins: Sequence[str]
    address_policy: str | None
    max_pages: str | None
    max_depth: str | None
    max_redirects: str | None
    max_body_bytes: str | None
    extra: Sequence[str]


def _scan_result_with_count(count: int) -> ScanResult:
    return ScanResult(
        findings=tuple(cast(FindingEvidence, object()) for _ in range(count))
    )


def _finding_record(target: str) -> FindingEvidence:
    parsed = parse_target_url(target)
    finding = build_passive_finding(
        rule_id="passive.hsts.not_enforced.v1",
        kind=PassiveFindingKind.HARDENING,
        target=parsed,
        requested_target=parsed,
        observation="HTTPS response did not enforce Strict-Transport-Security.",
        rationale=(
            "Missing or ineffective HSTS is a transport-hardening observation, "
            "not proof of exploitability."
        ),
        evidence=(("state", "missing"),),
    )
    return FindingEvidence(
        finding=finding,
        response=ResponseEvidence(
            status=200,
            final_target=parsed,
            requested_target=parsed,
            body_length=0,
            body_sha256=_EMPTY_BODY_SHA256,
        ),
    )


def _scan_result_with_findings(count: int, *, target: str) -> ScanResult:
    return ScanResult(findings=tuple(_finding_record(target) for _ in range(count)))


def _scan_argv(
    *,
    target: str | None = _TARGET,
    allow_origins: Sequence[str] | None = None,
    address_policy: str | None = "public",
    max_pages: str | None = "1",
    max_depth: str | None = "0",
    max_redirects: str | None = "0",
    max_body_bytes: str | None = "65536",
    connect_timeout: str | None = None,
    read_timeout: str | None = None,
    write_timeout: str | None = None,
    pool_timeout: str | None = None,
    report_format: str | None = None,
    extra: Sequence[str] = (),
) -> list[str]:
    argv: list[str] = ["scan"]
    if target is not None:
        argv.append(target)
    origins: Sequence[str] = (_TARGET,) if allow_origins is None else allow_origins
    for origin in origins:
        argv.extend(["--allow-origin", origin])
    if address_policy is not None:
        argv.extend(["--address-policy", address_policy])
    if max_pages is not None:
        argv.extend(["--max-pages", max_pages])
    if max_depth is not None:
        argv.extend(["--max-depth", max_depth])
    if max_redirects is not None:
        argv.extend(["--max-redirects", max_redirects])
    if max_body_bytes is not None:
        argv.extend(["--max-body-bytes", max_body_bytes])
    if connect_timeout is not None:
        argv.extend(["--connect-timeout", connect_timeout])
    if read_timeout is not None:
        argv.extend(["--read-timeout", read_timeout])
    if write_timeout is not None:
        argv.extend(["--write-timeout", write_timeout])
    if pool_timeout is not None:
        argv.extend(["--pool-timeout", pool_timeout])
    if report_format is not None:
        argv.extend(["--format", report_format])
    argv.extend(extra)
    return argv


def _patch_cli_name(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: object,
    *,
    raising: bool = False,
) -> None:
    monkeypatch.setattr(f"boundary.cli.{name}", value, raising=raising)
    monkeypatch.setattr(f"boundary.scan.{name}", value, raising=False)


def _patch_reporting_name(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: object,
) -> None:
    monkeypatch.setattr(f"boundary.cli.{name}", value, raising=False)
    monkeypatch.setattr(f"boundary.reporting.{name}", value)


def _scan_parser() -> ArgumentParser:
    parser = build_parser()
    subparsers_action = next(
        action for action in parser._actions if action.dest == "command"
    )
    choices = subparsers_action.choices
    assert isinstance(choices, dict)
    scan_parser = choices["scan"]
    assert isinstance(scan_parser, ArgumentParser)
    return scan_parser


def _scan_option_strings() -> set[str]:
    return {
        option for action in _scan_parser()._actions for option in action.option_strings
    }


def _format_action() -> Action:
    matches = [
        action
        for action in _scan_parser()._actions
        if "--format" in action.option_strings
    ]
    assert len(matches) == 1
    return matches[0]


def _format_ids(extra: Sequence[str]) -> str:
    if extra == ():
        return "omitted"
    if extra == ("--format", "text"):
        return "text"
    if extra == ("--format", "json"):
        return "json"
    return "sarif"


@pytest.fixture(autouse=True)
def _reject_dns_transport_discovery_and_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if the CLI reaches DNS, HTTP, crawl, or page scanning."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)
    monkeypatch.setattr("boundary.discovery.crawl", _reject_cli_network)
    monkeypatch.setattr("boundary.passive.scan_page", _reject_cli_network)
    monkeypatch.setattr("boundary.passive.scan_pages", _reject_cli_network)
    monkeypatch.setattr(
        "boundary.evidence.capture_response_evidence",
        _reject_cli_network,
    )
    monkeypatch.setattr("boundary.transport.request_once", _reject_cli_network)
    monkeypatch.setattr(
        "boundary.transport.request_with_redirects",
        _reject_cli_network,
    )
    monkeypatch.setattr("boundary.authorization.request_as", _reject_cli_network)
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.resolve",
        _reject_cli_network,
    )


@pytest.fixture
def scan_run(monkeypatch: pytest.MonkeyPatch) -> RunRecorder:
    recorder = RunRecorder()
    _patch_cli_name(monkeypatch, "run_passive_scan", recorder.fake_run)
    return recorder


@pytest.fixture
def reporting_calls(monkeypatch: pytest.MonkeyPatch) -> ReportingRecorder:
    recorder = ReportingRecorder()
    _patch_reporting_name(monkeypatch, "build_scan_report", recorder.build)
    _patch_reporting_name(monkeypatch, "render_scan_report_json", recorder.render_json)
    _patch_reporting_name(
        monkeypatch, "render_scan_report_sarif", recorder.render_sarif
    )
    return recorder


def _assert_argparse_error(
    argv: Sequence[str],
    capsys: CaptureFixture[str],
) -> str:
    with pytest.raises(SystemExit) as caught:
        main(list(argv))
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "findings" not in captured.out
    return captured.err


def test_no_arguments_does_not_start_a_scan(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    main([])

    output = capsys.readouterr().out
    assert output.startswith("usage: boundary")
    assert "Evidence-driven Web and API security scanner." in output
    assert "--format" not in output
    assert "json" not in output.lower()
    assert "sarif" not in output.lower()
    assert scan_run.calls == []


def test_scan_help_documents_required_and_optional_flags(
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["scan", "-h"])

    assert caught.value.code == 0
    help_text = capsys.readouterr().out
    assert "usage:" in help_text
    for option in _REQUIRED_OPTIONS:
        assert option in help_text
    for option in _OPTIONAL_TIMEOUTS:
        assert option in help_text
    assert "target" in help_text
    assert "public" in help_text
    assert "local_lab" in help_text
    assert "--format" in help_text
    assert "{text,json,sarif}" in help_text
    assert "[--format {text,json,sarif}]" in help_text
    for option in _OPTIONAL_TIMEOUTS:
        assert f"[{option}" in help_text
    for option in _REQUIRED_OPTIONS:
        assert f"[{option}" not in help_text


def test_scan_help_omits_deferred_product_flags(
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["scan", "-h"])

    assert caught.value.code == 0
    help_text = capsys.readouterr().out
    lowered = help_text.lower()
    for flag in _FORBIDDEN_FLAGS:
        assert flag not in help_text
        assert flag not in lowered
    for marker in _FORBIDDEN_HELP_MARKERS:
        assert marker not in lowered
    assert "--json" not in help_text
    assert "--sarif" not in help_text
    assert "--output" not in help_text


def test_format_option_is_optional_with_locked_choices_and_text_default() -> None:
    action = _format_action()
    assert action.option_strings == ["--format"]
    assert action.dest == "format"
    assert action.required is False
    assert action.default == "text"
    assert action.nargs is None
    assert action.choices is not None
    assert tuple(action.choices) == _FORMAT_CHOICES
    args = build_parser().parse_args(_scan_argv())
    assert args.format == "text"
    assert args.format == action.default
    for value in _FORMAT_CHOICES:
        parsed = build_parser().parse_args(_scan_argv(report_format=value))
        assert parsed.format == value
    assert _scan_option_strings() == _EXPECTED_SCAN_OPTION_STRINGS
    root_options = {
        option for action in build_parser()._actions for option in action.option_strings
    }
    assert "--format" not in root_options
    assert "--output" not in _scan_option_strings()


@pytest.mark.parametrize("option", _REQUIRED_OPTIONS)
def test_missing_required_option_is_argparse_error(
    option: str,
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    overrides: _ScanArgvOverrides
    if option == "--allow-origin":
        overrides = {"allow_origins": ()}
    elif option == "--address-policy":
        overrides = {"address_policy": None}
    elif option == "--max-pages":
        overrides = {"max_pages": None}
    elif option == "--max-depth":
        overrides = {"max_depth": None}
    elif option == "--max-redirects":
        overrides = {"max_redirects": None}
    else:
        overrides = {"max_body_bytes": None}

    stderr = _assert_argparse_error(_scan_argv(**overrides), capsys)

    assert option in stderr
    assert scan_run.calls == []


def test_missing_target_is_argparse_error(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    stderr = _assert_argparse_error(_scan_argv(target=None), capsys)

    assert "target" in stderr.lower()
    assert scan_run.calls == []


def test_extra_positional_argument_is_argparse_error(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    stderr = _assert_argparse_error(
        _scan_argv(extra=["https://other.test/"]),
        capsys,
    )

    assert "unrecognized" in stderr.lower()
    assert scan_run.calls == []


def test_invalid_address_policy_is_argparse_error(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    stderr = _assert_argparse_error(
        _scan_argv(address_policy="internet"),
        capsys,
    )

    assert "--address-policy" in stderr
    assert scan_run.calls == []


def test_uppercase_address_policy_value_is_rejected(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    stderr = _assert_argparse_error(
        _scan_argv(address_policy="PUBLIC"),
        capsys,
    )

    assert "--address-policy" in stderr
    assert scan_run.calls == []


@pytest.mark.parametrize("value", _INVALID_FORMATS)
def test_invalid_format_is_argparse_error(
    value: str,
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    stderr = _assert_argparse_error(_scan_argv(report_format=value), capsys)

    assert "--format" in stderr
    assert "invalid choice" in stderr.lower()
    assert "unrecognized" not in stderr.lower()
    assert value in stderr
    assert scan_run.calls == []


def test_format_option_without_value_is_argparse_error(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    stderr = _assert_argparse_error(_scan_argv(extra=["--format"]), capsys)

    assert "--format" in stderr
    assert "expected" in stderr.lower()
    assert "unrecognized" not in stderr.lower()
    assert scan_run.calls == []


def test_format_does_not_relax_required_scan_options(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    stderr = _assert_argparse_error(
        _scan_argv(max_pages=None, report_format="json"),
        capsys,
    )

    assert "--max-pages" in stderr
    assert scan_run.calls == []


@pytest.mark.parametrize("flag", _FORBIDDEN_FLAGS)
def test_deferred_product_flag_is_rejected(
    flag: str,
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    stderr = _assert_argparse_error(_scan_argv(extra=[flag]), capsys)

    assert flag in stderr
    assert "unrecognized" in stderr.lower()
    assert scan_run.calls == []


def test_cli_parses_target_and_allow_origin_with_parse_target_url(
    monkeypatch: pytest.MonkeyPatch,
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    recorded: list[str] = []
    original = parse_target_url
    target = "https://app.test/path?q=1"
    allow_origins = ("https://app.test/admin", "https://cdn.test:8443/assets")

    def wrapper(raw: str) -> object:
        recorded.append(raw)
        return original(raw)

    monkeypatch.setattr("boundary.scope.parse_target_url", wrapper)
    monkeypatch.setattr("boundary.cli.parse_target_url", wrapper, raising=False)

    main(
        _scan_argv(
            target=target,
            allow_origins=allow_origins,
        )
    )

    assert recorded.count(target) >= 1
    for origin_url in allow_origins:
        assert recorded.count(origin_url) >= 1
    assert scan_run.calls[0].target == original(target)
    assert scan_run.calls[0].allowed_origins == tuple(
        original(origin_url).origin for origin_url in allow_origins
    )
    assert all(type(origin) is Origin for origin in scan_run.calls[0].allowed_origins)
    assert capsys.readouterr().out == "0 findings\n"


@pytest.mark.parametrize("extra", _ALL_FORMAT_ARGV, ids=_format_ids)
def test_scan_wires_one_config_and_one_run_passive_scan(
    extra: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    constructed: list[ScanConfig] = []
    resolvers: list[SystemAddressResolver] = []
    real_scan_config = ScanConfig
    real_resolver = SystemAddressResolver

    def capturing_scan_config(*args: object, **kwargs: object) -> ScanConfig:
        construct: Callable[..., ScanConfig] = real_scan_config
        config = construct(*args, **kwargs)
        constructed.append(config)
        return config

    def capturing_resolver(*args: object, **kwargs: object) -> SystemAddressResolver:
        resolver = real_resolver(*args, **kwargs)
        resolvers.append(resolver)
        return resolver

    _patch_cli_name(monkeypatch, "ScanConfig", capturing_scan_config)
    monkeypatch.setattr("boundary.cli.SystemAddressResolver", capturing_resolver)
    target = "https://app.test/path?q=1"
    allow_origins = ("https://app.test/", "https://cdn.test:8443/assets")

    main(
        _scan_argv(
            target=target,
            allow_origins=allow_origins,
            address_policy="local_lab",
            max_pages="3",
            max_depth="2",
            max_redirects="4",
            max_body_bytes="1024",
            connect_timeout="1.5",
            read_timeout="2.25",
            write_timeout="3",
            pool_timeout="0",
            extra=extra,
        )
    )

    assert constructed == scan_run.calls
    assert len(scan_run.calls) == 1
    assert len(resolvers) == 1
    config = scan_run.calls[0]
    assert type(config) is ScanConfig
    assert config.resolver is resolvers[0]
    assert config.target == parse_target_url(target)
    assert config.allowed_origins == (
        parse_target_url(allow_origins[0]).origin,
        parse_target_url(allow_origins[1]).origin,
    )
    assert config.policy is AddressPolicy.LOCAL_LAB
    assert type(config.resolver) is SystemAddressResolver
    assert config.request_limits == RequestLimits(
        max_body_bytes=1024,
        connect_timeout=1.5,
        read_timeout=2.25,
        write_timeout=3.0,
        pool_timeout=0.0,
    )
    assert config.max_redirects == 4
    assert config.discovery_limits == DiscoveryLimits(max_pages=3, max_depth=2)
    if extra in _TEXT_FORMAT_ARGV:
        assert capsys.readouterr().out == "0 findings\n"


def test_omitted_timeouts_map_to_none(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    main(_scan_argv())

    limits = scan_run.calls[0].request_limits
    assert limits.max_body_bytes == 65536
    assert limits.connect_timeout is None
    assert limits.read_timeout is None
    assert limits.write_timeout is None
    assert limits.pool_timeout is None
    assert capsys.readouterr().out == "0 findings\n"


def test_public_address_policy_maps_to_enum_member(
    scan_run: RunRecorder,
) -> None:
    main(_scan_argv(address_policy="public"))

    assert scan_run.calls[0].policy is AddressPolicy.PUBLIC


@pytest.mark.parametrize(
    ("kwargs", "raw"),
    [
        (
            {"target": f"https://user:{_SECRET}@app.test/"},
            f"https://user:{_SECRET}@app.test/",
        ),
        ({"target": "ftp://app.test/"}, "ftp://app.test/"),
        ({"target": "https://app.test:99999/"}, "https://app.test:99999/"),
        (
            {"allow_origins": [f"https://user:{_SECRET}@app.test/"]},
            f"https://user:{_SECRET}@app.test/",
        ),
        ({"allow_origins": ["ftp://app.test/"]}, "ftp://app.test/"),
    ],
)
def test_invalid_url_input_fails_via_parse_target_url_before_scan(
    kwargs: _ScanArgvOverrides,
    raw: str,
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(UrlValidationError) as expected:
        parse_target_url(raw)
    with pytest.raises(UrlValidationError) as actual:
        main(_scan_argv(**kwargs))

    assert type(actual.value) is UrlValidationError
    assert actual.value.code is expected.value.code
    assert str(actual.value) == str(expected.value)
    assert _SECRET not in str(actual.value)
    assert scan_run.calls == []
    assert "findings" not in capsys.readouterr().out


def test_missing_seed_origin_is_not_auto_inserted(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    target = "https://app.test/admin"
    other = "https://other.test/"
    expected_target = parse_target_url(target)
    allowed_origins = (parse_target_url(other).origin,)

    with pytest.raises(ScopeValidationError) as expected:
        require_allowed_origin(expected_target, allowed_origins)
    with pytest.raises(ScopeValidationError) as actual:
        main(_scan_argv(target=target, allow_origins=(other,)))

    assert type(actual.value) is ScopeValidationError
    assert actual.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
    assert actual.value.code is expected.value.code
    assert str(actual.value) == str(expected.value)
    assert expected_target.origin not in allowed_origins
    assert scan_run.calls == []
    assert "findings" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("kwargs", "builder"),
    [
        ({"max_pages": "0"}, lambda: DiscoveryLimits(max_pages=0, max_depth=0)),
        ({"max_depth": "-1"}, lambda: DiscoveryLimits(max_pages=1, max_depth=-1)),
        (
            {"max_body_bytes": "-1"},
            lambda: RequestLimits(
                max_body_bytes=-1,
                connect_timeout=None,
                read_timeout=None,
                write_timeout=None,
                pool_timeout=None,
            ),
        ),
        (
            {"max_redirects": "-1"},
            lambda: ScanConfig(
                target=parse_target_url(_TARGET),
                allowed_origins=(parse_target_url(_TARGET).origin,),
                policy=AddressPolicy.PUBLIC,
                resolver=SystemAddressResolver(),
                request_limits=RequestLimits(
                    max_body_bytes=65536,
                    connect_timeout=None,
                    read_timeout=None,
                    write_timeout=None,
                    pool_timeout=None,
                ),
                max_redirects=-1,
                discovery_limits=DiscoveryLimits(max_pages=1, max_depth=0),
            ),
        ),
    ],
)
def test_invalid_limit_fails_in_existing_domain_type_before_scan(
    kwargs: _ScanArgvOverrides,
    builder: Callable[[], object],
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    with pytest.raises(ValueError) as expected:
        builder()
    with pytest.raises(ValueError) as actual:
        main(_scan_argv(**kwargs))

    assert type(actual.value) is ValueError
    assert str(actual.value) == str(expected.value)
    assert scan_run.calls == []
    assert "findings" not in capsys.readouterr().out


def test_clean_result_prints_zero_findings(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    scan_run.result = ScanResult(findings=())

    main(_scan_argv())

    captured = capsys.readouterr()
    assert captured.out == "0 findings\n"
    assert captured.err == ""


def test_success_prints_only_the_operational_finding_count(
    scan_run: RunRecorder,
    capsys: CaptureFixture[str],
) -> None:
    scan_run.result = _scan_result_with_count(2)
    target = f"https://app.test/search?token={_QUERY_TOKEN}"

    main(_scan_argv(target=target, allow_origins=(_TARGET,)))

    captured = capsys.readouterr()
    assert captured.out == "2 findings\n"
    assert captured.err == ""
    assert _QUERY_TOKEN not in captured.out
    assert _QUERY_TOKEN not in captured.err
    assert "json" not in captured.out.lower()
    assert "sarif" not in captured.out.lower()
    assert "markdown" not in captured.out.lower()


@pytest.mark.parametrize("extra", _TEXT_FORMAT_ARGV, ids=_format_ids)
def test_text_format_prints_operational_count_without_building_a_report(
    extra: tuple[str, ...],
    scan_run: RunRecorder,
    reporting_calls: ReportingRecorder,
    capsys: CaptureFixture[str],
) -> None:
    scan_run.result = _scan_result_with_count(2)

    main(_scan_argv(extra=extra))

    captured = capsys.readouterr()
    assert captured.out == "2 findings\n"
    assert captured.err == ""
    assert len(scan_run.calls) == 1
    assert reporting_calls.build_attempts == 0
    assert reporting_calls.json_attempts == 0
    assert reporting_calls.sarif_attempts == 0
    assert reporting_calls.build_calls == []
    assert reporting_calls.json_calls == []
    assert reporting_calls.sarif_calls == []


def test_json_format_prints_renderer_output_from_one_scan_report(
    scan_run: RunRecorder,
    reporting_calls: ReportingRecorder,
    capsys: CaptureFixture[str],
) -> None:
    target = f"https://app.test/search?token={_QUERY_TOKEN}"
    scan_run.result = _scan_result_with_findings(2, target=target)

    main(_scan_argv(target=target, allow_origins=(_TARGET,), report_format="json"))

    assert len(scan_run.calls) == 1
    assert reporting_calls.build_attempts == 1
    assert reporting_calls.json_attempts == 1
    assert reporting_calls.sarif_attempts == 0
    passed_target, passed_result, report = reporting_calls.build_calls[0]
    assert type(passed_target) is TargetUrl
    assert passed_target is scan_run.calls[0].target
    assert passed_target == parse_target_url(target)
    assert passed_result is scan_run.result
    rendered_report, rendered = reporting_calls.json_calls[0]
    assert rendered_report is report
    captured = capsys.readouterr()
    assert captured.out == rendered + "\n"
    assert captured.err == ""
    assert captured.out != "2 findings\n"
    assert "2 findings" not in captured.out
    assert _QUERY_TOKEN not in captured.out
    assert _QUERY_TOKEN not in captured.err
    assert target not in captured.out


def test_sarif_format_prints_renderer_output_from_one_scan_report(
    scan_run: RunRecorder,
    reporting_calls: ReportingRecorder,
    capsys: CaptureFixture[str],
) -> None:
    target = f"https://app.test/search?token={_QUERY_TOKEN}"
    scan_run.result = _scan_result_with_findings(2, target=target)

    main(_scan_argv(target=target, allow_origins=(_TARGET,), report_format="sarif"))

    assert len(scan_run.calls) == 1
    assert reporting_calls.build_attempts == 1
    assert reporting_calls.sarif_attempts == 1
    assert reporting_calls.json_attempts == 0
    passed_target, passed_result, report = reporting_calls.build_calls[0]
    assert type(passed_target) is TargetUrl
    assert passed_target is scan_run.calls[0].target
    assert passed_target == parse_target_url(target)
    assert passed_result is scan_run.result
    rendered_report, rendered = reporting_calls.sarif_calls[0]
    assert rendered_report is report
    captured = capsys.readouterr()
    assert captured.out == rendered + "\n"
    assert captured.err == ""
    assert captured.out != "2 findings\n"
    assert "2 findings" not in captured.out
    assert _QUERY_TOKEN not in captured.out
    assert _QUERY_TOKEN not in captured.err
    assert target not in captured.out


@pytest.mark.parametrize("extra", _ALL_FORMAT_ARGV, ids=_format_ids)
def test_scan_failure_is_not_rewritten_as_zero_findings(
    extra: tuple[str, ...],
    scan_run: RunRecorder,
    reporting_calls: ReportingRecorder,
    capsys: CaptureFixture[str],
) -> None:
    scan_run.error = TransportError(
        TransportErrorCode.RESPONSE_TOO_LARGE,
        "response exceeded limit",
    )

    with pytest.raises(TransportError) as caught:
        main(_scan_argv(extra=extra))

    assert caught.value is scan_run.error
    assert caught.value.code is TransportErrorCode.RESPONSE_TOO_LARGE
    captured = capsys.readouterr()
    assert "findings" not in captured.out
    assert captured.out == ""
    assert reporting_calls.build_attempts == 0
    assert reporting_calls.json_attempts == 0
    assert reporting_calls.sarif_attempts == 0


@pytest.mark.parametrize("extra", _ALL_FORMAT_ARGV, ids=_format_ids)
def test_scan_failure_does_not_retry_or_fallback(
    extra: tuple[str, ...],
    scan_run: RunRecorder,
    reporting_calls: ReportingRecorder,
) -> None:
    scan_run.error = RuntimeError("scan failed")

    with pytest.raises(RuntimeError, match="scan failed"):
        main(_scan_argv(extra=extra))

    assert len(scan_run.calls) == 1
    assert reporting_calls.build_attempts == 0
    assert reporting_calls.json_attempts == 0
    assert reporting_calls.sarif_attempts == 0


@pytest.mark.parametrize("report_format", _REPORT_FORMATS)
def test_build_scan_report_failure_propagates_without_text_fallback(
    report_format: str,
    scan_run: RunRecorder,
    reporting_calls: ReportingRecorder,
    capsys: CaptureFixture[str],
) -> None:
    scan_run.result = _scan_result_with_count(2)
    reporting_calls.build_error = ValueError("projection failed")

    with pytest.raises(ValueError) as caught:
        main(_scan_argv(report_format=report_format))

    assert caught.value is reporting_calls.build_error
    assert len(scan_run.calls) == 1
    assert reporting_calls.build_attempts == 1
    assert reporting_calls.json_attempts == 0
    assert reporting_calls.sarif_attempts == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "findings" not in captured.out
    assert "2 findings" not in captured.err


@pytest.mark.parametrize("report_format", _REPORT_FORMATS)
def test_renderer_failure_propagates_without_text_fallback(
    report_format: str,
    scan_run: RunRecorder,
    reporting_calls: ReportingRecorder,
    capsys: CaptureFixture[str],
) -> None:
    error = RuntimeError("renderer failed")
    if report_format == "json":
        reporting_calls.json_error = error
    else:
        reporting_calls.sarif_error = error

    with pytest.raises(RuntimeError) as caught:
        main(_scan_argv(report_format=report_format))

    assert caught.value is error
    assert len(scan_run.calls) == 1
    assert reporting_calls.build_attempts == 1
    if report_format == "json":
        assert reporting_calls.json_attempts == 1
        assert reporting_calls.sarif_attempts == 0
    else:
        assert reporting_calls.sarif_attempts == 1
        assert reporting_calls.json_attempts == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "findings" not in captured.out
    assert "0 findings" not in captured.err


def test_cli_stays_a_thin_adapter() -> None:
    source = inspect.getsource(cli)
    for marker in _FORBIDDEN_CLI_MARKERS:
        assert marker not in source
