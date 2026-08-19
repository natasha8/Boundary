"""Offline tests for safe report URL projection (Milestone 8, Slice A)."""

from __future__ import annotations

import gc
import inspect
import socket
from dataclasses import MISSING, FrozenInstanceError, fields, is_dataclass
from typing import get_type_hints

import anyio
import pytest

from boundary.reporting import (
    QUERY_REDACTION_MARKER,
    ReportUrl,
    project_report_target,
)
from boundary.scope import TargetUrl, parse_target_url

_SAFE_HTTPS = "https://app.test/reset"
_SAFE_HTTPS_REDACTED = "https://app.test/reset?REDACTED"
_TOKEN_KEY = "token"
_SESSION_KEY = "session"
_API_KEY = "api_key"
_TOKEN_VALUE = "reset-token-7f3a9c21"
_SESSION_VALUE = "session-id-9c21aabb"
_API_KEY_VALUE = "sk_live_51NotARealKey"
_SECRET_VALUE = "supersecret-query-value"
_ADR_QUERY = "token=secret&session=abc"
_UNICODE_QUERY = "q=%E2%9C%93&note=%D1%81%D0%B5%D0%BA%D1%80%D0%B5%D1%82"
_UNICODE_MARKERS = ("%E2%9C%93", "%D1%81%D0%B5%D0%BA%D1%80%D0%B5%D1%82")
_FORBIDDEN_REPORT_URL_FIELDS = (
    "target",
    "query",
    "scheme",
    "host",
    "port",
    "path",
    "fragment",
    "source",
    "original",
    "raw",
)
_REJECTED_QUERY_URLS = (
    "https://app.test/reset?token=secret",
    "https://app.test/reset?REDACTED&x=1",
    "https://app.test/reset?REDACTED=",
    "https://app.test/reset?redacted",
    "https://app.test/reset?REDACTED ",
    "https://app.test/reset??REDACTED",
    "https://app.test/reset?",
    "https://app.test/reset?token=REDACTED",
    "https://app.test/reset?REDACTED%20",
    "https://app.test/reset?%52EDACTED",
)
_FRAGMENT_URLS = (
    "https://app.test/reset#section",
    "https://app.test/reset?REDACTED#section",
    "https://app.test/#token=secret",
    "#only",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("report URL projection must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if reporting reaches network or scan entry points."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)
    monkeypatch.setattr("boundary.discovery.crawl", _reject_network)
    monkeypatch.setattr("boundary.transport.request_once", _reject_network)
    monkeypatch.setattr("boundary.transport.request_with_redirects", _reject_network)
    monkeypatch.setattr(
        "boundary.resolver.SystemAddressResolver.resolve",
        _reject_network,
    )


def _snapshot(target: TargetUrl) -> tuple[str, str, int, str, str, str]:
    return (
        target.scheme,
        target.host,
        target.port,
        target.path,
        target.query,
        target.url,
    )


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


def _assert_query_contract(report: ReportUrl) -> None:
    assert "#" not in report.url
    if "?" in report.url:
        assert report.url.split("?", 1)[1] == QUERY_REDACTION_MARKER
    else:
        assert QUERY_REDACTION_MARKER not in report.url


def _assert_secrets_absent(report: ReportUrl, markers: tuple[str, ...]) -> None:
    rendered = (report.url, repr(report), str(report))
    for marker in markers:
        for text in rendered:
            assert marker not in text


def test_query_redaction_marker_is_the_locked_ascii_literal() -> None:
    assert QUERY_REDACTION_MARKER == "REDACTED"
    assert len(QUERY_REDACTION_MARKER) == 8
    assert QUERY_REDACTION_MARKER.isascii()
    assert QUERY_REDACTION_MARKER.isalpha()
    assert QUERY_REDACTION_MARKER.isupper()
    assert QUERY_REDACTION_MARKER != "[redacted]"
    assert QUERY_REDACTION_MARKER != "***"
    assert "=" not in QUERY_REDACTION_MARKER
    assert "%" not in QUERY_REDACTION_MARKER


def test_report_url_fields_match_the_approved_model() -> None:
    names = tuple(field.name for field in fields(ReportUrl))

    assert is_dataclass(ReportUrl)
    assert names == ("url",)
    for forbidden in _FORBIDDEN_REPORT_URL_FIELDS:
        assert forbidden not in names


def test_report_url_constructor_accepts_url_positionally_and_as_keyword() -> None:
    parameters = list(inspect.signature(ReportUrl).parameters)
    url_parameter = inspect.signature(ReportUrl).parameters["url"]

    assert parameters == ["url"]
    assert url_parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert url_parameter.default is inspect.Parameter.empty
    assert ReportUrl(_SAFE_HTTPS) == ReportUrl(url=_SAFE_HTTPS)
    assert ReportUrl(_SAFE_HTTPS).url == _SAFE_HTTPS


def test_report_url_has_no_hidden_field_defaults() -> None:
    url_field = fields(ReportUrl)[0]

    assert url_field.default is MISSING
    assert url_field.default_factory is MISSING


def test_report_url_type_hints_match_the_approved_contract() -> None:
    hints = get_type_hints(ReportUrl)

    assert hints == {"url": str}


def test_report_url_is_frozen_and_slotted() -> None:
    report = ReportUrl(url=_SAFE_HTTPS)
    dataclass_params = ReportUrl.__dataclass_params__  # type: ignore[attr-defined]

    with pytest.raises(FrozenInstanceError):
        report.url = "https://app.test/other"  # type: ignore[misc]

    assert dataclass_params.frozen is True
    assert dataclass_params.slots is True
    assert set(ReportUrl.__slots__) == {"url"}
    assert not hasattr(report, "__dict__")


def test_report_url_is_not_a_str_subclass_and_has_no_custom_string_behavior() -> None:
    report = ReportUrl(url=_SAFE_HTTPS_REDACTED)

    assert not issubclass(ReportUrl, str)
    assert not isinstance(report, str)
    assert "__str__" not in ReportUrl.__dict__
    assert "__format__" not in ReportUrl.__dict__
    assert str(report) != report.url
    assert repr(report) != report.url
    assert format(report) != report.url
    assert not str(report).startswith("https://")
    assert not repr(report).startswith("https://")


def test_report_url_does_not_store_a_target_url() -> None:
    report = ReportUrl(url=_SAFE_HTTPS)
    hints = get_type_hints(ReportUrl)

    assert "target" not in {field.name for field in fields(ReportUrl)}
    assert TargetUrl not in hints.values()
    assert not any(isinstance(value, TargetUrl) for value in gc.get_referents(report))


def test_empty_report_url_raises_value_error() -> None:
    with pytest.raises(ValueError) as caught:
        ReportUrl(url="")

    assert "token=" not in str(caught.value)


@pytest.mark.parametrize("url", _FRAGMENT_URLS)
def test_report_url_rejects_fragments(url: str) -> None:
    with pytest.raises(ValueError) as caught:
        ReportUrl(url=url)

    message = str(caught.value)
    assert url not in message
    assert "token=secret" not in message
    assert "#section" not in message


@pytest.mark.parametrize("url", _REJECTED_QUERY_URLS)
def test_report_url_rejects_non_marker_query_content(url: str) -> None:
    with pytest.raises(ValueError) as caught:
        ReportUrl(url=url)

    message = str(caught.value)
    remainder = url.split("?", 1)[1]
    assert "token=secret" not in message
    assert "token=REDACTED" not in message
    if remainder:
        assert remainder not in message


def test_report_url_accepts_exact_redaction_marker_query() -> None:
    report = ReportUrl(url=_SAFE_HTTPS_REDACTED)

    assert report.url == _SAFE_HTTPS_REDACTED
    assert report.url.split("?", 1)[1] == QUERY_REDACTION_MARKER


def test_report_url_accepts_urls_without_query() -> None:
    report = ReportUrl(url=_SAFE_HTTPS)

    assert report.url == _SAFE_HTTPS
    assert "?" not in report.url


def test_project_report_target_signature_matches_the_approved_contract() -> None:
    signature = inspect.signature(project_report_target)
    parameter = signature.parameters["target"]
    hints = get_type_hints(project_report_target)

    assert tuple(signature.parameters) == ("target",)
    assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameter.default is inspect.Parameter.empty
    assert hints["target"] is TargetUrl
    assert hints["return"] is ReportUrl


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param(
            "http://example.com/api",
            "http://example.com/api",
            id="http_default_port",
        ),
        pytest.param(
            "http://example.com:80/api",
            "http://example.com/api",
            id="http_explicit_default_port",
        ),
        pytest.param(
            "https://example.com/path",
            "https://example.com/path",
            id="https_default_port",
        ),
        pytest.param(
            "https://example.com:443/path",
            "https://example.com/path",
            id="https_explicit_default_port",
        ),
        pytest.param(
            "http://127.0.0.1:3000/health",
            "http://127.0.0.1:3000/health",
            id="non_default_port",
        ),
        pytest.param(
            "https://app.test/reset",
            "https://app.test/reset",
            id="hostname",
        ),
        pytest.param(
            "https://localhost/admin",
            "https://localhost/admin",
            id="localhost",
        ),
        pytest.param(
            "http://192.0.2.10/status",
            "http://192.0.2.10/status",
            id="ipv4",
        ),
        pytest.param(
            "http://[::1]:8080/health?q=1",
            "http://[::1]:8080/health?REDACTED",
            id="ipv6",
        ),
        pytest.param(
            "http://[::1]/health",
            "http://[::1]/health",
            id="ipv6_default_port",
        ),
        pytest.param(
            "https://app.test/",
            "https://app.test/",
            id="root_path",
        ),
        pytest.param(
            "https://app.test/a/b/c",
            "https://app.test/a/b/c",
            id="nested_path",
        ),
        pytest.param(
            "https://app.test/reset",
            "https://app.test/reset",
            id="no_query",
        ),
        pytest.param(
            "https://app.test/reset?x=1",
            "https://app.test/reset?REDACTED",
            id="simple_query",
        ),
        pytest.param(
            "https://app.test/reset?token=secret&session=abc",
            "https://app.test/reset?REDACTED",
            id="multiple_query_parameters",
        ),
        pytest.param(
            "https://app.test/reset?token=&session=",
            "https://app.test/reset?REDACTED",
            id="empty_values",
        ),
        pytest.param(
            "https://app.test/reset?x=%2e%2e",
            "https://app.test/reset?REDACTED",
            id="percent_encoded_query",
        ),
        pytest.param(
            f"https://app.test/reset?token={_TOKEN_VALUE}",
            "https://app.test/reset?REDACTED",
            id="token_shaped_query",
        ),
        pytest.param(
            f"https://app.test/reset?api_key={_API_KEY_VALUE}",
            "https://app.test/reset?REDACTED",
            id="api_key_shaped_query",
        ),
        pytest.param(
            f"https://app.test/reset?session={_SESSION_VALUE}",
            "https://app.test/reset?REDACTED",
            id="session_shaped_query",
        ),
        pytest.param(
            f"https://app.test/search?{_UNICODE_QUERY}",
            "https://app.test/search?REDACTED",
            id="unicode_percent_encoded_query",
        ),
        pytest.param(
            "https://app.test/reset?REDACTED",
            "https://app.test/reset?REDACTED",
            id="query_content_equal_to_redacted_marker",
        ),
    ],
)
def test_project_report_target_covers_the_url_projection_matrix(
    raw: str,
    expected: str,
) -> None:
    target = parse_target_url(raw)
    before = _snapshot(target)

    report = project_report_target(target)

    assert isinstance(report, ReportUrl)
    assert report.url == expected
    _assert_query_contract(report)
    assert _snapshot(target) == before
    assert target.url == parse_target_url(raw).url


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param(
            "https://app.test/reset?token=secret&session=abc",
            "https://app.test/reset?REDACTED",
            id="adr_token_session_query",
        ),
        pytest.param(
            "https://app.test/reset",
            "https://app.test/reset",
            id="adr_empty_query",
        ),
        pytest.param(
            "https://EXAMPLE.com:443/path?x=1",
            "https://example.com/path?REDACTED",
            id="adr_normalized_host_default_https_port",
        ),
        pytest.param(
            "http://127.0.0.1:3000/health",
            "http://127.0.0.1:3000/health",
            id="adr_ipv4_non_default_port",
        ),
        pytest.param(
            "http://[::1]:8080/health?q=1",
            "http://[::1]:8080/health?REDACTED",
            id="adr_ipv6_non_default_port",
        ),
        pytest.param(
            "https://app.test/a%2fb/../etc?x=%2e%2e",
            "https://app.test/a%2fb/../etc?REDACTED",
            id="adr_encoded_path_preserved",
        ),
    ],
)
def test_project_report_target_matches_locked_adr_examples(
    raw: str,
    expected: str,
) -> None:
    report = project_report_target(parse_target_url(raw))

    assert report.url == expected


def test_empty_source_query_omits_the_question_mark() -> None:
    report = project_report_target(parse_target_url("https://app.test/reset"))

    assert report.url == "https://app.test/reset"
    assert "?" not in report.url
    assert QUERY_REDACTION_MARKER not in report.url


def test_any_non_empty_source_query_becomes_exactly_the_marker() -> None:
    report = project_report_target(parse_target_url("https://app.test/reset?x=1"))

    assert report.url == _SAFE_HTTPS_REDACTED
    assert report.url.endswith(f"?{QUERY_REDACTION_MARKER}")
    assert report.url.count("?") == 1
    assert report.url.split("?", 1)[1] == QUERY_REDACTION_MARKER


def test_redacted_query_content_is_presence_not_trusted_input() -> None:
    parsed = parse_target_url("https://app.test/reset?REDACTED")
    other_query = parse_target_url("https://app.test/reset?token=secret&session=abc")
    poisoned = _component_target(
        scheme="https",
        host="app.test",
        port=443,
        path="/reset",
        query="REDACTED",
        url="https://leaked.test/reset?REDACTED&token=still-secret",
    )

    parsed_report = project_report_target(parsed)
    other_report = project_report_target(other_query)
    poisoned_report = project_report_target(poisoned)

    assert parsed.query == QUERY_REDACTION_MARKER
    assert parsed_report.url == _SAFE_HTTPS_REDACTED
    assert parsed_report == other_report
    assert poisoned_report.url == _SAFE_HTTPS_REDACTED
    assert poisoned_report.url != poisoned.url
    _assert_secrets_absent(
        poisoned_report,
        ("leaked.test", "still-secret", _TOKEN_KEY, "token=still-secret"),
    )


def test_all_query_parameters_are_replaced_not_heuristically_filtered() -> None:
    target = parse_target_url(
        "https://app.test/reset?public=1&q=ok&id=2&token=secret&session=abc"
    )
    report = project_report_target(target)

    assert report.url == _SAFE_HTTPS_REDACTED
    _assert_secrets_absent(
        report,
        (
            "public",
            "q=ok",
            "id=2",
            _TOKEN_KEY,
            _SESSION_KEY,
            "secret",
            "abc",
            "public=1",
        ),
    )


def test_sensitive_query_material_is_absent_from_url_repr_and_str() -> None:
    target = parse_target_url(
        "https://app.test/reset?"
        f"{_TOKEN_KEY}={_TOKEN_VALUE}&"
        f"{_SESSION_KEY}={_SESSION_VALUE}&"
        f"{_API_KEY}={_API_KEY_VALUE}&"
        f"password={_SECRET_VALUE}&"
        f"{_ADR_QUERY}&"
        f"{_UNICODE_QUERY}&"
        "x=%2e%2e&"
        "access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
    )
    report = project_report_target(target)

    assert report.url == _SAFE_HTTPS_REDACTED
    _assert_secrets_absent(
        report,
        (
            target.query,
            target.url,
            _ADR_QUERY,
            _TOKEN_KEY,
            _SESSION_KEY,
            _API_KEY,
            _TOKEN_VALUE,
            _SESSION_VALUE,
            _API_KEY_VALUE,
            _SECRET_VALUE,
            "password",
            "secret",
            "abc",
            "access_token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "x=%2e%2e",
            "%2e%2e",
            *_UNICODE_MARKERS,
        ),
    )
    _assert_query_contract(report)


def test_project_report_target_does_not_read_target_url() -> None:
    mismatched_url = _component_target(
        scheme="https",
        host="app.test",
        port=443,
        path="/reset",
        query="token=secret&session=abc",
        url="https://MUST-NOT-READ.example/reset?token=secret&session=abc&api_key=leaked",
    )
    query_without_marker_in_url = _component_target(
        scheme="https",
        host="app.test",
        port=443,
        path="/reset",
        query="token=secret",
        url="https://app.test/reset",
    )
    empty_query_with_query_in_url = _component_target(
        scheme="https",
        host="app.test",
        port=443,
        path="/reset",
        query="",
        url="https://app.test/reset?token=secret",
    )
    default_port_with_port_in_url = _component_target(
        scheme="http",
        host="example.com",
        port=80,
        path="/api",
        query="",
        url="http://example.com:80/api",
    )
    non_default_port_omitted_in_url = _component_target(
        scheme="http",
        host="example.com",
        port=8080,
        path="/api",
        query="",
        url="http://example.com/api",
    )
    ipv6_unbracketed_in_url = _component_target(
        scheme="http",
        host="::1",
        port=8080,
        path="/health",
        query="q=1",
        url="http://::1:8080/health?q=1",
    )

    assert project_report_target(mismatched_url).url == _SAFE_HTTPS_REDACTED
    assert (
        project_report_target(query_without_marker_in_url).url == _SAFE_HTTPS_REDACTED
    )
    assert project_report_target(empty_query_with_query_in_url).url == _SAFE_HTTPS
    assert project_report_target(default_port_with_port_in_url).url == (
        "http://example.com/api"
    )
    assert project_report_target(non_default_port_omitted_in_url).url == (
        "http://example.com:8080/api"
    )
    assert project_report_target(ipv6_unbracketed_in_url).url == (
        "http://[::1]:8080/health?REDACTED"
    )
    _assert_secrets_absent(
        project_report_target(mismatched_url),
        ("MUST-NOT-READ.example", "api_key", "leaked", "token", "secret", "session"),
    )
    _assert_secrets_absent(
        project_report_target(empty_query_with_query_in_url),
        ("token", "secret", "?"),
    )


def test_project_report_target_does_not_retain_the_source_target() -> None:
    target = parse_target_url("https://app.test/reset?token=secret")
    report = project_report_target(target)

    assert not isinstance(report, TargetUrl)
    assert "target" not in {field.name for field in fields(type(report))}
    assert all(getattr(report, name) is not target for name in type(report).__slots__)
    assert target not in gc.get_referents(report)
    assert not any(isinstance(value, TargetUrl) for value in gc.get_referents(report))
    assert not any(value is target.url for value in gc.get_referents(report))


def test_project_report_target_does_not_mutate_the_source_target() -> None:
    target = parse_target_url("https://app.test/reset?token=secret&session=abc")
    before = _snapshot(target)
    identity = id(target)

    report = project_report_target(target)

    assert id(target) == identity
    assert _snapshot(target) == before
    assert target.query == "token=secret&session=abc"
    assert target.url == "https://app.test/reset?token=secret&session=abc"
    assert report.url == _SAFE_HTTPS_REDACTED


def test_two_targets_that_differ_only_in_query_share_one_report_url() -> None:
    left = project_report_target(
        parse_target_url("https://app.test/reset?token=secret")
    )
    right = project_report_target(
        parse_target_url("https://app.test/reset?session=abc")
    )
    unmarked = project_report_target(parse_target_url("https://app.test/reset"))

    assert left.url == right.url == _SAFE_HTTPS_REDACTED
    assert left == right
    assert hash(left) == hash(right)
    assert unmarked.url == _SAFE_HTTPS
    assert left != unmarked


def test_project_report_target_is_deterministic_and_side_effect_free() -> None:
    target = parse_target_url("http://[::1]:8080/health?q=1")
    before = _snapshot(target)

    first = project_report_target(target)
    second = project_report_target(target)

    assert first == second
    assert first.url == second.url == "http://[::1]:8080/health?REDACTED"
    assert _snapshot(target) == before


def test_project_report_target_preserves_paths_without_redacting_them() -> None:
    encoded = project_report_target(
        parse_target_url("https://app.test/a%2fb/../etc?x=%2e%2e")
    )
    nested = project_report_target(parse_target_url("https://app.test/reset/SECRET"))

    assert encoded.url == "https://app.test/a%2fb/../etc?REDACTED"
    assert nested.url == "https://app.test/reset/SECRET"
    assert "/reset/SECRET" in nested.url
    assert "?" not in nested.url


@pytest.mark.parametrize(
    "scheme",
    ["ftp", "ws", "file", "HTTP", "HTTPS", ""],
)
def test_project_report_target_rejects_unsupported_scheme(scheme: str) -> None:
    target = _component_target(
        scheme=scheme,
        host="app.test",
        port=21,
        path="/reset",
        query="token=secret",
        url=f"{scheme}://app.test/reset?token=secret",
    )

    with pytest.raises(ValueError, match="unsupported URL scheme") as caught:
        project_report_target(target)

    message = str(caught.value)
    assert "token=secret" not in message
    assert "secret" not in message
    assert target.url not in message
    assert target.query not in message


@pytest.mark.parametrize(
    ("host", "path"),
    [
        ("", "/reset"),
        ("app.test", ""),
        ("", ""),
    ],
    ids=("empty_host", "empty_path", "empty_host_and_path"),
)
def test_project_report_target_rejects_empty_host_or_path(host: str, path: str) -> None:
    target = _component_target(
        scheme="https",
        host=host,
        port=443,
        path=path,
        query="token=secret",
        url="https://app.test/reset?token=secret",
    )

    with pytest.raises(ValueError, match="host and path are required") as caught:
        project_report_target(target)

    message = str(caught.value)
    assert "token=secret" not in message
    assert target.query not in message
    assert target.url not in message


def test_projection_does_not_emit_fragments() -> None:
    target = parse_target_url("http://example.com/api?limit=10#section")
    report = project_report_target(target)

    assert target.query == "limit=10"
    assert "#" not in target.url
    assert report.url == "http://example.com/api?REDACTED"
    assert "#" not in report.url
    assert "section" not in report.url
    assert "limit" not in report.url
