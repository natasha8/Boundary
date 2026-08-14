"""Offline tests for deterministic passive header hardening rules (Slice B)."""

from __future__ import annotations

import socket
from collections.abc import Collection

import anyio
import pytest

from boundary.discovery import DiscoveredPage, is_html_response
from boundary.passive import (
    PassiveFinding,
    PassiveFindingKind,
    _check_enforced_csp,
    _check_frame_protection,
    _check_hsts,
    _check_nosniff,
)
from boundary.scope import parse_target_url
from boundary.transport import TransportResponse

_HSTS_ID = "passive.hsts.not_enforced.v1"
_NOSNIFF_ID = "passive.nosniff.missing_or_invalid.v1"
_CSP_ID = "passive.csp.missing_enforced_policy.v1"
_FRAME_ID = "passive.framing.missing_protection.v1"

_BEARER = "Bearer secret-token-abc"
_COOKIE = "session=secret-cookie-value"
_BODY_SECRET = b"password=supersecret"


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if header rules perform DNS or real TCP I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)


def _page(
    *,
    url: str = "https://app.test/",
    requested: str | None = None,
    status: int = 200,
    headers: Collection[tuple[bytes, bytes]] = (),
    body: bytes = b"<html></html>",
    depth: int = 0,
) -> DiscoveredPage:
    final_target = parse_target_url(url)
    requested_target = (
        parse_target_url(requested) if requested is not None else final_target
    )
    return DiscoveredPage(
        target=requested_target,
        depth=depth,
        response=TransportResponse(
            status=status,
            headers=tuple(headers),
            body=body,
            final_target=final_target,
        ),
    )


def _html(*headers: tuple[bytes, bytes]) -> tuple[tuple[bytes, bytes], ...]:
    return ((b"content-type", b"text/html"), *headers)


def _json(*headers: tuple[bytes, bytes]) -> tuple[tuple[bytes, bytes], ...]:
    return ((b"content-type", b"application/json"), *headers)


def _evidence(
    *,
    state: str,
    status: int = 200,
    header: str | None = None,
    count: str | None = None,
) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = [("state", state), ("status", str(status))]
    if header is not None:
        pairs.append(("header", header))
    if count is not None:
        pairs.append(("count", count))
    return tuple(sorted(pairs))


def _assert_hardening(
    findings: tuple[PassiveFinding, ...],
    *,
    page: DiscoveredPage,
    rule_id: str,
    evidence: tuple[tuple[str, str], ...],
) -> PassiveFinding:
    assert isinstance(findings, tuple)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == rule_id
    assert finding.kind is PassiveFindingKind.HARDENING
    assert finding.target is page.response.final_target
    assert finding.requested_target is page.target
    assert isinstance(finding.observation, str)
    assert finding.observation
    assert isinstance(finding.rationale, str)
    assert finding.rationale
    assert finding.evidence == evidence
    return finding


def test_https_missing_hsts_produces_a_hardening_finding() -> None:
    page = _page(headers=_html())

    finding = _assert_hardening(
        _check_hsts(page),
        page=page,
        rule_id=_HSTS_ID,
        evidence=_evidence(
            header="strict-transport-security",
            state="missing",
            count="0",
        ),
    )
    assert "exploit" not in finding.observation.lower()
    assert "downgrade" not in finding.observation.lower()


def test_https_valid_hsts_max_age_produces_no_finding() -> None:
    page = _page(headers=_html((b"strict-transport-security", b"max-age=31536000")))

    assert _check_hsts(page) == ()


def test_http_missing_hsts_does_not_apply() -> None:
    page = _page(url="http://app.test/", headers=_html())

    assert _check_hsts(page) == ()


def test_http_valid_hsts_does_not_apply() -> None:
    page = _page(
        url="http://app.test/",
        headers=_html((b"strict-transport-security", b"max-age=31536000")),
    )

    assert _check_hsts(page) == ()


def test_hsts_header_name_matching_is_case_insensitive() -> None:
    page = _page(
        headers=_html((b"Strict-Transport-Security", b"max-age=31536000")),
    )

    assert _check_hsts(page) == ()


def test_hsts_accepts_directive_casing_and_optional_whitespace() -> None:
    page = _page(
        headers=_html((b"strict-transport-security", b"  MAX-AGE = 31536000  ")),
    )

    assert _check_hsts(page) == ()


def test_hsts_unknown_directives_do_not_invalidate_positive_max_age() -> None:
    page = _page(
        headers=_html(
            (
                b"strict-transport-security",
                b"includeSubDomains; max-age=31536000; preload; foo=bar",
            ),
        ),
    )

    assert _check_hsts(page) == ()


def test_duplicate_hsts_headers_are_ambiguous() -> None:
    page = _page(
        headers=_html(
            (b"strict-transport-security", b"max-age=31536000"),
            (b"Strict-Transport-Security", b"max-age=60"),
        ),
    )

    _assert_hardening(
        _check_hsts(page),
        page=page,
        rule_id=_HSTS_ID,
        evidence=_evidence(
            header="strict-transport-security",
            state="ambiguous",
            count="2",
        ),
    )


def test_duplicate_hsts_max_age_directives_are_ambiguous() -> None:
    page = _page(
        headers=_html(
            (b"strict-transport-security", b"max-age=31536000; max-age=60"),
        ),
    )

    _assert_hardening(
        _check_hsts(page),
        page=page,
        rule_id=_HSTS_ID,
        evidence=_evidence(
            header="strict-transport-security",
            state="ambiguous",
            count="1",
        ),
    )


@pytest.mark.parametrize(
    "value",
    [
        b"includeSubDomains; preload",
        b"max-age",
        b"max-age=",
        b'max-age="31536000"',
        b"max-age=abc",
        b"max-age=-1",
        b"max-age=31536000.0",
        b"max-age=+31536000",
    ],
)
def test_invalid_hsts_max_age_produces_a_finding(value: bytes) -> None:
    page = _page(headers=_html((b"strict-transport-security", value)))

    _assert_hardening(
        _check_hsts(page),
        page=page,
        rule_id=_HSTS_ID,
        evidence=_evidence(
            header="strict-transport-security",
            state="invalid",
            count="1",
        ),
    )


def test_hsts_max_age_zero_is_disabled() -> None:
    page = _page(headers=_html((b"strict-transport-security", b"max-age=0")))

    _assert_hardening(
        _check_hsts(page),
        page=page,
        rule_id=_HSTS_ID,
        evidence=_evidence(
            header="strict-transport-security",
            state="disabled",
            count="1",
        ),
    )


def test_non_ascii_hsts_value_is_invalid_and_not_copied_into_evidence() -> None:
    raw = b"max-age=\xff"
    page = _page(headers=_html((b"strict-transport-security", raw)))

    finding = _assert_hardening(
        _check_hsts(page),
        page=page,
        rule_id=_HSTS_ID,
        evidence=_evidence(
            header="strict-transport-security",
            state="invalid",
            count="1",
        ),
    )
    serialized = "".join(value for _key, value in finding.evidence)
    assert "\xff" not in serialized
    assert raw.decode("latin1") not in finding.observation


def test_hsts_uses_final_target_scheme_not_requested_target_scheme() -> None:
    https_final = _page(
        url="https://app.test/final",
        requested="http://app.test/start",
        headers=_html(),
    )
    http_final = _page(
        url="http://app.test/final",
        requested="https://app.test/start",
        headers=_html(),
    )

    assert _check_hsts(https_final)[0].rule_id == _HSTS_ID
    assert _check_hsts(http_final) == ()


def test_html_nosniff_produces_no_finding() -> None:
    page = _page(headers=_html((b"x-content-type-options", b"nosniff")))

    assert is_html_response(page.response.headers)
    assert _check_nosniff(page) == ()


def test_html_missing_nosniff_produces_a_hardening_finding() -> None:
    page = _page(headers=_html())

    _assert_hardening(
        _check_nosniff(page),
        page=page,
        rule_id=_NOSNIFF_ID,
        evidence=_evidence(
            header="x-content-type-options",
            state="missing",
            count="0",
        ),
    )


def test_html_wrong_nosniff_value_produces_a_finding() -> None:
    page = _page(headers=_html((b"x-content-type-options", b"sniff")))

    _assert_hardening(
        _check_nosniff(page),
        page=page,
        rule_id=_NOSNIFF_ID,
        evidence=_evidence(
            header="x-content-type-options",
            state="invalid",
            count="1",
        ),
    )


def test_nosniff_accepts_header_and_value_casing_and_ows() -> None:
    page = _page(headers=_html((b"X-Content-Type-Options", b"  NoSniff  ")))

    assert _check_nosniff(page) == ()


def test_duplicate_nosniff_headers_are_ambiguous() -> None:
    page = _page(
        headers=_html(
            (b"x-content-type-options", b"nosniff"),
            (b"X-Content-Type-Options", b"nosniff"),
        ),
    )

    _assert_hardening(
        _check_nosniff(page),
        page=page,
        rule_id=_NOSNIFF_ID,
        evidence=_evidence(
            header="x-content-type-options",
            state="ambiguous",
            count="2",
        ),
    )


def test_non_ascii_nosniff_value_is_invalid_and_not_copied_into_evidence() -> None:
    page = _page(headers=_html((b"x-content-type-options", b"nosniff\xff")))

    finding = _assert_hardening(
        _check_nosniff(page),
        page=page,
        rule_id=_NOSNIFF_ID,
        evidence=_evidence(
            header="x-content-type-options",
            state="invalid",
            count="1",
        ),
    )
    assert all(value.isascii() for _key, value in finding.evidence)


def test_http_html_missing_nosniff_still_applies() -> None:
    page = _page(url="http://app.test/", headers=_html())

    assert _check_nosniff(page)[0].rule_id == _NOSNIFF_ID


def test_non_html_missing_nosniff_does_not_apply() -> None:
    page = _page(headers=_json())

    assert not is_html_response(page.response.headers)
    assert _check_nosniff(page) == ()


def test_ambiguous_content_type_is_not_html_for_nosniff() -> None:
    page = _page(
        headers=(
            (b"content-type", b"text/html"),
            (b"content-type", b"text/html"),
        ),
    )

    assert not is_html_response(page.response.headers)
    assert _check_nosniff(page) == ()


def test_html_missing_csp_produces_a_hardening_finding() -> None:
    page = _page(headers=_html())

    _assert_hardening(
        _check_enforced_csp(page),
        page=page,
        rule_id=_CSP_ID,
        evidence=_evidence(
            header="content-security-policy",
            state="missing",
            count="0",
        ),
    )


def test_html_enforced_csp_produces_no_finding() -> None:
    page = _page(
        headers=_html((b"content-security-policy", b"default-src 'self'")),
    )

    assert _check_enforced_csp(page) == ()


def test_html_report_only_csp_does_not_satisfy_enforced_csp() -> None:
    page = _page(
        headers=_html(
            (b"content-security-policy-report-only", b"default-src 'none'"),
        ),
    )

    finding = _assert_hardening(
        _check_enforced_csp(page),
        page=page,
        rule_id=_CSP_ID,
        evidence=_evidence(
            header="content-security-policy",
            state="report_only",
            count="0",
        ),
    )
    assert "default-src" not in "".join(value for _key, value in finding.evidence)
    assert "xss" not in finding.observation.lower()


def test_enforced_csp_and_report_only_together_satisfy_the_rule() -> None:
    page = _page(
        headers=_html(
            (b"content-security-policy", b"default-src 'self'"),
            (b"content-security-policy-report-only", b"default-src 'none'"),
        ),
    )

    assert _check_enforced_csp(page) == ()


def test_multiple_enforced_csp_fields_are_accepted() -> None:
    page = _page(
        headers=_html(
            (b"content-security-policy", b"default-src 'self'"),
            (b"Content-Security-Policy", b"frame-ancestors 'none'"),
        ),
    )

    assert _check_enforced_csp(page) == ()


def test_empty_enforced_csp_does_not_satisfy_the_rule() -> None:
    page = _page(headers=_html((b"content-security-policy", b"   ")))

    _assert_hardening(
        _check_enforced_csp(page),
        page=page,
        rule_id=_CSP_ID,
        evidence=_evidence(
            header="content-security-policy",
            state="invalid",
            count="1",
        ),
    )


def test_non_ascii_enforced_csp_is_invalid_and_not_copied_into_evidence() -> None:
    page = _page(headers=_html((b"content-security-policy", b"default-src '\xff'")))

    finding = _assert_hardening(
        _check_enforced_csp(page),
        page=page,
        rule_id=_CSP_ID,
        evidence=_evidence(
            header="content-security-policy",
            state="invalid",
            count="1",
        ),
    )
    assert all(value.isascii() for _key, value in finding.evidence)


def test_non_html_missing_csp_does_not_apply() -> None:
    page = _page(headers=_json())

    assert _check_enforced_csp(page) == ()


def test_csp_header_name_matching_is_case_insensitive() -> None:
    page = _page(
        headers=_html((b"Content-Security-Policy", b"default-src 'self'")),
    )

    assert _check_enforced_csp(page) == ()


def test_html_missing_frame_protection_produces_a_hardening_finding() -> None:
    page = _page(headers=_html())

    _assert_hardening(
        _check_frame_protection(page),
        page=page,
        rule_id=_FRAME_ID,
        evidence=_evidence(state="missing"),
    )


@pytest.mark.parametrize("value", [b"DENY", b"SAMEORIGIN", b" deny ", b"SameOrigin"])
def test_recognized_x_frame_options_suppresses_the_finding(value: bytes) -> None:
    page = _page(headers=_html((b"x-frame-options", value)))

    assert _check_frame_protection(page) == ()


def test_x_frame_options_header_name_matching_is_case_insensitive() -> None:
    page = _page(headers=_html((b"X-Frame-Options", b"DENY")))

    assert _check_frame_protection(page) == ()


def test_duplicate_x_frame_options_does_not_satisfy_protection() -> None:
    page = _page(
        headers=_html(
            (b"x-frame-options", b"DENY"),
            (b"x-frame-options", b"DENY"),
        ),
    )

    _assert_hardening(
        _check_frame_protection(page),
        page=page,
        rule_id=_FRAME_ID,
        evidence=_evidence(state="missing"),
    )


def test_allow_from_x_frame_options_does_not_satisfy_protection() -> None:
    page = _page(
        headers=_html((b"x-frame-options", b"ALLOW-FROM https://app.test/")),
    )

    assert _check_frame_protection(page)[0].rule_id == _FRAME_ID


def test_malformed_x_frame_options_does_not_satisfy_protection() -> None:
    page = _page(headers=_html((b"x-frame-options", b"\xff")))

    finding = _check_frame_protection(page)[0]
    assert finding.rule_id == _FRAME_ID
    assert all(value.isascii() for _key, value in finding.evidence)


def test_enforced_csp_frame_ancestors_suppresses_the_finding() -> None:
    page = _page(
        headers=_html(
            (b"content-security-policy", b"default-src 'self'; frame-ancestors 'none'"),
        ),
    )

    assert _check_frame_protection(page) == ()


def test_frame_ancestors_directive_name_is_case_insensitive() -> None:
    page = _page(
        headers=_html((b"content-security-policy", b"FRAME-ANCESTORS 'self'")),
    )

    assert _check_frame_protection(page) == ()


def test_empty_frame_ancestors_directive_does_not_satisfy_protection() -> None:
    page = _page(headers=_html((b"content-security-policy", b"frame-ancestors")))

    assert _check_frame_protection(page)[0].rule_id == _FRAME_ID


def test_report_only_frame_ancestors_does_not_satisfy_protection() -> None:
    page = _page(
        headers=_html(
            (
                b"content-security-policy-report-only",
                b"frame-ancestors 'none'",
            ),
        ),
    )

    assert _check_frame_protection(page)[0].rule_id == _FRAME_ID


def test_unrelated_csp_directives_do_not_satisfy_frame_protection() -> None:
    page = _page(
        headers=_html((b"content-security-policy", b"default-src 'none'")),
    )

    assert _check_enforced_csp(page) == ()
    assert _check_frame_protection(page)[0].rule_id == _FRAME_ID


def test_duplicate_xfo_is_ignored_when_enforced_frame_ancestors_is_present() -> None:
    page = _page(
        headers=_html(
            (b"x-frame-options", b"DENY"),
            (b"x-frame-options", b"SAMEORIGIN"),
            (b"content-security-policy", b"frame-ancestors 'none'"),
        ),
    )

    assert _check_frame_protection(page) == ()


def test_deny_xfo_satisfies_protection_even_if_csp_is_only_report_only() -> None:
    page = _page(
        headers=_html(
            (b"x-frame-options", b"DENY"),
            (b"content-security-policy-report-only", b"frame-ancestors 'none'"),
        ),
    )

    assert _check_frame_protection(page) == ()


def test_non_html_missing_frame_protection_does_not_apply() -> None:
    page = _page(headers=_json())

    assert _check_frame_protection(page) == ()


def test_findings_use_final_target_and_retain_requested_target() -> None:
    page = _page(
        url="https://app.test/final",
        requested="https://app.test/start",
        headers=_html(),
    )

    for findings in (
        _check_hsts(page),
        _check_nosniff(page),
        _check_enforced_csp(page),
        _check_frame_protection(page),
    ):
        finding = findings[0]
        assert finding.target is page.response.final_target
        assert finding.target.url == "https://app.test/final"
        assert finding.requested_target is page.target
        assert finding.requested_target.url == "https://app.test/start"


def test_header_rules_do_not_copy_unsafe_raw_values_into_findings() -> None:
    headers = _html(
        (b"authorization", _BEARER.encode("ascii")),
        (b"set-cookie", _COOKIE.encode("ascii")),
        (b"www-authenticate", _BEARER.encode("ascii")),
    )
    page = _page(headers=headers, body=_BODY_SECRET)

    for findings in (
        _check_hsts(page),
        _check_nosniff(page),
        _check_enforced_csp(page),
        _check_frame_protection(page),
    ):
        finding = findings[0]
        rendered = " ".join(
            [
                finding.observation,
                finding.rationale,
                *(value for _key, value in finding.evidence),
            ]
        )
        assert _BEARER not in rendered
        assert _COOKIE not in rendered
        assert "secret-token-abc" not in rendered
        assert "secret-cookie-value" not in rendered
        assert "supersecret" not in rendered
        assert "authorization" not in {key for key, _value in finding.evidence}


def test_header_rule_fingerprints_are_deterministic() -> None:
    first = _page(headers=_html((b"server", b"test")))
    second = _page(headers=_html((b"x-unused", b"1"), (b"server", b"test")))

    left = _check_hsts(first)[0].fingerprint
    right = _check_hsts(second)[0].fingerprint
    again = _check_hsts(first)[0].fingerprint

    assert left == right
    assert left == again
    assert len(left) == 64


def test_unrelated_duplicate_headers_do_not_change_singleton_rule_outcomes() -> None:
    page = _page(
        headers=_html(
            (b"set-cookie", b"a=1"),
            (b"set-cookie", b"b=2"),
            (b"strict-transport-security", b"max-age=31536000"),
            (b"x-content-type-options", b"nosniff"),
            (b"content-security-policy", b"frame-ancestors 'none'"),
        ),
    )

    assert _check_hsts(page) == ()
    assert _check_nosniff(page) == ()
    assert _check_enforced_csp(page) == ()
    assert _check_frame_protection(page) == ()


def test_header_rules_do_not_mutate_the_discovered_page() -> None:
    headers = _html((b"server", b"test"))
    body = b"<html>unchanged</html>"
    page = _page(headers=headers, body=body)

    _check_hsts(page)
    _check_nosniff(page)
    _check_enforced_csp(page)
    _check_frame_protection(page)

    assert page.response.headers is headers
    assert page.response.body is body
    assert page.response.body == b"<html>unchanged</html>"


def test_malformed_hsts_does_not_prevent_other_header_rules() -> None:
    page = _page(headers=_html((b"strict-transport-security", b"\xff")))

    assert _check_hsts(page)[0].rule_id == _HSTS_ID
    assert _check_nosniff(page)[0].rule_id == _NOSNIFF_ID
    assert _check_enforced_csp(page)[0].rule_id == _CSP_ID
    assert _check_frame_protection(page)[0].rule_id == _FRAME_ID


def test_bare_https_html_page_fires_all_four_header_rules() -> None:
    page = _page(headers=_html(), status=404)

    hsts = _check_hsts(page)[0]
    nosniff = _check_nosniff(page)[0]
    csp = _check_enforced_csp(page)[0]
    frame = _check_frame_protection(page)[0]

    assert [finding.rule_id for finding in (hsts, nosniff, csp, frame)] == [
        _HSTS_ID,
        _NOSNIFF_ID,
        _CSP_ID,
        _FRAME_ID,
    ]
    assert hsts.evidence == _evidence(
        header="strict-transport-security",
        state="missing",
        count="0",
        status=404,
    )


def test_header_rule_functions_return_tuples() -> None:
    page = _page(
        headers=_html(
            (b"strict-transport-security", b"max-age=31536000"),
            (b"x-content-type-options", b"nosniff"),
            (b"content-security-policy", b"frame-ancestors 'none'"),
        ),
    )

    assert _check_hsts(page) == ()
    assert isinstance(_check_hsts(page), tuple)
    assert isinstance(_check_nosniff(page), tuple)
    assert isinstance(_check_enforced_csp(page), tuple)
    assert isinstance(_check_frame_protection(page), tuple)
