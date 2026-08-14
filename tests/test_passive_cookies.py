"""Offline tests for deterministic passive Set-Cookie configuration rules (Slice C)."""

from __future__ import annotations

import socket
from collections.abc import Collection

import anyio
import pytest

from boundary.discovery import DiscoveredPage
from boundary.passive import (
    PassiveFinding,
    PassiveFindingKind,
    _check_cookie_secure,
    _check_hsts,
    _check_samesite_none_secure,
)
from boundary.scope import parse_target_url
from boundary.transport import TransportResponse

_SECURE_ID = "passive.cookie.secure_missing_https.v1"
_SAMESITE_ID = "passive.cookie.samesite_none_without_secure.v1"
_SECRET = "opaque-session-token-9f3a"


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if cookie rules perform DNS or real TCP I/O."""
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


def _set_cookie(*fields: bytes) -> tuple[tuple[bytes, bytes], ...]:
    return tuple((b"set-cookie", field) for field in fields)


def _cookie(name: str, *attributes: str) -> bytes:
    pair = f"{name}={_SECRET}"
    if attributes:
        return "; ".join((pair, *attributes)).encode("ascii")
    return pair.encode("ascii")


def _evidence(
    *,
    cookie: str,
    status: int = 200,
    secure: str | None = None,
    same_site: str | None = None,
) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = [
        ("cookie", cookie),
        ("status", str(status)),
    ]
    if secure is not None:
        pairs.append(("secure", secure))
    if same_site is not None:
        pairs.append(("same_site", same_site))
    return tuple(sorted(pairs))


def _assert_misconfiguration(
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
    assert finding.kind is PassiveFindingKind.MISCONFIGURATION
    assert finding.target is page.response.final_target
    assert finding.requested_target is page.target
    assert isinstance(finding.observation, str)
    assert finding.observation
    assert isinstance(finding.rationale, str)
    assert finding.rationale
    assert finding.evidence == evidence
    _assert_no_secret(finding)
    return finding


def _assert_no_secret(finding: PassiveFinding) -> None:
    rendered = " ".join(
        [
            finding.observation,
            finding.rationale,
            *(value for _key, value in finding.evidence),
        ]
    )
    assert _SECRET not in rendered
    assert f"session={_SECRET}" not in rendered
    assert "set-cookie" not in {key.lower() for key, _value in finding.evidence}


def test_https_cookie_without_secure_produces_a_misconfiguration() -> None:
    page = _page(headers=_set_cookie(_cookie("session")))

    _assert_misconfiguration(
        _check_cookie_secure(page),
        page=page,
        rule_id=_SECURE_ID,
        evidence=_evidence(cookie="session", secure="missing"),
    )


def test_https_cookie_with_secure_produces_no_finding() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "Secure")))

    assert _check_cookie_secure(page) == ()


@pytest.mark.parametrize("attribute", ["Secure", "secure", "SECURE"])
def test_secure_attribute_name_matching_is_case_insensitive(attribute: str) -> None:
    page = _page(headers=_set_cookie(_cookie("session", attribute)))

    assert _check_cookie_secure(page) == ()


def test_secure_flag_with_an_ignored_attribute_value_still_counts_as_present() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "Secure=0")))

    assert _check_cookie_secure(page) == ()


def test_repeated_secure_flags_still_count_as_present() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "Secure", "Secure")))

    assert _check_cookie_secure(page) == ()


def test_http_cookie_without_secure_does_not_apply() -> None:
    page = _page(url="http://app.test/", headers=_set_cookie(_cookie("session")))

    assert _check_cookie_secure(page) == ()


def test_cookie_secure_uses_final_target_scheme_not_requested_target() -> None:
    https_final = _page(
        url="https://app.test/final",
        requested="http://app.test/start",
        headers=_set_cookie(_cookie("session")),
    )
    http_final = _page(
        url="http://app.test/final",
        requested="https://app.test/start",
        headers=_set_cookie(_cookie("session")),
    )

    assert _check_cookie_secure(https_final)[0].rule_id == _SECURE_ID
    assert _check_cookie_secure(http_final) == ()


def test_empty_cookie_value_can_be_analyzed_but_is_not_retained() -> None:
    page = _page(headers=((b"set-cookie", b"session="),))

    finding = _assert_misconfiguration(
        _check_cookie_secure(page),
        page=page,
        rule_id=_SECURE_ID,
        evidence=_evidence(cookie="session", secure="missing"),
    )
    assert finding.evidence == _evidence(cookie="session", secure="missing")


def test_quoted_cookie_value_is_not_retained() -> None:
    page = _page(headers=((b"set-cookie", f'session="{_SECRET}"'.encode("ascii")),))

    finding = _assert_misconfiguration(
        _check_cookie_secure(page),
        page=page,
        rule_id=_SECURE_ID,
        evidence=_evidence(cookie="session", secure="missing"),
    )
    assert _SECRET not in finding.observation
    assert _SECRET not in finding.rationale


def test_set_cookie_header_name_matching_is_case_insensitive() -> None:
    page = _page(headers=((b"Set-Cookie", _cookie("session")),))

    assert _check_cookie_secure(page)[0].rule_id == _SECURE_ID


def test_expires_commas_are_not_treated_as_cookie_separators() -> None:
    field = (
        b"session="
        + _SECRET.encode("ascii")
        + b"; Expires=Wed, 21 Oct 2015 07:28:00 GMT"
    )
    page = _page(headers=((b"set-cookie", field),))

    findings = _check_cookie_secure(page)
    assert len(findings) == 1
    assert dict(findings[0].evidence)["cookie"] == "session"
    _assert_no_secret(findings[0])


def test_unknown_attributes_are_ignored() -> None:
    page = _page(
        headers=_set_cookie(_cookie("session", "Path=/", "HttpOnly", "Max-Age=60")),
    )

    finding = _assert_misconfiguration(
        _check_cookie_secure(page),
        page=page,
        rule_id=_SECURE_ID,
        evidence=_evidence(cookie="session", secure="missing"),
    )
    assert "path" not in {key.lower() for key, _value in finding.evidence}
    assert "httponly" not in {key.lower() for key, _value in finding.evidence}


def test_two_insecure_https_cookies_produce_findings_in_header_order() -> None:
    page = _page(
        headers=_set_cookie(_cookie("sid"), _cookie("tracking")),
    )

    findings = _check_cookie_secure(page)
    assert [dict(finding.evidence)["cookie"] for finding in findings] == [
        "sid",
        "tracking",
    ]
    assert findings[0].fingerprint != findings[1].fingerprint
    for finding in findings:
        _assert_no_secret(finding)


def test_secure_and_insecure_cookies_are_evaluated_independently() -> None:
    page = _page(
        headers=_set_cookie(_cookie("safe", "Secure"), _cookie("unsafe")),
    )

    findings = _check_cookie_secure(page)
    assert len(findings) == 1
    assert dict(findings[0].evidence)["cookie"] == "unsafe"


def test_samesite_none_without_secure_fires_on_https() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "SameSite=None")))

    _assert_misconfiguration(
        _check_samesite_none_secure(page),
        page=page,
        rule_id=_SAMESITE_ID,
        evidence=_evidence(cookie="session", same_site="none", secure="missing"),
    )


def test_samesite_none_without_secure_fires_on_http() -> None:
    page = _page(
        url="http://app.test/",
        headers=_set_cookie(_cookie("session", "SameSite=None")),
    )

    _assert_misconfiguration(
        _check_samesite_none_secure(page),
        page=page,
        rule_id=_SAMESITE_ID,
        evidence=_evidence(cookie="session", same_site="none", secure="missing"),
    )


def test_samesite_none_with_secure_produces_no_finding() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "SameSite=None", "Secure")))

    assert _check_samesite_none_secure(page) == ()


def test_samesite_none_attribute_order_does_not_change_semantics() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "Secure", "SameSite=None")))

    assert _check_samesite_none_secure(page) == ()


@pytest.mark.parametrize(
    "attribute",
    ["SameSite=None", "samesite=none", "SAMESITE=NONE"],
)
def test_samesite_none_matching_is_case_insensitive(attribute: str) -> None:
    page = _page(headers=_set_cookie(_cookie("session", attribute)))

    assert _check_samesite_none_secure(page)[0].rule_id == _SAMESITE_ID


@pytest.mark.parametrize("attribute", [" SameSite = None ", "\tSameSite\t=\tNone\t"])
def test_samesite_none_accepts_permitted_surrounding_whitespace(attribute: str) -> None:
    page = _page(headers=_set_cookie(_cookie("session", attribute)))

    assert _check_samesite_none_secure(page)[0].rule_id == _SAMESITE_ID


@pytest.mark.parametrize(
    "attribute",
    [
        "SameSite=Lax",
        "SameSite=Strict",
        "SameSite=",
        "SameSite=invalid",
        "SameSite",
    ],
)
def test_non_none_samesite_does_not_fire(attribute: str) -> None:
    page = _page(headers=_set_cookie(_cookie("session", attribute)))

    assert _check_samesite_none_secure(page) == ()


def test_missing_samesite_does_not_fire_the_samesite_rule() -> None:
    page = _page(headers=_set_cookie(_cookie("session")))

    assert _check_samesite_none_secure(page) == ()


def test_malformed_samesite_value_does_not_fire() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "SameSite=None extra")))

    assert _check_samesite_none_secure(page) == ()


def test_cookie_rules_are_not_limited_to_html_responses() -> None:
    page = _page(
        headers=((b"content-type", b"application/json"),)
        + _set_cookie(_cookie("session", "SameSite=None")),
    )

    assert _check_cookie_secure(page)[0].rule_id == _SECURE_ID
    assert _check_samesite_none_secure(page)[0].rule_id == _SAMESITE_ID


def test_duplicate_samesite_attributes_do_not_fire_the_samesite_rule() -> None:
    page = _page(
        headers=_set_cookie(_cookie("session", "SameSite=None", "SameSite=None")),
    )

    assert _check_samesite_none_secure(page) == ()
    assert _check_cookie_secure(page)[0].rule_id == _SECURE_ID


def test_conflicting_samesite_attributes_do_not_fire_the_samesite_rule() -> None:
    page = _page(
        headers=_set_cookie(_cookie("session", "SameSite=None", "SameSite=Lax")),
    )

    assert _check_samesite_none_secure(page) == ()


def test_https_cookie_can_fire_both_cookie_rules() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "SameSite=None")))

    secure = _check_cookie_secure(page)[0]
    samesite = _check_samesite_none_secure(page)[0]
    assert secure.rule_id == _SECURE_ID
    assert samesite.rule_id == _SAMESITE_ID
    assert secure.fingerprint != samesite.fingerprint


@pytest.mark.parametrize(
    "field",
    [
        b"",
        b"session",
        b"=value",
        b" session=value",
        b"ses sion=value",
        b"session\xff=value",
        b"; Secure",
    ],
)
def test_malformed_cookie_fields_are_skipped_without_a_finding(field: bytes) -> None:
    page = _page(headers=((b"set-cookie", field),))

    assert _check_cookie_secure(page) == ()
    assert _check_samesite_none_secure(page) == ()


def test_malformed_cookie_does_not_block_a_later_valid_cookie() -> None:
    page = _page(
        headers=_set_cookie(b"session", _cookie("later")),
    )

    findings = _check_cookie_secure(page)
    assert [dict(finding.evidence)["cookie"] for finding in findings] == ["later"]


def test_valid_cookie_is_kept_when_a_later_field_is_malformed() -> None:
    page = _page(
        headers=_set_cookie(_cookie("first"), b"=broken"),
    )

    findings = _check_cookie_secure(page)
    assert [dict(finding.evidence)["cookie"] for finding in findings] == ["first"]


def test_malformed_cookie_does_not_block_unrelated_header_rules() -> None:
    page = _page(headers=_set_cookie(b"session") + ((b"content-type", b"text/html"),))

    assert _check_cookie_secure(page) == ()
    assert _check_hsts(page)[0].rule_id == "passive.hsts.not_enforced.v1"


def test_cookie_findings_use_final_target_and_retain_requested_target() -> None:
    page = _page(
        url="https://app.test/final",
        requested="https://app.test/start",
        headers=_set_cookie(_cookie("session", "SameSite=None")),
    )

    for findings in (_check_cookie_secure(page), _check_samesite_none_secure(page)):
        finding = findings[0]
        assert finding.target is page.response.final_target
        assert finding.target.url == "https://app.test/final"
        assert finding.requested_target is page.target
        assert finding.requested_target.url == "https://app.test/start"


def test_cookie_values_never_appear_in_findings_or_evidence() -> None:
    headers = (
        (b"set-cookie", _cookie("session", "SameSite=None")),
        (b"authorization", b"Bearer other-secret"),
    )
    page = _page(headers=headers, body=b"token=supersecret")

    for findings in (_check_cookie_secure(page), _check_samesite_none_secure(page)):
        finding = findings[0]
        _assert_no_secret(finding)
        rendered = " ".join(
            [
                finding.observation,
                finding.rationale,
                *(value for _key, value in finding.evidence),
            ]
        )
        assert "Bearer other-secret" not in rendered
        assert "supersecret" not in rendered
        assert dict(finding.evidence)["cookie"] == "session"


def test_cookie_fingerprints_are_deterministic() -> None:
    first = _page(
        headers=_set_cookie(_cookie("session")) + ((b"server", b"test"),),
    )
    second = _page(
        headers=((b"x-unused", b"1"),) + _set_cookie(_cookie("session")),
    )

    left = _check_cookie_secure(first)[0].fingerprint
    right = _check_cookie_secure(second)[0].fingerprint
    again = _check_cookie_secure(first)[0].fingerprint

    assert left == right
    assert left == again
    assert len(left) == 64


def test_different_cookie_names_produce_different_fingerprints() -> None:
    sid = _page(headers=_set_cookie(_cookie("sid")))
    tracking = _page(headers=_set_cookie(_cookie("tracking")))

    assert (
        _check_cookie_secure(sid)[0].fingerprint
        != _check_cookie_secure(tracking)[0].fingerprint
    )


def test_identical_cookie_fields_are_emitted_independently_in_field_order() -> None:
    page = _page(headers=_set_cookie(_cookie("session"), _cookie("session")))

    findings = _check_cookie_secure(page)
    assert len(findings) == 2
    assert dict(findings[0].evidence)["cookie"] == "session"
    assert dict(findings[1].evidence)["cookie"] == "session"
    assert findings[0].fingerprint == findings[1].fingerprint


def test_unrelated_duplicate_headers_do_not_change_cookie_outcomes() -> None:
    page = _page(
        headers=(
            (b"set-cookie", _cookie("session", "Secure", "SameSite=None")),
            (b"set-cookie", _cookie("session", "Secure", "SameSite=None")),
            (b"x-unused", b"1"),
            (b"x-unused", b"2"),
        ),
    )

    assert _check_cookie_secure(page) == ()
    assert _check_samesite_none_secure(page) == ()


def test_cookie_rules_do_not_mutate_the_discovered_page() -> None:
    headers = _set_cookie(_cookie("session"))
    body = b"<html>unchanged</html>"
    page = _page(headers=headers, body=body)

    _check_cookie_secure(page)
    _check_samesite_none_secure(page)

    assert page.response.headers is headers
    assert page.response.body is body


def test_cookie_rule_functions_return_tuples() -> None:
    page = _page(headers=_set_cookie(_cookie("session", "Secure")))

    assert isinstance(_check_cookie_secure(page), tuple)
    assert isinstance(_check_samesite_none_secure(page), tuple)
    assert _check_cookie_secure(page) == ()
