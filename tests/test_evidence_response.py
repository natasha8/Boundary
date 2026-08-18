"""Offline tests for safe response evidence capture (Slice B)."""

from __future__ import annotations

import inspect
import socket
from collections.abc import Collection
from dataclasses import fields
from typing import Any, cast, get_type_hints

import anyio
import pytest

from boundary.evidence import (
    FindingEvidence,
    ResponseEvidence,
    capture_response_evidence,
)
from boundary.scope import TargetUrl, parse_target_url
from boundary.transport import TransportResponse

_EMPTY_BODY = b""
_ASCII_BODY = b"hello"
_BINARY_BODY = bytes((0xFF, 0xFE, 0x00, 0x80))
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_ASCII_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
_BINARY_SHA256 = "5a741968f40e57485ed6e1a1af381adeb2714223c35acedf1ad0670e42df2eb5"
_AUTH_VALUE = "Bearer secret-authorization-token-7f3a"
_COOKIE_VALUE = "session=secret-cookie-value-9c21"
_SET_COOKIE_VALUE = "session=secret-set-cookie-value-4d88; Secure"
_BODY_SECRET = b"password=supersecret-body-token"
_SPECULATIVE_PUBLIC_NAMES = (
    "EvidenceEngine",
    "EvidenceStore",
    "EvidenceRepository",
    "EvidenceRecord",
    "Evidence",
    "build_finding_evidence",
    "compare_responses",
    "compare_evidence",
    "scan_evidence",
)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


def _reject_network(*args: object, **kwargs: object) -> None:
    raise AssertionError("evidence capture must not perform network activity")


@pytest.fixture(autouse=True)
def _reject_dns_transport_and_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if capture reaches network entry points."""
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


def _final_target() -> TargetUrl:
    return parse_target_url("https://app.test/")


def _requested_target() -> TargetUrl:
    return parse_target_url("https://app.test/start")


def _response(
    *,
    status: int = 200,
    headers: Collection[tuple[bytes, bytes]] = (),
    body: bytes = _ASCII_BODY,
    final_target: TargetUrl | None = None,
) -> TransportResponse:
    return TransportResponse(
        status=status,
        headers=tuple(headers),
        body=body,
        final_target=_final_target() if final_target is None else final_target,
    )


def _capture(
    response: TransportResponse | None = None,
    *,
    requested_target: TargetUrl | None = None,
) -> ResponseEvidence:
    evidence = capture_response_evidence(
        _response() if response is None else response,
        requested_target=(
            _requested_target() if requested_target is None else requested_target
        ),
    )
    assert isinstance(evidence, ResponseEvidence)
    return evidence


def _field_surface(evidence: ResponseEvidence) -> str:
    parts = [repr(evidence)]
    for field in fields(evidence):
        value = getattr(evidence, field.name)
        parts.append(str(value))
        parts.append(repr(value))
    return "\n".join(parts)


def test_capture_returns_response_evidence() -> None:
    evidence = _capture()

    assert type(evidence) is ResponseEvidence
    assert isinstance(evidence, ResponseEvidence)


@pytest.mark.parametrize(
    "status",
    [200, 404, 302, 500],
    ids=("ok", "not_found", "redirect", "server_error"),
)
def test_capture_preserves_status_exactly(status: int) -> None:
    evidence = _capture(_response(status=status))

    assert evidence.status == status


def test_capture_preserves_final_target_object_identity() -> None:
    final_target = parse_target_url("https://app.test/final")
    response = _response(final_target=final_target)

    evidence = _capture(response)

    assert evidence.final_target is final_target
    assert evidence.final_target is response.final_target


def test_capture_preserves_requested_target_object_identity() -> None:
    requested_target = parse_target_url("https://app.test/start")
    response = _response()

    evidence = capture_response_evidence(
        response,
        requested_target=requested_target,
    )

    assert evidence.requested_target is requested_target
    assert evidence.requested_target is not response.final_target


def test_capture_keeps_redirect_provenance_explicit() -> None:
    """requested_target is caller-supplied provenance, never inferred from final_target."""
    final_target = parse_target_url("https://app.test/final")
    requested_target = parse_target_url("https://app.test/start")
    response = _response(status=302, final_target=final_target)

    evidence = capture_response_evidence(
        response,
        requested_target=requested_target,
    )

    assert evidence.final_target is final_target
    assert evidence.requested_target is requested_target
    assert evidence.final_target.url == "https://app.test/final"
    assert evidence.requested_target.url == "https://app.test/start"


def test_empty_body_uses_locked_empty_digest() -> None:
    evidence = _capture(_response(body=_EMPTY_BODY))

    assert evidence.body_length == 0
    assert isinstance(evidence.body_sha256, str)
    assert evidence.body_sha256 == _EMPTY_SHA256
    assert evidence.body_sha256 != ""


def test_ascii_body_matches_locked_digest_vector() -> None:
    evidence = _capture(_response(body=_ASCII_BODY))

    assert evidence.body_length == 5
    assert evidence.body_length == len(_ASCII_BODY)
    assert evidence.body_sha256 == _ASCII_SHA256


def test_binary_body_matches_locked_digest_vector() -> None:
    evidence = _capture(_response(body=_BINARY_BODY))

    assert evidence.body_length == 4
    assert evidence.body_length == len(_BINARY_BODY)
    assert evidence.body_sha256 == _BINARY_SHA256


def test_body_length_is_retained_byte_count_not_content_length() -> None:
    """Content-Length is untrusted and must not determine body_length or the digest."""
    headers = ((b"content-length", b"9999"),)
    response = _response(headers=headers, body=_ASCII_BODY)

    evidence = _capture(response)

    assert len(response.body) == 5
    assert evidence.body_length == 5
    assert evidence.body_length != 9999
    assert evidence.body_sha256 == _ASCII_SHA256


def test_headers_do_not_affect_captured_evidence() -> None:
    final_target = parse_target_url("https://app.test/")
    requested_target = parse_target_url("https://app.test/start")
    body = _ASCII_BODY
    secret_headers = (
        (b"authorization", _AUTH_VALUE.encode("ascii")),
        (b"cookie", _COOKIE_VALUE.encode("ascii")),
        (b"set-cookie", _SET_COOKIE_VALUE.encode("ascii")),
        (b"content-length", b"1"),
    )
    other_headers = ((b"x-ignored", b"different"),)

    left = capture_response_evidence(
        TransportResponse(
            status=200,
            headers=secret_headers,
            body=body,
            final_target=final_target,
        ),
        requested_target=requested_target,
    )
    right = capture_response_evidence(
        TransportResponse(
            status=200,
            headers=other_headers,
            body=body,
            final_target=final_target,
        ),
        requested_target=requested_target,
    )
    empty = capture_response_evidence(
        TransportResponse(
            status=200,
            headers=(),
            body=body,
            final_target=final_target,
        ),
        requested_target=requested_target,
    )

    assert left == right == empty
    assert left.body_length == 5
    assert left.body_sha256 == _ASCII_SHA256


def test_one_byte_change_changes_digest() -> None:
    original = _capture(_response(body=_ASCII_BODY))
    changed = _capture(_response(body=b"hallo"))

    assert original.body_length == changed.body_length
    assert original.body_sha256 == _ASCII_SHA256
    assert changed.body_sha256 != _ASCII_SHA256


def test_trailing_newline_changes_digest() -> None:
    original = _capture(_response(body=_ASCII_BODY))
    changed = _capture(_response(body=_ASCII_BODY + b"\n"))

    assert original.body_sha256 == _ASCII_SHA256
    assert changed.body_length == len(_ASCII_BODY) + 1
    assert changed.body_sha256 != _ASCII_SHA256


def test_equal_body_bytes_from_separate_objects_produce_equal_evidence() -> None:
    left_body = b"hello"
    right_body = bytes(bytearray(left_body))
    final_target = parse_target_url("https://app.test/")
    requested_target = parse_target_url("https://app.test/start")

    assert left_body is not right_body
    assert left_body == right_body

    left = capture_response_evidence(
        TransportResponse(
            status=200,
            headers=(),
            body=left_body,
            final_target=final_target,
        ),
        requested_target=requested_target,
    )
    right = capture_response_evidence(
        TransportResponse(
            status=200,
            headers=((b"x-unused", b"1"),),
            body=right_body,
            final_target=final_target,
        ),
        requested_target=requested_target,
    )

    assert left == right
    assert left.body_length == 5
    assert left.body_sha256 == _ASCII_SHA256
    assert right.body_sha256 == _ASCII_SHA256


def test_unicode_encodings_are_hashed_as_distinct_bytes() -> None:
    text = "café"
    utf8_body = text.encode("utf-8")
    latin1_body = text.encode("latin-1")

    assert utf8_body != latin1_body

    utf8_evidence = _capture(_response(body=utf8_body))
    latin1_evidence = _capture(_response(body=latin1_body))

    assert utf8_evidence.body_length == len(utf8_body)
    assert latin1_evidence.body_length == len(latin1_body)
    assert utf8_evidence.body_sha256 != latin1_evidence.body_sha256
    assert utf8_evidence.body_sha256 != _EMPTY_SHA256
    assert latin1_evidence.body_sha256 != _EMPTY_SHA256


def test_json_key_order_is_not_canonicalized() -> None:
    left = _capture(_response(body=b'{"a":1,"b":2}'))
    right = _capture(_response(body=b'{"b":2,"a":1}'))

    assert left.body_length == right.body_length
    assert left.body_sha256 != right.body_sha256


def test_response_content_secrets_are_absent_from_fields_and_repr() -> None:
    headers = (
        (b"authorization", _AUTH_VALUE.encode("ascii")),
        (b"cookie", _COOKIE_VALUE.encode("ascii")),
        (b"set-cookie", _SET_COOKIE_VALUE.encode("ascii")),
    )
    response = _response(headers=headers, body=_BODY_SECRET)
    evidence = _capture(response)
    surface = _field_surface(evidence).lower()
    field_names = {field.name for field in fields(evidence)}

    assert "headers" not in field_names
    assert "body" not in field_names
    assert "raw" not in field_names
    assert "excerpt" not in field_names
    for secret in (
        _AUTH_VALUE,
        _COOKIE_VALUE,
        _SET_COOKIE_VALUE,
        _BODY_SECRET.decode("ascii"),
        "secret-authorization-token-7f3a",
        "secret-cookie-value-9c21",
        "secret-set-cookie-value-4d88",
        "password=supersecret-body-token",
    ):
        assert secret.lower() not in surface
    for header_name in ("authorization", "cookie", "set-cookie"):
        assert header_name not in surface


def test_query_string_in_target_is_preserved_as_inherited_boundary() -> None:
    """Query parameters on TargetUrl are inherited from Scope and are not redacted."""
    target = parse_target_url("https://app.test/reset?token=secret-query-token")
    response = _response(final_target=target, body=_EMPTY_BODY)

    evidence = capture_response_evidence(response, requested_target=target)

    assert evidence.final_target is target
    assert evidence.requested_target is target
    assert evidence.final_target.query == "token=secret-query-token"
    assert "secret-query-token" in evidence.final_target.url
    assert "secret-query-token" in repr(evidence)


def test_repeated_capture_is_deterministic_and_equal() -> None:
    response = _response(body=_ASCII_BODY)
    requested_target = parse_target_url("https://app.test/start")

    first = capture_response_evidence(response, requested_target=requested_target)
    second = capture_response_evidence(response, requested_target=requested_target)

    assert first == second
    assert first.body_sha256 == _ASCII_SHA256
    assert second.body_sha256 == _ASCII_SHA256


def test_capture_does_not_mutate_inputs() -> None:
    headers = (
        (b"authorization", _AUTH_VALUE.encode("ascii")),
        (b"set-cookie", _SET_COOKIE_VALUE.encode("ascii")),
    )
    body = b"hello"
    final_target = parse_target_url("https://app.test/")
    requested_target = parse_target_url("https://app.test/start")
    response = TransportResponse(
        status=302,
        headers=headers,
        body=body,
        final_target=final_target,
    )

    _capture(response, requested_target=requested_target)

    assert response.status == 302
    assert response.headers is headers
    assert response.body is body
    assert response.final_target is final_target
    assert response.headers == (
        (b"authorization", _AUTH_VALUE.encode("ascii")),
        (b"set-cookie", _SET_COOKIE_VALUE.encode("ascii")),
    )
    assert response.body == b"hello"
    assert requested_target.url == "https://app.test/start"
    assert final_target.url == "https://app.test/"


def test_capture_is_synchronous() -> None:
    assert inspect.isfunction(capture_response_evidence)
    assert not inspect.iscoroutinefunction(capture_response_evidence)
    assert not inspect.isasyncgenfunction(capture_response_evidence)

    evidence = capture_response_evidence(
        _response(),
        requested_target=_requested_target(),
    )

    assert type(evidence) is ResponseEvidence


def test_capture_requested_target_is_keyword_only() -> None:
    signature = inspect.signature(capture_response_evidence)
    parameters = signature.parameters

    assert list(parameters) == ["response", "requested_target"]
    assert parameters["response"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert parameters["requested_target"].kind is inspect.Parameter.KEYWORD_ONLY

    capture = cast(Any, capture_response_evidence)
    with pytest.raises(TypeError):
        capture(_response())
    with pytest.raises(TypeError):
        capture(_response(), _requested_target())


def test_captured_digest_is_64_lowercase_hex() -> None:
    evidence = _capture(_response(body=_BINARY_BODY))

    assert len(evidence.body_sha256) == 64
    assert evidence.body_sha256 == evidence.body_sha256.lower()
    assert all(character in "0123456789abcdef" for character in evidence.body_sha256)
    assert evidence.body_sha256 == _BINARY_SHA256


def test_capture_response_evidence_type_hints_resolve() -> None:
    """Annotations name domain types; TYPE_CHECKING names are supplied for resolution."""
    hints = get_type_hints(
        capture_response_evidence,
        globalns={
            **capture_response_evidence.__globals__,
            "TransportResponse": TransportResponse,
            "TargetUrl": TargetUrl,
        },
    )

    assert hints["response"] is TransportResponse
    assert hints["requested_target"] is TargetUrl
    assert hints["return"] is ResponseEvidence


def test_evidence_module_binds_no_network_callables() -> None:
    import boundary.evidence as evidence

    bound = vars(evidence)
    for name in (
        "socket",
        "httpcore",
        "anyio",
        "crawl",
        "request_once",
        "request_with_redirects",
        "SystemAddressResolver",
        "DiscoveredPage",
        "scan_page",
        "scan_pages",
    ):
        assert name not in bound

    _capture(_response(body=_EMPTY_BODY))


def test_slice_b_public_surface_is_exactly_the_approved_api() -> None:
    import boundary.evidence as evidence

    assert hasattr(evidence, "ResponseEvidence")
    assert hasattr(evidence, "FindingEvidence")
    assert hasattr(evidence, "capture_response_evidence")
    assert evidence.ResponseEvidence is ResponseEvidence
    assert evidence.FindingEvidence is FindingEvidence
    assert evidence.capture_response_evidence is capture_response_evidence
    assert not hasattr(evidence, "__all__")
    for name in _SPECULATIVE_PUBLIC_NAMES:
        assert not hasattr(evidence, name)
