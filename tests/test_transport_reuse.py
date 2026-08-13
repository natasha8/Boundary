"""Offline tests for connection reuse identity (Milestone 2 Slice E).

These tests establish the minimum safe reuse key:

    (scheme, host, port, pinned_ip)

They intentionally stop at the identity/policy boundary. They do not require
a pool manager, cache, or keep-alive lifecycle, and they do not weaken
request_once isolation.
"""

from __future__ import annotations

import socket
from dataclasses import FrozenInstanceError, fields
from ipaddress import ip_address

import anyio
import pytest

from boundary.scope import parse_target_url
from boundary.transport import ConnectionReuseKey, connection_reuse_key

_EXAMPLE_IP = "93.184.216.34"
_OTHER_IP = "93.184.216.35"
_IPV6_EXPANDED = "2001:0db8:0000:0000:0000:0000:0000:0001"
_IPV6_CANONICAL = "2001:db8::1"


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if reuse tests perform DNS or real TCP I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)


def test_reuse_key_fields_are_exactly_scheme_host_port_pinned_ip() -> None:
    names = tuple(field.name for field in fields(ConnectionReuseKey))
    assert names == ("scheme", "host", "port", "pinned_ip")


def test_reuse_key_is_immutable() -> None:
    key = connection_reuse_key(
        parse_target_url("https://example.com/"),
        _EXAMPLE_IP,
    )

    with pytest.raises(FrozenInstanceError):
        key.pinned_ip = _OTHER_IP  # type: ignore[misc]


def test_same_scheme_host_port_and_pinned_ip_keys_are_equal() -> None:
    target = parse_target_url("https://example.com/a")
    left = connection_reuse_key(target, _EXAMPLE_IP)
    right = connection_reuse_key(target, _EXAMPLE_IP)

    assert left == right
    assert hash(left) == hash(right)


def test_different_scheme_must_not_reuse() -> None:
    http_key = connection_reuse_key(
        parse_target_url("http://example.com/"),
        _EXAMPLE_IP,
    )
    https_key = connection_reuse_key(
        parse_target_url("https://example.com/"),
        _EXAMPLE_IP,
    )

    assert http_key != https_key


def test_different_host_must_not_reuse() -> None:
    left = connection_reuse_key(
        parse_target_url("https://example.com/"),
        _EXAMPLE_IP,
    )
    right = connection_reuse_key(
        parse_target_url("https://api.example.com/"),
        _EXAMPLE_IP,
    )

    assert left != right
    assert left.host != right.host
    assert left.pinned_ip == right.pinned_ip


def test_different_port_must_not_reuse() -> None:
    left = connection_reuse_key(
        parse_target_url("https://example.com/"),
        _EXAMPLE_IP,
    )
    right = connection_reuse_key(
        parse_target_url("https://example.com:8443/"),
        _EXAMPLE_IP,
    )

    assert left != right
    assert left.port == 443
    assert right.port == 8443


def test_different_pinned_ip_must_not_reuse() -> None:
    target = parse_target_url("https://example.com/")
    left = connection_reuse_key(target, _EXAMPLE_IP)
    right = connection_reuse_key(target, _OTHER_IP)

    assert left != right
    assert left.host == right.host
    assert left.scheme == right.scheme
    assert left.port == right.port


def test_ipv6_pinned_addresses_use_canonical_representation() -> None:
    key = connection_reuse_key(
        parse_target_url("https://example.com/"),
        _IPV6_EXPANDED,
    )

    assert key.pinned_ip == _IPV6_CANONICAL
    assert key.pinned_ip == str(ip_address(_IPV6_EXPANDED))
    assert key.pinned_ip != _IPV6_EXPANDED


def test_equivalent_normalized_origins_produce_equivalent_reuse_keys() -> None:
    with_default_port = connection_reuse_key(
        parse_target_url("https://example.com/path"),
        _EXAMPLE_IP,
    )
    with_explicit_port = connection_reuse_key(
        parse_target_url("https://example.com:443/other?q=1"),
        _EXAMPLE_IP,
    )
    uppercase_scheme_host = connection_reuse_key(
        parse_target_url("HTTPS://EXAMPLE.COM/"),
        _EXAMPLE_IP,
    )

    assert with_default_port == with_explicit_port
    assert with_default_port == uppercase_scheme_host
    assert with_default_port == ConnectionReuseKey(
        scheme="https",
        host="example.com",
        port=443,
        pinned_ip=_EXAMPLE_IP,
    )


def test_same_origin_redirect_with_same_pinned_ip_may_reuse() -> None:
    first = connection_reuse_key(
        parse_target_url("https://example.com/start"),
        _EXAMPLE_IP,
    )
    second = connection_reuse_key(
        parse_target_url("https://example.com/next"),
        _EXAMPLE_IP,
    )

    assert first == second


def test_same_origin_redirect_resolving_to_different_ip_must_not_reuse() -> None:
    first = connection_reuse_key(
        parse_target_url("https://example.com/start"),
        _EXAMPLE_IP,
    )
    second = connection_reuse_key(
        parse_target_url("https://example.com/next"),
        _OTHER_IP,
    )

    assert first != second


def test_cross_origin_redirect_must_not_reuse_even_when_ip_matches() -> None:
    first = connection_reuse_key(
        parse_target_url("https://example.com/start"),
        _EXAMPLE_IP,
    )
    second = connection_reuse_key(
        parse_target_url("https://api.example.com/v1"),
        _EXAMPLE_IP,
    )

    assert first.pinned_ip == second.pinned_ip
    assert first != second


def test_reuse_key_cannot_be_selected_by_hostname_alone() -> None:
    shared_host_a = connection_reuse_key(
        parse_target_url("https://example.com/"),
        _EXAMPLE_IP,
    )
    shared_host_b = connection_reuse_key(
        parse_target_url("https://example.com/"),
        _OTHER_IP,
    )
    shared_host_http = connection_reuse_key(
        parse_target_url("http://example.com/"),
        _EXAMPLE_IP,
    )

    assert shared_host_a.host == shared_host_b.host == shared_host_http.host
    assert shared_host_a != shared_host_b
    assert shared_host_a != shared_host_http
    assert "host" in {field.name for field in fields(ConnectionReuseKey)}
    assert "pinned_ip" in {field.name for field in fields(ConnectionReuseKey)}
    assert len(fields(ConnectionReuseKey)) == 4


def test_reuse_key_cannot_be_selected_by_ip_alone() -> None:
    shared_ip_a = connection_reuse_key(
        parse_target_url("https://example.com/"),
        _EXAMPLE_IP,
    )
    shared_ip_b = connection_reuse_key(
        parse_target_url("https://api.example.com/"),
        _EXAMPLE_IP,
    )
    shared_ip_port = connection_reuse_key(
        parse_target_url("https://example.com:8443/"),
        _EXAMPLE_IP,
    )

    assert (
        shared_ip_a.pinned_ip
        == shared_ip_b.pinned_ip
        == shared_ip_port.pinned_ip
        == _EXAMPLE_IP
    )
    assert shared_ip_a != shared_ip_b
    assert shared_ip_a != shared_ip_port


def test_non_ip_pinned_value_is_rejected() -> None:
    target = parse_target_url("https://example.com/")

    with pytest.raises(ValueError):
        connection_reuse_key(target, "example.com")
