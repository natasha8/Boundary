import asyncio
import socket

import pytest

from boundary.resolver import SystemAddressResolver
from boundary.scope import (
    AddressPolicy,
    ScopeErrorCode,
    ScopeValidationError,
    resolve_allowed_addresses,
)

_HOST = "app.test"
_PORT = 8443


class FakeEventLoop:
    """Event loop double that records getaddrinfo calls without network I/O."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []
        self.results: list[object] = []

    async def getaddrinfo(
        self,
        host: str,
        port: int,
        *,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[object]:
        self.calls.append((host, port))
        return list(self.results)


def _ipv4_addrinfo(
    address: str, port: int
) -> tuple[int, int, int, str, tuple[str, int]]:
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, port),
    )


def _ipv6_addrinfo(
    address: str,
    port: int,
) -> tuple[int, int, int, str, tuple[str, int, int, int]]:
    return (
        socket.AF_INET6,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, port, 0, 0),
    )


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


@pytest.fixture(autouse=True)
def fake_loop(monkeypatch: pytest.MonkeyPatch) -> FakeEventLoop:
    loop = FakeEventLoop()
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop)
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    return loop


@pytest.fixture(autouse=True)
def unfiltered_addresses(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ...]]:
    """Record raw SystemAddressResolver output before policy enforcement."""
    observed: list[tuple[str, ...]] = []
    original = SystemAddressResolver.resolve

    async def resolve(
        self: SystemAddressResolver,
        host: str,
        port: int,
    ) -> tuple[str, ...]:
        addresses = await original(self, host, port)
        observed.append(addresses)
        return addresses

    monkeypatch.setattr(SystemAddressResolver, "resolve", resolve)
    return observed


def _compose(policy: AddressPolicy) -> tuple[str, ...]:
    resolver = SystemAddressResolver()
    return asyncio.run(
        resolve_allowed_addresses(
            host=_HOST,
            port=_PORT,
            policy=policy,
            resolver=resolver,
        )
    )


def test_public_accepts_mixed_public_ipv4_and_ipv6(
    fake_loop: FakeEventLoop,
    unfiltered_addresses: list[tuple[str, ...]],
) -> None:
    fake_loop.results = [
        _ipv4_addrinfo("8.8.8.8", _PORT),
        _ipv6_addrinfo("2606:4700:4700::1111", _PORT),
    ]

    result = _compose(AddressPolicy.PUBLIC)

    assert fake_loop.calls == [(_HOST, _PORT)]
    assert unfiltered_addresses == [("8.8.8.8", "2606:4700:4700::1111")]
    assert result == ("8.8.8.8", "2606:4700:4700::1111")


def test_composition_canonicalizes_and_deduplicates_equivalent_ipv6(
    fake_loop: FakeEventLoop,
    unfiltered_addresses: list[tuple[str, ...]],
) -> None:
    fake_loop.results = [
        _ipv6_addrinfo("2606:4700:4700:0:0:0:0:1111", _PORT),
        _ipv6_addrinfo("2606:4700:4700::1111", _PORT),
    ]

    result = _compose(AddressPolicy.PUBLIC)

    assert unfiltered_addresses == [
        ("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111")
    ]
    assert result == ("2606:4700:4700::1111",)


def test_public_rejects_entire_result_when_one_address_is_private(
    fake_loop: FakeEventLoop,
    unfiltered_addresses: list[tuple[str, ...]],
) -> None:
    fake_loop.results = [
        _ipv4_addrinfo("8.8.8.8", _PORT),
        _ipv4_addrinfo("192.168.1.10", _PORT),
    ]

    with pytest.raises(ScopeValidationError) as error:
        _compose(AddressPolicy.PUBLIC)

    assert unfiltered_addresses == [("8.8.8.8", "192.168.1.10")]
    assert error.value.code is ScopeErrorCode.ADDRESS_NOT_ALLOWED


def test_local_lab_accepts_loopback_and_private_addresses(
    fake_loop: FakeEventLoop,
    unfiltered_addresses: list[tuple[str, ...]],
) -> None:
    fake_loop.results = [
        _ipv4_addrinfo("127.0.0.1", _PORT),
        _ipv4_addrinfo("192.168.1.10", _PORT),
        _ipv6_addrinfo("::1", _PORT),
    ]

    result = _compose(AddressPolicy.LOCAL_LAB)

    assert unfiltered_addresses == [("127.0.0.1", "192.168.1.10", "::1")]
    assert result == ("127.0.0.1", "192.168.1.10", "::1")


def test_empty_getaddrinfo_result_raises_no_resolved_addresses(
    fake_loop: FakeEventLoop,
    unfiltered_addresses: list[tuple[str, ...]],
) -> None:
    fake_loop.results = []

    with pytest.raises(ScopeValidationError) as error:
        _compose(AddressPolicy.PUBLIC)

    assert fake_loop.calls == [(_HOST, _PORT)]
    assert unfiltered_addresses == [()]
    assert error.value.code is ScopeErrorCode.NO_RESOLVED_ADDRESSES
