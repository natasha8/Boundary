import asyncio
import socket

import pytest
from boundary.resolver import SystemAddressResolver

_HOST = "app.test"
_PORT = 8443


class FakeEventLoop:
    """Minimal loop double that records getaddrinfo calls without network I/O."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.results: list[object] = []
        self.error: BaseException | None = None

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
        self.calls.append(
            {
                "host": host,
                "port": port,
                "family": family,
                "type": type,
                "proto": proto,
                "flags": flags,
            }
        )
        if self.error is not None:
            raise self.error
        return list(self.results)


def _ipv4_addrinfo(
    address: str,
    port: int,
    *,
    canonname: str = "",
) -> tuple[int, int, int, str, tuple[str, int]]:
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        canonname,
        (address, port),
    )


def _ipv6_addrinfo(
    address: str,
    port: int,
    *,
    flowinfo: int = 0,
    scope_id: int = 0,
    canonname: str = "",
) -> tuple[int, int, int, str, tuple[str, int, int, int]]:
    return (
        socket.AF_INET6,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        canonname,
        (address, port, flowinfo, scope_id),
    )


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


@pytest.fixture(autouse=True)
def fake_loop(monkeypatch: pytest.MonkeyPatch) -> FakeEventLoop:
    loop = FakeEventLoop()
    monkeypatch.setattr(asyncio, "get_running_loop", lambda: loop)
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    return loop


def _resolve(host: str = _HOST, port: int = _PORT) -> tuple[str, ...]:
    resolver = SystemAddressResolver()
    return asyncio.run(resolver.resolve(host=host, port=port))


def test_resolve_calls_getaddrinfo_once_with_host_port_family_and_type(
    fake_loop: FakeEventLoop,
) -> None:
    fake_loop.results = [_ipv4_addrinfo("192.0.2.10", _PORT)]

    addresses = _resolve(host=_HOST, port=_PORT)

    assert fake_loop.calls == [
        {
            "host": _HOST,
            "port": _PORT,
            "family": socket.AF_UNSPEC,
            "type": socket.SOCK_STREAM,
            "proto": 0,
            "flags": 0,
        }
    ]
    assert addresses == ("192.0.2.10",)


def test_resolve_extracts_ipv4_address_from_sockaddr(
    fake_loop: FakeEventLoop,
) -> None:
    fake_loop.results = [
        _ipv4_addrinfo(
            "192.0.2.10",
            _PORT,
            canonname="should-not-appear.test",
        )
    ]

    addresses = _resolve()

    assert addresses == ("192.0.2.10",)
    assert isinstance(addresses, tuple)
    assert fake_loop.calls[0]["host"] == _HOST


def test_resolve_extracts_ipv6_address_from_sockaddr(
    fake_loop: FakeEventLoop,
) -> None:
    fake_loop.results = [
        _ipv6_addrinfo(
            "2001:0db8:0000:0000:0000:0000:0000:0001",
            _PORT,
            flowinfo=1,
            scope_id=2,
            canonname="should-not-appear.test",
        )
    ]

    addresses = _resolve()

    assert addresses == ("2001:0db8:0000:0000:0000:0000:0000:0001",)
    assert isinstance(addresses, tuple)


def test_resolve_preserves_mixed_ipv4_and_ipv6_order(
    fake_loop: FakeEventLoop,
) -> None:
    fake_loop.results = [
        _ipv6_addrinfo("2001:db8::1", _PORT),
        _ipv4_addrinfo("192.0.2.10", _PORT),
        _ipv6_addrinfo("2001:db8::2", _PORT),
        _ipv4_addrinfo("198.51.100.10", _PORT),
    ]

    addresses = _resolve()

    assert addresses == (
        "2001:db8::1",
        "192.0.2.10",
        "2001:db8::2",
        "198.51.100.10",
    )


def test_resolve_preserves_duplicate_addresses(
    fake_loop: FakeEventLoop,
) -> None:
    fake_loop.results = [
        _ipv4_addrinfo("192.0.2.10", _PORT),
        _ipv4_addrinfo("192.0.2.10", _PORT),
        _ipv6_addrinfo("2001:db8::1", _PORT),
        _ipv6_addrinfo("2001:db8::1", _PORT),
    ]

    addresses = _resolve()

    assert addresses == (
        "192.0.2.10",
        "192.0.2.10",
        "2001:db8::1",
        "2001:db8::1",
    )


def test_resolve_returns_empty_tuple_for_empty_getaddrinfo_result(
    fake_loop: FakeEventLoop,
) -> None:
    fake_loop.results = []

    addresses = _resolve()

    assert addresses == ()
    assert isinstance(addresses, tuple)
    assert len(fake_loop.calls) == 1


def test_resolve_propagates_getaddrinfo_exception_unchanged(
    fake_loop: FakeEventLoop,
) -> None:
    error = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    fake_loop.error = error

    with pytest.raises(socket.gaierror) as caught:
        _resolve()

    assert caught.value is error
    assert len(fake_loop.calls) == 1
