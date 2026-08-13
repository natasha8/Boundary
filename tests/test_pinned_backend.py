import asyncio
import socket
from collections.abc import Iterable
from dataclasses import dataclass

import httpcore
import pytest
from boundary.transport import PinnedAsyncNetworkBackend

_PINNED_IPV4 = "93.184.216.34"
_PINNED_IPV6 = "2001:db8::1"
_HOSTNAME = "example.com"


@dataclass(frozen=True, slots=True)
class ConnectTcpCall:
    """One recorded inner connect_tcp invocation."""

    host: str
    port: int
    timeout: float | None
    local_address: str | None
    socket_options: Iterable[httpcore.SOCKET_OPTION] | None


class FakeNetworkStream(httpcore.AsyncNetworkStream):
    """Smallest stream double used only to assert return identity."""


class RecordingBackend(httpcore.AsyncNetworkBackend):
    """Inner backend that records calls and performs no network I/O."""

    def __init__(
        self,
        stream: httpcore.AsyncNetworkStream | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.connect_tcp_calls: list[ConnectTcpCall] = []
        self.connect_unix_socket_calls: list[str] = []
        self.sleep_calls: list[float] = []
        self.stream: httpcore.AsyncNetworkStream = (
            stream if stream is not None else FakeNetworkStream()
        )
        self.error = error

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connect_tcp_calls.append(
            ConnectTcpCall(
                host=host,
                port=port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
            )
        )
        if self.error is not None:
            raise self.error
        return self.stream

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connect_unix_socket_calls.append(path)
        raise AssertionError("Unix-domain sockets must not be forwarded")

    async def sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


@pytest.fixture(autouse=True)
def _reject_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if the pinned backend performs DNS resolution."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)


def test_constructor_accepts_ipv4_literal() -> None:
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV4,
        inner=RecordingBackend(),
    )

    assert isinstance(backend, httpcore.AsyncNetworkBackend)


def test_constructor_accepts_ipv6_literal() -> None:
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV6,
        inner=RecordingBackend(),
    )

    assert isinstance(backend, httpcore.AsyncNetworkBackend)


def test_constructor_rejects_hostname() -> None:
    with pytest.raises(ValueError):
        PinnedAsyncNetworkBackend(
            pinned_ip=_HOSTNAME,
            inner=RecordingBackend(),
        )


@pytest.mark.parametrize(
    "pinned_ip",
    [
        "",
        "not-an-ip",
        "256.256.256.256",
        "93.184.216.34:443",
        "2001:db8::1/64",
        "[2001:db8::1]",
    ],
)
def test_constructor_rejects_malformed_ip(pinned_ip: str) -> None:
    with pytest.raises(ValueError):
        PinnedAsyncNetworkBackend(
            pinned_ip=pinned_ip,
            inner=RecordingBackend(),
        )


def test_connect_tcp_calls_inner_once_with_pinned_ip_not_hostname() -> None:
    inner = RecordingBackend()
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV4,
        inner=inner,
    )

    asyncio.run(
        backend.connect_tcp(
            host=_HOSTNAME,
            port=443,
            timeout=5.0,
            local_address=None,
            socket_options=None,
        )
    )

    assert len(inner.connect_tcp_calls) == 1
    call = inner.connect_tcp_calls[0]
    assert call.host == _PINNED_IPV4
    assert call.host != _HOSTNAME
    assert call.port == 443


def test_connect_tcp_preserves_port_timeout_local_address_and_socket_options() -> None:
    inner = RecordingBackend()
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV4,
        inner=inner,
    )
    socket_options: list[httpcore.SOCKET_OPTION] = [
        (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
    ]
    local_address = "192.0.2.10"

    asyncio.run(
        backend.connect_tcp(
            host=_HOSTNAME,
            port=8443,
            timeout=2.5,
            local_address=local_address,
            socket_options=socket_options,
        )
    )

    assert inner.connect_tcp_calls == [
        ConnectTcpCall(
            host=_PINNED_IPV4,
            port=8443,
            timeout=2.5,
            local_address=local_address,
            socket_options=socket_options,
        )
    ]
    call = inner.connect_tcp_calls[0]
    assert call.local_address is local_address
    assert call.socket_options is socket_options


def test_connect_tcp_returns_inner_stream_identity() -> None:
    stream = FakeNetworkStream()
    inner = RecordingBackend(stream=stream)
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV4,
        inner=inner,
    )

    returned = asyncio.run(
        backend.connect_tcp(
            host=_HOSTNAME,
            port=443,
            timeout=5.0,
            local_address=None,
            socket_options=None,
        )
    )

    assert returned is stream


def test_connect_tcp_forwards_ipv6_literal_unchanged() -> None:
    inner = RecordingBackend()
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV6,
        inner=inner,
    )

    asyncio.run(
        backend.connect_tcp(
            host=_HOSTNAME,
            port=443,
            timeout=5.0,
            local_address=None,
            socket_options=None,
        )
    )

    assert inner.connect_tcp_calls[0].host == _PINNED_IPV6


def test_connect_tcp_propagates_inner_exception_unchanged() -> None:
    error = RuntimeError("inner connect failed")
    inner = RecordingBackend(error=error)
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV4,
        inner=inner,
    )

    with pytest.raises(RuntimeError) as caught:
        asyncio.run(
            backend.connect_tcp(
                host=_HOSTNAME,
                port=443,
                timeout=5.0,
                local_address=None,
                socket_options=None,
            )
        )

    assert caught.value is error


def test_connect_unix_socket_is_refused() -> None:
    inner = RecordingBackend()
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV4,
        inner=inner,
    )

    with pytest.raises(NotImplementedError):
        asyncio.run(
            backend.connect_unix_socket(
                path="/tmp/boundary.sock",
                timeout=1.0,
                socket_options=None,
            )
        )

    assert inner.connect_unix_socket_calls == []
    assert inner.connect_tcp_calls == []


def test_sleep_delegates_to_inner_with_exact_duration() -> None:
    inner = RecordingBackend()
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV4,
        inner=inner,
    )

    asyncio.run(backend.sleep(1.5))

    assert inner.sleep_calls == [1.5]


def test_connect_tcp_does_not_perform_dns_resolution() -> None:
    inner = RecordingBackend()
    backend = PinnedAsyncNetworkBackend(
        pinned_ip=_PINNED_IPV4,
        inner=inner,
    )

    asyncio.run(
        backend.connect_tcp(
            host=_HOSTNAME,
            port=443,
            timeout=5.0,
            local_address=None,
            socket_options=None,
        )
    )

    assert inner.connect_tcp_calls[0].host == _PINNED_IPV4
