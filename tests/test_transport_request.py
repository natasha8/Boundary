import asyncio
import contextlib
import math
import socket
import ssl
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import FrozenInstanceError, dataclass
from typing import Protocol

import anyio
import httpcore
import pytest

from boundary.scope import parse_target_url
from boundary.transport import (
    PinnedAsyncNetworkBackend,
    RequestLimits,
    TransportError,
    TransportErrorCode,
    TransportResponse,
    request_once,
)

_PINNED_IPV4 = "93.184.216.34"
_HOSTNAME = "example.com"


@dataclass(frozen=True, slots=True)
class ConnectTcpCall:
    """One recorded inner connect_tcp invocation."""

    host: str
    port: int
    timeout: float | None = None


@dataclass(frozen=True, slots=True)
class StartTlsCall:
    """One recorded start_tls invocation."""

    server_hostname: str | None
    timeout: float | None = None


class FakeHttpStream(httpcore.AsyncNetworkStream):
    """In-memory HTTP/1.1 stream that records I/O and performs no network operations."""

    def __init__(
        self,
        response: bytes,
        *,
        read_error: BaseException | None = None,
        read_chunk_size: int | None = None,
    ) -> None:
        self._buffer = bytearray(response)
        self._writes = bytearray()
        self._read_error = read_error
        self._read_chunk_size = read_chunk_size
        self.start_tls_calls: list[StartTlsCall] = []
        self.read_timeouts: list[float | None] = []
        self.write_timeouts: list[float | None] = []
        self.aclose_calls = 0
        self.bytes_delivered = 0

    @property
    def request_bytes(self) -> bytes:
        """Return the raw HTTP request bytes written by HTTPCore."""
        return bytes(self._writes)

    @property
    def closed(self) -> bool:
        """Return whether aclose() has been called."""
        return self.aclose_calls > 0

    @property
    def unread(self) -> bytes:
        """Return response bytes that have not yet been delivered to HTTPCore."""
        return bytes(self._buffer)

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self.read_timeouts.append(timeout)
        if not self._buffer:
            if self._read_error is not None:
                raise self._read_error
            return b""
        limit = max_bytes
        if self._read_chunk_size is not None:
            limit = min(limit, self._read_chunk_size)
        chunk = bytes(self._buffer[:limit])
        del self._buffer[:limit]
        self.bytes_delivered += len(chunk)
        return chunk

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.write_timeouts.append(timeout)
        self._writes.extend(buffer)

    async def aclose(self) -> None:
        self.aclose_calls += 1

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.start_tls_calls.append(
            StartTlsCall(server_hostname=server_hostname, timeout=timeout)
        )
        return self


class RecordingBackend(httpcore.AsyncNetworkBackend):
    """Inner backend that records connect_tcp and performs no network I/O."""

    def __init__(self, stream: FakeHttpStream) -> None:
        self.stream = stream
        self.connect_tcp_calls: list[ConnectTcpCall] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connect_tcp_calls.append(
            ConnectTcpCall(host=host, port=port, timeout=timeout)
        )
        return self.stream

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise AssertionError("Unix-domain sockets must not be used")

    async def sleep(self, seconds: float) -> None:
        raise AssertionError("sleep must not be called when retries are disabled")


@dataclass(slots=True)
class RecordingHttp:
    """Installed fake inner backend and the stream it returns."""

    inner: RecordingBackend
    stream: FakeHttpStream


class RecordingHttpFactory(Protocol):
    def __call__(
        self,
        *,
        response: bytes,
        read_error: BaseException | None = None,
        read_chunk_size: int | None = None,
    ) -> RecordingHttp: ...


def _limits(
    *,
    max_body_bytes: int = 1024,
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
    write_timeout: float | None = None,
    pool_timeout: float | None = None,
) -> RequestLimits:
    return RequestLimits(
        max_body_bytes=max_body_bytes,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        write_timeout=write_timeout,
        pool_timeout=pool_timeout,
    )


def _http_response(
    *,
    status: int = 200,
    reason: str = "OK",
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
) -> bytes:
    status_line = f"HTTP/1.1 {status} {reason}\r\n"
    header_lines = "".join(f"{name}: {value}\r\n" for name, value in headers)
    if not any(name.lower() == "content-length" for name, _ in headers):
        header_lines += f"Content-Length: {len(body)}\r\n"
    return (status_line + header_lines + "\r\n").encode("ascii") + body


def _host_header(request_bytes: bytes) -> bytes:
    for line in request_bytes.split(b"\r\n"):
        if line.lower().startswith(b"host:"):
            return line.split(b":", 1)[1].strip()
    raise AssertionError("Host header is missing from the HTTP request")


def _request_line(request_bytes: bytes) -> bytes:
    return request_bytes.split(b"\r\n", 1)[0]


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if request_once performs DNS or real TCP I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)


@pytest.fixture
def recording_http(monkeypatch: pytest.MonkeyPatch) -> RecordingHttpFactory:
    """Inject a recording inner backend into the real pinned backend."""

    def factory(
        *,
        response: bytes,
        read_error: BaseException | None = None,
        read_chunk_size: int | None = None,
    ) -> RecordingHttp:
        stream = FakeHttpStream(
            response=response,
            read_error=read_error,
            read_chunk_size=read_chunk_size,
        )
        inner = RecordingBackend(stream=stream)
        original_init = PinnedAsyncNetworkBackend.__init__

        def _init(
            self: PinnedAsyncNetworkBackend,
            pinned_ip: str,
            inner_backend: httpcore.AsyncNetworkBackend,
        ) -> None:
            original_init(self, pinned_ip, inner)

        monkeypatch.setattr(PinnedAsyncNetworkBackend, "__init__", _init)
        return RecordingHttp(inner=inner, stream=stream)

    return factory


def test_response_too_large_code_is_stable() -> None:
    assert TransportErrorCode.RESPONSE_TOO_LARGE.value == "response_too_large"


def test_request_limits_are_immutable() -> None:
    limits = _limits(max_body_bytes=8, connect_timeout=1.0)

    with pytest.raises(FrozenInstanceError):
        limits.max_body_bytes = 16  # type: ignore[misc]


def test_request_limits_accepts_finite_timeouts() -> None:
    limits = RequestLimits(
        max_body_bytes=512,
        connect_timeout=1.25,
        read_timeout=2.5,
        write_timeout=3.75,
        pool_timeout=4.0,
    )

    assert limits.max_body_bytes == 512
    assert limits.connect_timeout == 1.25
    assert limits.read_timeout == 2.5
    assert limits.write_timeout == 3.75
    assert limits.pool_timeout == 4.0


def test_request_limits_accepts_none_timeouts() -> None:
    limits = RequestLimits(
        max_body_bytes=0,
        connect_timeout=None,
        read_timeout=None,
        write_timeout=None,
        pool_timeout=None,
    )

    assert limits.connect_timeout is None
    assert limits.read_timeout is None
    assert limits.write_timeout is None
    assert limits.pool_timeout is None


def test_request_limits_accepts_zero_timeouts() -> None:
    limits = RequestLimits(
        max_body_bytes=1,
        connect_timeout=0.0,
        read_timeout=0.0,
        write_timeout=0.0,
        pool_timeout=0.0,
    )

    assert limits.connect_timeout == 0.0
    assert limits.read_timeout == 0.0
    assert limits.write_timeout == 0.0
    assert limits.pool_timeout == 0.0


def test_negative_max_body_bytes_is_rejected() -> None:
    with pytest.raises(ValueError):
        _limits(max_body_bytes=-1)


@pytest.mark.parametrize(
    ("connect_timeout", "read_timeout", "write_timeout", "pool_timeout"),
    [
        (-0.1, None, None, None),
        (None, -1.0, None, None),
        (None, None, -2.5, None),
        (None, None, None, -3.0),
    ],
)
def test_negative_timeout_is_rejected(
    connect_timeout: float | None,
    read_timeout: float | None,
    write_timeout: float | None,
    pool_timeout: float | None,
) -> None:
    with pytest.raises(ValueError):
        RequestLimits(
            max_body_bytes=1024,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
            pool_timeout=pool_timeout,
        )


@pytest.mark.parametrize(
    ("connect_timeout", "read_timeout", "write_timeout", "pool_timeout"),
    [
        (math.nan, None, None, None),
        (None, math.nan, None, None),
        (None, None, math.nan, None),
        (None, None, None, math.nan),
    ],
)
def test_nan_timeout_is_rejected(
    connect_timeout: float | None,
    read_timeout: float | None,
    write_timeout: float | None,
    pool_timeout: float | None,
) -> None:
    with pytest.raises(ValueError):
        RequestLimits(
            max_body_bytes=1024,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
            pool_timeout=pool_timeout,
        )


@pytest.mark.parametrize(
    ("connect_timeout", "read_timeout", "write_timeout", "pool_timeout"),
    [
        (math.inf, None, None, None),
        (None, math.inf, None, None),
        (None, None, math.inf, None),
        (None, None, None, math.inf),
        (-math.inf, None, None, None),
        (None, -math.inf, None, None),
        (None, None, -math.inf, None),
        (None, None, None, -math.inf),
    ],
)
def test_infinite_timeout_is_rejected(
    connect_timeout: float | None,
    read_timeout: float | None,
    write_timeout: float | None,
    pool_timeout: float | None,
) -> None:
    with pytest.raises(ValueError):
        RequestLimits(
            max_body_bytes=1024,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            write_timeout=write_timeout,
            pool_timeout=pool_timeout,
        )


def test_http_tcp_connects_to_pinned_ip_not_hostname(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("http://example.com/")

    response = asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(),
        )
    )

    assert isinstance(response, TransportResponse)
    assert recorded.inner.connect_tcp_calls == [
        ConnectTcpCall(host=_PINNED_IPV4, port=80)
    ]
    assert recorded.inner.connect_tcp_calls[0].host != _HOSTNAME
    assert recorded.stream.start_tls_calls == []
    assert recorded.stream.closed


def test_http_request_host_header_uses_target_host_not_pinned_ip(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("http://example.com/")

    asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(),
        )
    )

    host = _host_header(recorded.stream.request_bytes)
    assert host == _HOSTNAME.encode("ascii")
    assert host != _PINNED_IPV4.encode("ascii")
    assert _PINNED_IPV4.encode("ascii") not in recorded.stream.request_bytes


def test_https_start_tls_uses_target_host_sni_and_pinned_tcp(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("https://example.com/")

    asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(),
        )
    )

    assert recorded.inner.connect_tcp_calls == [
        ConnectTcpCall(host=_PINNED_IPV4, port=443)
    ]
    assert recorded.stream.start_tls_calls == [StartTlsCall(server_hostname=_HOSTNAME)]
    assert _host_header(recorded.stream.request_bytes) == _HOSTNAME.encode("ascii")
    assert recorded.stream.closed


def test_non_default_port_is_preserved_on_tcp_and_host_header(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("http://example.com:8080/api")

    asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(),
        )
    )

    assert recorded.inner.connect_tcp_calls == [
        ConnectTcpCall(host=_PINNED_IPV4, port=8080)
    ]
    assert _request_line(recorded.stream.request_bytes) == b"GET /api HTTP/1.1"
    assert _host_header(recorded.stream.request_bytes) == b"example.com:8080"
    assert recorded.stream.closed


def test_response_preserves_status_raw_headers_and_body(
    recording_http: RecordingHttpFactory,
) -> None:
    body = b"hi\xff\x00z"
    recorded = recording_http(
        response=_http_response(
            status=201,
            reason="Created",
            headers=(("X-Test", "Ok"), ("Content-Type", "application/octet-stream")),
            body=body,
        )
    )
    target = parse_target_url("http://example.com/")

    response = asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(),
        )
    )

    assert response.status == 201
    assert isinstance(response.headers, tuple)
    assert (b"X-Test", b"Ok") in response.headers
    assert (b"Content-Type", b"application/octet-stream") in response.headers
    assert response.body == body
    assert recorded.stream.closed


def test_body_exactly_at_max_body_bytes_is_accepted(
    recording_http: RecordingHttpFactory,
) -> None:
    body = b"12345678"
    recorded = recording_http(response=_http_response(body=body))
    target = parse_target_url("http://example.com/")

    response = asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(max_body_bytes=len(body)),
        )
    )

    assert response.body == body
    assert recorded.stream.closed


def test_body_exceeding_max_body_bytes_stops_reading_and_closes(
    recording_http: RecordingHttpFactory,
) -> None:
    body = b"abcdefghij"
    recorded = recording_http(
        response=_http_response(body=body),
        read_chunk_size=1,
    )
    target = parse_target_url("http://example.com/")

    with pytest.raises(TransportError) as caught:
        asyncio.run(
            request_once(
                target,
                _PINNED_IPV4,
                limits=_limits(max_body_bytes=3),
            )
        )

    assert caught.value.code is TransportErrorCode.RESPONSE_TOO_LARGE
    assert recorded.stream.unread == b"efghij"
    assert recorded.stream.closed


def test_zero_max_body_bytes_accepts_empty_body(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b""))
    target = parse_target_url("http://example.com/")

    response = asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(max_body_bytes=0),
        )
    )

    assert response.body == b""
    assert recorded.stream.closed


def test_zero_max_body_bytes_rejects_any_response_byte(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"x"))
    target = parse_target_url("http://example.com/")

    with pytest.raises(TransportError) as caught:
        asyncio.run(
            request_once(
                target,
                _PINNED_IPV4,
                limits=_limits(max_body_bytes=0),
            )
        )

    assert caught.value.code is TransportErrorCode.RESPONSE_TOO_LARGE
    assert recorded.stream.closed


def test_302_response_is_returned_and_not_followed(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(
        response=_http_response(
            status=302,
            reason="Found",
            headers=(("Location", "http://example.com/other"),),
            body=b"",
        )
    )
    target = parse_target_url("http://example.com/")

    response = asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(),
        )
    )

    assert response.status == 302
    assert (b"Location", b"http://example.com/other") in response.headers
    assert recorded.inner.connect_tcp_calls == [
        ConnectTcpCall(host=_PINNED_IPV4, port=80)
    ]
    assert recorded.stream.request_bytes.count(b"GET ") == 1
    assert _request_line(recorded.stream.request_bytes) == b"GET / HTTP/1.1"
    assert b"GET /other" not in recorded.stream.request_bytes
    assert recorded.stream.closed


def test_stream_read_exception_propagates_and_closes_resources(
    recording_http: RecordingHttpFactory,
) -> None:
    error = RuntimeError("stream read failed")
    recorded = recording_http(
        response=_http_response(headers=(("Content-Length", "10"),), body=b""),
        read_error=error,
    )
    target = parse_target_url("http://example.com/")

    with pytest.raises(RuntimeError) as caught:
        asyncio.run(
            request_once(
                target,
                _PINNED_IPV4,
                limits=_limits(),
            )
        )

    assert caught.value is error
    assert recorded.stream.closed


def test_connect_timeout_is_passed_to_connect_tcp(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("http://example.com/")

    asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(
                connect_timeout=1.5,
                read_timeout=2.5,
                write_timeout=3.5,
                pool_timeout=4.5,
            ),
        )
    )

    assert recorded.inner.connect_tcp_calls == [
        ConnectTcpCall(host=_PINNED_IPV4, port=80, timeout=1.5)
    ]


def test_read_timeout_is_passed_to_stream_read(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("http://example.com/")

    asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(
                connect_timeout=1.5,
                read_timeout=2.5,
                write_timeout=3.5,
                pool_timeout=4.5,
            ),
        )
    )

    assert recorded.stream.read_timeouts
    assert recorded.stream.read_timeouts == [2.5] * len(recorded.stream.read_timeouts)


def test_write_timeout_is_passed_to_stream_write(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("http://example.com/")

    asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(
                connect_timeout=1.5,
                read_timeout=2.5,
                write_timeout=3.5,
                pool_timeout=4.5,
            ),
        )
    )

    assert recorded.stream.write_timeouts
    assert recorded.stream.write_timeouts == [3.5] * len(recorded.stream.write_timeouts)


def test_https_start_tls_receives_connect_timeout(
    recording_http: RecordingHttpFactory,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("https://example.com/")

    asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=_limits(
                connect_timeout=1.5,
                read_timeout=2.5,
                write_timeout=3.5,
                pool_timeout=4.5,
            ),
        )
    )

    assert recorded.stream.start_tls_calls == [
        StartTlsCall(server_hostname=_HOSTNAME, timeout=1.5)
    ]


def test_request_passes_httpcore_timeout_extension(
    recording_http: RecordingHttpFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = recording_http(response=_http_response(body=b"ok"))
    target = parse_target_url("http://example.com/")
    captured: list[object] = []
    original_stream = httpcore.AsyncConnectionPool.stream
    limits = _limits(
        connect_timeout=1.5,
        read_timeout=2.5,
        write_timeout=3.5,
        pool_timeout=4.5,
    )

    @contextlib.asynccontextmanager
    async def capture_stream(
        self: httpcore.AsyncConnectionPool,
        method: bytes | str,
        url: httpcore.URL | bytes | str,
        *,
        headers: (
            Sequence[tuple[bytes | str, bytes | str]]
            | Mapping[bytes | str, bytes | str]
            | None
        ) = None,
        content: bytes | None = None,
        extensions: dict[str, object] | None = None,
    ) -> AsyncIterator[httpcore.Response]:
        captured.append(extensions)
        async with original_stream(
            self,
            method,
            url,
            headers=headers,
            content=content,
            extensions=extensions,
        ) as response:
            yield response

    monkeypatch.setattr(httpcore.AsyncConnectionPool, "stream", capture_stream)

    asyncio.run(
        request_once(
            target,
            _PINNED_IPV4,
            limits=limits,
        )
    )

    assert captured == [
        {
            "timeout": {
                "connect": 1.5,
                "read": 2.5,
                "write": 3.5,
                "pool": 4.5,
            }
        }
    ]
    assert recorded.stream.closed
