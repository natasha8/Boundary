"""Pinned HTTPCore backend and single-request HTTP transport."""

from collections.abc import Collection, Iterable
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address

import httpcore

from boundary.scope import TargetUrl


class TransportErrorCode(StrEnum):
    """Stable machine-readable codes for transport failures."""

    RESPONSE_TOO_LARGE = "response_too_large"


class TransportError(RuntimeError):
    """Raised when a transport request fails a safety limit."""

    def __init__(self, code: TransportErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """Immutable HTTP response from a single transport request."""

    status: int
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes


class PinnedAsyncNetworkBackend(httpcore.AsyncNetworkBackend):
    """HTTPCore backend that dials a prevalidated IP and ignores the requested host."""

    def __init__(
        self,
        pinned_ip: str,
        inner: httpcore.AsyncNetworkBackend,
    ) -> None:
        self._pinned_ip = str(ip_address(pinned_ip))
        self._inner = inner

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._inner.connect_tcp(
            host=self._pinned_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise NotImplementedError(
            "Unix-domain sockets are not supported by the pinned backend."
        )

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


async def request_once(
    target: TargetUrl,
    pinned_ip: str,
    *,
    method: str = "GET",
    headers: Collection[tuple[bytes, bytes]] = (),
    max_body_bytes: int,
) -> TransportResponse:
    """Send one HTTP request through a pinned connection without following redirects."""
    if max_body_bytes < 0:
        raise ValueError("Maximum response body size cannot be negative.")

    inner = httpcore.AnyIOBackend()
    backend = PinnedAsyncNetworkBackend(pinned_ip, inner)

    async with httpcore.AsyncConnectionPool(
        network_backend=backend,
        max_connections=1,
        max_keepalive_connections=0,
        http1=True,
        http2=False,
        retries=0,
        uds=None,
    ) as pool:
        async with pool.stream(
            method,
            target.url,
            headers=tuple(headers),
        ) as response:
            body = bytearray()

            async for chunk in response.aiter_stream():
                if len(body) + len(chunk) > max_body_bytes:
                    raise TransportError(
                        TransportErrorCode.RESPONSE_TOO_LARGE,
                        "Response body exceeds the configured limit.",
                    )

                body.extend(chunk)

            return TransportResponse(
                status=response.status,
                headers=tuple(response.headers),
                body=bytes(body),
            )
