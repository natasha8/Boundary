"""Pinned HTTPCore backend and controlled HTTP transport."""

import math
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address

import httpcore

from boundary.scope import (
    AddressPolicy,
    AddressResolver,
    Origin,
    TargetUrl,
    require_allowed_origin,
    resolve_allowed_addresses,
    resolve_allowed_redirect,
)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class TransportErrorCode(StrEnum):
    """Stable machine-readable codes for transport failures."""

    RESPONSE_TOO_LARGE = "response_too_large"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    REDIRECT_LOOP = "redirect_loop"
    INVALID_REDIRECT = "invalid_redirect"
    CROSS_ORIGIN_CREDENTIAL_REDIRECT = "cross_origin_credential_redirect"


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
    final_target: TargetUrl


_CREDENTIAL_HEADER_ALLOWLIST = frozenset({b"authorization", b"cookie"})


@dataclass(frozen=True, slots=True)
class OriginBoundCredentials:
    """Ephemeral credential headers bound to one exact origin."""

    origin: Origin
    headers: tuple[tuple[bytes, bytes], ...]

    def __post_init__(self) -> None:
        if not self.headers:
            raise ValueError("Origin-bound credentials cannot be empty.")

        seen: set[bytes] = set()
        for pair in self.headers:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or type(pair[0]) is not bytes
                or type(pair[1]) is not bytes
            ):
                raise ValueError("Credential headers must be a tuple of byte pairs.")

            name, _value = pair
            lowered = name.lower()
            if lowered not in _CREDENTIAL_HEADER_ALLOWLIST:
                raise ValueError("Credential header name is not on the allowlist.")
            if lowered in seen:
                raise ValueError("Credential header name is duplicated.")
            seen.add(lowered)

    def __repr__(self) -> str:
        return (
            f"OriginBoundCredentials(origin={self.origin!r}, "
            f"header_count={len(self.headers)})"
        )

    def __str__(self) -> str:
        return repr(self)


@dataclass(frozen=True, slots=True)
class ConnectionReuseKey:
    """Identity under which a keep-alive connection may be shared."""

    scheme: str
    host: str
    port: int
    pinned_ip: str


def connection_reuse_key(
    target: TargetUrl,
    pinned_ip: str,
) -> ConnectionReuseKey:
    """Build a reuse key from a normalized target and a prevalidated pinned IP."""
    return ConnectionReuseKey(
        scheme=target.scheme,
        host=target.host,
        port=target.port,
        pinned_ip=str(ip_address(pinned_ip)),
    )


def _validate_timeout(name: str, value: float | None) -> None:
    if value is None:
        return
    if value < 0 or not math.isfinite(value):
        raise ValueError(f"{name} timeout must be None, 0, or a positive finite float.")


@dataclass(frozen=True, slots=True)
class RequestLimits:
    """Validated size and timeout limits for a single transport request."""

    max_body_bytes: int
    connect_timeout: float | None
    read_timeout: float | None
    write_timeout: float | None
    pool_timeout: float | None

    def __post_init__(self) -> None:
        if self.max_body_bytes < 0:
            raise ValueError("Maximum response body size cannot be negative.")
        _validate_timeout("connect", self.connect_timeout)
        _validate_timeout("read", self.read_timeout)
        _validate_timeout("write", self.write_timeout)
        _validate_timeout("pool", self.pool_timeout)


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
    limits: RequestLimits,
) -> TransportResponse:
    """Send one HTTP request through a pinned connection without following redirects."""
    inner = httpcore.AnyIOBackend()
    backend = PinnedAsyncNetworkBackend(pinned_ip, inner)

    extensions = {
        "timeout": {
            "connect": limits.connect_timeout,
            "read": limits.read_timeout,
            "write": limits.write_timeout,
            "pool": limits.pool_timeout,
        }
    }

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
            extensions=extensions,
        ) as response:
            body = bytearray()

            async for chunk in response.aiter_stream():
                if len(body) + len(chunk) > limits.max_body_bytes:
                    raise TransportError(
                        TransportErrorCode.RESPONSE_TOO_LARGE,
                        "Response body exceeds the configured limit.",
                    )

                body.extend(chunk)

            return TransportResponse(
                status=response.status,
                headers=tuple(response.headers),
                body=bytes(body),
                final_target=target,
            )


def _unique_location(headers: Collection[tuple[bytes, bytes]]) -> bytes | None:
    """Return the unique Location value, or None if absent."""
    locations = [value for name, value in headers if name.lower() == b"location"]
    if not locations:
        return None
    if len(locations) > 1:
        raise TransportError(
            TransportErrorCode.INVALID_REDIRECT,
            "Redirect response contains multiple Location headers.",
        )
    return locations[0]


def _credential_request_headers(
    headers: Collection[tuple[bytes, bytes]],
    credentials: OriginBoundCredentials,
) -> tuple[tuple[bytes, bytes], ...]:
    """Merge caller headers with origin-bound credentials, rejecting overlap."""
    for name, _value in headers:
        if name.lower() in _CREDENTIAL_HEADER_ALLOWLIST:
            raise ValueError("Caller headers overlap the credential header bag.")
    return tuple(headers) + credentials.headers


async def request_with_redirects(
    target: TargetUrl,
    *,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: AddressResolver,
    limits: RequestLimits,
    max_redirects: int,
    method: str = "GET",
    headers: Collection[tuple[bytes, bytes]] = (),
    credentials: OriginBoundCredentials | None = None,
) -> TransportResponse:
    """Send an HTTP request and follow in-scope redirects under hop and loop limits."""
    if max_redirects < 0:
        raise ValueError("max_redirects must be non-negative")

    hop_headers: Collection[tuple[bytes, bytes]] = headers
    if credentials is not None:
        if target.origin != credentials.origin:
            raise ValueError(
                "The initial request origin differs from the bound origin."
            )
        hop_headers = _credential_request_headers(headers, credentials)

    current = target
    visited: set[str] = set()
    redirects_followed = 0

    while True:
        require_allowed_origin(
            current,
            allowed_origins,
        )

        addresses = await resolve_allowed_addresses(
            current.host,
            current.port,
            policy,
            resolver,
        )

        pinned_ip = addresses[0]

        visited.add(current.url)

        response = await request_once(
            current,
            pinned_ip,
            method=method,
            headers=hop_headers,
            limits=limits,
        )

        if response.status not in _REDIRECT_STATUSES:
            return response

        location_value = _unique_location(response.headers)
        if location_value is None:
            return response

        location = location_value.decode("ascii")

        next_target = resolve_allowed_redirect(
            current=current,
            location=location,
            allowed_origins=allowed_origins,
        )

        if redirects_followed >= max_redirects:
            raise TransportError(
                TransportErrorCode.TOO_MANY_REDIRECTS,
                "Maximum redirect count exceeded.",
            )

        if next_target.url in visited:
            raise TransportError(
                TransportErrorCode.REDIRECT_LOOP,
                "Redirect loop detected.",
            )

        if credentials is not None and next_target.origin != credentials.origin:
            raise TransportError(
                TransportErrorCode.CROSS_ORIGIN_CREDENTIAL_REDIRECT,
                "The redirect destination origin differs from the bound origin.",
            )

        redirects_followed += 1
        current = next_target
