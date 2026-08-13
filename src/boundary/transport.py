"""Pinned HTTPCore backend that dials a prevalidated IP."""

from collections.abc import Iterable
from ipaddress import ip_address

import httpcore


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
