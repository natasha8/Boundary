import asyncio
import socket
from typing import Any, cast


class SystemAddressResolver:
    async def resolve(
        self,
        host: str,
        port: int,
    ) -> tuple[str, ...]:
        loop = asyncio.get_running_loop()
        results = cast(
            list[tuple[Any, Any, Any, Any, tuple[str, ...]]],
            await loop.getaddrinfo(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            ),
        )

        return tuple(result[4][0] for result in results)
