"""Target URL parsing and scope allowlist checks for BOUNDARY."""

from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
)
from typing import Protocol
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit


class UrlErrorCode(StrEnum):
    """Stable machine-readable codes for URL validation failures."""

    MALFORMED_URL = "malformed_url"
    UNSUPPORTED_SCHEME = "unsupported_scheme"
    MISSING_HOST = "missing_host"
    INVALID_HOST = "invalid_host"
    EMBEDDED_CREDENTIALS = "embedded_credentials"
    INVALID_PORT = "invalid_port"
    UNSAFE_CHARACTER = "unsafe_character"
    NON_ASCII_HOST = "non_ascii_host"


class UrlValidationError(ValueError):
    """Raised when a target URL fails structural validation."""

    def __init__(self, code: UrlErrorCode, message: str) -> None:
        """Attach a stable error code to the validation failure."""
        self.code = code
        super().__init__(message)


class ScopeErrorCode(StrEnum):
    """Stable machine-readable codes for scope validation failures."""

    ORIGIN_NOT_ALLOWED = "origin_not_allowed"
    INVALID_IP_ADDRESS = "invalid_ip_address"
    ADDRESS_NOT_ALLOWED = "address_not_allowed"
    NO_RESOLVED_ADDRESSES = "no_resolved_addresses"


class AddressPolicy(StrEnum):
    """Policies that classify which resolved IP addresses are allowed."""

    PUBLIC = "public"
    LOCAL_LAB = "local_lab"


class AddressResolver(Protocol):
    """Minimal async resolver used to obtain addresses for a host."""

    async def resolve(
        self,
        host: str,
        port: int,
    ) -> Collection[str]: ...


class ScopeValidationError(ValueError):
    """Raised when a target is outside the configured scope."""

    def __init__(self, code: ScopeErrorCode, message: str) -> None:
        """Attach a stable error code to the scope failure."""
        self.code = code
        super().__init__(message)


_LOCAL_LAB_IPV4_NETWORKS = (
    IPv4Network("127.0.0.0/8"),
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("169.254.0.0/16"),
)

_LOCAL_LAB_IPV6_NETWORKS = (
    IPv6Network("::1/128"),
    IPv6Network("fe80::/10"),
    IPv6Network("fc00::/7"),
)

_NON_LAB_SPECIAL_USE_IPV6_NETWORKS = (
    IPv6Network("64:ff9b::/96"),
    IPv6Network("::ffff:0:0:0/96"),
    IPv6Network("::/96"),
    IPv6Network("fec0::/10"),
    IPv6Network("2001:20::/28"),
    IPv6Network("5f00::/16"),
)


@dataclass(frozen=True, slots=True)
class Origin:
    """Immutable scheme/host/port identity used for exact allowlist matching."""

    scheme: str
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class TargetUrl:
    """Normalized absolute HTTP(S) target produced by URL parsing."""

    scheme: str
    host: str
    port: int
    path: str
    query: str
    url: str

    @property
    def origin(self) -> Origin:
        """Return the exact origin of this target."""
        return Origin(
            scheme=self.scheme,
            host=self.host,
            port=self.port,
        )


_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


def parse_target_url(raw: str) -> TargetUrl:
    """Parse and normalize an absolute HTTP or HTTPS target URL."""
    if not raw:
        raise UrlValidationError(
            UrlErrorCode.MALFORMED_URL,
            "Target URL cannot be empty.",
        )

    if _contains_unsafe_character(raw):
        raise UrlValidationError(
            UrlErrorCode.UNSAFE_CHARACTER,
            "Target URL contains unsafe characters.",
        )

    try:
        parsed = urlsplit(raw)
    except ValueError as error:
        raise UrlValidationError(
            UrlErrorCode.MALFORMED_URL,
            "Target URL is malformed.",
        ) from error

    if not parsed.scheme:
        raise UrlValidationError(
            UrlErrorCode.MALFORMED_URL,
            "Target URL must be absolute.",
        )

    scheme = parsed.scheme.lower()

    if scheme not in _DEFAULT_PORTS:
        raise UrlValidationError(
            UrlErrorCode.UNSUPPORTED_SCHEME,
            f"Unsupported URL scheme: {scheme}.",
        )

    if parsed.username is not None or parsed.password is not None:
        raise UrlValidationError(
            UrlErrorCode.EMBEDDED_CREDENTIALS,
            "Embedded URL credentials are not allowed.",
        )

    host = _extract_host(parsed)
    default_port = _DEFAULT_PORTS[scheme]
    port = _resolve_port(parsed, default_port)

    if not parsed.path.isascii() or not parsed.query.isascii():
        raise UrlValidationError(
            UrlErrorCode.UNSAFE_CHARACTER,
            "Target URL contains unsafe characters.",
        )

    path = parsed.path or "/"
    netloc = _format_netloc(host, port, default_port)

    normalized_url = urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )

    return TargetUrl(
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=parsed.query,
        url=normalized_url,
    )


def require_allowed_origin(
    target: TargetUrl,
    allowed_origins: Collection[Origin],
) -> None:
    """Require that a target origin is present in the exact allowlist."""
    if target.origin not in allowed_origins:
        raise ScopeValidationError(
            ScopeErrorCode.ORIGIN_NOT_ALLOWED,
            "Target origin is not allowed.",
        )


def resolve_allowed_redirect(
    current: TargetUrl,
    location: str,
    allowed_origins: Collection[Origin],
) -> TargetUrl:
    """Resolve a Location against the current URL and enforce origin allowlisting."""
    if _contains_unsafe_character(location):
        raise UrlValidationError(
            UrlErrorCode.UNSAFE_CHARACTER,
            "Redirect location contains unsafe characters.",
        )

    if not location or location.startswith("#"):
        raise UrlValidationError(
            UrlErrorCode.MALFORMED_URL,
            "Redirect location must identify a new resource.",
        )

    try:
        resolved = urljoin(current.url, location)
    except ValueError as error:
        raise UrlValidationError(
            UrlErrorCode.MALFORMED_URL,
            "Redirect location is malformed.",
        ) from error

    target = parse_target_url(resolved)
    require_allowed_origin(target, allowed_origins)
    return target


def require_allowed_address(
    address: str,
    policy: AddressPolicy,
) -> None:
    """Require that a resolved IP address is allowed by the given policy."""
    _parse_allowed_address(address, policy)


async def resolve_allowed_addresses(
    host: str,
    port: int,
    policy: AddressPolicy,
    resolver: AddressResolver,
) -> tuple[str, ...]:
    """Resolve a host once and require every address under the given policy."""
    addresses = await resolver.resolve(host, port)

    if not addresses:
        raise ScopeValidationError(
            ScopeErrorCode.NO_RESOLVED_ADDRESSES,
            "Host resolved to no addresses.",
        )

    resolved: list[str] = []
    seen: set[str] = set()

    for address in addresses:
        parsed = _parse_allowed_address(address, policy)
        normalized = str(parsed)

        if normalized not in seen:
            seen.add(normalized)
            resolved.append(normalized)

    return tuple(resolved)


def _extract_host(parsed: SplitResult) -> str:
    host = parsed.hostname

    if host is None:
        raise UrlValidationError(
            UrlErrorCode.MISSING_HOST,
            "Target URL must contain a host.",
        )

    if not host.isascii():
        raise UrlValidationError(
            UrlErrorCode.NON_ASCII_HOST,
            "Unicode hostnames must be supplied in ASCII Punycode form.",
        )

    return _normalize_host(host)


def _resolve_port(parsed: SplitResult, default_port: int) -> int:
    if parsed.netloc.endswith(":"):
        raise UrlValidationError(
            UrlErrorCode.INVALID_PORT,
            "Target URL contains an empty port.",
        )

    try:
        parsed_port = parsed.port
    except ValueError as error:
        raise UrlValidationError(
            UrlErrorCode.INVALID_PORT,
            "Target URL contains an invalid port.",
        ) from error

    port = default_port if parsed_port is None else parsed_port

    if not 1 <= port <= 65535:
        raise UrlValidationError(
            UrlErrorCode.INVALID_PORT,
            "Target URL port must be between 1 and 65535.",
        )

    return port


def _format_netloc(host: str, port: int, default_port: int) -> str:
    display_host = f"[{host}]" if ":" in host else host
    if port == default_port:
        return display_host
    return f"{display_host}:{port}"


def _parse_allowed_address(
    address: str,
    policy: AddressPolicy,
) -> IPv4Address | IPv6Address:
    try:
        parsed = ip_address(address)
    except ValueError as error:
        raise ScopeValidationError(
            ScopeErrorCode.INVALID_IP_ADDRESS,
            "IP address is invalid.",
        ) from error

    if not _is_address_allowed(parsed, policy):
        raise ScopeValidationError(
            ScopeErrorCode.ADDRESS_NOT_ALLOWED,
            "IP address is not allowed.",
        )

    return parsed


def _is_address_allowed(
    address: IPv4Address | IPv6Address,
    policy: AddressPolicy,
) -> bool:
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return _is_address_allowed(address.ipv4_mapped, policy)

    if policy is AddressPolicy.LOCAL_LAB and isinstance(address, IPv6Address):
        if any(address in network for network in _LOCAL_LAB_IPV6_NETWORKS):
            return True

    if isinstance(address, IPv6Address) and any(
        address in network for network in _NON_LAB_SPECIAL_USE_IPV6_NETWORKS
    ):
        return False

    if address.is_global and not address.is_multicast:
        return True

    if policy is AddressPolicy.PUBLIC:
        return False

    networks: tuple[IPv4Network, ...] | tuple[IPv6Network, ...]
    if isinstance(address, IPv4Address):
        networks = _LOCAL_LAB_IPV4_NETWORKS
    else:
        networks = _LOCAL_LAB_IPV6_NETWORKS

    return any(address in network for network in networks)


def _normalize_host(host: str) -> str:
    host = host.lower()

    if "%" in host:
        raise UrlValidationError(
            UrlErrorCode.INVALID_HOST,
            "Percent-encoded hostnames are not allowed.",
        )

    if host.endswith("."):
        host = host[:-1]

    if not host:
        raise UrlValidationError(
            UrlErrorCode.MISSING_HOST,
            "Target URL must contain a valid host.",
        )

    # Bracketed IPv6 literals are returned without brackets by urlsplit.
    if ":" not in host and any(label == "" for label in host.split(".")):
        raise UrlValidationError(
            UrlErrorCode.INVALID_HOST,
            "Target URL contains an ambiguous host.",
        )

    return host


def _contains_unsafe_character(raw: str) -> bool:
    return any(
        character == "\\"
        or character.isspace()
        or ord(character) < 32
        or ord(character) == 127
        for character in raw
    )
