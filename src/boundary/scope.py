from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit


class UrlErrorCode(StrEnum):
    MALFORMED_URL = "malformed_url"
    UNSUPPORTED_SCHEME = "unsupported_scheme"
    MISSING_HOST = "missing_host"
    INVALID_HOST = "invalid_host"
    EMBEDDED_CREDENTIALS = "embedded_credentials"
    INVALID_PORT = "invalid_port"
    UNSAFE_CHARACTER = "unsafe_character"
    NON_ASCII_HOST = "non_ascii_host"


class UrlValidationError(ValueError):
    def __init__(self, code: UrlErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TargetUrl:
    scheme: str
    host: str
    port: int
    path: str
    query: str
    url: str


_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


def parse_target_url(raw: str) -> TargetUrl:
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

    host = _normalize_host(host)

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

    default_port = _DEFAULT_PORTS[scheme]
    port = default_port if parsed_port is None else parsed_port

    if not 1 <= port <= 65535:
        raise UrlValidationError(
            UrlErrorCode.INVALID_PORT,
            "Target URL port must be between 1 and 65535.",
        )

    path = parsed.path or "/"
    display_host = f"[{host}]" if ":" in host else host

    netloc = display_host if port == default_port else f"{display_host}:{port}"

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
