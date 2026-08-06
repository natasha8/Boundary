import pytest

from boundary.scope import (
    UrlErrorCode,
    UrlValidationError,
    parse_target_url,
)


@pytest.mark.parametrize(
    (
        "raw",
        "scheme",
        "host",
        "port",
        "path",
        "query",
        "normalized",
    ),
    [
        (
            "https://EXAMPLE.com",
            "https",
            "example.com",
            443,
            "/",
            "",
            "https://example.com/",
        ),
        (
            "http://example.com:8080/api/items?limit=10#section",
            "http",
            "example.com",
            8080,
            "/api/items",
            "limit=10",
            "http://example.com:8080/api/items?limit=10",
        ),
        (
            "https://Example.COM.:443/",
            "https",
            "example.com",
            443,
            "/",
            "",
            "https://example.com/",
        ),
        (
            "http://127.0.0.1:3000/health",
            "http",
            "127.0.0.1",
            3000,
            "/health",
            "",
            "http://127.0.0.1:3000/health",
        ),
        (
            "http://[::1]:8080/health",
            "http",
            "::1",
            8080,
            "/health",
            "",
            "http://[::1]:8080/health",
        ),
        (
            "https://localhost/admin",
            "https",
            "localhost",
            443,
            "/admin",
            "",
            "https://localhost/admin",
        ),
        (
            "https://xn--exmple-cua.com/",
            "https",
            "xn--exmple-cua.com",
            443,
            "/",
            "",
            "https://xn--exmple-cua.com/",
        ),
        (
            "https://example.com./path",
            "https",
            "example.com",
            443,
            "/path",
            "",
            "https://example.com/path",
        ),
        (
            "https://example.com/a%2fb/../etc?x=%2e%2e",
            "https",
            "example.com",
            443,
            "/a%2fb/../etc",
            "x=%2e%2e",
            "https://example.com/a%2fb/../etc?x=%2e%2e",
        ),
    ],
)
def test_parse_target_url_normalizes_valid_urls(
    raw: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    query: str,
    normalized: str,
) -> None:
    target = parse_target_url(raw)

    assert target.scheme == scheme
    assert target.host == host
    assert target.port == port
    assert target.path == path
    assert target.query == query
    assert target.url == normalized


@pytest.mark.parametrize(
    ("raw", "expected_code"),
    [
        ("", UrlErrorCode.MALFORMED_URL),
        ("/admin", UrlErrorCode.MALFORMED_URL),
        ("ftp://example.com/", UrlErrorCode.UNSUPPORTED_SCHEME),
        ("https:///admin", UrlErrorCode.MISSING_HOST),
        (
            "https://user:password@example.com/",
            UrlErrorCode.EMBEDDED_CREDENTIALS,
        ),
        ("https://example.com:99999/", UrlErrorCode.INVALID_PORT),
        ("https://example.com:", UrlErrorCode.INVALID_PORT),
        ("https://[::1]:", UrlErrorCode.INVALID_PORT),
        (
            "https://example.com/\nadmin",
            UrlErrorCode.UNSAFE_CHARACTER,
        ),
        (
            "https://example.com\\@attacker.test/",
            UrlErrorCode.UNSAFE_CHARACTER,
        ),
        (
            "https://exämple.com/",
            UrlErrorCode.NON_ASCII_HOST,
        ),
        ("https://example..com/", UrlErrorCode.INVALID_HOST),
        ("https://.example.com/", UrlErrorCode.INVALID_HOST),
        ("https://example%2ecom/", UrlErrorCode.INVALID_HOST),
        ("https://example.com../", UrlErrorCode.INVALID_HOST),
        ("https://[::1", UrlErrorCode.MALFORMED_URL),
    ],
)
def test_parse_target_url_rejects_unsafe_input(
    raw: str,
    expected_code: UrlErrorCode,
) -> None:
    with pytest.raises(UrlValidationError) as error:
        parse_target_url(raw)

    assert error.value.code is expected_code
