import pytest

from boundary.scope import (
    Origin,
    ScopeErrorCode,
    ScopeValidationError,
    UrlErrorCode,
    UrlValidationError,
    parse_target_url,
    require_allowed_origin,
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


def test_origin_is_immutable_and_hashable() -> None:
    origin = Origin(scheme="https", host="example.com", port=443)
    same = Origin(scheme="https", host="example.com", port=443)

    assert origin.scheme == "https"
    assert origin.host == "example.com"
    assert origin.port == 443
    assert {origin, same} == {origin}
    assert hash(origin) == hash(same)

    with pytest.raises(AttributeError):
        origin.host = "evil.test"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("left_url", "right_url"),
    [
        ("https://example.com/", "https://example.com:443/admin"),
        ("https://EXAMPLE.com/a", "https://example.com/b?x=1#frag"),
        ("http://127.0.0.1/", "http://127.0.0.1:80/health"),
        ("http://[::1]/", "http://[::1]:80/health"),
    ],
)
def test_origin_equality_ignores_path_query_fragment_and_default_port(
    left_url: str,
    right_url: str,
) -> None:
    left = parse_target_url(left_url).origin
    right = parse_target_url(right_url).origin

    assert left == right
    assert hash(left) == hash(right)


@pytest.mark.parametrize(
    ("left_url", "right_url"),
    [
        ("https://example.com/", "http://example.com/"),
        ("https://example.com/", "https://example.com:8443/"),
        ("https://example.com/", "https://api.example.com/"),
        ("http://127.0.0.1/", "http://127.0.0.1:3000/"),
        ("http://[::1]/", "http://[::1]:8080/"),
    ],
)
def test_origin_inequality_for_scheme_host_and_port(
    left_url: str,
    right_url: str,
) -> None:
    left = parse_target_url(left_url).origin
    right = parse_target_url(right_url).origin

    assert left != right


@pytest.mark.parametrize(
    ("raw", "scheme", "host", "port"),
    [
        ("https://example.com/admin?x=1#frag", "https", "example.com", 443),
        ("https://example.com:443/", "https", "example.com", 443),
        ("http://example.com:8080/api", "http", "example.com", 8080),
        ("http://127.0.0.1:3000/health", "http", "127.0.0.1", 3000),
        ("http://[::1]:8080/health", "http", "::1", 8080),
    ],
)
def test_target_url_origin_property(
    raw: str,
    scheme: str,
    host: str,
    port: int,
) -> None:
    target = parse_target_url(raw)

    assert target.origin == Origin(scheme=scheme, host=host, port=port)


def test_require_allowed_origin_accepts_exact_match() -> None:
    target = parse_target_url("https://example.com/admin?x=1#frag")
    allowed = {Origin(scheme="https", host="example.com", port=443)}

    require_allowed_origin(target, allowed)


def test_require_allowed_origin_accepts_default_port_equivalent() -> None:
    target = parse_target_url("https://example.com:443/path")
    allowed = {Origin(scheme="https", host="example.com", port=443)}

    require_allowed_origin(target, allowed)


@pytest.mark.parametrize(
    ("raw", "allowed"),
    [
        (
            "https://example.com/",
            {Origin(scheme="http", host="example.com", port=80)},
        ),
        (
            "https://example.com:8443/",
            {Origin(scheme="https", host="example.com", port=443)},
        ),
        (
            "https://api.example.com/",
            {Origin(scheme="https", host="example.com", port=443)},
        ),
        (
            "http://127.0.0.1:3000/",
            {Origin(scheme="http", host="127.0.0.1", port=80)},
        ),
        (
            "http://[::1]:8080/",
            {Origin(scheme="http", host="::1", port=80)},
        ),
    ],
)
def test_require_allowed_origin_rejects_mismatches(
    raw: str,
    allowed: set[Origin],
) -> None:
    target = parse_target_url(raw)

    with pytest.raises(ScopeValidationError) as error:
        require_allowed_origin(target, allowed)

    assert error.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED


def test_require_allowed_origin_rejects_empty_allowlist() -> None:
    target = parse_target_url("https://example.com/")

    with pytest.raises(ScopeValidationError) as error:
        require_allowed_origin(target, set())

    assert error.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED
