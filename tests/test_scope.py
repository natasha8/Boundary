import asyncio
from collections.abc import Collection
from ipaddress import ip_address

import pytest

from boundary.scope import (
    AddressPolicy,
    Origin,
    ScopeErrorCode,
    ScopeValidationError,
    UrlErrorCode,
    UrlValidationError,
    parse_target_url,
    require_allowed_address,
    require_allowed_origin,
    resolve_allowed_addresses,
    resolve_allowed_redirect,
)


class FakeAddressResolver:
    """Test double that returns predefined addresses without network I/O."""

    def __init__(self, addresses: Collection[str]) -> None:
        self._addresses = list(addresses)
        self.calls = 0
        self.received_host: str | None = None
        self.received_port: int | None = None

    async def resolve(self, host: str, port: int) -> Collection[str]:
        self.calls += 1
        self.received_host = host
        self.received_port = port
        return list(self._addresses)


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
    """Empty allowlists must reject every origin."""
    target = parse_target_url("https://example.com/")

    with pytest.raises(ScopeValidationError) as error:
        require_allowed_origin(target, set())

    assert error.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED


def test_address_policy_values() -> None:
    assert AddressPolicy.PUBLIC.value == "public"
    assert AddressPolicy.LOCAL_LAB.value == "local_lab"
    assert set(AddressPolicy) == {
        AddressPolicy.PUBLIC,
        AddressPolicy.LOCAL_LAB,
    }


def test_scope_error_code_includes_address_policy_codes() -> None:
    assert ScopeErrorCode.INVALID_IP_ADDRESS.value == "invalid_ip_address"
    assert ScopeErrorCode.ADDRESS_NOT_ALLOWED.value == "address_not_allowed"
    assert ScopeErrorCode.NO_RESOLVED_ADDRESSES.value == "no_resolved_addresses"


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ],
)
def test_require_allowed_address_accepts_public_addresses(address: str) -> None:
    require_allowed_address(address, AddressPolicy.PUBLIC)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
    ],
)
def test_require_allowed_address_rejects_non_public_addresses(
    address: str,
) -> None:
    with pytest.raises(ScopeValidationError) as error:
        require_allowed_address(address, AddressPolicy.PUBLIC)

    assert error.value.code is ScopeErrorCode.ADDRESS_NOT_ALLOWED


@pytest.mark.parametrize(
    "address",
    [
        "64:ff9b::7f00:1",
        "::ffff:0:7f00:1",
        "::7f00:1",
        "fec0::1",
        "2001:20::1",
        "5f00::1",
    ],
)
def test_require_allowed_address_rejects_special_use_ipv6_under_public(
    address: str,
) -> None:
    with pytest.raises(ScopeValidationError) as error:
        require_allowed_address(address, AddressPolicy.PUBLIC)

    assert error.value.code is ScopeErrorCode.ADDRESS_NOT_ALLOWED


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "::1",
        "fe80::1",
        "fc00::1",
    ],
)
def test_require_allowed_address_accepts_local_lab_addresses(
    address: str,
) -> None:
    require_allowed_address(address, AddressPolicy.LOCAL_LAB)


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "::",
        "ff02::1",
        "2001:db8::1",
    ],
)
def test_require_allowed_address_rejects_non_local_lab_addresses(
    address: str,
) -> None:
    with pytest.raises(ScopeValidationError) as error:
        require_allowed_address(address, AddressPolicy.LOCAL_LAB)

    assert error.value.code is ScopeErrorCode.ADDRESS_NOT_ALLOWED


@pytest.mark.parametrize(
    "policy",
    [
        AddressPolicy.PUBLIC,
        AddressPolicy.LOCAL_LAB,
    ],
)
def test_require_allowed_address_rejects_invalid_ip_syntax(
    policy: AddressPolicy,
) -> None:
    with pytest.raises(ScopeValidationError) as error:
        require_allowed_address("invalid-ip", policy)

    assert error.value.code is ScopeErrorCode.INVALID_IP_ADDRESS


@pytest.mark.parametrize(
    ("current_url", "location", "expected_url"),
    [
        (
            "https://example.com/account",
            "/login",
            "https://example.com/login",
        ),
        (
            "https://example.com/account/settings",
            "../profile",
            "https://example.com/profile",
        ),
        (
            "https://example.com/account/settings",
            "next",
            "https://example.com/account/next",
        ),
        (
            "https://example.com/items?page=1",
            "?page=2",
            "https://example.com/items?page=2",
        ),
    ],
)
def test_resolve_allowed_redirect_resolves_relative_locations(
    current_url: str,
    location: str,
    expected_url: str,
) -> None:
    current = parse_target_url(current_url)
    allowed = {current.origin}

    result = resolve_allowed_redirect(current, location, allowed)

    assert result.url == expected_url
    assert result.origin == current.origin


@pytest.mark.parametrize(
    ("current_url", "location", "allowed", "expected_url"),
    [
        (
            "https://example.com/account",
            "https://example.com/dashboard",
            {Origin(scheme="https", host="example.com", port=443)},
            "https://example.com/dashboard",
        ),
        (
            "https://example.com/account",
            "//example.com/path",
            {Origin(scheme="https", host="example.com", port=443)},
            "https://example.com/path",
        ),
        (
            "https://example.com/",
            "http://example.com/switched",
            {
                Origin(scheme="https", host="example.com", port=443),
                Origin(scheme="http", host="example.com", port=80),
            },
            "http://example.com/switched",
        ),
    ],
)
def test_resolve_allowed_redirect_accepts_allowed_absolute_and_scheme_relative(
    current_url: str,
    location: str,
    allowed: set[Origin],
    expected_url: str,
) -> None:
    current = parse_target_url(current_url)

    result = resolve_allowed_redirect(current, location, allowed)

    assert result.url == expected_url


@pytest.mark.parametrize(
    ("current_url", "location", "allowed", "expected_url", "expected_port"),
    [
        (
            "https://example.com/start",
            "https://example.com:443/next",
            {Origin(scheme="https", host="example.com", port=443)},
            "https://example.com/next",
            443,
        ),
        (
            "https://example.com:8443/start",
            "/next",
            {Origin(scheme="https", host="example.com", port=8443)},
            "https://example.com:8443/next",
            8443,
        ),
        (
            "https://example.com/",
            "https://example.com:8443/next",
            {
                Origin(scheme="https", host="example.com", port=443),
                Origin(scheme="https", host="example.com", port=8443),
            },
            "https://example.com:8443/next",
            8443,
        ),
    ],
)
def test_resolve_allowed_redirect_handles_default_and_non_default_ports(
    current_url: str,
    location: str,
    allowed: set[Origin],
    expected_url: str,
    expected_port: int,
) -> None:
    current = parse_target_url(current_url)

    result = resolve_allowed_redirect(current, location, allowed)

    assert result.url == expected_url
    assert result.port == expected_port


def test_resolve_allowed_redirect_removes_fragments() -> None:
    current = parse_target_url("https://example.com/account")
    allowed = {current.origin}

    result = resolve_allowed_redirect(current, "/login#section", allowed)

    assert result.url == "https://example.com/login"
    assert "#" not in result.url


@pytest.mark.parametrize(
    ("current_url", "location", "allowed"),
    [
        (
            "https://example.com/account",
            "https://evil.test/phish",
            {Origin(scheme="https", host="example.com", port=443)},
        ),
        (
            "https://example.com/account",
            "https://api.example.com/",
            {Origin(scheme="https", host="example.com", port=443)},
        ),
        (
            "https://example.com/account",
            "http://example.com/switched",
            {Origin(scheme="https", host="example.com", port=443)},
        ),
        (
            "https://example.com/account",
            "https://example.com:8443/next",
            {Origin(scheme="https", host="example.com", port=443)},
        ),
        (
            "https://example.com/account",
            "//evil.test/path",
            {Origin(scheme="https", host="example.com", port=443)},
        ),
    ],
)
def test_resolve_allowed_redirect_rejects_disallowed_origins(
    current_url: str,
    location: str,
    allowed: set[Origin],
) -> None:
    current = parse_target_url(current_url)

    with pytest.raises(ScopeValidationError) as error:
        resolve_allowed_redirect(current, location, allowed)

    assert error.value.code is ScopeErrorCode.ORIGIN_NOT_ALLOWED


@pytest.mark.parametrize(
    ("location", "expected_code"),
    [
        ("", UrlErrorCode.MALFORMED_URL),
        ("#section", UrlErrorCode.MALFORMED_URL),
        (
            "https://user:password@example.com/",
            UrlErrorCode.EMBEDDED_CREDENTIALS,
        ),
        ("javascript:alert(1)", UrlErrorCode.UNSUPPORTED_SCHEME),
        ("ftp://example.com/", UrlErrorCode.UNSUPPORTED_SCHEME),
        ("/login\\next", UrlErrorCode.UNSAFE_CHARACTER),
        ("/login next", UrlErrorCode.UNSAFE_CHARACTER),
        ("/login\tnext", UrlErrorCode.UNSAFE_CHARACTER),
        ("/login\rnext", UrlErrorCode.UNSAFE_CHARACTER),
        ("/login\nnext", UrlErrorCode.UNSAFE_CHARACTER),
        ("\x00", UrlErrorCode.UNSAFE_CHARACTER),
        ("\x1f", UrlErrorCode.UNSAFE_CHARACTER),
        ("\x7f", UrlErrorCode.UNSAFE_CHARACTER),
    ],
)
def test_resolve_allowed_redirect_rejects_unsafe_location(
    location: str,
    expected_code: UrlErrorCode,
) -> None:
    current = parse_target_url("https://example.com/account")
    allowed = {current.origin}

    with pytest.raises(UrlValidationError) as error:
        resolve_allowed_redirect(current, location, allowed)

    assert error.value.code is expected_code


@pytest.mark.parametrize("location", ["http://[::1", "//[::1"])
def test_resolve_allowed_redirect_wraps_urljoin_parse_failures(
    location: str,
) -> None:
    current = parse_target_url("https://example.com/account")
    allowed = {current.origin}

    with pytest.raises(UrlValidationError) as error:
        resolve_allowed_redirect(current, location, allowed)

    assert error.value.code is UrlErrorCode.MALFORMED_URL


@pytest.mark.parametrize(
    ("current_url", "location", "expected_path", "expected_query", "expected_url"),
    [
        (
            "https://example.com/",
            "/a%2fb/c?x=%2e%2e",
            "/a%2fb/c",
            "x=%2e%2e",
            "https://example.com/a%2fb/c?x=%2e%2e",
        ),
        (
            "https://example.com/dir/page",
            "./foo/%2e%2e/bar",
            "/dir/foo/%2e%2e/bar",
            "",
            "https://example.com/dir/foo/%2e%2e/bar",
        ),
    ],
)
def test_resolve_allowed_redirect_preserves_encoding_and_urljoin_resolution(
    current_url: str,
    location: str,
    expected_path: str,
    expected_query: str,
    expected_url: str,
) -> None:
    current = parse_target_url(current_url)
    allowed = {current.origin}

    result = resolve_allowed_redirect(current, location, allowed)

    assert result.path == expected_path
    assert result.query == expected_query
    assert result.url == expected_url


@pytest.mark.parametrize(
    ("addresses", "expected"),
    [
        (
            ["8.8.8.8", "1.1.1.1"],
            ("8.8.8.8", "1.1.1.1"),
        ),
        (
            ["8.8.8.8", "8.8.8.8"],
            ("8.8.8.8",),
        ),
        (
            [
                "2606:4700:4700:0:0:0:0:1111",
                "2606:4700:4700::1111",
            ],
            ("2606:4700:4700::1111",),
        ),
    ],
)
def test_resolve_allowed_addresses_accepts_public_results(
    addresses: list[str],
    expected: tuple[str, ...],
) -> None:
    resolver = FakeAddressResolver(addresses)

    result = asyncio.run(
        resolve_allowed_addresses(
            "example.com",
            443,
            AddressPolicy.PUBLIC,
            resolver,
        )
    )

    assert result == expected
    assert all(item == str(ip_address(item)) for item in result)
    assert resolver.calls == 1
    assert resolver.received_host == "example.com"
    assert resolver.received_port == 443


@pytest.mark.parametrize(
    ("addresses", "expected_code"),
    [
        (
            ["8.8.8.8", "127.0.0.1"],
            ScopeErrorCode.ADDRESS_NOT_ALLOWED,
        ),
        (
            ["192.168.1.10"],
            ScopeErrorCode.ADDRESS_NOT_ALLOWED,
        ),
        (
            ["invalid-ip"],
            ScopeErrorCode.INVALID_IP_ADDRESS,
        ),
        (
            [],
            ScopeErrorCode.NO_RESOLVED_ADDRESSES,
        ),
    ],
)
def test_resolve_allowed_addresses_rejects_public_results(
    addresses: list[str],
    expected_code: ScopeErrorCode,
) -> None:
    resolver = FakeAddressResolver(addresses)

    with pytest.raises(ScopeValidationError) as error:
        asyncio.run(
            resolve_allowed_addresses(
                "example.com",
                443,
                AddressPolicy.PUBLIC,
                resolver,
            )
        )

    assert error.value.code is expected_code
    assert resolver.calls == 1


@pytest.mark.parametrize(
    ("addresses", "expected"),
    [
        (
            ["127.0.0.1", "192.168.1.10"],
            ("127.0.0.1", "192.168.1.10"),
        ),
        (
            ["::1", "fc00::1"],
            ("::1", "fc00::1"),
        ),
    ],
)
def test_resolve_allowed_addresses_accepts_local_lab_results(
    addresses: list[str],
    expected: tuple[str, ...],
) -> None:
    resolver = FakeAddressResolver(addresses)

    result = asyncio.run(
        resolve_allowed_addresses(
            "localhost",
            8080,
            AddressPolicy.LOCAL_LAB,
            resolver,
        )
    )

    assert result == expected
    assert all(item == str(ip_address(item)) for item in result)
    assert resolver.calls == 1
    assert resolver.received_host == "localhost"
    assert resolver.received_port == 8080
