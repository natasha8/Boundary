import socket
from urllib.parse import urljoin

import anyio
import pytest

from boundary import discovery
from boundary.discovery import resolve_candidate
from boundary.scope import Origin, TargetUrl, parse_target_url

_UNSUPPORTED_SCHEME_REFERENCES = [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "mailto:admin@app.test",
    "tel:+15550100",
    "file:///etc/passwd",
    "ftp://files.app.test/dump.sql",
]

_UNENUMERATED_SCHEME_REFERENCES = [
    "ws://app.test/socket",
    "gopher://app.test/1",
    "boundary-app://open",
]

_MALFORMED_REFERENCES = [
    "https://app.test:abc/next",
    "https://app.test:/next",
    "https://app.test:99999/next",
    "https://app..test/next",
    "https://.app.test/next",
    "https://app.test%2enext/",
    "https:///next",
    "http://[::1",
    "//[::1",
]

_CREDENTIAL_REFERENCES = [
    "https://user:password@app.test/next",
    "//user:password@app.test/next",
    "https://user@app.test/next",
]

_HTML_URL_ATTRIBUTE_WHITESPACE = " \t\n\f\r"

_UNSAFE_CHARACTER_REFERENCES = [
    "/api/ users",
    "/api/\tusers",
    "/api/\rusers",
    "/api/\nusers",
    "/api/\\users",
    "\\evil.test/path",
    "/api/\x00users",
    "/api/\x1fusers",
    "/api/\x7fusers",
    "  /api/\nusers  ",
]


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if candidate resolution performs DNS or real TCP I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)


def _origins(*raw_urls: str) -> frozenset[Origin]:
    """Build an exact origin allowlist from URLs parsed by the Scope Engine."""
    return frozenset(parse_target_url(raw).origin for raw in raw_urls)


def _accept(
    base: TargetUrl,
    reference: str,
    allowed_origins: frozenset[Origin],
) -> TargetUrl:
    """Resolve a reference that must be accepted and stay inside the allowlist."""
    result = resolve_candidate(base, reference, allowed_origins)

    assert result is not None
    assert result.origin in allowed_origins
    return result


def test_discovery_module_has_no_transport_or_resolver_surface() -> None:
    forbidden = {
        "httpcore",
        "socket",
        "anyio",
        "request_once",
        "request_with_redirects",
        "AddressPolicy",
        "AddressResolver",
        "resolve_allowed_addresses",
    }

    assert forbidden.isdisjoint(vars(discovery))


@pytest.mark.parametrize(
    ("base_url", "reference", "expected_url"),
    [
        (
            "https://app.test/account/profile",
            "../api/users",
            "https://app.test/api/users",
        ),
        (
            "https://app.test/account/profile",
            "/api/users",
            "https://app.test/api/users",
        ),
        (
            "https://app.test/account/profile",
            "settings",
            "https://app.test/account/settings",
        ),
        (
            "https://app.test/account/profile",
            "./sibling",
            "https://app.test/account/sibling",
        ),
        (
            "https://app.test/account/profile",
            "https://app.test/api/users",
            "https://app.test/api/users",
        ),
        (
            "https://app.test/items?page=1",
            "?page=2",
            "https://app.test/items?page=2",
        ),
        (
            "https://app.test/items",
            "?page=2",
            "https://app.test/items?page=2",
        ),
        (
            "https://app.test/account",
            "/account#profile",
            "https://app.test/account",
        ),
    ],
)
def test_same_origin_references_resolve_to_normalized_candidates(
    base_url: str,
    reference: str,
    expected_url: str,
) -> None:
    base = parse_target_url(base_url)
    allowed = _origins("https://app.test/")

    result = _accept(base, reference, allowed)

    assert result.url == expected_url


def test_scheme_relative_reference_inherits_the_base_scheme() -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/", "https://api.test/")

    result = _accept(base, "//api.test/v1", allowed)

    assert result.url == "https://api.test/v1"
    assert result.scheme == "https"
    assert result.host == "api.test"


def test_scheme_relative_reference_requires_its_own_allowlisted_origin() -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, "//api.test/v1", allowed) is None


def test_explicitly_allowlisted_cross_origin_reference_is_accepted() -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/", "https://api.test/")

    result = _accept(base, "https://api.test/v1/items", allowed)

    assert result.url == "https://api.test/v1/items"


def test_fragment_is_removed_from_an_otherwise_useful_reference() -> None:
    base = parse_target_url("https://app.test/start")
    allowed = _origins("https://app.test/")

    result = _accept(base, "/account#profile", allowed)

    assert result.url == "https://app.test/account"
    assert "#" not in result.url


@pytest.mark.parametrize(
    "reference",
    ["", "   ", "\t", "\n", "\f", "\r\n", " \t\n\f\r", "#", "#section", "#/spa/route"],
)
def test_references_that_identify_nothing_new_are_rejected(reference: str) -> None:
    base = parse_target_url("https://app.test/account")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, reference, allowed) is None


def test_fragment_only_reference_does_not_reproduce_the_current_document() -> None:
    base = parse_target_url("https://app.test/account?page=1")
    allowed = _origins("https://app.test/")

    # urljoin resolves a fragment-only reference back to the base document, so
    # rejection cannot come from parse_target_url alone.
    assert urljoin(base.url, "#section") == "https://app.test/account?page=1#section"
    assert resolve_candidate(base, "#section", allowed) is None


@pytest.mark.parametrize(
    "reference",
    [
        "  /api/users  ",
        "\n/api/users\n",
        "\t/api/users\r\n",
        "\f/api/users\f",
        " \t\n\f\r/api/users \t\n\f\r",
    ],
)
def test_surrounding_html_ascii_whitespace_is_stripped_before_resolution(
    reference: str,
) -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/")

    result = _accept(base, reference, allowed)

    assert result.url == "https://app.test/api/users"


@pytest.mark.parametrize("padding", list(_HTML_URL_ATTRIBUTE_WHITESPACE))
def test_each_html_url_attribute_whitespace_character_is_stripped(
    padding: str,
) -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/")

    result = _accept(base, f"{padding}/api/users{padding}", allowed)

    assert result.url == "https://app.test/api/users"


@pytest.mark.parametrize(
    "reference",
    [
        "\v/api/users",
        "/api/users\v",
        "\xa0/api/users",
        "/api/users\xa0",
    ],
)
def test_non_html_whitespace_is_not_stripped_from_references(reference: str) -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/")

    # Vertical tab and NBSP are stripped by str.strip() with no arguments, but
    # they are not HTML URL-attribute whitespace and must remain rejected.
    assert resolve_candidate(base, reference, allowed) is None


@pytest.mark.parametrize("reference", _UNSUPPORTED_SCHEME_REFERENCES)
def test_unsupported_scheme_references_are_rejected(reference: str) -> None:
    base = parse_target_url("https://app.test/account")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, reference, allowed) is None


@pytest.mark.parametrize("reference", _UNENUMERATED_SCHEME_REFERENCES)
def test_schemes_no_blocklist_enumerates_are_rejected_as_well(reference: str) -> None:
    base = parse_target_url("https://app.test/account")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, reference, allowed) is None


@pytest.mark.parametrize("reference", _MALFORMED_REFERENCES)
def test_malformed_references_are_rejected(reference: str) -> None:
    base = parse_target_url("https://app.test/account")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, reference, allowed) is None


def test_a_reference_urljoin_cannot_parse_is_rejected_rather_than_raising() -> None:
    base = parse_target_url("https://app.test/account")
    allowed = _origins("https://app.test/")

    with pytest.raises(ValueError):
        urljoin(base.url, "http://[::1")

    # Scope Engine converts that urljoin failure into UrlValidationError.
    # Discovery only maps UrlValidationError and ScopeValidationError to None.
    assert resolve_candidate(base, "http://[::1", allowed) is None


@pytest.mark.parametrize("reference", _CREDENTIAL_REFERENCES)
def test_credential_bearing_references_are_rejected(reference: str) -> None:
    base = parse_target_url("https://app.test/account")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, reference, allowed) is None


@pytest.mark.parametrize("reference", _UNSAFE_CHARACTER_REFERENCES)
def test_unsafe_whitespace_and_control_character_references_are_rejected(
    reference: str,
) -> None:
    base = parse_target_url("https://app.test/account")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, reference, allowed) is None


@pytest.mark.parametrize(
    "reference",
    ["/api/\nusers", "/api/\rusers", "/api/\tusers"],
)
def test_internal_ascii_whitespace_is_not_repaired_into_a_candidate(
    reference: str,
) -> None:
    base = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")

    # urlsplit silently removes tab, CR and LF, so the joined value looks valid
    # and rejection cannot rely on parse_target_url seeing the raw characters.
    assert urljoin(base.url, reference) == "https://app.test/api/users"
    assert resolve_candidate(base, reference, allowed) is None


def test_surrounding_strip_does_not_remove_internal_unsafe_whitespace() -> None:
    base = parse_target_url("https://app.test/")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, "  /api/\nusers  ", allowed) is None


def test_same_origin_candidate_succeeds_when_the_base_origin_is_allowlisted() -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/")

    result = _accept(base, "/dashboard", allowed)

    assert result.origin == base.origin
    assert result.url == "https://app.test/dashboard"


@pytest.mark.parametrize(
    "reference",
    [
        "https://evil.test/phish",
        "https://api.app.test/v1",
        "https://app.test:8443/next",
        "http://app.test/next",
        "//evil.test/path",
        "//api.app.test/v1",
    ],
)
def test_references_outside_the_exact_origin_allowlist_are_rejected(
    reference: str,
) -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/")

    assert resolve_candidate(base, reference, allowed) is None


@pytest.mark.parametrize(
    "reference",
    ["/api/users", "settings", "https://app.test/", "//app.test/x", "?page=2"],
)
def test_empty_allowlist_rejects_every_reference(reference: str) -> None:
    base = parse_target_url("https://app.test/account/profile")

    assert resolve_candidate(base, reference, frozenset()) is None


def test_alternate_port_needs_its_own_exact_origin_entry() -> None:
    base = parse_target_url("https://app.test/start")
    reference = "https://app.test:8443/next"
    without_port = _origins("https://app.test/")
    with_port = _origins("https://app.test/", "https://app.test:8443/")

    assert resolve_candidate(base, reference, without_port) is None

    result = _accept(base, reference, with_port)

    assert result.url == "https://app.test:8443/next"
    assert result.port == 8443


def test_alternate_scheme_needs_its_own_exact_origin_entry() -> None:
    base = parse_target_url("https://app.test/start")
    reference = "http://app.test/next"
    without_http = _origins("https://app.test/")
    with_http = _origins("https://app.test/", "http://app.test/")

    assert resolve_candidate(base, reference, without_http) is None

    result = _accept(base, reference, with_http)

    assert result.url == "http://app.test/next"
    assert result.scheme == "http"
    assert result.port == 80


@pytest.mark.parametrize(
    ("base_url", "reference", "expected_url"),
    [
        (
            "http://127.0.0.1:3000/health",
            "/admin",
            "http://127.0.0.1:3000/admin",
        ),
        (
            "http://127.0.0.1:3000/health",
            "http://127.0.0.1:3000/admin",
            "http://127.0.0.1:3000/admin",
        ),
        (
            "http://[::1]:8080/health",
            "/admin",
            "http://[::1]:8080/admin",
        ),
        (
            "http://[::1]:8080/health",
            "//[::1]:8080/admin",
            "http://[::1]:8080/admin",
        ),
    ],
)
def test_ip_literal_candidates_resolve_for_their_exact_origin(
    base_url: str,
    reference: str,
    expected_url: str,
) -> None:
    base = parse_target_url(base_url)
    allowed = _origins(base_url)

    result = _accept(base, reference, allowed)

    assert result.url == expected_url


@pytest.mark.parametrize(
    ("base_url", "reference"),
    [
        ("http://127.0.0.1:3000/health", "http://127.0.0.1:4000/admin"),
        ("http://[::1]:8080/health", "http://[::1]:9090/admin"),
        ("http://127.0.0.1:3000/health", "http://127.0.0.2:3000/admin"),
    ],
)
def test_ip_literal_candidates_on_unapproved_origins_are_rejected(
    base_url: str,
    reference: str,
) -> None:
    base = parse_target_url(base_url)
    allowed = _origins(base_url)

    assert resolve_candidate(base, reference, allowed) is None


@pytest.mark.parametrize(
    ("reference", "expected_url"),
    [
        ("https://APP.TEST/Admin", "https://app.test/Admin"),
        ("HTTPS://app.test/Admin", "https://app.test/Admin"),
        ("https://app.test:443/Admin", "https://app.test/Admin"),
        ("https://app.test./Admin", "https://app.test/Admin"),
        ("/Admin#section", "https://app.test/Admin"),
        ("/Admin?", "https://app.test/Admin"),
    ],
)
def test_target_url_normalization_stays_authoritative(
    reference: str,
    expected_url: str,
) -> None:
    base = parse_target_url("https://app.test/start")
    allowed = _origins("https://app.test/")

    result = _accept(base, reference, allowed)

    assert result.url == expected_url
    assert result.scheme == "https"
    assert result.host == "app.test"
    assert result.port == 443


def test_default_http_port_is_collapsed_by_normalization() -> None:
    base = parse_target_url("http://app.test/start")
    allowed = _origins("http://app.test/")

    result = _accept(base, "http://app.test:80/next", allowed)

    assert result.url == "http://app.test/next"
    assert result.port == 80


@pytest.mark.parametrize(
    ("base_url", "reference", "expected_url"),
    [
        ("https://app.test/a/b/", "../c", "https://app.test/a/c"),
        ("https://app.test/a/b", "../c", "https://app.test/c"),
        ("https://app.test/a/b/", "./c", "https://app.test/a/b/c"),
        ("https://app.test/a/b/", "../../c", "https://app.test/c"),
        ("https://app.test/a/b/", "../../../c", "https://app.test/c"),
    ],
)
def test_dot_segments_are_resolved_only_by_urljoin(
    base_url: str,
    reference: str,
    expected_url: str,
) -> None:
    base = parse_target_url(base_url)
    allowed = _origins("https://app.test/")

    result = _accept(base, reference, allowed)

    assert result.url == expected_url
    assert result.url == urljoin(base.url, reference)


def test_percent_encoded_dot_segments_are_not_collapsed() -> None:
    base = parse_target_url("https://app.test/dir/page")
    allowed = _origins("https://app.test/")

    result = _accept(base, "./foo/%2e%2e/bar", allowed)

    assert result.url == "https://app.test/dir/foo/%2e%2e/bar"
    assert result.path == "/dir/foo/%2e%2e/bar"


@pytest.mark.parametrize(
    ("base_url", "reference", "expected_url", "expected_query"),
    [
        (
            "https://app.test/a%2fb/c?x=%2e%2e",
            "d",
            "https://app.test/a%2fb/d",
            "",
        ),
        (
            "https://app.test/a%2fb/c?x=%2e%2e",
            "?y=1",
            "https://app.test/a%2fb/c?y=1",
            "y=1",
        ),
        (
            "https://app.test/items?page=1&sort=desc",
            "?page=2",
            "https://app.test/items?page=2",
            "page=2",
        ),
        (
            "https://app.test:8443/deep/path/here",
            "../up",
            "https://app.test:8443/deep/up",
            "",
        ),
    ],
)
def test_base_target_remains_the_source_of_reference_resolution(
    base_url: str,
    reference: str,
    expected_url: str,
    expected_query: str,
) -> None:
    base = parse_target_url(base_url)
    allowed = _origins(base_url)

    result = _accept(base, reference, allowed)

    assert result.url == expected_url
    assert result.query == expected_query


@pytest.mark.parametrize(
    "reference",
    [
        "/api/users",
        "../api/users",
        "?page=2",
        "#section",
        "",
        "mailto:admin@app.test",
        "https://evil.test/phish",
        "/log\nin",
    ],
)
def test_resolution_is_deterministic_and_side_effect_free(reference: str) -> None:
    base = parse_target_url("https://app.test/account/profile")
    allowed = _origins("https://app.test/")

    first = resolve_candidate(base, reference, allowed)
    second = resolve_candidate(base, reference, allowed)

    assert first == second


def test_allowlist_may_be_any_collection_of_origins() -> None:
    base = parse_target_url("https://app.test/start")
    allowed = (Origin(scheme="https", host="app.test", port=443),)

    result = resolve_candidate(base, "/next", allowed)

    assert result is not None
    assert result.url == "https://app.test/next"


def test_resolve_candidate_does_not_mutate_base_or_allowed_origins() -> None:
    base = parse_target_url("https://app.test/account/profile?page=1")
    unchanged_base = parse_target_url("https://app.test/account/profile?page=1")
    allowed = {Origin(scheme="https", host="app.test", port=443)}
    unchanged_allowed = set(allowed)

    assert resolve_candidate(base, "../api/users", allowed) is not None
    assert resolve_candidate(base, "https://evil.test/phish", allowed) is None
    assert resolve_candidate(base, "#section", allowed) is None

    assert base == unchanged_base
    assert base.url == "https://app.test/account/profile?page=1"
    assert allowed == unchanged_allowed
    assert len(allowed) == 1
