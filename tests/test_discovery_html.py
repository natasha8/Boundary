import inspect
import socket
from html.parser import HTMLParser

import anyio
import pytest

from boundary import discovery
from boundary.discovery import extract_html_references, is_html_response

_ACCEPTED_CONTENT_TYPES = [
    b"text/html",
    b"Text/HTML",
    b"TEXT/HTML",
    b"text/html; charset=utf-8",
    b"text/html;charset=UTF-8",
    b"TEXT/HTML; charset=UTF-8",
    b"text/html; charset=UTF-8",
    b" text/html",
    b"text/html ",
    b"  text/html  ",
    b"\ttext/html\t",
    b" text/html; charset=utf-8 ",
    b"text/html ; charset=utf-8",
    b"text/html;",
    b"text/html; charset=utf-8; foo=bar",
]

_REJECTED_MEDIA_TYPES = [
    b"application/json",
    b"text/plain",
    b"application/javascript",
    b"application/xhtml+xml",
    b"application/xhtml+xml; charset=utf-8",
    b"text/css",
    b"image/svg+xml",
    b"text/htmlx",
    b"text/xml",
    b"text/html+xml",
]

_MALFORMED_MEDIA_TYPES = [
    b"",
    b"   ",
    b"\t",
    b"text",
    b"text/",
    b"/html",
    b"text html",
    b"text / html",
    b"text/html charset=utf-8",
    b"; charset=utf-8",
    b"charset=utf-8",
    b"*/*",
    b"text/*",
]

_NON_ASCII_CONTENT_TYPES = [
    b"text/html\xff",
    b"text/html; charset=\xff",
    "text/html; charset=utf-8é".encode(),
    b"\xc3\xa9",
]

_EXCLUDED_MARKUP = [
    '<img src="/x.png">',
    '<iframe src="/frame"></iframe>',
    '<source src="/clip.mp4">',
    '<video src="/clip.mp4"></video>',
    '<audio src="/clip.mp3"></audio>',
    '<object data="/widget"></object>',
    '<embed src="/plugin">',
    '<area href="/map">',
    '<base href="https://evil.test/">',
    '<meta http-equiv="refresh" content="0;url=/next">',
    "<style>body { background: url(/css.png); }</style>",
    '<div style="background: url(/inline.png)"></div>',
    "<a onclick=\"location.href='/js'\">click</a>",
    '<a data-href="/data">',
    "<script>const x = '<a href=\"/fake\">';</script>",
]


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if HTML extraction performs DNS or real TCP I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)


def _extract(html: str) -> tuple[str, ...]:
    return extract_html_references(html.encode("utf-8"))


@pytest.mark.parametrize(
    "name",
    [b"Content-Type", b"content-type", b"CONTENT-TYPE", b"Content-type"],
)
def test_content_type_header_name_matching_is_case_insensitive(name: bytes) -> None:
    assert is_html_response(((name, b"text/html"),)) is True


@pytest.mark.parametrize("value", _ACCEPTED_CONTENT_TYPES)
def test_text_html_media_type_is_accepted(value: bytes) -> None:
    assert is_html_response(((b"Content-Type", value),)) is True


def test_surrounding_headers_do_not_affect_html_detection() -> None:
    headers = (
        (b"Server", b"test"),
        (b"Content-Type", b"text/html; charset=utf-8"),
        (b"Content-Length", b"12"),
        (b"Accept", b"application/json"),
    )

    assert is_html_response(headers) is True


def test_content_type_headers_may_be_supplied_as_a_list() -> None:
    assert is_html_response([(b"Content-Type", b"text/html")]) is True


@pytest.mark.parametrize("value", _REJECTED_MEDIA_TYPES)
def test_non_html_media_types_including_xhtml_and_svg_are_rejected(
    value: bytes,
) -> None:
    assert is_html_response(((b"Content-Type", value),)) is False


def test_missing_content_type_is_not_html() -> None:
    assert is_html_response(()) is False
    assert is_html_response(((b"Server", b"test"),)) is False
    assert is_html_response(((b"X-Content-Type", b"text/html"),)) is False
    assert is_html_response(((b"Accept", b"text/html"),)) is False


@pytest.mark.parametrize(
    "headers",
    [
        (
            (b"Content-Type", b"text/html"),
            (b"Content-Type", b"text/html"),
        ),
        (
            (b"content-type", b"text/html"),
            (b"CONTENT-TYPE", b"text/plain"),
        ),
        (
            (b"Content-Type", b"application/json"),
            (b"content-type", b"text/html"),
        ),
        (
            (b"Content-Type", b"text/html"),
            (b"X-Other", b"1"),
            (b"content-type", b"text/html"),
        ),
        (
            (b"Content-Type", b"text/html"),
            (b"Content-Type", b"text/html"),
            (b"Content-Type", b"text/html"),
        ),
    ],
)
def test_multiple_content_type_headers_are_rejected(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    # Fail closed: do not choose the first or last Content-Type value.
    assert is_html_response(headers) is False


def test_empty_content_type_value_is_rejected() -> None:
    assert is_html_response(((b"Content-Type", b""),)) is False


@pytest.mark.parametrize("value", _NON_ASCII_CONTENT_TYPES)
def test_non_ascii_content_type_value_is_rejected(value: bytes) -> None:
    assert is_html_response(((b"Content-Type", value),)) is False


@pytest.mark.parametrize("value", _MALFORMED_MEDIA_TYPES)
def test_malformed_media_type_values_are_rejected(value: bytes) -> None:
    assert is_html_response(((b"Content-Type", value),)) is False


def test_untrusted_content_type_headers_do_not_raise() -> None:
    headers = (
        ((b"Content-Type", b"text/html\xff"),),
        ((b"Content-Type", b""),),
        ((b"Content-Type", b"text / html"),),
        (
            (b"Content-Type", b"text/html"),
            (b"Content-Type", b"text/plain"),
        ),
        (),
    )

    for field in headers:
        assert is_html_response(field) is False


def test_approved_url_attributes_are_extracted_in_document_order() -> None:
    html = """
    <a href="/a">
    <script src="/one.js"></script>
    <form action="/submit"></form>
    <link href="/style.css">
    """

    assert _extract(html) == ("/a", "/one.js", "/submit", "/style.css")


def test_duplicate_references_are_preserved() -> None:
    html = '<a href="/same"></a><a href="/same"></a>'

    assert _extract(html) == ("/same", "/same")


def test_duplicates_are_preserved_across_tag_types() -> None:
    html = '<a href="/x"><link href="/x"><form action="/x"></form>'

    assert _extract(html) == ("/x", "/x", "/x")


def test_attribute_values_are_preserved_exactly() -> None:
    html = '<a href="  /api  ">'

    assert _extract(html) == ("  /api  ",)


def test_empty_attribute_values_are_returned() -> None:
    assert _extract('<a href=""></a>') == ("",)
    assert _extract('<form action=""></form>') == ("",)
    assert _extract('<script src=""></script>') == ("",)
    assert _extract('<link href="">') == ("",)
    assert _extract('<a href=""></a><a href=""></a>') == ("", "")


def test_missing_relevant_attributes_produce_no_references() -> None:
    html = "<a>text</a><form></form><script></script><link>"

    assert _extract(html) == ()


def test_boolean_href_without_a_value_is_not_a_reference() -> None:
    assert _extract("<a href>") == ()


def test_tag_names_are_case_insensitive() -> None:
    html = (
        '<A href="/a">'
        '<FoRm action="/submit"></FoRm>'
        '<SCRIPT src="/one.js"></SCRIPT>'
        '<LINK href="/style.css">'
    )

    assert _extract(html) == ("/a", "/submit", "/one.js", "/style.css")


def test_attribute_names_are_case_insensitive() -> None:
    html = (
        '<a HREF="/a">'
        '<form AcTiOn="/submit"></form>'
        '<script SRC="/one.js"></script>'
        '<link HrEf="/style.css">'
    )

    assert _extract(html) == ("/a", "/submit", "/one.js", "/style.css")


def test_unrelated_attributes_do_not_affect_extraction() -> None:
    html = (
        '<a class="x" href="/a" id="y">'
        '<form method="POST" action="/submit" novalidate></form>'
        '<script type="module" src="/mod.js" defer></script>'
        '<link rel="stylesheet" href="/style.css" media="all">'
    )

    assert _extract(html) == ("/a", "/submit", "/mod.js", "/style.css")


def test_wrong_attributes_on_approved_tags_are_ignored() -> None:
    html = (
        '<a src="/nope">'
        '<form href="/nope"></form>'
        '<script href="/nope"></script>'
        '<link src="/nope">'
        '<a href="/keep" src="/ignored">'
        '<form href="/ignored" action="/yes"></form>'
    )

    assert _extract(html) == ("/keep", "/yes")


def test_first_duplicate_relevant_attribute_wins() -> None:
    # HTMLParser exposes both attributes in parser order. This slice uses the
    # first relevant occurrence and does not invent browser DOM repair.
    assert _extract('<a href="/first" href="/second">') == ("/first",)
    assert _extract('<a href="/first" HREF="/second" href="/third">') == ("/first",)
    assert _extract('<form action="/first" action="/second"></form>') == ("/first",)
    assert _extract('<script src="/first.js" src="/second.js"></script>') == (
        "/first.js",
    )
    assert _extract('<link href="/first.css" href="/second.css">') == ("/first.css",)


def test_self_closing_link_is_extracted() -> None:
    assert _extract('<link href="/style.css" />') == ("/style.css",)
    assert _extract('<link href="/style.css"/>') == ("/style.css",)


def test_comments_are_not_mined_for_references() -> None:
    html = '<!-- <a href="/hidden"> --><a href="/visible">'

    assert _extract(html) == ("/visible",)
    assert _extract('<!-- <a href="/hidden"> -->') == ()


def test_script_text_is_not_parsed_for_urls() -> None:
    html = """
    <script>
        const x = '<a href="/fake">';
    </script>
    """

    assert _extract(html) == ()


def test_script_src_is_extracted_without_mining_script_text() -> None:
    html = """
    <script src="/real.js">
        const x = '<a href="/fake">';
    </script>
    """

    assert _extract(html) == ("/real.js",)


def test_html_entities_follow_htmlparser_behavior() -> None:
    # html.parser.HTMLParser unescapes character references once.
    assert _extract('<a href="/search?a=1&amp;b=2">') == ("/search?a=1&b=2",)
    assert _extract('<a href="/x&amp;amp;y">') == ("/x&amp;y",)
    assert _extract('<a href="/x&lt;y">') == ("/x<y",)
    assert _extract('<a href="/a&b">') == ("/a&b",)


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        ('<a href="/a"><form action="/b">', ("/a", "/b")),
        ('<a href="/a"><a href="/tru', ("/a",)),
        ('<a href="/a" <b href="/b">', ("/a",)),
        ('<a href="/broken>', ()),
        ('<a href="/outer"><a href="/inner"></a></a>', ("/outer", "/inner")),
        ('<!DOCTYPE html><a href="/a">', ("/a",)),
        ("<a href=/unquoted>", ("/unquoted",)),
        ("<a href='/single'>", ("/single",)),
    ],
)
def test_malformed_html_follows_htmlparser_behavior(
    html: str,
    expected: tuple[str, ...],
) -> None:
    assert _extract(html) == expected


def test_valid_utf8_html_is_decoded_strictly() -> None:
    body = '<p>Привет</p><a href="/café">'.encode()

    assert extract_html_references(body) == ("/café",)


def test_invalid_utf8_raises_unicode_decode_error() -> None:
    with pytest.raises(UnicodeDecodeError):
        extract_html_references(b'<a href="/a">\xff')

    with pytest.raises(UnicodeDecodeError):
        extract_html_references(b"\xff")

    with pytest.raises(UnicodeDecodeError):
        extract_html_references(b"\xc3")


def test_empty_body_returns_no_references() -> None:
    assert extract_html_references(b"") == ()


def test_non_html_utf8_bytes_return_no_references() -> None:
    assert extract_html_references(b"hello world") == ()
    assert extract_html_references(b'{"href":"/a"}') == ()
    assert extract_html_references(b"<html></html>") == ()
    assert extract_html_references(b"   \n") == ()


@pytest.mark.parametrize("html", _EXCLUDED_MARKUP)
def test_excluded_elements_and_url_sources_produce_no_references(html: str) -> None:
    assert _extract(html) == ()


def test_excluded_markup_does_not_displace_approved_references() -> None:
    html = """
    <img src="/x.png">
    <iframe src="/frame"></iframe>
    <a href="/keep">ok</a>
    <meta http-equiv="refresh" content="0;url=/next">
    <style>body { background: url(/css.png); }</style>
    <script>const x = '<a href="/fake">';</script>
    <base href="https://evil.test/">
    """

    assert _extract(html) == ("/keep",)


def test_raw_references_are_not_resolved_or_filtered() -> None:
    html = (
        '<a href="javascript:alert(1)">'
        '<a href="https://evil.test/phish">'
        '<a href="#section">'
        '<form action="mailto:admin@app.test"></form>'
    )

    assert _extract(html) == (
        "javascript:alert(1)",
        "https://evil.test/phish",
        "#section",
        "mailto:admin@app.test",
    )


def test_extraction_is_deterministic() -> None:
    body = (
        b'<a href="/a"><script src="/one.js"></script>'
        b'<form action="/submit"></form><link href="/style.css">'
        b'<a href="/a">'
    )

    assert extract_html_references(body) == extract_html_references(body)
    assert extract_html_references(body) == (
        "/a",
        "/one.js",
        "/submit",
        "/style.css",
        "/a",
    )


def test_html_parser_subclass_is_not_part_of_the_public_discovery_surface() -> None:
    exported_subclasses = [
        name
        for name, value in vars(discovery).items()
        if inspect.isclass(value)
        and issubclass(value, HTMLParser)
        and value is not HTMLParser
        and not name.startswith("_")
    ]

    assert exported_subclasses == []
