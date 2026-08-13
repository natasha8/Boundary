import inspect
import socket
from dataclasses import FrozenInstanceError

import anyio
import pytest

from boundary.discovery import DiscoveryLimits, Frontier, FrontierItem
from boundary.scope import parse_target_url

_EQUIVALENT_URL_PAIRS = [
    ("https://app.test/a", "https://APP.test/a"),
    ("https://app.test/a", "https://app.test:443/a"),
    ("http://app.test/a", "http://app.test:80/a"),
    ("https://app.test/a", "https://app.test./a"),
    ("https://app.test/a#one", "https://app.test/a#two"),
    ("https://app.test/a", "https://app.test/a?"),
    ("https://EXAMPLE.com", "https://example.com/"),
    ("https://example.com/", "https://example.com/#fragment"),
]

_DISTINCT_URL_PAIRS = [
    ("https://app.test/a", "https://app.test/b"),
    ("https://app.test/a", "https://app.test/a/"),
    ("https://app.test/a?page=1", "https://app.test/a?page=2"),
    ("https://app.test/a?b=1&c=2", "https://app.test/a?c=2&b=1"),
    ("https://app.test/a", "https://app.test:8443/a"),
    ("http://app.test/a", "https://app.test/a"),
    ("https://app.test/a", "https://api.app.test/a"),
    ("https://app.test/b", "https://app.test/a/../b"),
]


def _reject_socket_getaddrinfo(*args: object, **kwargs: object) -> None:
    raise AssertionError("socket.getaddrinfo must not be called")


def _reject_create_connection(*args: object, **kwargs: object) -> object:
    raise AssertionError("socket.create_connection must not be called")


async def _reject_anyio_connect_tcp(*args: object, **kwargs: object) -> object:
    raise AssertionError("anyio.connect_tcp must not be called")


@pytest.fixture(autouse=True)
def _reject_dns_and_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail immediately if the frontier performs DNS or real TCP I/O."""
    monkeypatch.setattr(socket, "getaddrinfo", _reject_socket_getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", _reject_create_connection)
    monkeypatch.setattr(anyio, "connect_tcp", _reject_anyio_connect_tcp)


def _drain(frontier: Frontier) -> list[tuple[str, int]]:
    """Dequeue every pending item as (normalized url, depth) pairs."""
    drained: list[tuple[str, int]] = []

    while (item := frontier.dequeue()) is not None:
        drained.append((item.target.url, item.depth))

    return drained


def test_discovery_limits_accepts_minimum_values() -> None:
    limits = DiscoveryLimits(max_pages=1, max_depth=0)

    assert limits.max_pages == 1
    assert limits.max_depth == 0


def test_discovery_limits_preserves_larger_values() -> None:
    limits = DiscoveryLimits(max_pages=250, max_depth=4)

    assert limits.max_pages == 250
    assert limits.max_depth == 4


@pytest.mark.parametrize("max_pages", [0, -1, -1000])
def test_non_positive_max_pages_is_rejected(max_pages: int) -> None:
    with pytest.raises(ValueError):
        DiscoveryLimits(max_pages=max_pages, max_depth=0)


@pytest.mark.parametrize("max_depth", [-1, -2, -1000])
def test_negative_max_depth_is_rejected(max_depth: int) -> None:
    with pytest.raises(ValueError):
        DiscoveryLimits(max_pages=1, max_depth=max_depth)


def test_discovery_limits_is_immutable_and_slotted() -> None:
    limits = DiscoveryLimits(max_pages=10, max_depth=2)

    with pytest.raises(FrozenInstanceError):
        limits.max_pages = 20  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        limits.max_depth = 3  # type: ignore[misc]

    assert limits.max_pages == 10
    assert limits.max_depth == 2
    assert not hasattr(limits, "__dict__")


def test_frontier_item_pairs_a_target_with_a_depth() -> None:
    target = parse_target_url("https://app.test/a")

    item = FrontierItem(target=target, depth=3)

    assert item.target == target
    assert item.depth == 3


def test_frontier_item_is_immutable_and_slotted() -> None:
    item = FrontierItem(target=parse_target_url("https://app.test/a"), depth=0)

    with pytest.raises(FrozenInstanceError):
        item.depth = 1  # type: ignore[misc]

    assert item.depth == 0
    assert not hasattr(item, "__dict__")


def test_new_frontier_is_empty() -> None:
    frontier = Frontier()

    assert len(frontier) == 0
    assert frontier.dequeue() is None


def test_frontier_is_constructed_without_configuration() -> None:
    assert list(inspect.signature(Frontier).parameters) == []


def test_frontier_exposes_no_extra_public_surface() -> None:
    frontier = Frontier()

    public = {name for name in dir(frontier) if not name.startswith("_")}

    assert public == {"enqueue", "dequeue", "mark_seen"}


def test_enqueue_admits_a_new_identity() -> None:
    frontier = Frontier()
    target = parse_target_url("https://app.test/a")

    assert frontier.enqueue(target, 0) is True
    assert len(frontier) == 1
    assert frontier.dequeue() == FrontierItem(target=target, depth=0)


@pytest.mark.parametrize("depth", [0, 1, 2, 7, 1000])
def test_enqueue_preserves_depth_exactly(depth: int) -> None:
    frontier = Frontier()
    target = parse_target_url("https://app.test/a")

    assert frontier.enqueue(target, depth) is True

    item = frontier.dequeue()

    assert item is not None
    assert item.depth == depth


def test_dequeue_returns_items_in_fifo_order() -> None:
    frontier = Frontier()
    first = parse_target_url("https://app.test/a")
    second = parse_target_url("https://app.test/b")
    third = parse_target_url("https://app.test/c")

    assert frontier.enqueue(first, 0) is True
    assert frontier.enqueue(second, 1) is True
    assert frontier.enqueue(third, 2) is True

    assert frontier.dequeue() == FrontierItem(target=first, depth=0)
    assert frontier.dequeue() == FrontierItem(target=second, depth=1)
    assert frontier.dequeue() == FrontierItem(target=third, depth=2)
    assert frontier.dequeue() is None


def test_fifo_order_is_unaffected_by_depth() -> None:
    frontier = Frontier()
    first = parse_target_url("https://app.test/a")
    second = parse_target_url("https://app.test/b")
    third = parse_target_url("https://app.test/c")

    assert frontier.enqueue(first, 9) is True
    assert frontier.enqueue(second, 0) is True
    assert frontier.enqueue(third, 4) is True

    assert _drain(frontier) == [
        (first.url, 9),
        (second.url, 0),
        (third.url, 4),
    ]


def test_interleaved_enqueue_and_dequeue_stays_fifo() -> None:
    frontier = Frontier()
    first = parse_target_url("https://app.test/a")
    second = parse_target_url("https://app.test/b")
    third = parse_target_url("https://app.test/c")
    fourth = parse_target_url("https://app.test/d")

    assert frontier.enqueue(first, 0) is True
    assert frontier.enqueue(second, 1) is True
    assert frontier.dequeue() == FrontierItem(target=first, depth=0)

    assert frontier.enqueue(third, 2) is True
    assert frontier.dequeue() == FrontierItem(target=second, depth=1)

    assert frontier.enqueue(fourth, 3) is True

    assert _drain(frontier) == [(third.url, 2), (fourth.url, 3)]


def test_duplicate_enqueue_does_not_grow_or_reorder_the_queue() -> None:
    frontier = Frontier()
    first = parse_target_url("https://app.test/a")
    second = parse_target_url("https://app.test/b")

    assert frontier.enqueue(first, 0) is True
    assert frontier.enqueue(second, 1) is True
    assert frontier.enqueue(first, 5) is False
    assert len(frontier) == 2

    assert _drain(frontier) == [(first.url, 0), (second.url, 1)]


def test_identity_is_the_normalized_url_not_the_instance() -> None:
    frontier = Frontier()
    first = parse_target_url("https://app.test/a")
    second = parse_target_url("https://app.test/a")

    assert first is not second
    assert first == second

    assert frontier.enqueue(first, 0) is True
    assert frontier.enqueue(second, 0) is False
    assert len(frontier) == 1


def test_identity_is_neither_host_nor_origin_only() -> None:
    frontier = Frontier()
    root = parse_target_url("https://app.test/")
    page = parse_target_url("https://app.test/admin")

    assert root.origin == page.origin
    assert root.host == page.host

    assert frontier.enqueue(root, 0) is True
    assert frontier.enqueue(page, 1) is True
    assert len(frontier) == 2


@pytest.mark.parametrize(("first_raw", "second_raw"), _EQUIVALENT_URL_PAIRS)
def test_equivalent_normalized_urls_are_one_identity(
    first_raw: str,
    second_raw: str,
) -> None:
    frontier = Frontier()
    first = parse_target_url(first_raw)
    second = parse_target_url(second_raw)

    assert first.url == second.url

    assert frontier.enqueue(first, 0) is True
    assert frontier.enqueue(second, 1) is False
    assert len(frontier) == 1

    assert _drain(frontier) == [(first.url, 0)]


@pytest.mark.parametrize(("first_raw", "second_raw"), _DISTINCT_URL_PAIRS)
def test_distinct_normalized_urls_stay_separate_identities(
    first_raw: str,
    second_raw: str,
) -> None:
    frontier = Frontier()
    first = parse_target_url(first_raw)
    second = parse_target_url(second_raw)

    assert first.url != second.url

    assert frontier.enqueue(first, 0) is True
    assert frontier.enqueue(second, 1) is True
    assert len(frontier) == 2

    assert _drain(frontier) == [(first.url, 0), (second.url, 1)]


def test_dequeue_does_not_release_the_seen_identity() -> None:
    frontier = Frontier()
    target = parse_target_url("https://app.test/a")

    assert frontier.enqueue(target, 0) is True
    assert frontier.dequeue() == FrontierItem(target=target, depth=0)
    assert len(frontier) == 0

    assert frontier.enqueue(target, 0) is False
    assert len(frontier) == 0
    assert frontier.dequeue() is None


def test_mark_seen_records_an_identity_without_queueing_it() -> None:
    frontier = Frontier()
    target = parse_target_url("https://app.test/a")

    assert frontier.mark_seen(target) is True
    assert len(frontier) == 0
    assert frontier.dequeue() is None


def test_mark_seen_returns_false_for_a_repeated_identity() -> None:
    frontier = Frontier()
    target = parse_target_url("https://app.test/a")

    assert frontier.mark_seen(target) is True
    assert frontier.mark_seen(target) is False
    assert len(frontier) == 0


def test_mark_seen_returns_false_for_an_already_queued_identity() -> None:
    frontier = Frontier()
    target = parse_target_url("https://app.test/a")

    assert frontier.enqueue(target, 0) is True
    assert frontier.mark_seen(target) is False
    assert len(frontier) == 1

    assert _drain(frontier) == [(target.url, 0)]


def test_mark_seen_blocks_a_later_enqueue() -> None:
    frontier = Frontier()
    target = parse_target_url("https://app.test/a")

    assert frontier.mark_seen(target) is True
    assert frontier.enqueue(target, 0) is False
    assert len(frontier) == 0
    assert frontier.dequeue() is None


def test_mark_seen_does_not_disturb_fifo_order() -> None:
    frontier = Frontier()
    first = parse_target_url("https://app.test/a")
    second = parse_target_url("https://app.test/b")
    marked = parse_target_url("https://app.test/redirected")

    assert frontier.enqueue(first, 0) is True
    assert frontier.enqueue(second, 1) is True
    assert frontier.mark_seen(marked) is True
    assert len(frontier) == 2

    assert _drain(frontier) == [(first.url, 0), (second.url, 1)]


@pytest.mark.parametrize(("first_raw", "second_raw"), _EQUIVALENT_URL_PAIRS)
def test_mark_seen_blocks_equivalent_normalized_urls(
    first_raw: str,
    second_raw: str,
) -> None:
    frontier = Frontier()

    assert frontier.mark_seen(parse_target_url(first_raw)) is True
    assert frontier.enqueue(parse_target_url(second_raw), 0) is False
    assert len(frontier) == 0


@pytest.mark.parametrize(("first_raw", "second_raw"), _DISTINCT_URL_PAIRS)
def test_mark_seen_does_not_block_a_distinct_identity(
    first_raw: str,
    second_raw: str,
) -> None:
    frontier = Frontier()
    second = parse_target_url(second_raw)

    assert frontier.mark_seen(parse_target_url(first_raw)) is True
    assert frontier.enqueue(second, 0) is True
    assert len(frontier) == 1

    assert _drain(frontier) == [(second.url, 0)]


def test_len_reports_queued_items_not_seen_identities() -> None:
    frontier = Frontier()

    for index in range(2):
        target = parse_target_url(f"https://app.test/queued/{index}")
        assert frontier.enqueue(target, 0) is True

    for index in range(3):
        target = parse_target_url(f"https://app.test/marked/{index}")
        assert frontier.mark_seen(target) is True

    assert len(frontier) == 2

    assert frontier.dequeue() is not None
    assert len(frontier) == 1


def test_frontier_enforces_no_page_budget() -> None:
    frontier = Frontier()

    for index in range(100):
        target = parse_target_url(f"https://app.test/page/{index}")
        assert frontier.enqueue(target, 1) is True

    assert len(frontier) == 100


def test_frontier_enforces_no_depth_limit() -> None:
    frontier = Frontier()
    target = parse_target_url("https://app.test/deep")

    assert frontier.enqueue(target, 10_000) is True
    assert frontier.dequeue() == FrontierItem(target=target, depth=10_000)
