"""Discovery limits, frontier, HTML extraction, and breadth-first crawl."""

from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator, Collection
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import TYPE_CHECKING

from boundary.scope import (
    Origin,
    ScopeValidationError,
    TargetUrl,
    UrlErrorCode,
    UrlValidationError,
    parse_target_url,
    resolve_allowed_redirect,
)

if TYPE_CHECKING:
    from boundary.scope import AddressPolicy, AddressResolver
    from boundary.transport import RequestLimits, TransportResponse


@dataclass(frozen=True, slots=True)
class DiscoveryLimits:
    """Validated immutable traversal limits for one discovery run."""

    max_pages: int
    max_depth: int

    def __post_init__(self) -> None:
        if self.max_pages <= 0:
            raise ValueError("Maximum page count must be greater than zero.")
        if self.max_depth < 0:
            raise ValueError("Maximum traversal depth cannot be negative.")


@dataclass(frozen=True, slots=True)
class FrontierItem:
    """A normalized target paired with the depth it was discovered at."""

    target: TargetUrl
    depth: int


class Frontier:
    """FIFO frontier that admits each normalized URL identity at most once."""

    def __init__(self) -> None:
        self._queue: deque[FrontierItem] = deque()
        self._seen: set[str] = set()

    def enqueue(self, target: TargetUrl, depth: int) -> bool:
        """Queue a target unless its normalized URL has already been seen."""
        if target.url in self._seen:
            return False

        self._seen.add(target.url)
        self._queue.append(FrontierItem(target=target, depth=depth))
        return True

    def dequeue(self) -> FrontierItem | None:
        """Remove and return the oldest pending item, leaving it seen."""
        if not self._queue:
            return None

        return self._queue.popleft()

    def mark_seen(self, target: TargetUrl) -> bool:
        """Record a normalized URL as seen without queueing anything."""
        if target.url in self._seen:
            return False

        self._seen.add(target.url)
        return True

    def __len__(self) -> int:
        return len(self._queue)


def resolve_candidate(
    base: TargetUrl,
    reference: str,
    allowed_origins: Collection[Origin],
) -> TargetUrl | None:
    """Resolve an HTML URL reference into a scope-approved target, or None."""
    stripped = reference.strip(" \t\n\f\r")

    if not stripped or stripped.startswith("#"):
        return None

    try:
        parse_target_url(stripped)
    except UrlValidationError as error:
        if error.code is not UrlErrorCode.MALFORMED_URL:
            return None

    try:
        return resolve_allowed_redirect(
            current=base,
            location=stripped,
            allowed_origins=allowed_origins,
        )
    except (UrlValidationError, ScopeValidationError):
        return None


def is_html_response(
    headers: Collection[tuple[bytes, bytes]],
) -> bool:
    """Return True when headers carry exactly one text/html Content-Type."""
    values = [value for name, value in headers if name.lower() == b"content-type"]
    if len(values) != 1:
        return False

    try:
        decoded = values[0].decode("ascii")
    except UnicodeDecodeError:
        return False

    media_type = decoded.split(";", 1)[0].strip(" \t")
    return media_type.lower() == "text/html"


class _HtmlReferenceParser(HTMLParser):
    _ATTRIBUTES = {
        "a": "href",
        "form": "action",
        "script": "src",
        "link": "href",
    }

    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        wanted = self._ATTRIBUTES.get(tag)
        if wanted is None:
            return

        for name, value in attrs:
            if name == wanted:
                if value is not None:
                    self.references.append(value)
                break


def extract_html_references(
    body: bytes,
) -> tuple[str, ...]:
    """Return document-order URL attributes from UTF-8 HTML bytes."""
    text = body.decode("utf-8")
    parser = _HtmlReferenceParser()
    parser.feed(text)
    parser.close()
    return tuple(parser.references)


@dataclass(frozen=True, slots=True)
class DiscoveredPage:
    """One successfully requested discovery page and its transport response."""

    target: TargetUrl
    depth: int
    response: TransportResponse


async def crawl(
    seed: TargetUrl,
    *,
    allowed_origins: Collection[Origin],
    policy: AddressPolicy,
    resolver: AddressResolver,
    request_limits: RequestLimits,
    max_redirects: int,
    limits: DiscoveryLimits,
) -> AsyncIterator[DiscoveredPage]:
    """Yield pages from a deterministic single-flight breadth-first crawl."""
    from boundary.transport import request_with_redirects

    frontier = Frontier()
    frontier.enqueue(seed, 0)
    visited_count = 0

    while True:
        item = frontier.dequeue()
        if item is None:
            return

        visited_count += 1

        response = await request_with_redirects(
            item.target,
            allowed_origins=allowed_origins,
            policy=policy,
            resolver=resolver,
            limits=request_limits,
            max_redirects=max_redirects,
            method="GET",
        )

        frontier.mark_seen(response.final_target)

        yield DiscoveredPage(
            target=item.target,
            depth=item.depth,
            response=response,
        )

        if item.depth >= limits.max_depth:
            continue

        if not is_html_response(response.headers):
            continue

        for reference in extract_html_references(response.body):
            candidate = resolve_candidate(
                base=response.final_target,
                reference=reference,
                allowed_origins=allowed_origins,
            )
            if candidate is None:
                continue

            if visited_count + len(frontier) >= limits.max_pages:
                continue

            frontier.enqueue(candidate, item.depth + 1)
