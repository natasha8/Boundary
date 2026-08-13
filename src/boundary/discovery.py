"""Discovery limits and the bounded frontier used by controlled traversal."""

from collections import deque
from collections.abc import Collection
from dataclasses import dataclass

from boundary.scope import (
    Origin,
    ScopeValidationError,
    TargetUrl,
    UrlErrorCode,
    UrlValidationError,
    parse_target_url,
    resolve_allowed_redirect,
)


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
