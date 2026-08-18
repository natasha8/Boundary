"""Explicit identity labels and ordered authorization comparison cases."""

from __future__ import annotations

import re
from dataclasses import dataclass

from boundary.scope import TargetUrl

_IDENTITY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True, slots=True)
class Identity:
    """Public identity label that is safe to store in findings."""

    identity_id: str

    def __post_init__(self) -> None:
        if _IDENTITY_ID_PATTERN.fullmatch(self.identity_id) is None:
            raise ValueError(
                "identity_id must be a non-empty ASCII token of letters, "
                "digits, dots, underscores and hyphens."
            )


@dataclass(frozen=True, slots=True)
class AuthorizationCase:
    """One explicit target plus two ordered, distinct identities."""

    target: TargetUrl
    baseline: Identity
    comparison: Identity

    def __post_init__(self) -> None:
        if self.baseline.identity_id == self.comparison.identity_id:
            raise ValueError("baseline and comparison identities must be distinct.")
