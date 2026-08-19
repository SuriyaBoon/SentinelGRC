"""Shared fail-closed validation primitives for external contracts."""

from __future__ import annotations

import re
from datetime import datetime


CANONICAL_TEXT_PATTERN = (
    r"^[^\s\u0000-\u001F\u007F]"
    r"(?:[^\u0000-\u001F\u007F]*[^\s\u0000-\u001F\u007F])?$"
)
CANONICAL_TEXT = re.compile(CANONICAL_TEXT_PATTERN)
RFC3339_PATTERN = (
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
RFC3339_TIMESTAMP = re.compile(RFC3339_PATTERN, re.ASCII)
UTC_OFFSET = "+00:00"


def is_canonical_text(value: object, maximum: int) -> bool:
    """Accept bounded text without controls or boundary whitespace."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and CANONICAL_TEXT.fullmatch(value) is not None
    )


def parse_rfc3339(value: object, label: str, name: str) -> datetime:
    """Parse the repository's strict timezone-bearing RFC3339 profile."""
    if not isinstance(value, str) or RFC3339_TIMESTAMP.fullmatch(value) is None:
        raise ValueError(f"{label} {name} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", UTC_OFFSET))
    except ValueError as error:
        raise ValueError(f"{label} {name} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} {name} must include a timezone")
    return parsed
