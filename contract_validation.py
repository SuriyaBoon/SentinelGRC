"""Shared fail-closed validation primitives for external contracts."""
from __future__ import annotations

import re
from datetime import datetime


CANONICAL_TEXT_PATTERN = (
    r"^[^\s\u0000-\u001F\u007F\u0080-\u009F\u200B\u2028\u2029\uFEFF]"
    r"(?:[^\u0000-\u001F\u007F\u0080-\u009F\u200B\u2028\u2029\uFEFF]*"
    r"[^\s\u0000-\u001F\u007F\u0080-\u009F\u200B\u2028\u2029\uFEFF])?$"
)
CANONICAL_TEXT = re.compile(CANONICAL_TEXT_PATTERN)
IDENTIFIER_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
IDENTIFIER = re.compile(IDENTIFIER_PATTERN, re.ASCII)
SOURCE_IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9._:-]{0,127}$"
SOURCE_IDENTIFIER = re.compile(SOURCE_IDENTIFIER_PATTERN, re.ASCII)
# Connector evidence does not require custom ports. Keeping one shared profile
# prevents a looser connector from bypassing the portfolio contract boundary.
EVIDENCE_HOST_PATTERN = (
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*"
)
EVIDENCE_TEXT_PATTERN = (
    r"[^\s\u0000-\u001F\u007F\u0080-\u009F\u200B\u2028\u2029\uFEFF]"
)
EVIDENCE_REFERENCE_PATTERN = (
    r"^(?:urn:"
    + EVIDENCE_TEXT_PATTERN
    + r"+|(?:https|azblob|sample)://"
    + EVIDENCE_HOST_PATTERN
    + r"(?:[/?#]"
    + EVIDENCE_TEXT_PATTERN
    + r"*)?)$"
)
EVIDENCE_REFERENCE = re.compile(EVIDENCE_REFERENCE_PATTERN, re.ASCII)
# The optional fractional-second group is deliberately capped at six digits:
# datetime storage and this repository's normalization are microsecond-based,
# so a longer fraction could not be represented faithfully - distinct instants
# would silently collapse to the same microsecond timestamp.
RFC3339_PATTERN = (
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
RFC3339_TIMESTAMP = re.compile(RFC3339_PATTERN, re.ASCII)

# A source's input timestamp may carry any RFC3339 offset (RFC3339_PATTERN,
# above). Every _timestamp() normalizer in portfolio_contracts.py always
# converts to UTC and renders it with a trailing "Z" - so a *normalized*
# record's timestamp fields are always a strict subset of RFC3339_PATTERN.
# The normalized-record schemas (asset-context-normalized.v1,
# remediation-ticket-normalized.v1) should use this pattern instead of the
# offset-permitting one, since a normalized record with a "+07:00" offset
# would indicate normalize_*_v1() itself is broken, not a legitimate input
# variation to accept.
NORMALIZED_RFC3339_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
UTC_OFFSET = "+00:00"


def is_canonical_text(value: object, maximum: int) -> bool:
    """Accept bounded text without controls or boundary whitespace."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and CANONICAL_TEXT.fullmatch(value) is not None
    )


def is_identifier(value: object) -> bool:
    """Accept one canonical external identifier."""
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def is_source_identifier(value: object) -> bool:
    """Accept one canonical lowercase external source identifier."""
    return (
        isinstance(value, str)
        and SOURCE_IDENTIFIER.fullmatch(value) is not None
    )


def is_evidence_reference(value: object) -> bool:
    """Accept one canonical evidence URI from the repository allowlist."""
    return (
        is_canonical_text(value, 512)
        and EVIDENCE_REFERENCE.fullmatch(value) is not None
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
