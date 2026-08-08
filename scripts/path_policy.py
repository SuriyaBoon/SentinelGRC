"""Fail-closed filesystem boundaries for command-line runtime paths."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def resolve_under_root(
    value: str | Path,
    root: str | Path,
    *,
    purpose: str = "runtime path",
) -> Path:
    """Resolve a path and require it to remain inside the trusted root."""
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise ValueError(f"{purpose} must be a non-empty filesystem path")
    if "\x00" in str(value):
        raise ValueError(f"{purpose} contains a null byte")

    boundary = Path(root).expanduser().resolve(strict=False)
    supplied = Path(value).expanduser()
    candidate = supplied if supplied.is_absolute() else boundary / supplied
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(boundary)
    except ValueError as error:
        raise ValueError(f"{purpose} must remain under {boundary}") from error
    return resolved


def read_text_under_root(
    value: str | Path,
    root: str | Path,
    *,
    purpose: str = "input path",
) -> str:
    path = resolve_under_root(value, root, purpose=purpose)
    return path.read_text(encoding="utf-8")


def load_json_under_root(
    value: str | Path,
    root: str | Path,
    *,
    purpose: str = "JSON input path",
) -> Any:
    return json.loads(read_text_under_root(value, root, purpose=purpose))


def write_text_under_root(
    value: str | Path,
    root: str | Path,
    content: str,
    *,
    purpose: str = "output path",
) -> Path:
    """Write text only after resolving the destination inside a trusted root."""
    if not isinstance(content, str):
        raise TypeError("output content must be text")
    path = resolve_under_root(value, root, purpose=purpose)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def require_exact_output(value: str, expected: str, *, purpose: str) -> None:
    """Require a CLI output argument to match its documented fixed path."""
    normalized = value.replace("\\", "/")
    if normalized != expected:
        raise ValueError(f"{purpose} must be exactly {expected}")
