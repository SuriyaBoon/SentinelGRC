"""Fail-closed trust boundaries for local paths and outbound URLs."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit


_SQLITE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}


def configured_runtime_root() -> Path:
    """Return the operator-controlled process boundary, never a CLI value."""
    configured = os.environ.get("SENTINEL_RUNTIME_ROOT")
    boundary = Path(configured) if configured else Path.cwd()
    resolved = boundary.expanduser().resolve(strict=False)
    if resolved.exists() and not resolved.is_dir():
        raise ValueError("SENTINEL_RUNTIME_ROOT must identify a directory")
    return resolved


def resolve_under_root(
    value: str | Path,
    root: str | Path,
    *,
    purpose: str = "runtime path",
) -> Path:
    """Resolve one path and reject traversal or symlink escape from root."""
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise ValueError(f"{purpose} must be a non-empty filesystem path")
    raw = str(value)
    if "\x00" in raw:
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


def resolve_existing_file_under_root(
    value: str | Path,
    root: str | Path,
    *,
    purpose: str = "input file",
) -> Path:
    path = resolve_under_root(value, root, purpose=purpose)
    if not path.is_file():
        raise ValueError(f"{purpose} must be an existing regular file")
    return path


def resolve_directory_under_root(
    value: str | Path,
    root: str | Path,
    *,
    purpose: str = "runtime directory",
    create: bool = False,
) -> Path:
    path = resolve_under_root(value, root, purpose=purpose)
    if path.exists() and not path.is_dir():
        raise ValueError(f"{purpose} must be a directory")
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def select_storage_root(
    value: str | Path,
    configured_root: str | Path | None,
) -> Path:
    """Select the trusted root for a local state database without nesting ternaries."""
    supplied = Path(value).expanduser()
    if configured_root is not None:
        return Path(configured_root)
    if supplied.is_absolute():
        return supplied.parent
    return Path.cwd()


def resolve_sqlite_database_under_root(
    value: str | Path,
    root: str | Path,
    *,
    purpose: str = "SQLite database",
) -> Path:
    """Return a confined local SQLite filename, never a connection URI."""
    raw = str(value).strip()
    if raw.lower().startswith("file:") or "?" in raw or "#" in raw:
        raise ValueError(f"{purpose} must be a local filename, not a URI")
    path = resolve_under_root(value, root, purpose=purpose)
    if path.suffix.lower() not in _SQLITE_SUFFIXES:
        raise ValueError(f"{purpose} must end in .db, .sqlite, or .sqlite3")
    return path


def validate_outbound_url(
    value: str,
    *,
    allowed_hosts: set[str],
    allow_loopback_http: bool = False,
) -> str:
    """Require HTTPS and an exact host allowlist; HTTP is loopback-only opt-in."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("outbound URL must be non-empty")
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    normalized_hosts = {item.lower().rstrip(".") for item in allowed_hosts if item}
    if not host or host not in normalized_hosts:
        raise ValueError("outbound URL host is not allowlisted")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("outbound URL cannot contain credentials or a fragment")
    if parsed.scheme != "https":
        if parsed.scheme != "http" or not allow_loopback_http:
            raise ValueError("outbound URL must use HTTPS")
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise ValueError(
                "plain HTTP is allowed only for an explicit loopback lab target"
            )
    return parsed.geturl()
