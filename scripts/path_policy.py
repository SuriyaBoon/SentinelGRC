"""Fail-closed filesystem boundaries for command-line runtime paths."""

from __future__ import annotations

import json
import re
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


def _allowed_output_path(value: str | Path, root: str | Path, *, purpose: str) -> Path:
    """Select a fixed output route and validate any worker-owned evidence ID."""
    boundary = Path(root).expanduser().resolve(strict=False)
    resolved = resolve_under_root(value, boundary, purpose=purpose)
    relative = resolved.relative_to(boundary).as_posix()
    fixed_outputs = {
        "runtime/remediation-queue.json": Path("runtime/remediation-queue.json"),
        "runtime/tickets.json": Path("runtime/tickets.json"),
        "runtime/executive-report.json": Path("runtime/executive-report.json"),
        "runtime/staging-assurance/offline-report.json": Path(
            "runtime/staging-assurance/offline-report.json"
        ),
        "remediation.json": Path("remediation.json"),
        "tickets.json": Path("tickets.json"),
        "report.json": Path("report.json"),
    }
    selected = fixed_outputs.get(relative)
    if selected is None:
        match = re.fullmatch(
            r"(?:(runtime)/)?(remediation|tickets|reports)/"
            r"([A-Za-z0-9][A-Za-z0-9._-]{0,126})\.json",
            relative,
        )
        if match is None:
            raise ValueError(f"{purpose} is not an allowed runtime output")
        runtime_prefix, family, evidence_id = match.groups()
        selected_directory = Path(family)
        if runtime_prefix is not None:
            selected_directory = Path("runtime") / selected_directory
        selected = selected_directory / f"{evidence_id}.json"
    return boundary / selected

def resolve_worker_output_directory(
    value: str | Path,
    root: str | Path,
    family: str,
    *,
    purpose: str = "worker output directory",
) -> Path:
    """Resolve one worker-owned output family without creating any artifact."""
    if family not in {"remediation", "tickets", "reports"}:
        raise ValueError("worker output family is not allowed")
    boundary = Path(root).expanduser().resolve(strict=False)
    resolved = resolve_under_root(value, boundary, purpose=purpose)
    relative = resolved.relative_to(boundary).as_posix()
    if relative not in {family, f"runtime/{family}"}:
        raise ValueError(f"{purpose} is not an allowed runtime output directory")
    return resolved


def write_text_under_root(
    value: str | Path,
    root: str | Path,
    content: str,
    *,
    purpose: str = "output path",
) -> Path:
    """Write text to a fixed allowlisted destination under a trusted root."""
    if not isinstance(content, str):
        raise TypeError("output content must be text")
    path = _allowed_output_path(value, root, purpose=purpose)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(content)
    return path

def require_exact_output(value: str, expected: str, *, purpose: str) -> None:
    """Require a CLI output argument to match its documented fixed path."""
    normalized = value.replace("\\", "/")
    if normalized != expected:
        raise ValueError(f"{purpose} must be exactly {expected}")
