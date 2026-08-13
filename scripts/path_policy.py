"""Fail-closed filesystem boundaries for command-line runtime paths."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from path_security import resolve_under_root


_EVIDENCE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def validate_evidence_id(value: str, *, purpose: str = "evidence ID") -> str:
    """Return one portable output identity or reject it before side effects."""
    if not isinstance(value, str) or _EVIDENCE_ID_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{purpose} must be 1-127 ASCII letters, digits, dots, underscores, or hyphens"
        )
    if value.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
        raise ValueError(f"{purpose} is a reserved filesystem name")
    return value


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
        "runtime/staging-assurance/offline-evidence.json": Path(
            "runtime/staging-assurance/offline-evidence.json"
        ),
        "runtime/staging-assurance/load-soak-evidence.json": Path(
            "runtime/staging-assurance/load-soak-evidence.json"
        ),
        "runtime/staging-assurance/hermetic-recovery-evidence.json": Path(
            "runtime/staging-assurance/hermetic-recovery-evidence.json"
        ),
        "runtime/staging-assurance/security-assessment-evidence.json": Path(
            "runtime/staging-assurance/security-assessment-evidence.json"
        ),
        "remediation.json": Path("remediation.json"),
        "tickets.json": Path("tickets.json"),
        "report.json": Path("report.json"),
    }
    selected = fixed_outputs.get(relative)
    if selected is None:
        match = re.fullmatch(
            r"(?:(runtime)/)?(remediation|tickets|reports)/([^/]+)\.json",
            relative,
        )
        if match is None:
            raise ValueError(f"{purpose} is not an allowed runtime output")
        runtime_prefix, family, evidence_id = match.groups()
        evidence_id = validate_evidence_id(evidence_id, purpose="output evidence ID")
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
