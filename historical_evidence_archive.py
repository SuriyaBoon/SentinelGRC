"""Validation boundary for sanitized historical staging evidence archives.

The archive contains metadata and hashes only. Raw cloud exports stay outside
the repository and can be verified separately when an authorized reviewer has
access to the private source directory.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "sentinel.historical_azure_evidence.v1"
README_NAME = "README.md"
MANIFEST_NAME = "manifest.json"
CHECKSUM_NAME = "SHA256SUMS.txt"
ARCHIVE_FILES = {README_NAME, MANIFEST_NAME, CHECKSUM_NAME}
CONTROL_STATUSES = {"passed", "partial", "failed", "not_tested"}
HISTORICAL_DECISION = "HISTORICAL_ONLY_NO_CURRENT_GATE_CREDIT"
MAX_MANIFEST_BYTES = 256 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARCHIVE_ID = re.compile(r"^[A-Z0-9][A-Z0-9-]{7,79}$")
_CONTROL_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_SOURCE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,127}\.json$")
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"/subscriptions/", re.IGNORECASE),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b"),
    re.compile(r"\b[A-Za-z0-9-]+\.(?:azure|windows)\.(?:com|net)\b", re.IGNORECASE),
    re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"),
)
_SENSITIVE_KEYS = {
    "access_key",
    "client_id",
    "client_secret",
    "connection_string",
    "email",
    "endpoint",
    "fqdn",
    "object_id",
    "password",
    "principal_id",
    "resource_id",
    "secret",
    "subscription_id",
    "tenant_id",
    "token",
    "url",
}


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"historical evidence contains duplicate key: {key}")
        result[key] = value
    return result


def _expect_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} fields are invalid")
    return value


def _expect_text(value: Any, label: str, *, maximum: int = 500) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} is invalid")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain ASCII text only") from error
    return value


def _expect_utc_timestamp(value: Any, label: str) -> str:
    text = _expect_text(value, label, maximum=20)
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ValueError(f"{label} must use UTC second precision") from error
    return text


def _reject_sensitive_material(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in _SENSITIVE_KEYS:
                raise ValueError(f"{path} contains prohibited sensitive field: {key}")
            _reject_sensitive_material(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive_material(item, f"{path}[{index}]")
        return
    if isinstance(value, str):
        for pattern in _SENSITIVE_VALUE_PATTERNS:
            if pattern.search(value):
                raise ValueError(f"{path} contains prohibited sensitive value")


def _validate_provenance(value: Any) -> None:
    provenance = _expect_exact_keys(
        value,
        {"source_commit_sha", "runtime_image_digest", "assurance_image_digest"},
        "historical evidence provenance",
    )
    if not _COMMIT_SHA.fullmatch(str(provenance["source_commit_sha"])):
        raise ValueError("historical evidence source commit SHA is invalid")
    for name in ("runtime_image_digest", "assurance_image_digest"):
        if not _IMAGE_DIGEST.fullmatch(str(provenance[name])):
            raise ValueError(f"historical evidence {name} is invalid")


def _validate_claim_boundary(value: Any) -> None:
    boundary = _expect_exact_keys(
        value,
        {"production_ready", "current_live_gate_credit", "decision", "statement"},
        "historical evidence claim boundary",
    )
    if boundary["production_ready"] is not False:
        raise ValueError("historical evidence cannot claim production readiness")
    if boundary["current_live_gate_credit"] is not False:
        raise ValueError("historical evidence cannot satisfy current live gates")
    if boundary["decision"] != HISTORICAL_DECISION:
        raise ValueError("historical evidence decision is invalid")
    _expect_text(boundary["statement"], "historical evidence claim statement")


def _validate_controls(value: Any) -> None:
    if not isinstance(value, list) or not value:
        raise ValueError("historical evidence controls are invalid")
    control_ids: set[str] = set()
    for index, item in enumerate(value):
        control = _expect_exact_keys(
            item,
            {"control_id", "status", "summary", "source_file", "source_sha256"},
            f"historical evidence control {index}",
        )
        control_id = str(control["control_id"])
        if not _CONTROL_ID.fullmatch(control_id) or control_id in control_ids:
            raise ValueError("historical evidence control identity is invalid")
        control_ids.add(control_id)
        status = control["status"]
        if status not in CONTROL_STATUSES:
            raise ValueError(f"historical evidence control status is invalid: {control_id}")
        _expect_text(control["summary"], f"historical evidence summary: {control_id}")
        if not _SOURCE_FILE.fullmatch(str(control["source_file"])):
            raise ValueError(f"historical evidence source filename is invalid: {control_id}")
        if not _SHA256.fullmatch(str(control["source_sha256"])):
            raise ValueError(f"historical evidence source hash is invalid: {control_id}")


def validate_manifest(manifest: Any) -> dict[str, Any]:
    document = _expect_exact_keys(
        manifest,
        {
            "schema_version",
            "archive_id",
            "classification",
            "environment",
            "captured_from_utc",
            "captured_to_utc",
            "provenance",
            "claim_boundary",
            "controls",
        },
        "historical evidence manifest",
    )
    _reject_sensitive_material(document)
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("historical evidence schema is invalid")
    if not _ARCHIVE_ID.fullmatch(str(document["archive_id"])):
        raise ValueError("historical evidence archive identity is invalid")
    if document["classification"] != "historical_sanitized_staging_evidence":
        raise ValueError("historical evidence classification is invalid")
    if document["environment"] != "staging":
        raise ValueError("historical evidence environment is invalid")
    captured_from = _expect_utc_timestamp(document["captured_from_utc"], "captured_from_utc")
    captured_to = _expect_utc_timestamp(document["captured_to_utc"], "captured_to_utc")
    if captured_from > captured_to:
        raise ValueError("historical evidence capture interval is invalid")
    _validate_provenance(document["provenance"])
    _validate_claim_boundary(document["claim_boundary"])
    _validate_controls(document["controls"])
    return document


def canonical_manifest_bytes(manifest: Any) -> bytes:
    validated = validate_manifest(manifest)
    return (json.dumps(validated, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def manifest_sha256(manifest: Any) -> str:
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def canonical_text_bytes(raw: bytes, label: str) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} must contain valid UTF-8") from error
    if "\x00" in text:
        raise ValueError(f"{label} contains a prohibited null byte")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def load_manifest(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError as error:
        raise ValueError("historical evidence manifest cannot be read") from error
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("historical evidence manifest size is invalid")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("historical evidence manifest JSON is invalid") from error
    return validate_manifest(parsed)


def _read_expected_checksums(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("historical evidence checksum file cannot be read") from error
    if len(lines) != 2:
        raise ValueError("historical evidence checksum file is invalid")
    expected: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(
            rf"([0-9a-f]{{64}}) {{2}}({re.escape(README_NAME)}|{re.escape(MANIFEST_NAME)})",
            line,
        )
        if match is None or match.group(2) in expected:
            raise ValueError("historical evidence checksum entry is invalid")
        expected[match.group(2)] = match.group(1)
    if set(expected) != {README_NAME, MANIFEST_NAME}:
        raise ValueError("historical evidence checksum coverage is invalid")
    return expected


def verify_archive(root: str | Path) -> dict[str, Any]:
    supplied_root = Path(root)
    if supplied_root.is_symlink():
        raise ValueError("historical evidence archive root is invalid")
    archive_root = supplied_root.resolve()
    if not archive_root.is_dir():
        raise ValueError("historical evidence archive root is invalid")
    entries = list(archive_root.iterdir())
    if (
        {item.name for item in entries} != ARCHIVE_FILES
        or any(not item.is_file() or item.is_symlink() for item in entries)
    ):
        raise ValueError("historical evidence archive files are invalid")
    manifest = load_manifest(archive_root / MANIFEST_NAME)
    expected = _read_expected_checksums(archive_root / CHECKSUM_NAME)
    actual = {
        README_NAME: hashlib.sha256(
            canonical_text_bytes((archive_root / README_NAME).read_bytes(), README_NAME)
        ).hexdigest(),
        MANIFEST_NAME: manifest_sha256(manifest),
    }
    if actual != expected:
        raise ValueError("historical evidence archive checksum mismatch")
    return {
        "archive_id": manifest["archive_id"],
        "manifest_sha256": actual[MANIFEST_NAME],
        "control_count": len(manifest["controls"]),
        "decision": manifest["claim_boundary"]["decision"],
        "current_live_gate_credit": False,
    }


def verify_private_sources(manifest: Any, private_root: str | Path) -> dict[str, str]:
    validated = validate_manifest(manifest)
    supplied_root = Path(private_root)
    if supplied_root.is_symlink():
        raise ValueError("private historical evidence root is invalid")
    root = supplied_root.resolve()
    if not root.is_dir():
        raise ValueError("private historical evidence root is invalid")
    expected_by_name: dict[str, str] = {}
    for control in validated["controls"]:
        name = control["source_file"]
        digest = control["source_sha256"]
        previous = expected_by_name.setdefault(name, digest)
        if previous != digest:
            raise ValueError("historical evidence source has conflicting hashes")
    verified: dict[str, str] = {}
    for name, expected in sorted(expected_by_name.items()):
        target = root / name
        if target.is_symlink() or target.resolve().parent != root:
            raise ValueError(f"private historical evidence path is invalid: {name}")
        try:
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError as error:
            raise ValueError(f"private historical evidence cannot be read: {name}") from error
        if actual != expected:
            raise ValueError(f"private historical evidence hash mismatch: {name}")
        verified[name] = actual
    return verified
