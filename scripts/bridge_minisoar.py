"""Bridge verified Mini-SOAR evidence bundles into SentinelGRC findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit_log import AuditLog, canonical_json
from minisoar_connector import normalize_minisoar_incident
from path_security import (
    configured_runtime_root,
    resolve_directory_under_root,
    resolve_sqlite_database_under_root,
    resolve_under_root,
)
from state_store import SQLiteStateStore

CONNECTOR_ACTOR = "minisoar-bridge-connector"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _new_result() -> dict[str, Any]:
    return {
        "bundle_read": False,
        "finding_created": False,
        "finding_reassessed": False,
        "finding_replayed": False,
        "skipped_reason": None,
        "sentinel_finding_id": None,
        "errors": 0,
    }


def _fail(result: dict[str, Any], message: str) -> dict[str, Any]:
    result["errors"] = 1
    result["skipped_reason"] = message
    return result


def _select_runtime_root(
    evidence_dir: str,
    governance_db: str,
    audit_log_path: str | None,
    runtime_root: str | Path | None,
) -> Path:
    if runtime_root is not None:
        return Path(runtime_root)
    candidates = [Path(evidence_dir), Path(governance_db)]
    if audit_log_path is not None:
        candidates.append(Path(audit_log_path))
    try:
        return Path(os.path.commonpath([str(path.resolve()) for path in candidates]))
    except ValueError as exc:
        raise ValueError("bridge paths must share a common runtime root") from exc


def _read_bundle(base: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
    finding = _read_json(base / "finding.json")
    alert = _read_json(base / "alert.json")
    verification_path = base / "verification.json"
    verification = _read_json(verification_path) if verification_path.exists() else None
    return finding, alert, verification


def _resolve_storage_paths(
    governance_db: str,
    audit_log_path: str | None,
    runtime_root: Path,
) -> tuple[Path, Path]:
    database_path = resolve_sqlite_database_under_root(
        governance_db,
        runtime_root,
        purpose="governance database",
    )
    requested_audit_path = audit_log_path or str(
        database_path.with_suffix(".audit.jsonl")
    )
    audit_path = resolve_under_root(
        requested_audit_path,
        runtime_root,
        purpose="Mini-SOAR audit log",
    )
    return database_path, audit_path


def _evidence_hash(normalized: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()


def _apply_import_action(
    result: dict[str, Any],
    finding_id: str,
    action: str,
) -> None:
    if action not in {"created", "reassessed", "replayed"}:
        raise ValueError("governance storage returned an invalid import action")
    result["sentinel_finding_id"] = finding_id
    result[f"finding_{action}"] = True


def run_minisoar_bridge(
    evidence_dir: str,
    governance_db: str,
    *,
    require_verification_pass: bool = True,
    audit_log_path: str | None = None,
    runtime_root: str | Path | None = None,
) -> dict[str, Any]:
    """Import one exported bundle and return a sanitized bridge outcome."""
    result = _new_result()
    try:
        selected_root = _select_runtime_root(
            evidence_dir, governance_db, audit_log_path, runtime_root
        )
        base = resolve_directory_under_root(
            evidence_dir,
            selected_root,
            purpose="Mini-SOAR evidence directory",
        )
    except (OSError, ValueError) as exc:
        return _fail(result, str(exc))

    try:
        finding, alert, verification = _read_bundle(base)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return _fail(result, "could not read required evidence bundle files")

    result["bundle_read"] = True
    try:
        normalized = normalize_minisoar_incident(
            finding, alert, verification,
            require_verification_pass=require_verification_pass,
        )
    except (TypeError, ValueError) as exc:
        return _fail(result, str(exc))

    if normalized is None:
        result["skipped_reason"] = "incident is not closed, synthetic, or independently verified"
        return result

    try:
        database_path, audit_path = _resolve_storage_paths(
            governance_db, audit_log_path, selected_root
        )
    except (OSError, ValueError) as exc:
        return _fail(result, str(exc))

    try:
        store = SQLiteStateStore(database_path, storage_root=selected_root)
        outcome = store.record_external_finding_import(
            normalized, _evidence_hash(normalized)
        )
        _apply_import_action(result, normalized["finding_id"], outcome["action"])
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        return _fail(result, f"governance storage failed: {exc}")

    audit_event = outcome["audit_event"]
    if audit_event is None:
        return result
    try:
        AuditLog(audit_path).append_idempotent(
            audit_event["event_id"],
            audit_event["event_type"],
            CONNECTOR_ACTOR,
            audit_event["finding_id"],
            audit_event["details"],
        )
        store.mark_external_finding_audit_delivered(audit_event["event_id"])
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        return _fail(
            result,
            f"finding state was persisted but audit delivery failed: {exc}",
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bridge closed, verified Mini-SOAR evidence into SentinelGRC findings.",
    )
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--governance-db", required=True)
    parser.add_argument("--audit-log", help="Optional SentinelGRC audit-log location.")
    parser.add_argument(
        "--allow-unverified", action="store_true",
        help="Permit a closed bundle without passing verification; off by default.",
    )
    args = parser.parse_args()
    outcome = run_minisoar_bridge(
        args.evidence_dir,
        args.governance_db,
        require_verification_pass=not args.allow_unverified,
        audit_log_path=args.audit_log,
        runtime_root=configured_runtime_root(),
    )
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 1 if outcome["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
