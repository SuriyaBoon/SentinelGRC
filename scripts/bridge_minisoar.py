"""Bridge verified Mini-SOAR evidence bundles into SentinelGRC findings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit_log import AuditLog
from minisoar_connector import normalize_minisoar_incident
from state_store import SQLiteStateStore

CONNECTOR_ACTOR = "minisoar-bridge-connector"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def run_minisoar_bridge(
    evidence_dir: str,
    governance_db: str,
    *,
    require_verification_pass: bool = True,
    audit_log_path: str | None = None,
) -> dict[str, Any]:
    """Import one exported bundle and return a sanitized bridge outcome."""
    result: dict[str, Any] = {
        "bundle_read": False,
        "finding_created": False,
        "finding_reassessed": False,
        "skipped_reason": None,
        "sentinel_finding_id": None,
        "errors": 0,
    }
    base = Path(evidence_dir)
    try:
        finding = _read_json(base / "finding.json")
        alert = _read_json(base / "alert.json")
        verification_path = base / "verification.json"
        verification = _read_json(verification_path) if verification_path.exists() else None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        result["errors"] = 1
        result["skipped_reason"] = "could not read required evidence bundle files"
        return result

    result["bundle_read"] = True
    try:
        normalized = normalize_minisoar_incident(
            finding, alert, verification,
            require_verification_pass=require_verification_pass,
        )
    except (TypeError, ValueError) as exc:
        result["errors"] = 1
        result["skipped_reason"] = str(exc)
        return result

    if normalized is None:
        result["skipped_reason"] = "incident is not closed, synthetic, or independently verified"
        return result

    store = SQLiteStateStore(governance_db)
    created = store.upsert_external_finding(normalized)
    result["sentinel_finding_id"] = normalized["finding_id"]
    result["finding_created" if created else "finding_reassessed"] = True

    audit_path = audit_log_path or str(Path(governance_db).with_suffix(".audit.jsonl"))
    AuditLog(audit_path).append(
        "bridge.minisoar.finding.created" if created else "bridge.minisoar.finding.reassessed",
        CONNECTOR_ACTOR,
        normalized["finding_id"],
        {"control_id": normalized["control_id"], "source": normalized["source"]},
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
    )
    print(json.dumps(outcome, indent=2, sort_keys=True))
    return 1 if outcome["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
