"""SentinelGRC Phase 7: deterministic end-to-end governance orchestration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts import governance, workflow
from audit_log import AuditLog
from governance_core import ActorContext, GovernanceCore
from sentinelgrc import append_evidence_atomic, build_evidence, canonical_json, evaluate_control, find_ledger_record, load_json
from state_store import SQLiteStateStore


def _write_json(path: str, value: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _input_hash(inputs: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(inputs).encode("utf-8")).hexdigest()


def run_pipeline(
    posture: dict[str, Any],
    controls: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    ledger_path: str,
    remediation_path: str,
    tickets_path: str,
    report_path: str,
    state_db: str,
    access_review: dict[str, Any] | None = None,
    created_at: datetime | None = None,
    audit_path: str | None = None,
    run_lease_seconds: int = 900,
    governance_db: str | None = None,
) -> dict[str, Any]:
    storage_mode = os.getenv("SENTINEL_STORAGE", "legacy").lower()
    if storage_mode not in {"legacy", "governance"}:
        raise ValueError("SENTINEL_STORAGE must be legacy or governance")
    governance_db = governance_db or os.getenv("SENTINEL_GOVERNANCE_DB")
    if storage_mode == "governance" and not governance_db:
        governance_db = "runtime/governance.db"
    if not isinstance(posture, dict) or not posture.get("asset_id") or not posture.get("hostname"):
        raise ValueError("Posture must contain asset_id and hostname.")
    if not isinstance(controls, list) or not isinstance(assets, list):
        raise ValueError("Controls and assets must be JSON arrays.")
    review = access_review or {"schema_version": "1.0", "users": []}
    inputs = {"posture": posture, "controls": controls, "assets": assets, "access_review": review}
    input_hash = _input_hash(inputs)
    run_id = "PL-" + input_hash[:12].upper()
    store = SQLiteStateStore(state_db)
    if not store.claim_pipeline_run(input_hash, lease_seconds=run_lease_seconds):
        existing = store.get_pipeline_run(input_hash)
        return {
            "status": "duplicate",
            "run_id": run_id,
            "input_hash": input_hash,
            "ledger_record_hash": existing["ledger_record_hash"] if existing else None,
            "remediation_path": existing["remediation_path"] if existing else remediation_path,
            "tickets_path": existing["tickets_path"] if existing else tickets_path,
            "report_path": existing["report_path"] if existing else report_path,
        }

    try:
        asset = governance.index_assets(assets).get(posture.get("asset_id"))
        if asset is None:
            raise ValueError(f"Asset {posture.get('asset_id')} is not registered.")
        evaluated_posture = {**posture, "criticality": asset["criticality"]}
        results = [evaluate_control(control, evaluated_posture) for control in controls]
        remediation = governance.build_remediation_queue(controls, posture, assets)
        if governance_db:
            governance_core = GovernanceCore(governance_db)
            pipeline_actor = ActorContext("sentinelgrc-pipeline", "analyst", "system")
            for item in remediation["findings"]:
                control = item["control"]
                governance_core.upsert_finding(
                    item["finding_id"],
                    str(control.get("control_id") or control.get("id") or "legacy"),
                    str(item["asset"]["asset_id"]),
                    str(control.get("control_name") or item["finding_id"]),
                    str(control.get("owner") or "Security Operations"),
                    str(control.get("severity") or "medium"),
                    pipeline_actor,
                )

        record = find_ledger_record(ledger_path, input_hash)
        if record is None:
            record = append_evidence_atomic(
                ledger_path, posture, results,
                {"input_hash": input_hash, "pipeline_run_id": run_id},
            )

        created = created_at or datetime.now(timezone.utc)
        tickets = workflow.generate_tickets(remediation, review, created)
        _write_json(remediation_path, remediation)
        _write_json(tickets_path, tickets)
        failed = [result for result in results if not result["passed"]]
        report = {
            "schema_version": "1.0",
            "run_id": run_id,
            "generated_at": created.isoformat().replace("+00:00", "Z"),
            "asset": {
                "asset_id": asset["asset_id"],
                "hostname": asset["hostname"],
                "business_service": asset["business_service"],
                "criticality": asset["criticality"],
            },
            "controls_evaluated": len(results),
            "controls_failed": len(failed),
            "risk_score": sum(result["risk_score"] for result in failed),
            "open_findings": sum(item["status"] == "open" for item in remediation["findings"]),
            "tickets_created": len(tickets["tickets"]),
            "evidence_hash": record["record_hash"],
            "access_review_included": bool(access_review),
        }
        _write_json(report_path, report)
        store.complete_pipeline_run(input_hash, record["record_hash"], remediation_path, tickets_path, report_path)
        if audit_path:
            AuditLog(audit_path).append(
                "pipeline.completed", "sentinelgrc-worker", run_id,
                {"asset_id": asset["asset_id"], "evidence_hash": record["record_hash"], "tickets_created": report["tickets_created"]},
            )
        return {
            "status": "accepted",
            "run_id": run_id,
            "input_hash": input_hash,
            "ledger_record_hash": record["record_hash"],
            "remediation_path": remediation_path,
            "tickets_path": tickets_path,
            "report_path": report_path,
            "controls_failed": report["controls_failed"],
            "tickets_created": report["tickets_created"],
        }
    except Exception as error:
        store.fail_pipeline_run(input_hash, str(error))
        raise


def run_from_files(args: argparse.Namespace) -> int:
    access_review = load_json(args.access_review) if args.access_review else None
    result = run_pipeline(
        load_json(args.posture), load_json(args.controls), load_json(args.assets),
        args.ledger, args.remediation, args.tickets, args.report, args.state_db,
        access_review, audit_path=args.audit_log, governance_db=args.governance_db,
    )
    print(json.dumps(result, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SentinelGRC governance pipeline.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--posture", required=True)
    run.add_argument("--controls", required=True)
    run.add_argument("--assets", required=True)
    run.add_argument("--access-review")
    run.add_argument("--ledger", default="evidence-ledger.jsonl")
    run.add_argument("--remediation", default="remediation-queue.json")
    run.add_argument("--tickets", default="tickets.json")
    run.add_argument("--report", default="executive-report.json")
    run.add_argument("--state-db", default="sentinelgrc-state.db")
    run.add_argument("--audit-log", default="runtime/audit-log.jsonl")
    run.add_argument("--governance-db")
    args = parser.parse_args()
    return run_from_files(args)


if __name__ == "__main__":
    raise SystemExit(main())
