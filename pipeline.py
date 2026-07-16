"""SentinelGRC Phase 7: deterministic end-to-end governance orchestration."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import governance
import workflow
from sentinelgrc import append_evidence, build_evidence, canonical_json, evaluate_control, load_json, read_last_hash
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
) -> dict[str, Any]:
    if not isinstance(posture, dict) or not posture.get("asset_id") or not posture.get("hostname"):
        raise ValueError("Posture must contain asset_id and hostname.")
    if not isinstance(controls, list) or not isinstance(assets, list):
        raise ValueError("Controls and assets must be JSON arrays.")
    review = access_review or {"schema_version": "1.0", "users": []}
    inputs = {"posture": posture, "controls": controls, "assets": assets, "access_review": review}
    input_hash = _input_hash(inputs)
    store = SQLiteStateStore(state_db)
    existing = store.get_pipeline_run(input_hash)
    if existing is not None:
        return {
            "status": "duplicate",
            "run_id": "PL-" + input_hash[:12].upper(),
            "input_hash": input_hash,
            "ledger_record_hash": existing["ledger_record_hash"],
            "remediation_path": existing["remediation_path"],
            "tickets_path": existing["tickets_path"],
            "report_path": existing["report_path"],
        }

    asset = governance.index_assets(assets).get(posture.get("asset_id"))
    if asset is None:
        raise ValueError(f"Asset {posture.get('asset_id')} is not registered.")
    evaluated_posture = {**posture, "criticality": asset["criticality"]}
    results = [evaluate_control(control, evaluated_posture) for control in controls]
    remediation = governance.build_remediation_queue(controls, posture, assets)

    record = build_evidence(posture, results, read_last_hash(ledger_path))
    append_evidence(ledger_path, record)

    created = created_at or datetime.now(timezone.utc)
    tickets = workflow.generate_tickets(remediation, review, created)
    _write_json(remediation_path, remediation)
    _write_json(tickets_path, tickets)
    failed = [result for result in results if not result["passed"]]
    report = {
        "schema_version": "1.0",
        "run_id": "PL-" + input_hash[:12].upper(),
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
    store.remember_pipeline_run(input_hash, record["record_hash"], remediation_path, tickets_path, report_path)
    return {
        "status": "accepted",
        "run_id": report["run_id"],
        "input_hash": input_hash,
        "ledger_record_hash": record["record_hash"],
        "remediation_path": remediation_path,
        "tickets_path": tickets_path,
        "report_path": report_path,
        "controls_failed": report["controls_failed"],
        "tickets_created": report["tickets_created"],
    }


def run_from_files(args: argparse.Namespace) -> int:
    access_review = load_json(args.access_review) if args.access_review else None
    result = run_pipeline(
        load_json(args.posture),
        load_json(args.controls),
        load_json(args.assets),
        args.ledger,
        args.remediation,
        args.tickets,
        args.report,
        args.state_db,
        access_review,
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
    args = parser.parse_args()
    return run_from_files(args)


if __name__ == "__main__":
    raise SystemExit(main())
