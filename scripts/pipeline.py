"""SentinelGRC Phase 7: deterministic end-to-end governance orchestration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts import governance, workflow
from scripts.path_policy import load_json_under_root, require_exact_output, resolve_under_root, write_text_under_root
from audit_log import AuditLog
from governance_core import ActorContext, GovernanceCore
from sentinelgrc import append_evidence_atomic, build_evidence, canonical_json, evaluate_control, find_ledger_record
from state_store import DEFAULT_STATE_DB, SQLiteStateStore


PIPELINE_PATHS = {
    "ledger": "runtime/evidence-ledger.jsonl",
    "remediation": "runtime/remediation-queue.json",
    "tickets": "runtime/tickets.json",
    "report": "runtime/executive-report.json",
    "state_db": DEFAULT_STATE_DB,
    "audit_log": "runtime/audit-log.jsonl",
    "governance_db": "runtime/governance.db",
}


def _write_json(path: str, value: dict[str, Any], root: Path) -> None:
    write_text_under_root(
        path,
        root,
        json.dumps(value, indent=2) + "\n",
        purpose="pipeline output path",
    )

def _input_hash(inputs: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(inputs).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PipelineRunOptions:
    run_lease_seconds: int = 900
    runtime_root: str | Path | None = None


@dataclass(frozen=True)
class _PipelinePaths:
    output_root: Path
    ledger: str
    remediation: str
    tickets: str
    report: str
    state_db: str
    audit_log: str | None
    governance_db: str | None


def configured_governance_database(explicit: str | None = None) -> str | None:
    """Return the effective governance database setting with strict mode validation."""
    storage_mode = os.getenv("SENTINEL_STORAGE", "legacy").lower()
    if storage_mode not in {"legacy", "governance"}:
        raise ValueError("SENTINEL_STORAGE must be legacy or governance")
    configured = explicit or os.getenv("SENTINEL_GOVERNANCE_DB")
    if storage_mode == "governance" and not configured:
        return "runtime/governance.db"
    return configured


def _resolve_pipeline_paths(
    ledger_path: str,
    remediation_path: str,
    tickets_path: str,
    report_path: str,
    state_db: str,
    audit_path: str | None,
    governance_db: str | None,
    options: PipelineRunOptions,
) -> _PipelinePaths:
    output_root = (
        Path(options.runtime_root).expanduser().resolve(strict=False)
        if options.runtime_root is not None
        else Path(state_db).expanduser().resolve(strict=False).parent
    )
    return _PipelinePaths(
        output_root=output_root,
        ledger=str(resolve_under_root(ledger_path, output_root, purpose="ledger path")),
        remediation=str(resolve_under_root(remediation_path, output_root, purpose="remediation path")),
        tickets=str(resolve_under_root(tickets_path, output_root, purpose="tickets path")),
        report=str(resolve_under_root(report_path, output_root, purpose="report path")),
        state_db=str(resolve_under_root(state_db, output_root, purpose="state database path")),
        audit_log=(
            str(resolve_under_root(audit_path, output_root, purpose="audit log path"))
            if audit_path
            else None
        ),
        governance_db=(
            str(resolve_under_root(governance_db, output_root, purpose="governance database path"))
            if governance_db
            else None
        ),
    )


def _validate_pipeline_inputs(
    posture: dict[str, Any], controls: list[dict[str, Any]], assets: list[dict[str, Any]]
) -> None:
    if not isinstance(posture, dict) or not posture.get("asset_id") or not posture.get("hostname"):
        raise ValueError("Posture must contain asset_id and hostname.")
    if not isinstance(controls, list) or not isinstance(assets, list):
        raise ValueError("Controls and assets must be JSON arrays.")


def _duplicate_pipeline_result(
    store: SQLiteStateStore,
    input_hash: str,
    run_id: str,
    paths: _PipelinePaths,
) -> dict[str, Any]:
    existing = store.get_pipeline_run(input_hash)
    return {
        "status": "duplicate",
        "run_id": run_id,
        "input_hash": input_hash,
        "ledger_record_hash": existing["ledger_record_hash"] if existing else None,
        "remediation_path": existing["remediation_path"] if existing else paths.remediation,
        "tickets_path": existing["tickets_path"] if existing else paths.tickets,
        "report_path": existing["report_path"] if existing else paths.report,
    }


def _execute_pipeline(
    posture: dict[str, Any],
    controls: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    review: dict[str, Any],
    access_review_included: bool,
    created_at: datetime | None,
    input_hash: str,
    run_id: str,
    paths: _PipelinePaths,
    store: SQLiteStateStore,
) -> dict[str, Any]:
    asset = governance.index_assets(assets).get(posture.get("asset_id"))
    if asset is None:
        raise ValueError(f"Asset {posture.get('asset_id')} is not registered.")
    evaluated_posture = {**posture, "criticality": asset["criticality"]}
    results = [evaluate_control(control, evaluated_posture) for control in controls]
    remediation = governance.build_remediation_queue(controls, posture, assets)
    if paths.governance_db:
        governance_core = GovernanceCore(paths.governance_db)
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

    record = find_ledger_record(paths.ledger, input_hash)
    if record is None:
        record = append_evidence_atomic(
            paths.ledger, posture, results,
            {"input_hash": input_hash, "pipeline_run_id": run_id},
        )

    created = created_at or datetime.now(timezone.utc)
    tickets = workflow.generate_tickets(remediation, review, created)
    _write_json(paths.remediation, remediation, paths.output_root)
    _write_json(paths.tickets, tickets, paths.output_root)
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
        "access_review_included": access_review_included,
    }
    _write_json(paths.report, report, paths.output_root)
    store.complete_pipeline_run(
        input_hash, record["record_hash"], paths.remediation, paths.tickets, paths.report
    )
    if paths.audit_log:
        AuditLog(paths.audit_log).append(
            "pipeline.completed", "sentinelgrc-worker", run_id,
            {"asset_id": asset["asset_id"], "evidence_hash": record["record_hash"], "tickets_created": report["tickets_created"]},
        )
    return {
        "status": "accepted",
        "run_id": run_id,
        "input_hash": input_hash,
        "ledger_record_hash": record["record_hash"],
        "remediation_path": paths.remediation,
        "tickets_path": paths.tickets,
        "report_path": paths.report,
        "controls_failed": report["controls_failed"],
        "tickets_created": report["tickets_created"],
    }


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
    governance_db: str | None = None,
    options: "PipelineRunOptions | None" = None,
) -> dict[str, Any]:
    governance_db = configured_governance_database(governance_db)
    options = options or PipelineRunOptions()
    paths = _resolve_pipeline_paths(
        ledger_path, remediation_path, tickets_path, report_path, state_db,
        audit_path, governance_db, options,
    )
    _validate_pipeline_inputs(posture, controls, assets)
    review = access_review or {"schema_version": "1.0", "users": []}
    inputs = {"posture": posture, "controls": controls, "assets": assets, "access_review": review}
    input_hash = _input_hash(inputs)
    run_id = "PL-" + input_hash[:12].upper()
    store = SQLiteStateStore(paths.state_db)
    if not store.claim_pipeline_run(input_hash, lease_seconds=options.run_lease_seconds):
        return _duplicate_pipeline_result(store, input_hash, run_id, paths)

    try:
        return _execute_pipeline(
            posture, controls, assets, review, bool(access_review), created_at,
            input_hash, run_id, paths, store
        )
    except Exception as error:
        store.fail_pipeline_run(input_hash, str(error))
        raise


def run_from_files(args: argparse.Namespace) -> int:
    root = Path.cwd()
    access_review = load_json_under_root(args.access_review, root, purpose="access review path") if args.access_review else None
    for argument, key, purpose in (
        (args.ledger, "ledger", "ledger path"),
        (args.remediation, "remediation", "remediation path"),
        (args.tickets, "tickets", "tickets path"),
        (args.report, "report", "report path"),
        (args.state_db, "state_db", "state database path"),
        (args.audit_log, "audit_log", "audit log path"),
    ):
        require_exact_output(argument, PIPELINE_PATHS[key], purpose=purpose)
    if args.governance_db:
        require_exact_output(args.governance_db, PIPELINE_PATHS["governance_db"], purpose="governance database path")
    result = run_pipeline(
        load_json_under_root(args.posture, root, purpose="posture path"),
        load_json_under_root(args.controls, root, purpose="controls path"),
        load_json_under_root(args.assets, root, purpose="assets path"),
        PIPELINE_PATHS["ledger"], PIPELINE_PATHS["remediation"],
        PIPELINE_PATHS["tickets"], PIPELINE_PATHS["report"],
        PIPELINE_PATHS["state_db"], access_review,
        audit_path=PIPELINE_PATHS["audit_log"],
        governance_db=PIPELINE_PATHS["governance_db"] if args.governance_db else None,
        options=PipelineRunOptions(runtime_root=root),
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
    run.add_argument("--ledger", default=PIPELINE_PATHS["ledger"])
    run.add_argument("--remediation", default=PIPELINE_PATHS["remediation"])
    run.add_argument("--tickets", default=PIPELINE_PATHS["tickets"])
    run.add_argument("--report", default=PIPELINE_PATHS["report"])
    run.add_argument("--state-db", default=PIPELINE_PATHS["state_db"])
    run.add_argument("--audit-log", default=PIPELINE_PATHS["audit_log"])
    run.add_argument("--governance-db")
    args = parser.parse_args()
    return run_from_files(args)


if __name__ == "__main__":
    raise SystemExit(main())
