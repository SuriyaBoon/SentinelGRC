"""SentinelGRC Phase 2: asset-aware remediation and exception governance."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Any

from sentinelgrc import evaluate_control, load_json


def index_assets(assets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {asset["asset_id"]: asset for asset in assets}


def build_remediation_queue(
    controls: list[dict[str, Any]],
    posture: dict[str, Any],
    assets: list[dict[str, Any]],
) -> dict[str, Any]:
    asset = index_assets(assets).get(posture.get("asset_id"))
    if asset is None:
        raise ValueError(f"Asset {posture.get('asset_id')} is not registered.")

    findings = []
    for control in controls:
        result = evaluate_control(control, {**posture, "criticality": asset["criticality"]})
        if not result["passed"]:
            findings.append(
                {
                    "finding_id": f"{asset['asset_id']}:{control['id']}",
                    "asset": asset,
                    "control": result,
                    "status": "open",
                    "due_date": None,
                    "exception": None,
                }
            )

    return {
        "schema_version": "1.0",
        "generated_on": date.today().isoformat(),
        "asset_id": asset["asset_id"],
        "risk_score": sum(item["control"]["risk_score"] for item in findings),
        "findings": findings,
    }


def approve_exception(
    queue: dict[str, Any],
    finding_id: str,
    approver: str,
    reason: str,
    expires_on: str,
) -> dict[str, Any]:
    if not approver.strip() or not reason.strip():
        raise ValueError("Approver and reason are required for an exception.")
    try:
        expiry = date.fromisoformat(expires_on)
    except ValueError as error:
        raise ValueError("expires_on must use YYYY-MM-DD format.") from error
    if expiry <= date.today():
        raise ValueError("Exception expiry must be in the future.")

    for finding in queue["findings"]:
        if finding["finding_id"] == finding_id:
            if finding.get("status") != "open":
                raise ValueError("Only open findings can receive an exception.")
            finding["status"] = "accepted-risk"
            finding["exception"] = {
                "approver": approver,
                "reason": reason,
                "expires_on": expires_on,
            }
            return queue
    raise ValueError(f"Finding {finding_id} was not found.")


def expire_exceptions(queue: dict[str, Any], today: date | None = None) -> dict[str, Any]:
    current = today or date.today()
    for finding in queue.get("findings", []):
        exception = finding.get("exception") or {}
        expires_on = exception.get("expires_on")
        if finding.get("status") == "accepted-risk" and expires_on:
            if date.fromisoformat(expires_on) <= current:
                finding["status"] = "open"
                finding["exception_status"] = "expired"
    return queue

def assess(args: argparse.Namespace) -> int:
    queue = build_remediation_queue(
        load_json(args.controls), load_json(args.posture), load_json(args.assets)
    )
    Path(args.output).write_text(json.dumps(queue, indent=2), encoding="utf-8")
    print(json.dumps(queue, indent=2))
    return 1 if any(item["status"] == "open" for item in queue["findings"]) else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run asset-aware SentinelGRC governance workflows."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    assess_parser = subparsers.add_parser("assess")
    assess_parser.add_argument("--controls", required=True)
    assess_parser.add_argument("--posture", required=True)
    assess_parser.add_argument("--assets", required=True)
    assess_parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "assess":
        return assess(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
