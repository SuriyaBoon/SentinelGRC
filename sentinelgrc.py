"""SentinelGRC Phase 1: control evaluation and evidence integrity."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 6, "critical": 10}
CRITICALITY_MULTIPLIER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def load_json(path: str) -> Any:
    with Path(path).open(encoding="utf-8") as file:
        return json.load(file)


def evaluate_control(control: dict[str, Any], posture: dict[str, Any]) -> dict[str, Any]:
    field = control["required_field"]
    observed = posture.get(field)
    if "expected" in control:
        passed = observed == control["expected"]
        expected = control["expected"]
    else:
        expected = f"<= {control['max_value']}"
        passed = isinstance(observed, (int, float)) and observed <= control["max_value"]

    severity = control["severity"]
    criticality = posture.get("criticality", "medium").lower()
    risk_score = 0 if passed else SEVERITY_WEIGHT[severity] * CRITICALITY_MULTIPLIER.get(criticality, 2)
    return {
        "control_id": control["id"],
        "control_name": control["name"],
        "owner": control["owner"],
        "framework_mapping": {
            "iso27002": control["iso27002"],
            "nist_csf": control["nist_csf"],
        },
        "field": field,
        "expected": expected,
        "observed": observed,
        "passed": passed,
        "severity": severity,
        "risk_score": risk_score,
    }


def build_evidence(
    posture: dict[str, Any],
    results: list[dict[str, Any]],
    previous_hash: str,
) -> dict[str, Any]:
    record = {
        "schema_version": "1.0",
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "asset": {
            key: posture.get(key)
            for key in ("asset_id", "hostname", "owner", "criticality", "collected_at")
        },
        "results": results,
        "previous_hash": previous_hash,
    }
    record["record_hash"] = hashlib.sha256(
        canonical_json(record).encode("utf-8")
    ).hexdigest()
    return record


def read_last_hash(ledger_path: str) -> str:
    path = Path(ledger_path)
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return GENESIS_HASH
    last_line = path.read_text(encoding="utf-8").strip().splitlines()[-1]
    return json.loads(last_line)["record_hash"]


def append_evidence(ledger_path: str, evidence: dict[str, Any]) -> None:
    with Path(ledger_path).open("a", encoding="utf-8") as file:
        file.write(canonical_json(evidence) + "\n")


def verify_ledger(ledger_path: str) -> tuple[bool, str]:
    previous_hash = GENESIS_HASH
    for line_number, line in enumerate(
        Path(ledger_path).read_text(encoding="utf-8").splitlines(), 1
    ):
        record = json.loads(line)
        supplied_hash = record.pop("record_hash", None)
        calculated_hash = hashlib.sha256(
            canonical_json(record).encode("utf-8")
        ).hexdigest()
        if record.get("previous_hash") != previous_hash or supplied_hash != calculated_hash:
            return False, f"Ledger integrity failed at record {line_number}."
        previous_hash = supplied_hash
    return True, "Ledger integrity verified."


def evaluate(args: argparse.Namespace) -> int:
    controls = load_json(args.controls)
    posture = load_json(args.posture)
    results = [evaluate_control(control, posture) for control in controls]
    evidence = build_evidence(posture, results, read_last_hash(args.ledger))
    append_evidence(args.ledger, evidence)
    failed = [result for result in results if not result["passed"]]
    summary = {
        "asset": posture["hostname"],
        "controls_evaluated": len(results),
        "controls_failed": len(failed),
        "risk_score": sum(result["risk_score"] for result in failed),
        "remediation_queue": failed,
        "evidence_hash": evidence["record_hash"],
    }
    print(json.dumps(summary, indent=2))
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate endpoint security controls and preserve evidence."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--controls", required=True)
    evaluate_parser.add_argument("--posture", required=True)
    evaluate_parser.add_argument("--ledger", required=True)
    verify_parser = subparsers.add_parser("verify-ledger")
    verify_parser.add_argument("--ledger", required=True)
    args = parser.parse_args()
    if args.command == "evaluate":
        return evaluate(args)
    valid, message = verify_ledger(args.ledger)
    print(message)
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
