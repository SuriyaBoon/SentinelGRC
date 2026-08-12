"""Collect one deterministic offline assurance evidence envelope."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from offline_evidence import collect_offline_evidence
from scripts.path_policy import resolve_under_root, write_text_under_root


OUTPUT_PATH = "runtime/staging-assurance/offline-evidence.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument(
        "--policy",
        default="config/staging-assurance.example.json",
    )
    parser.add_argument(
        "--alerts",
        default="docs/evidence/staging-readiness/logwatcher-security-alert.v1.jsonl",
    )
    args = parser.parse_args(argv)
    try:
        root = Path.cwd()
        policy = resolve_under_root(args.policy, root, purpose="policy path")
        alerts = resolve_under_root(args.alerts, root, purpose="alerts path")
        envelope = collect_offline_evidence(policy, alerts, args.source_commit)
        rendered = json.dumps(envelope, indent=2, sort_keys=True) + "\n"
        output = write_text_under_root(
            OUTPUT_PATH,
            root,
            rendered,
            purpose="offline evidence output path",
        )
        decision = envelope["document"]["results"]["offline_decision"]
        print(
            json.dumps(
                {
                    "decision": decision,
                    "document_sha256": envelope["document_sha256"],
                    "output": output.relative_to(root).as_posix(),
                    "current_live_gate_credit": False,
                    "production_decision": "NO_GO_PENDING_LIVE_EVIDENCE",
                },
                sort_keys=True,
            )
        )
        return 0 if decision == "READY_FOR_MANUAL_AZURE_STAGING" else 1
    except (OSError, TypeError, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
