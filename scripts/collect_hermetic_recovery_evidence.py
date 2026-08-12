"""Collect deterministic hermetic failure and recovery evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from hermetic_recovery import collect_hermetic_recovery_evidence
from scripts.path_policy import resolve_under_root, write_text_under_root


OUTPUT_PATH = "runtime/staging-assurance/hermetic-recovery-evidence.json"
READINESS_PATH = "runtime/staging-assurance/postgres-readiness.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--readiness", default=READINESS_PATH)
    args = parser.parse_args(argv)
    try:
        root = Path.cwd()
        readiness = resolve_under_root(
            args.readiness,
            root,
            purpose="PostgreSQL readiness evidence path",
        )
        envelope = collect_hermetic_recovery_evidence(root, readiness, args.source_commit)
        write_text_under_root(
            OUTPUT_PATH,
            root,
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            purpose="hermetic recovery evidence output path",
        )
        decision = envelope["document"]["decision"]
        print(
            json.dumps(
                {
                    "decision": decision,
                    "document_sha256": envelope["document_sha256"],
                    "output": OUTPUT_PATH,
                    "current_live_gate_credit": False,
                    "production_decision": "NO_GO_PENDING_LIVE_EVIDENCE",
                },
                sort_keys=True,
            )
        )
        return 0 if decision == "PASS" else 1
    except (OSError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())