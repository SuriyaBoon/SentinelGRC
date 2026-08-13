"""Collect one sanitized pre-live repository security assessment."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from scripts.path_policy import write_text_under_root
from security_assessment import (
    collect_security_assessment,
    decode_tool_report,
    validate_security_assessment,
)


OUTPUT_PATH = "runtime/staging-assurance/security-assessment-evidence.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--assessed-on", default=datetime.now(timezone.utc).date().isoformat())
    parser.add_argument(
        "--dependency-scan-outcome",
        choices=("success", "failure", "skipped", "cancelled"),
        required=True,
    )
    parser.add_argument("--dependency-report-base64", default="")
    args = parser.parse_args(argv)
    try:
        report = decode_tool_report(args.dependency_report_base64) if args.dependency_report_base64 else None
        envelope = collect_security_assessment(
            Path.cwd(),
            args.source_commit,
            args.assessed_on,
            args.dependency_scan_outcome,
            report,
        )
        validate_security_assessment(
            envelope,
            Path.cwd(),
            args.dependency_scan_outcome,
            report,
        )
        write_text_under_root(
            OUTPUT_PATH,
            Path.cwd(),
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            purpose="security assessment evidence output path",
        )
        document = envelope["document"]
        print(json.dumps({
            "assessment_decision": document["assessment_decision"],
            "current_live_gate_credit": False,
            "document_sha256": envelope["document_sha256"],
            "finding_count": len(document["findings"]),
            "output": OUTPUT_PATH,
            "production_decision": document["claim_boundary"]["production_decision"],
        }, sort_keys=True))
        return 0 if document["assessment_decision"] == "PASS_OFFLINE" else 1
    except (OSError, TypeError, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
