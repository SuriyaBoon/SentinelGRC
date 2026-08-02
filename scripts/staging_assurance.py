"""Run the deterministic SentinelGRC staging-assurance package offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from staging_assurance import run_offline_assurance


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        default="config/staging-assurance.example.json",
    )
    parser.add_argument(
        "--alerts",
        default="docs/evidence/staging-readiness/logwatcher-security-alert.v1.jsonl",
    )
    parser.add_argument("--live-evidence")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        live = None
        if args.live_evidence:
            live = json.loads(Path(args.live_evidence).read_text(encoding="utf-8"))
        report = run_offline_assurance(args.policy, args.alerts, live_evidence=live)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0 if report["offline_decision"] == "READY_FOR_MANUAL_AZURE_STAGING" else 1
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
