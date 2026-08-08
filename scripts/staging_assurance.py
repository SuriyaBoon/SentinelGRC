"""Run the deterministic SentinelGRC staging-assurance package offline."""

from __future__ import annotations

import argparse
import json
from scripts.path_policy import (
    read_text_under_root,
    resolve_under_root,
    write_text_under_root,
)
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
    parser.add_argument(
        "--runtime-root",
        default=".",
        help="Trusted filesystem boundary for all CLI paths.",
    )
    args = parser.parse_args(argv)
    try:
        policy = resolve_under_root(args.policy, args.runtime_root, purpose="policy path")
        alerts = resolve_under_root(args.alerts, args.runtime_root, purpose="alerts path")
        live = None
        if args.live_evidence:
            live = json.loads(
                read_text_under_root(
                    args.live_evidence,
                    args.runtime_root,
                    purpose="live evidence path",
                )
            )
        report = run_offline_assurance(str(policy), str(alerts), live_evidence=live)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            write_text_under_root(
                args.output,
                args.runtime_root,
                rendered,
                purpose="assurance output path",
            )
        print(rendered, end="")
        return 0 if report["offline_decision"] == "READY_FOR_MANUAL_AZURE_STAGING" else 1
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
