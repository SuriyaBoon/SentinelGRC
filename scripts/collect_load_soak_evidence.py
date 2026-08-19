"""Collect a bounded hermetic load and soak baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from load_soak_baseline import LoadSoakProfile, collect_load_soak_evidence, validate_load_soak_evidence
from scripts.path_policy import write_text_under_root


OUTPUT_PATH = "runtime/staging-assurance/load-soak-evidence.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--unique-findings", type=int, default=80)
    parser.add_argument("--replay-rounds", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--duration-seconds", type=float, default=1.0)
    parser.add_argument("--minimum-throughput-per-second", type=float, default=1.0)
    parser.add_argument("--maximum-p95-latency-ms", type=float, default=2_000.0)
    parser.add_argument(
        "--maximum-peak-traced-bytes", type=int, default=128 * 1024 * 1024
    )
    args = parser.parse_args(argv)
    try:
        profile = LoadSoakProfile(
            unique_findings=args.unique_findings,
            replay_rounds=args.replay_rounds,
            concurrency=args.concurrency,
            duration_seconds=args.duration_seconds,
            minimum_throughput_per_second=args.minimum_throughput_per_second,
            maximum_p95_latency_ms=args.maximum_p95_latency_ms,
            maximum_peak_traced_bytes=args.maximum_peak_traced_bytes,
        )
        envelope = collect_load_soak_evidence(profile, args.source_commit)
        validate_load_soak_evidence(envelope)
        write_text_under_root(
            OUTPUT_PATH,
            Path.cwd(),
            json.dumps(envelope, indent=2, sort_keys=True) + "\n",
            purpose="load and soak evidence output path",
        )
        document = envelope["document"]
        print(json.dumps({
            "decision": document["decision"],
            "document_sha256": envelope["document_sha256"],
            "output": OUTPUT_PATH,
            "current_live_gate_credit": False,
            "production_decision": document["claim_boundary"]["production_decision"],
        }, sort_keys=True))
        return 0 if document["decision"] == "PASS" else 1
    except (OSError, TypeError, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())