"""Inbox worker that connects authenticated ingestion to the governance pipeline."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import pipeline
from sentinelgrc import load_json


def process_inbox_once(
    inbox: str,
    controls: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    ledger: str,
    state_db: str,
    remediation_dir: str,
    tickets_dir: str,
    reports_dir: str,
    access_review: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    inbox_path = Path(inbox)
    inbox_path.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for posture_path in sorted(inbox_path.glob("*.json")):
        try:
            posture = json.loads(posture_path.read_text(encoding="utf-8"))
            stem = posture_path.stem
            result = pipeline.run_pipeline(
                posture,
                controls,
                assets,
                ledger,
                str(Path(remediation_dir) / f"{stem}.json"),
                str(Path(tickets_dir) / f"{stem}.json"),
                str(Path(reports_dir) / f"{stem}.json"),
                state_db,
                access_review,
            )
            results.append({"file": str(posture_path), **result})
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            results.append({"file": str(posture_path), "status": "error", "error": str(error)})
    return results


def serve(args: argparse.Namespace) -> int:
    controls = load_json(args.controls)
    assets = load_json(args.assets)
    access_review = load_json(args.access_review) if args.access_review else None
    while True:
        results = process_inbox_once(
            args.inbox, controls, assets, args.ledger, args.state_db,
            args.remediation_dir, args.tickets_dir, args.reports_dir, access_review,
        )
        for result in results:
            print(json.dumps(result, separators=(",", ":")))
        time.sleep(args.interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Process SentinelGRC posture evidence from an inbox.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("once", "serve"):
        worker = subparsers.add_parser(command)
        worker.add_argument("--inbox", default="evidence-inbox")
        worker.add_argument("--controls", required=True)
        worker.add_argument("--assets", required=True)
        worker.add_argument("--access-review")
        worker.add_argument("--ledger", default="evidence-ledger.jsonl")
        worker.add_argument("--state-db", default="sentinelgrc-state.db")
        worker.add_argument("--remediation-dir", default="runtime/remediation")
        worker.add_argument("--tickets-dir", default="runtime/tickets")
        worker.add_argument("--reports-dir", default="runtime/reports")
        if command == "serve":
            worker.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()
    if args.command == "once":
        results = process_inbox_once(
            args.inbox, load_json(args.controls), load_json(args.assets),
            args.ledger, args.state_db, args.remediation_dir, args.tickets_dir,
            args.reports_dir, load_json(args.access_review) if args.access_review else None,
        )
        print(json.dumps(results, indent=2))
        return 0 if all(item["status"] != "error" for item in results) else 1
    return serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
