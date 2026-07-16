"""Inbox worker that connects authenticated ingestion to the governance pipeline."""

from __future__ import annotations

import argparse
import json
import secrets
import time
from pathlib import Path
from typing import Any

import pipeline
from job_queue import SQLiteJobQueue
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
    max_attempts: int = 3,
    retry_delay: int = 60,
    audit_path: str | None = None,
) -> list[dict[str, Any]]:
    inbox_path = Path(inbox)
    inbox_path.mkdir(parents=True, exist_ok=True)
    queue = SQLiteJobQueue(state_db)
    for posture_path in sorted(inbox_path.glob("*.json")):
        queue.enqueue(str(posture_path))

    results: list[dict[str, Any]] = []
    worker_id = "worker-" + secrets.token_hex(6)
    while True:
        job = queue.claim(worker_id)
        if job is None:
            break
        posture_path = Path(job["payload_path"])
        try:
            posture = json.loads(posture_path.read_text(encoding="utf-8"))
            stem = posture_path.stem
            result = pipeline.run_pipeline(
                posture, controls, assets, ledger,
                str(Path(remediation_dir) / f"{stem}.json"),
                str(Path(tickets_dir) / f"{stem}.json"),
                str(Path(reports_dir) / f"{stem}.json"),
                state_db, access_review, audit_path=audit_path,
            )
            queue.complete(int(job["job_id"]))
            results.append({"file": str(posture_path), **result})
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            status = queue.fail(int(job["job_id"]), str(error), max_attempts, retry_delay)
            results.append({"file": str(posture_path), "status": "error", "queue_status": status, "error": str(error)})
    return results


def serve(args: argparse.Namespace) -> int:
    controls = load_json(args.controls)
    assets = load_json(args.assets)
    access_review = load_json(args.access_review) if args.access_review else None
    while True:
        results = process_inbox_once(
            args.inbox, controls, assets, args.ledger, args.state_db,
            args.remediation_dir, args.tickets_dir, args.reports_dir,
            access_review, args.max_attempts, args.retry_delay, args.audit_log,
        )
        for result in results:
            print(json.dumps(result, separators=(",", ":")))
        time.sleep(args.interval)


def add_worker_arguments(worker: argparse.ArgumentParser, command: str) -> None:
    worker.add_argument("--inbox", default="evidence-inbox")
    worker.add_argument("--controls", required=True)
    worker.add_argument("--assets", required=True)
    worker.add_argument("--access-review")
    worker.add_argument("--ledger", default="evidence-ledger.jsonl")
    worker.add_argument("--state-db", default="sentinelgrc-state.db")
    worker.add_argument("--remediation-dir", default="runtime/remediation")
    worker.add_argument("--tickets-dir", default="runtime/tickets")
    worker.add_argument("--reports-dir", default="runtime/reports")
    worker.add_argument("--max-attempts", type=int, default=3)
    worker.add_argument("--retry-delay", type=int, default=60)
    worker.add_argument("--audit-log", default="runtime/audit-log.jsonl")
    if command == "serve":
        worker.add_argument("--interval", type=int, default=30)


def main() -> int:
    parser = argparse.ArgumentParser(description="Process SentinelGRC posture evidence from an inbox.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    once = subparsers.add_parser("once")
    add_worker_arguments(once, "once")
    serve_parser = subparsers.add_parser("serve")
    add_worker_arguments(serve_parser, "serve")
    args = parser.parse_args()
    controls = load_json(args.controls)
    assets = load_json(args.assets)
    access_review = load_json(args.access_review) if args.access_review else None
    if args.command == "once":
        results = process_inbox_once(
            args.inbox, controls, assets, args.ledger, args.state_db,
            args.remediation_dir, args.tickets_dir, args.reports_dir,
            access_review, args.max_attempts, args.retry_delay, args.audit_log,
        )
        print(json.dumps(results, indent=2))
        return 0 if all(item["status"] != "error" for item in results) else 1
    return serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
