"""Inbox worker that connects authenticated ingestion to the governance pipeline."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts import pipeline
from scripts.path_policy import (
    resolve_under_root,
    resolve_worker_output_directory,
    validate_evidence_id,
)
from job_queue import SQLiteJobQueue
from sentinelgrc import load_json
from state_store import DEFAULT_STATE_DB


FAILPOINT_AFTER_PIPELINE_COMMIT = "after_pipeline_commit_before_queue_ack"
FAILPOINT_EXIT_CODE = 86


@dataclass(frozen=True)
class WorkerRunOptions:
    max_attempts: int = 3
    retry_delay: int = 60
    audit_path: str | None = None
    lease_seconds: int = 300
    runtime_root: str | Path | None = None
    governance_db: str | None = None


def _configured_test_failpoint() -> str | None:
    failpoint = os.getenv("SENTINEL_FAILPOINT", "").strip()
    if not failpoint:
        return None
    if os.getenv("SENTINEL_ENABLE_TEST_FAILPOINTS", "").strip().lower() != "true":
        raise RuntimeError(
            "SENTINEL_FAILPOINT requires SENTINEL_ENABLE_TEST_FAILPOINTS=true"
        )
    if os.getenv("SENTINEL_ENV", "lab").strip().lower() != "lab":
        raise RuntimeError("test failpoints are allowed only in SENTINEL_ENV=lab")
    if failpoint != FAILPOINT_AFTER_PIPELINE_COMMIT:
        raise RuntimeError(f"unsupported SENTINEL_FAILPOINT: {failpoint}")
    return failpoint


def _trigger_test_failpoint(configured: str | None, expected: str) -> None:
    if configured == expected:
        os._exit(FAILPOINT_EXIT_CODE)


def _renew_lease_until_stopped(
    queue: SQLiteJobQueue,
    stop: threading.Event,
    job_id: int,
    worker_id: str,
    lease_seconds: int,
) -> None:
    while not stop.wait(max(1, lease_seconds // 3)):
        if not queue.renew(job_id, worker_id, lease_seconds):
            break


def _validated_inbox_item(value: str | Path, inbox: Path) -> Path:
    """Require a top-level JSON payload with an output-safe stable identity."""
    path = resolve_under_root(value, inbox, purpose="inbox payload path")
    if path.parent != inbox or path.suffix.lower() != ".json":
        raise ValueError("inbox payload must be a top-level JSON file")
    validate_evidence_id(path.stem, purpose="inbox evidence ID")
    return path


def process_inbox_once(
    inbox: str, controls: list[dict[str, Any]], assets: list[dict[str, Any]],
    ledger: str, state_db: str, remediation_dir: str, tickets_dir: str,
    reports_dir: str, access_review: dict[str, Any] | None = None,
    options: WorkerRunOptions | None = None,
) -> list[dict[str, Any]]:
    options = options or WorkerRunOptions()
    failpoint = _configured_test_failpoint()
    inbox_path = Path(inbox).expanduser().resolve(strict=False)
    storage_root = (
        Path(options.runtime_root).expanduser().resolve(strict=False)
        if options.runtime_root is not None
        else inbox_path.parent
    )
    ledger = str(resolve_under_root(ledger, storage_root, purpose="ledger path"))
    state_db = str(resolve_under_root(state_db, storage_root, purpose="state database path"))
    remediation_dir = str(resolve_worker_output_directory(
        remediation_dir, storage_root, "remediation", purpose="remediation directory"
    ))
    tickets_dir = str(resolve_worker_output_directory(
        tickets_dir, storage_root, "tickets", purpose="tickets directory"
    ))
    reports_dir = str(resolve_worker_output_directory(
        reports_dir, storage_root, "reports", purpose="reports directory"
    ))
    audit_path = options.audit_path
    if audit_path is not None:
        audit_path = str(resolve_under_root(audit_path, storage_root, purpose="audit log path"))
    governance_db = pipeline.configured_governance_database(options.governance_db)
    if governance_db is not None:
        governance_db = str(resolve_under_root(
            governance_db, storage_root, purpose="governance database path"
        ))
    inbox_path.mkdir(parents=True, exist_ok=True)
    inbox_items = sorted(inbox_path.glob("*.json"))
    for posture_path in inbox_items:
        _validated_inbox_item(posture_path, inbox_path)
    queue = SQLiteJobQueue(state_db)
    for posture_path in inbox_items:
        queue.enqueue(str(posture_path))
    results: list[dict[str, Any]] = []
    worker_id = "worker-" + secrets.token_hex(6)
    while True:
        job = queue.claim(worker_id, lease_seconds=options.lease_seconds)
        if job is None:
            break
        try:
            posture_path = _validated_inbox_item(job["payload_path"], inbox_path)
        except (TypeError, ValueError) as error:
            status = queue.fail(
                int(job["job_id"]), worker_id, str(error),
                max_attempts=1, retry_delay=0,
            )
            results.append({
                "file": str(job["payload_path"]),
                "status": "error",
                "queue_status": status,
                "error": str(error),
            })
            continue
        stop = threading.Event()
        heartbeat_thread = threading.Thread(
            target=_renew_lease_until_stopped,
            args=(queue, stop, int(job["job_id"]), worker_id, options.lease_seconds),
            daemon=True,
        )
        heartbeat_thread.start()
        try:
            posture = json.loads(posture_path.read_text(encoding="utf-8"))
            stem = posture_path.stem
            result = pipeline.run_pipeline(
                posture, controls, assets, ledger,
                str(Path(remediation_dir) / f"{stem}.json"),
                str(Path(tickets_dir) / f"{stem}.json"),
                str(Path(reports_dir) / f"{stem}.json"),
                state_db, access_review, audit_path=audit_path,
                governance_db=governance_db,
                options=pipeline.PipelineRunOptions(
                    run_lease_seconds=options.lease_seconds,
                    runtime_root=storage_root,
                ),
            )
            _trigger_test_failpoint(failpoint, FAILPOINT_AFTER_PIPELINE_COMMIT)
            if not queue.complete(int(job["job_id"]), worker_id):
                results.append({"file": str(posture_path), "status": "lease_lost"})
            else:
                results.append({"file": str(posture_path), **result})
        except Exception as error:
            status = queue.fail(int(job["job_id"]), worker_id, str(error), options.max_attempts, options.retry_delay)
            results.append({"file": str(posture_path), "status": "error", "queue_status": status, "error": str(error)})
        finally:
            stop.set()
            heartbeat_thread.join(timeout=2)
    return results


def worker_options_from_args(args: argparse.Namespace) -> WorkerRunOptions:
    return WorkerRunOptions(
        max_attempts=args.max_attempts,
        retry_delay=args.retry_delay,
        audit_path=args.audit_log,
        lease_seconds=args.lease_seconds,
        runtime_root=args.runtime_root,
        governance_db=args.governance_db,
    )


def serve(args: argparse.Namespace) -> int:
    controls = load_json(args.controls)
    assets = load_json(args.assets)
    access_review = load_json(args.access_review) if args.access_review else None
    options = worker_options_from_args(args)
    while True:
        results = process_inbox_once(
            args.inbox, controls, assets, args.ledger, args.state_db,
            args.remediation_dir, args.tickets_dir, args.reports_dir,
            access_review, options,
        )
        for result in results:
            print(json.dumps(result, separators=(",", ":")))
        time.sleep(args.interval)


def add_worker_arguments(worker: argparse.ArgumentParser, command: str) -> None:
    worker.add_argument("--inbox", default="evidence-inbox")
    worker.add_argument("--runtime-root", default=".")
    worker.add_argument("--controls", required=True)
    worker.add_argument("--assets", required=True)
    worker.add_argument("--access-review")
    worker.add_argument("--ledger", default="evidence-ledger.jsonl")
    worker.add_argument("--state-db", default=DEFAULT_STATE_DB)
    worker.add_argument("--remediation-dir", default="runtime/remediation")
    worker.add_argument("--tickets-dir", default="runtime/tickets")
    worker.add_argument("--reports-dir", default="runtime/reports")
    worker.add_argument("--max-attempts", type=int, default=3)
    worker.add_argument("--retry-delay", type=int, default=60)
    worker.add_argument("--audit-log", default="runtime/audit-log.jsonl")
    worker.add_argument("--governance-db")
    worker.add_argument("--lease-seconds", type=int, default=300)
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
            access_review, worker_options_from_args(args),
        )
        print(json.dumps(results, indent=2))
        return 0 if all(item["status"] != "error" for item in results) else 1
    return serve(args)


if __name__ == "__main__":
    raise SystemExit(main())
