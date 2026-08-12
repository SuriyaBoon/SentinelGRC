"""Supervised publisher for SentinelGRC transactional outbox records."""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from pathlib import Path

from governance_core import GovernanceCore
from migration_runner import PostgresMigrationRunner
from outbox_delivery import (
    AzureServiceBusPublisher,
    GovernanceOutboxQueue,
    LocalOutboxPublisher,
    OutboxWorker,
)
from persistence import Database
from production_contract import Settings


def build_worker(settings: Settings, worker_id: str) -> OutboxWorker:
    errors = settings.validate_outbox_worker()
    if errors:
        raise RuntimeError("invalid Sentinel configuration: " + "; ".join(errors))
    if settings.environment == "production":
        raise RuntimeError("production outbox worker is blocked pending live validation")
    database = Database(settings.database_url)
    if database.dialect == "postgresql":
        PostgresMigrationRunner(
            database, str(Path(__file__).parent / "migrations" / "postgresql")
        ).apply()
    else:
        GovernanceCore(database=database)
    if settings.environment == "lab":
        publisher = LocalOutboxPublisher(settings.outbox_dir)
    else:
        publisher = AzureServiceBusPublisher(
            settings.service_bus_namespace,
            settings.service_bus_queue,
            managed_identity_client_id=settings.azure_managed_identity_client_id,
        )
    if not publisher.ready():
        database.close()
        raise RuntimeError("outbox publisher is not ready")
    return OutboxWorker(GovernanceOutboxQueue(database), publisher, worker_id)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-items", type=int, default=100)
    parser.add_argument("--worker-id", default=f"outbox-{uuid.uuid4().hex[:12]}")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--run-forever", action="store_true")
    parser.add_argument("--requeue-outbox")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if not 1 <= args.max_items <= 10_000:
        parser.error("--max-items must be between 1 and 10000")
    if not 0.1 <= args.poll_seconds <= 60:
        parser.error("--poll-seconds must be between 0.1 and 60")
    return args


def _run_worker_loop(
    worker: OutboxWorker,
    args: argparse.Namespace,
) -> tuple[dict[str, int], int]:
    counts = {"delivered": 0, "empty": 0, "retry": 0, "dead": 0, "stale": 0}
    while True:
        result = worker.run_once()
        counts[result] += 1
        if result == "empty":
            if not args.run_forever:
                return counts, 0
            time.sleep(args.poll_seconds)
        elif result in {"retry", "dead", "stale"}:
            print(json.dumps(counts, sort_keys=True), file=sys.stderr)
            if not args.run_forever:
                return counts, 1
            time.sleep(args.poll_seconds)
        if not args.run_forever and sum(counts.values()) >= args.max_items:
            return counts, 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        worker = build_worker(Settings.from_env(), args.worker_id)
        if args.requeue_outbox:
            changed = worker.queue.requeue_dead(args.requeue_outbox, args.confirm)
            print(json.dumps({"requeued": changed}, sort_keys=True))
            return 0 if changed else 1
        counts, exit_code = _run_worker_loop(worker, args)
        if exit_code == 0:
            print(json.dumps(counts, sort_keys=True))
        return exit_code
    except (RuntimeError, ValueError, PermissionError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
