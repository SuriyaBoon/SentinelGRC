"""Bounded worker that delivers transactional audit exports to the archive."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

from audit_archive import AzureBlobAuditArchive, LocalAuditArchive
from audit_delivery import AuditExportQueue, AuditExportWorker
from governance_core import GovernanceCore
from migration_runner import PostgresMigrationRunner
from persistence import Database
from production_contract import Settings


def build_worker(settings: Settings, worker_id: str) -> AuditExportWorker:
    errors = settings.validate()
    if errors:
        raise RuntimeError("invalid Sentinel configuration: " + "; ".join(errors))
    database = Database(settings.database_url)
    if database.dialect == "postgresql":
        PostgresMigrationRunner(
            database,
            str(Path(__file__).parent / "migrations" / "postgresql"),
        ).apply()
    else:
        GovernanceCore(database=database)
    if settings.environment == "lab":
        archive = LocalAuditArchive(settings.audit_dir)
    else:
        archive = AzureBlobAuditArchive(
            settings.audit_archive_url,
            managed_identity_client_id=settings.azure_managed_identity_client_id,
        )
    if not archive.ready():
        database.close()
        raise RuntimeError("audit archive is not ready")
    return AuditExportWorker(AuditExportQueue(database), archive, worker_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-items", type=int, default=100)
    parser.add_argument("--worker-id", default=f"audit-{uuid.uuid4().hex[:12]}")
    parser.add_argument("--requeue-export")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if not 1 <= args.max_items <= 10_000:
        parser.error("--max-items must be between 1 and 10000")
    try:
        worker = build_worker(Settings.from_env(), args.worker_id)
        if args.requeue_export:
            changed = worker.queue.requeue_dead(
                args.requeue_export,
                args.confirm,
            )
            print(json.dumps({"requeued": changed}, sort_keys=True))
            return 0 if changed else 1
        counts = {"archived": 0, "empty": 0, "retry": 0, "dead": 0, "stale": 0}
        for _ in range(args.max_items):
            result = worker.run_once()
            counts[result] += 1
            if result in {"empty", "retry", "dead", "stale"}:
                break
        print(json.dumps(counts, sort_keys=True))
        return 0 if counts["retry"] == counts["dead"] == counts["stale"] == 0 else 1
    except (RuntimeError, ValueError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
