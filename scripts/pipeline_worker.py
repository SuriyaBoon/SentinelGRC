"""Inbox worker that connects authenticated ingestion to the governance pipeline."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sqlite3
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
from publication_reconciliation import (
    is_evidence_filename,
    read_evidence_bytes,
    read_verified_evidence,
    reconcile_pending_publications,
)
from state_store import SQLITE_LOCK_TIMEOUT_SECONDS, SQLiteStateStore
from sentinelgrc import load_json
from state_store import DEFAULT_STATE_DB


FAILPOINT_AFTER_PIPELINE_COMMIT = "after_pipeline_commit_before_queue_ack"
FAILPOINT_EXIT_CODE = 86
# The heartbeat fires at lease/3; a lease of twice the shared SQLite lock
# timeout keeps a worst-case renewal lock wait (lease/3 + timeout) ahead of
# lease expiry with a positive margin.
MIN_WORKER_LEASE_SECONDS = SQLITE_LOCK_TIMEOUT_SECONDS * 2


@dataclass(frozen=True)
class WorkerRunOptions:
    max_attempts: int = 3
    retry_delay: int = 60
    audit_path: str | None = None
    lease_seconds: int = 300
    runtime_root: str | Path | None = None
    governance_db: str | None = None


@dataclass(frozen=True)
class WorkerConfiguration:
    controls: list[dict[str, Any]]
    assets: list[dict[str, Any]]
    access_review: dict[str, Any] | None = None


@dataclass(frozen=True)
class _WorkerPaths:
    inbox: Path
    storage_root: Path
    ledger: str
    state_db: str
    remediation_dir: str
    tickets_dir: str
    reports_dir: str
    audit_path: str | None
    governance_db: str | None


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


def _lease_renewal_interval(lease_seconds: int) -> float:
    """Bounded fractional cadence strictly shorter than any valid lease."""
    return max(0.05, lease_seconds / 3.0)


def _one_shot_exit_code(results: list[Any]) -> int:
    """Return success only when every one-shot result is explicitly complete."""
    successful_statuses = {"accepted", "duplicate"}
    succeeded = all(
        isinstance(item, dict) and item.get("status") in successful_statuses
        for item in results
    )
    return 0 if succeeded else 1


def _renew_lease_until_stopped(
    queue: SQLiteJobQueue,
    stop: threading.Event,
    lease_lost: threading.Event,
    job_id: int,
    worker_id: str,
    lease_seconds: int,
) -> None:
    """Extend the lease until stopped; flag any renewal loss fail-closed."""
    while not stop.wait(_lease_renewal_interval(lease_seconds)):
        try:
            if not queue.renew(job_id, worker_id, lease_seconds):
                lease_lost.set()
                break
        except sqlite3.Error:
            lease_lost.set()
            break


def _validated_inbox_item(value: str | Path, inbox: Path) -> Path:
    """Require a top-level JSON payload with an output-safe stable identity."""
    path = resolve_under_root(value, inbox, purpose="inbox payload path")
    if path.parent != inbox or path.suffix.lower() != ".json":
        raise ValueError("inbox payload must be a top-level JSON file")
    validate_evidence_id(path.stem, purpose="inbox evidence ID")
    return path


def _resolve_worker_paths(
    inbox: str,
    ledger: str,
    state_db: str,
    remediation_dir: str,
    tickets_dir: str,
    reports_dir: str,
    options: WorkerRunOptions,
) -> _WorkerPaths:
    inbox_path = Path(inbox).expanduser().resolve(strict=False)
    storage_root = (
        Path(options.runtime_root).expanduser().resolve(strict=False)
        if options.runtime_root is not None
        else inbox_path.parent
    )
    resolved_audit = (
        str(resolve_under_root(options.audit_path, storage_root, purpose="audit log path"))
        if options.audit_path is not None
        else None
    )
    governance_db = pipeline.configured_governance_database(options.governance_db)
    return _WorkerPaths(
        inbox=inbox_path,
        storage_root=storage_root,
        ledger=str(resolve_under_root(ledger, storage_root, purpose="ledger path")),
        state_db=str(resolve_under_root(state_db, storage_root, purpose="state database path")),
        remediation_dir=str(resolve_worker_output_directory(
            remediation_dir, storage_root, "remediation", purpose="remediation directory"
        )),
        tickets_dir=str(resolve_worker_output_directory(
            tickets_dir, storage_root, "tickets", purpose="tickets directory"
        )),
        reports_dir=str(resolve_worker_output_directory(
            reports_dir, storage_root, "reports", purpose="reports directory"
        )),
        audit_path=resolved_audit,
        governance_db=(
            str(resolve_under_root(governance_db, storage_root, purpose="governance database path"))
            if governance_db is not None
            else None
        ),
    )


def _read_claimed_payload(
    path: Path, publication_state: SQLiteStateStore
) -> bytes:
    """Read managed evidence once and bind those bytes to committed state."""
    if not is_evidence_filename(path.stem):
        payload = read_evidence_bytes(path)
        if payload is None:
            raise ValueError("inbox payload must be a regular readable file")
        return payload
    record = publication_state.find_payload_by_evidence_id(path.stem)
    if record is None or record["status"] != "committed":
        raise ValueError("managed inbox payload is not committed")
    payload = read_verified_evidence(path, str(record["payload_hash"]))
    if payload is None:
        # Recovery requires the reviewed operator procedure in docs/pipeline-worker-recovery.md.
        raise ValueError("managed inbox payload failed committed hash verification")
    return payload


def _process_claimed_job(
    queue: SQLiteJobQueue,
    job: dict[str, Any],
    paths: _WorkerPaths,
    publication_state: SQLiteStateStore,
    controls: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    access_review: dict[str, Any] | None,
    options: WorkerRunOptions,
    worker_id: str,
    failpoint: str | None,
) -> dict[str, Any]:
    # Lease supervision precedes any blocking evidence I/O: an immediate
    # synchronous renewal proves ownership before the read (an expected
    # queue-storage failure means ownership is unknown, so it fails closed
    # too), the heartbeat keeps the lease alive across the read and the
    # pipeline run, and lease_lost turns any renewal failure into an
    # explicit stop signal instead of a silent background-thread exit.
    job_file = str(job["payload_path"])
    try:
        lease_owned = queue.renew(
            int(job["job_id"]), worker_id, options.lease_seconds
        )
    except sqlite3.Error:
        return {"file": job_file, "status": "lease_lost"}
    if not lease_owned:
        return {"file": job_file, "status": "lease_lost"}
    stop = threading.Event()
    lease_lost = threading.Event()
    heartbeat_thread = threading.Thread(
        target=_renew_lease_until_stopped,
        args=(queue, stop, lease_lost, int(job["job_id"]), worker_id, options.lease_seconds),
        daemon=True,
    )
    heartbeat_thread.start()
    heartbeat_joined = False

    def shutdown_heartbeat() -> None:
        """Stop and join the heartbeat at most once."""
        nonlocal heartbeat_joined
        if heartbeat_joined:
            return
        stop.set()
        heartbeat_thread.join()
        heartbeat_joined = True

    try:
        try:
            posture_path = _validated_inbox_item(job["payload_path"], paths.inbox)
            posture_bytes = _read_claimed_payload(posture_path, publication_state)
            if lease_lost.is_set():
                return {"file": job_file, "status": "lease_lost"}
        except OSError:
            status = queue.fail(
                int(job["job_id"]), worker_id,
                "evidence storage is temporarily unavailable",
                options.max_attempts, options.retry_delay,
            )
            return {
                "file": job_file,
                "status": "error",
                "queue_status": status,
                "error": "evidence storage is temporarily unavailable",
            }
        except (TypeError, ValueError) as error:
            status = queue.fail(
                int(job["job_id"]), worker_id, str(error),
                max_attempts=1, retry_delay=0,
            )
            return {
                "file": job_file,
                "status": "error",
                "queue_status": status,
                "error": str(error),
            }

        posture = json.loads(posture_bytes.decode("utf-8"))
        stem = posture_path.stem
        result = pipeline.run_pipeline(
            posture, controls, assets, paths.ledger,
            str(Path(paths.remediation_dir) / f"{stem}.json"),
            str(Path(paths.tickets_dir) / f"{stem}.json"),
            str(Path(paths.reports_dir) / f"{stem}.json"),
            paths.state_db, access_review, audit_path=paths.audit_path,
            governance_db=paths.governance_db,
            options=pipeline.PipelineRunOptions(
                run_lease_seconds=options.lease_seconds,
                runtime_root=paths.storage_root,
            ),
        )
        _trigger_test_failpoint(failpoint, FAILPOINT_AFTER_PIPELINE_COMMIT)
        shutdown_heartbeat()
        if lease_lost.is_set():
            # A detected loss is not success; pipeline side effects already
            # performed are not rolled back by this check.
            return {"file": str(posture_path), "status": "lease_lost"}
        if not queue.complete(int(job["job_id"]), worker_id):
            return {"file": str(posture_path), "status": "lease_lost"}
        return {"file": str(posture_path), **result}
    except Exception as error:
        status = queue.fail(
            int(job["job_id"]), worker_id, str(error),
            options.max_attempts, options.retry_delay,
        )
        return {
            "file": job_file,
            "status": "error",
            "queue_status": status,
            "error": str(error),
        }
    finally:
        shutdown_heartbeat()


def _validate_worker_run_options(options: WorkerRunOptions) -> None:
    """Reject unsafe run options at the public boundary, before side effects."""
    if options.lease_seconds < MIN_WORKER_LEASE_SECONDS:
        raise ValueError(
            f"lease_seconds must be at least {MIN_WORKER_LEASE_SECONDS} to keep the "
            "heartbeat cadence ahead of the shared SQLite lock timeout"
        )
    if options.max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    if options.retry_delay < 0:
        raise ValueError("retry_delay must not be negative")


def process_inbox_once(
    inbox: str, controls: list[dict[str, Any]], assets: list[dict[str, Any]],
    ledger: str, state_db: str, remediation_dir: str, tickets_dir: str,
    reports_dir: str, access_review: dict[str, Any] | None = None,
    options: WorkerRunOptions | None = None,
) -> list[dict[str, Any]]:
    options = options or WorkerRunOptions()
    _validate_worker_run_options(options)
    failpoint = _configured_test_failpoint()
    paths = _resolve_worker_paths(
        inbox, ledger, state_db, remediation_dir, tickets_dir, reports_dir, options
    )
    paths.inbox.mkdir(parents=True, exist_ok=True)
    inbox_items = sorted(paths.inbox.glob("*.json"))
    for posture_path in inbox_items:
        _validated_inbox_item(posture_path, paths.inbox)
    publication_state = SQLiteStateStore(paths.state_db, storage_root=paths.storage_root)
    # Uses the default grace period (not 0): unlike a server's one-time
    # startup sweep, this poll-cycle sweep covers only the posture inbox
    # at paths.inbox, potentially concurrently with a live ingestion
    # server that may have a request genuinely in flight right now. This
    # recurring sweep is also what protects a long-running ingestion
    # server that has not restarted in a while - the server's own startup
    # sweep only runs once, at process start. Portfolio directories are
    # not reconciled here; they are covered at server startup or through
    # the explicit reconciliation CLI.
    reconcile_pending_publications(publication_state, [paths.inbox])
    queue = SQLiteJobQueue(paths.state_db)
    for posture_path in inbox_items:
        if (
            not is_evidence_filename(posture_path.stem)
            or publication_state.is_evidence_committed(posture_path.stem)
        ):
            queue.enqueue(str(posture_path))
    results: list[dict[str, Any]] = []
    worker_id = "worker-" + secrets.token_hex(6)
    while True:
        job = queue.claim(worker_id, lease_seconds=options.lease_seconds)
        if job is None:
            break
        results.append(_process_claimed_job(
            queue, job, paths, publication_state, controls, assets, access_review, options,
            worker_id, failpoint,
        ))
    return results


def resolve_worker_roots(args: argparse.Namespace) -> tuple[Path, Path]:
    """Resolve declared read-only configuration and writable runtime roots once."""
    runtime_root = Path(args.runtime_root).expanduser().resolve(strict=False)
    config_value = args.config_root if args.config_root is not None else runtime_root
    config_root = Path(config_value).expanduser().resolve(strict=False)
    return config_root, runtime_root


def load_worker_configuration(
    args: argparse.Namespace, config_root: str | Path
) -> WorkerConfiguration:
    """Load every worker configuration input through one explicit boundary."""
    controls = load_json(
        args.controls, root=config_root, purpose="control catalogue"
    )
    assets = load_json(args.assets, root=config_root, purpose="asset registry")
    access_review = (
        load_json(
            args.access_review,
            root=config_root,
            purpose="access review input",
        )
        if args.access_review
        else None
    )
    return WorkerConfiguration(controls, assets, access_review)


def worker_options_from_args(
    args: argparse.Namespace, runtime_root: str | Path
) -> WorkerRunOptions:
    return WorkerRunOptions(
        max_attempts=args.max_attempts,
        retry_delay=args.retry_delay,
        audit_path=args.audit_log,
        lease_seconds=args.lease_seconds,
        runtime_root=runtime_root,
        governance_db=args.governance_db,
    )


def serve(
    args: argparse.Namespace,
    configuration: WorkerConfiguration,
    options: WorkerRunOptions,
) -> int:
    while True:
        results = process_inbox_once(
            args.inbox, configuration.controls, configuration.assets,
            args.ledger, args.state_db, args.remediation_dir, args.tickets_dir,
            args.reports_dir, configuration.access_review, options,
        )
        for result in results:
            print(json.dumps(result, separators=(",", ":")))
        time.sleep(args.interval)


def add_worker_arguments(worker: argparse.ArgumentParser, command: str) -> None:
    worker.add_argument("--inbox", default="evidence-inbox")
    worker.add_argument("--runtime-root", default=".")
    worker.add_argument("--config-root")
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
    config_root, runtime_root = resolve_worker_roots(args)
    options = worker_options_from_args(args, runtime_root)
    try:
        _validate_worker_run_options(options)
    except ValueError as error:
        parser.error(str(error))
    configuration = load_worker_configuration(args, config_root)
    if args.command == "once":
        results = process_inbox_once(
            args.inbox, configuration.controls, configuration.assets,
            args.ledger, args.state_db, args.remediation_dir, args.tickets_dir,
            args.reports_dir, configuration.access_review, options,
        )
        print(json.dumps(results, indent=2))
        return _one_shot_exit_code(results)
    return serve(args, configuration, options)


if __name__ == "__main__":
    raise SystemExit(main())
