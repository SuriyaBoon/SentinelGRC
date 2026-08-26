"""Deterministic hermetic failure and recovery evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any

from scripts import pipeline_worker
from state_store import SQLITE_LOCK_TIMEOUT_SECONDS


DOCUMENT_SCHEMA = "sentinel.hermetic_recovery_evidence.v1"
ENVELOPE_SCHEMA = "sentinel.hermetic_recovery_evidence_envelope.v1"
READINESS_SCHEMA = "sentinel.hermetic_postgres_readiness.v1"
PRODUCTION_DECISION = "NO_GO_PENDING_LIVE_EVIDENCE"
MAX_EVIDENCE_BYTES = 256 * 1024
HERMETIC_EVIDENCE_FILENAME = "hermetic-evidence.json"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_GUID = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}"
    r"-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)
_URL = re.compile(r"(?:https?|sample)://", re.IGNORECASE)
_PROHIBITED_KEYS = {
    "client_id",
    "connection_string",
    "container_id",
    "email",
    "endpoint",
    "fqdn",
    "object_id",
    "password",
    "principal_id",
    "resource_id",
    "secret",
    "subscription_id",
    "tenant_id",
    "token",
    "url",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"hermetic evidence contains duplicate key: {key}")
        result[key] = value
    return result


def _exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} fields are invalid")
    return value


def _reject_sensitive(value: Any, location: str = "hermetic evidence") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in _PROHIBITED_KEYS:
                raise ValueError(f"{location} contains prohibited field: {key}")
            _reject_sensitive(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive(item, f"{location}[{index}]")
    elif isinstance(value, str) and (
        "/subscriptions/" in value.lower()
        or _GUID.search(value)
        or _URL.search(value)
        or "@" in value
    ):
        raise ValueError(f"{location} contains prohibited value")


def _table_count(database: Path, table: str) -> int:
    queries = {
        "findings": "SELECT COUNT(*) FROM findings",
        "governance_events": "SELECT COUNT(*) FROM governance_events",
        "governance_outbox": "SELECT COUNT(*) FROM governance_outbox",
    }
    try:
        query = queries[table]
    except KeyError as error:
        raise ValueError("hermetic recovery table is not allowlisted") from error
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(query).fetchone()
    return int(row[0])


def _queue_completed(database: Path) -> bool:
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM pipeline_jobs WHERE status = 'completed'"
        ).fetchone()
    return int(row[0]) == 1


def _expire_crashed_running_job(database: Path) -> None:
    """Expire exactly one crashed queue lease in a bounded transaction."""
    with closing(
        sqlite3.connect(database, timeout=SQLITE_LOCK_TIMEOUT_SECONDS)
    ) as connection:
        connection.execute("BEGIN IMMEDIATE")
        expired = connection.execute(
            "UPDATE pipeline_jobs SET locked_until = 0 WHERE status = 'running'"
        )
        if expired.rowcount != 1:
            connection.rollback()
            raise RuntimeError(
                "expected exactly one crashed running queue job, "
                f"found {expired.rowcount}"
            )
        connection.commit()


def _hash_outputs(paths: list[Path], root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
        if path.is_file()
    }


def _pipeline_command(root: Path, repository: Path) -> list[str]:
    return [
        sys.executable,
        "-m",
        "scripts.pipeline_worker",
        "once",
        "--inbox",
        str(root / "inbox"),
        "--runtime-root",
        str(root),
        "--config-root",
        str(repository),
        "--controls",
        str(repository / "controls.json"),
        "--assets",
        str(repository / "assets.json"),
        "--access-review",
        str(repository / "sample_ad_access_review.json"),
        "--ledger",
        str(root / "evidence-ledger.jsonl"),
        "--state-db",
        str(root / "sentinelgrc-state.db"),
        "--audit-log",
        str(root / "runtime" / "audit-log.jsonl"),
        "--governance-db",
        str(root / "runtime" / "governance.db"),
    ]


def run_pipeline_commit_ack_recovery(repository_root: str | Path) -> dict[str, bool]:
    """Crash at the real commit-before-ack boundary and verify replay invariants."""
    repository = Path(repository_root).resolve(strict=True)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        inbox = root / "inbox"
        inbox.mkdir()
        (inbox / HERMETIC_EVIDENCE_FILENAME).write_text(
            (repository / "sample_posture.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        command = _pipeline_command(root, repository)
        crash_environment = {
            **os.environ,
            "SENTINEL_ENV": "lab",
            "SENTINEL_ENABLE_TEST_FAILPOINTS": "true",
            "SENTINEL_FAILPOINT": pipeline_worker.FAILPOINT_AFTER_PIPELINE_COMMIT,
        }
        crashed = subprocess.run(
            command,
            cwd=repository,
            env=crash_environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if crashed.returncode != pipeline_worker.FAILPOINT_EXIT_CODE:
            # Never manufacture recovery evidence from a process that did
            # not reach the commit-before-ack failpoint.
            raise RuntimeError(
                f"crash process exited with {crashed.returncode}, expected "
                f"failpoint exit {pipeline_worker.FAILPOINT_EXIT_CODE}"
            )
        protected = [
            root / "evidence-ledger.jsonl",
            root / "runtime" / "audit-log.jsonl",
            root / "runtime" / "remediation" / HERMETIC_EVIDENCE_FILENAME,
            root / "runtime" / "tickets" / HERMETIC_EVIDENCE_FILENAME,
            root / "runtime" / "reports" / HERMETIC_EVIDENCE_FILENAME,
        ]
        before_hashes = _hash_outputs(protected, root)
        governance_db = root / "runtime" / "governance.db"
        before_counts = tuple(
            _table_count(governance_db, table)
            for table in ("findings", "governance_events", "governance_outbox")
        )
        # Expire the crashed lease deterministically instead of sleeping out a
        # real lease; the crashed job must be the only running queue job.
        _expire_crashed_running_job(root / "sentinelgrc-state.db")
        replay_environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"SENTINEL_ENABLE_TEST_FAILPOINTS", "SENTINEL_FAILPOINT"}
        }
        replayed = subprocess.run(
            command,
            cwd=repository,
            env=replay_environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        after_hashes = _hash_outputs(protected, root)
        after_counts = tuple(
            _table_count(governance_db, table)
            for table in ("findings", "governance_events", "governance_outbox")
        )
        return {
            "failpoint_exit_observed": (
                crashed.returncode == pipeline_worker.FAILPOINT_EXIT_CODE
            ),
            "durable_outputs_present": len(before_hashes) == len(protected),
            "replay_succeeded": replayed.returncode == 0,
            "replay_reported_duplicate": '"status": "duplicate"' in replayed.stdout,
            "output_hashes_unchanged": before_hashes == after_hashes,
            "database_counts_unchanged": before_counts == after_counts,
            "business_records_present": all(count > 0 for count in before_counts),
            "queue_completed_once": _queue_completed(root / "sentinelgrc-state.db"),
        }


def load_postgres_readiness(path: str | Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("PostgreSQL readiness evidence is not valid UTF-8 JSON") from error
    report = _exact_object(
        value,
        {
            "schema_version",
            "initial_http_status",
            "loss_http_status",
            "recovered_http_status",
            "initial_status",
            "loss_status",
            "recovered_status",
            "sqlite_fallback_observed",
        },
        "PostgreSQL readiness evidence",
    )
    if report["schema_version"] != READINESS_SCHEMA:
        raise ValueError("PostgreSQL readiness evidence schema is invalid")
    _reject_sensitive(report)
    return report


def _readiness_gates(report: dict[str, Any]) -> dict[str, bool]:
    return {
        "initial_ready": (
            report["initial_http_status"] == 200
            and report["initial_status"] == "ready"
        ),
        "dependency_loss_failed_closed": (
            report["loss_http_status"] == 503
            and report["loss_status"] == "not_ready"
            and report["sqlite_fallback_observed"] is False
        ),
        "dependency_recovered": (
            report["recovered_http_status"] == 200
            and report["recovered_status"] == "ready"
        ),
    }


def _validate_document(value: Any) -> dict[str, Any]:
    document = _exact_object(
        value,
        {
            "schema_version",
            "mode",
            "source_commit_sha",
            "pipeline_recovery",
            "postgres_readiness",
            "decision",
            "claim_boundary",
        },
        "hermetic recovery document",
    )
    _reject_sensitive(document)
    if document["schema_version"] != DOCUMENT_SCHEMA or document["mode"] != "hermetic_ci":
        raise ValueError("hermetic recovery document identity is invalid")
    if _COMMIT_SHA.fullmatch(str(document["source_commit_sha"])) is None:
        raise ValueError("hermetic recovery source commit SHA is invalid")
    pipeline = _exact_object(
        document["pipeline_recovery"],
        {
            "failpoint_exit_observed",
            "durable_outputs_present",
            "replay_succeeded",
            "replay_reported_duplicate",
            "output_hashes_unchanged",
            "database_counts_unchanged",
            "business_records_present",
            "queue_completed_once",
        },
        "pipeline recovery results",
    )
    readiness = _exact_object(
        document["postgres_readiness"],
        {"initial_ready", "dependency_loss_failed_closed", "dependency_recovered"},
        "PostgreSQL readiness results",
    )
    if any(not isinstance(item, bool) for item in (*pipeline.values(), *readiness.values())):
        raise ValueError("hermetic recovery gate value is invalid")
    expected = "PASS" if all((*pipeline.values(), *readiness.values())) else "NO_GO"
    if document["decision"] != expected:
        raise ValueError("hermetic recovery decision is inconsistent")
    boundary = _exact_object(
        document["claim_boundary"],
        {"azure_mutation_performed", "current_live_gate_credit", "production_decision"},
        "hermetic recovery claim boundary",
    )
    if boundary != {
        "azure_mutation_performed": False,
        "current_live_gate_credit": False,
        "production_decision": PRODUCTION_DECISION,
    }:
        raise ValueError("hermetic recovery claim boundary is invalid")
    return document


def canonical_document_bytes(value: Any) -> bytes:
    document = _validate_document(value)
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def create_envelope(document: Any) -> dict[str, Any]:
    validated = _validate_document(document)
    return {
        "schema_version": ENVELOPE_SCHEMA,
        "document": validated,
        "document_sha256": hashlib.sha256(canonical_document_bytes(validated)).hexdigest(),
    }


def validate_envelope(value: Any) -> dict[str, Any]:
    envelope = _exact_object(
        value,
        {"schema_version", "document", "document_sha256"},
        "hermetic recovery envelope",
    )
    if envelope["schema_version"] != ENVELOPE_SCHEMA:
        raise ValueError("hermetic recovery envelope identity is invalid")
    document = _validate_document(envelope["document"])
    expected = hashlib.sha256(canonical_document_bytes(document)).hexdigest()
    if not isinstance(envelope["document_sha256"], str) or envelope["document_sha256"] != expected:
        raise ValueError("hermetic recovery envelope checksum mismatch")
    return envelope


def load_envelope(path: str | Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise ValueError("hermetic recovery envelope cannot be read") from error
    if not raw or len(raw) > MAX_EVIDENCE_BYTES:
        raise ValueError("hermetic recovery envelope size is invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("hermetic recovery envelope JSON is invalid") from error
    return validate_envelope(value)


def collect_hermetic_recovery_evidence(
    repository_root: str | Path,
    readiness_path: str | Path,
    source_commit_sha: str,
) -> dict[str, Any]:
    if _COMMIT_SHA.fullmatch(source_commit_sha) is None:
        raise ValueError("hermetic recovery source commit SHA is invalid")
    pipeline = run_pipeline_commit_ack_recovery(repository_root)
    readiness = _readiness_gates(load_postgres_readiness(readiness_path))
    decision = "PASS" if all((*pipeline.values(), *readiness.values())) else "NO_GO"
    return create_envelope(
        {
            "schema_version": DOCUMENT_SCHEMA,
            "mode": "hermetic_ci",
            "source_commit_sha": source_commit_sha,
            "pipeline_recovery": pipeline,
            "postgres_readiness": readiness,
            "decision": decision,
            "claim_boundary": {
                "azure_mutation_performed": False,
                "current_live_gate_credit": False,
                "production_decision": PRODUCTION_DECISION,
            },
        }
    )
