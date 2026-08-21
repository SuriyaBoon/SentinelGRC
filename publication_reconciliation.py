"""Self-healing for publication records orphaned by a crash mid-write.

Lives outside scripts/ingestion_api.py deliberately: pipeline_worker.py is
not an HTTP component and should not have to import the HTTP ingestion
module just to reuse this logic. Both scripts/ingestion_api.py (at server
startup and via its `reconcile` CLI subcommand) and scripts/pipeline_worker.py
(every process_inbox_once() cycle) import reconcile_pending_publications()
from here.
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path

from state_store import SQLiteStateStore


# Reconciliation grace is intentionally independent from request-auth clock skew.
MAX_CLOCK_SKEW_SECONDS = 300
# How long a payload may sit in 'pending' state before reconciliation treats
# it as crash-orphaned rather than a normal in-flight request. Reusing the
# clock-skew window's value is a deliberate choice, not a coincidence: both
# numbers answer "how long is a single request cycle allowed to take," they
# are just named separately because they gate different failure modes. This
# is the *default* for callers that may run concurrently with live traffic
# (the pipeline_worker poll loop, the operator-triggered `reconcile` CLI
# subcommand) - a fresh server at startup should pass grace_seconds=0
# instead, since nothing can be legitimately in-flight before the process
# has started accepting requests. See IngestionServer.__init__.
RECONCILIATION_GRACE_SECONDS = MAX_CLOCK_SKEW_SECONDS


def is_evidence_filename(value: str) -> bool:
    """Return whether a filename stem uses the managed evidence identity form."""
    return len(value) == 24 and all(
        character in "0123456789abcdef" for character in value
    )


def read_evidence_bytes(path: Path) -> bytes | None:
    """Read one regular file descriptor without following a replaced pathname."""
    descriptor: int | None = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return None
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            return None
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            return stream.read()
    except OSError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_verified_evidence(path: Path, expected_hash: str) -> bytes | None:
    """Return bytes only when one securely opened file matches its committed hash."""
    payload = read_evidence_bytes(path)
    if payload is None or hashlib.sha256(payload).hexdigest() != expected_hash:
        return None
    return payload


def _pending_candidate(
    state_store: SQLiteStateStore,
    path: Path,
    grace_seconds: int,
    current: float,
) -> dict | None:
    """Return a hash-verified pending record eligible for reconciliation."""
    evidence_id = path.stem
    if not is_evidence_filename(evidence_id):
        return None
    record = state_store.find_payload_by_evidence_id(evidence_id)
    if record is None or record["status"] == "committed":
        return None
    if current - float(record["accepted_at"]) < grace_seconds:
        return None
    if read_verified_evidence(path, str(record["payload_hash"])) is None:
        return None
    return record


def reconcile_pending_publications(
    state_store: SQLiteStateStore,
    directories: list[Path],
    *,
    grace_seconds: int = RECONCILIATION_GRACE_SECONDS,
    now: float | None = None,
) -> list[str]:
    """Commit crash-orphaned records only after secure content verification."""
    if grace_seconds < 0:
        raise ValueError("grace_seconds must not be negative")
    current = time.time() if now is None else now
    reconciled: list[str] = []
    for directory in directories:
        try:
            candidates = sorted(Path(directory).glob("*.json"))
        except OSError:
            continue
        for path in candidates:
            record = _pending_candidate(
                state_store, path, grace_seconds, current
            )
            if record is None:
                continue
            evidence_id = path.stem
            if state_store.commit_payload(str(record["payload_hash"]), evidence_id):
                reconciled.append(evidence_id)
    return reconciled
