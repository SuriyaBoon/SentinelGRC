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
import time
from pathlib import Path

from state_store import SQLiteStateStore


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


def reconcile_pending_publications(
    state_store: SQLiteStateStore,
    directories: list[Path],
    *,
    grace_seconds: int = RECONCILIATION_GRACE_SECONDS,
    now: float | None = None,
) -> list[str]:
    """Self-heal publication records stuck in 'pending' after a crash.

    _persist_validated_body() writes in this order: fsync the temp file's
    content, os.replace() it into place, fsync the directory entry, THEN
    call commit_payload(). If the process crashes after the file is fully
    durable but before commit_payload() runs, the file is visible on disk
    and completely safe to use, but the state store still says 'pending' -
    and every consumer that gates on is_evidence_committed() (notably
    pipeline_worker.process_inbox_once()) will skip that file forever,
    because a client that never retries leaves nothing else to trigger a
    fix.

    This function is intentionally conservative:
      - it only commits a pending row when the file on disk exists, is a
        regular file (not a symlink or other special file - a symlink
        could point anywhere, including outside the managed directory, and
        following it to compute a hash would make reconciliation an
        arbitrary-file-read primitive for anyone who can create a symlink
        in a watched directory),
      - re-hashing its content reproduces the exact payload_hash that was
        recorded at begin_payload() time, so a record is never marked
        committed based on filename alone,
      - it waits out `grace_seconds` from accepted_at before touching a
        row, so it never races a request that is legitimately still
        between begin_payload() and commit_payload() right now. A caller
        that can prove nothing could possibly be in-flight yet (a server
        that has not started accepting requests) may pass grace_seconds=0.

    Returns the evidence_ids that were reconciled (for logging/tests).
    """
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
            evidence_id = path.stem
            if len(evidence_id) != 24 or any(
                character not in "0123456789abcdef" for character in evidence_id
            ):
                continue  # not one of ours - filename doesn't match our identity scheme
            if path.is_symlink() or not path.is_file():
                continue  # never follow a symlink or read a non-regular file
            record = state_store.find_payload_by_evidence_id(evidence_id)
            if record is None or record["status"] == "committed":
                continue
            if current - float(record["accepted_at"]) < grace_seconds:
                continue  # may still be an in-flight request; leave it alone
            try:
                on_disk_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
            if on_disk_hash != record["payload_hash"]:
                continue  # file doesn't match the reserved identity; do not touch it
            if state_store.commit_payload(record["payload_hash"], evidence_id):
                reconciled.append(evidence_id)
    return reconciled
