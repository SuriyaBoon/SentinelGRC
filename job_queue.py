"""SQLite-backed durable queue with leases, retries, and a dead-letter state."""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from state_store import DEFAULT_STATE_DB, SQLITE_LOCK_TIMEOUT_SECONDS


class SQLiteJobQueue:
    def __init__(self, path: str = DEFAULT_STATE_DB):
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pipeline_jobs (
                    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload_path TEXT UNIQUE NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'running', 'completed', 'dead')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at REAL NOT NULL,
                    locked_until REAL,
                    worker_id TEXT,
                    last_error TEXT
                )
                """
            )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        """Single place where queue connections apply the shared lock policy."""
        return sqlite3.connect(self.path, timeout=SQLITE_LOCK_TIMEOUT_SECONDS)

    def enqueue(self, payload_path: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO pipeline_jobs(payload_path, status, available_at) VALUES (?, 'pending', ?)",
                (payload_path, current),
            )
            connection.commit()
        return cursor.rowcount == 1

    def claim(self, worker_id: str, lease_seconds: int = 300, now: float | None = None) -> dict[str, Any] | None:
        if not worker_id.strip() or lease_seconds <= 0:
            raise ValueError("worker_id and a positive lease_seconds are required")
        current = time.time() if now is None else now
        with closing(self._connect()) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM pipeline_jobs
                """
                "WHERE (status = 'pending' AND available_at <= ?) "
                "   OR (status = 'running' AND locked_until <= ?) "
                "ORDER BY job_id LIMIT 1",
                (current, current),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            connection.execute(
                "UPDATE pipeline_jobs SET status = 'running', attempts = attempts + 1, locked_until = ?, worker_id = ? WHERE job_id = ?",
                (current + lease_seconds, worker_id, row["job_id"]),
            )
            connection.commit()
            result = dict(row)
            result["attempts"] = int(row["attempts"]) + 1
            return result

    def renew(self, job_id: int, worker_id: str, lease_seconds: int = 300, now: float | None = None) -> bool:
        """Extend a held lease, sampling implicit time after the write lock."""
        if not worker_id.strip() or lease_seconds <= 0:
            raise ValueError("worker_id and a positive lease_seconds are required")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = now if now is not None else time.time()
            cursor = connection.execute(
                "UPDATE pipeline_jobs SET locked_until = ? WHERE job_id = ? AND status = 'running' AND worker_id = ? AND locked_until > ?",
                (current + lease_seconds, job_id, worker_id, current),
            )
            connection.commit()
        return cursor.rowcount == 1

    def complete(self, job_id: int, worker_id: str, now: float | None = None) -> bool:
        """Complete only a job still leased to the calling worker."""
        if not worker_id.strip():
            raise ValueError("worker_id is required")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = now if now is not None else time.time()
            cursor = connection.execute(
                "UPDATE pipeline_jobs SET status = 'completed', locked_until = NULL, last_error = NULL "
                "WHERE job_id = ? AND status = 'running' AND worker_id = ? AND locked_until > ?",
                (job_id, worker_id, current),
            )
            connection.commit()
        return cursor.rowcount == 1

    def fail(self, job_id: int, worker_id: str, error: str, max_attempts: int = 3, retry_delay: int = 60, now: float | None = None) -> str:
        """Return lease_lost rather than mutating a job reclaimed by another worker."""
        if not worker_id.strip() or max_attempts < 1 or retry_delay < 0:
            raise ValueError("worker_id, max_attempts, and retry_delay are invalid")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = now if now is not None else time.time()
            row = connection.execute(
                "SELECT attempts, status, worker_id, locked_until FROM pipeline_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                connection.rollback()
                raise ValueError(f"Unknown job {job_id}.")
            if row[1] != "running" or row[2] != worker_id or row[3] is None or row[3] <= current:
                connection.rollback()
                return "lease_lost"
            status = "dead" if row[0] >= max_attempts else "pending"
            cursor = connection.execute(
                "UPDATE pipeline_jobs SET status = ?, available_at = ?, locked_until = NULL, worker_id = NULL, last_error = ? "
                "WHERE job_id = ? AND status = 'running' AND worker_id = ? AND locked_until > ?",
                (status, current + (0 if status == "dead" else retry_delay), error[:2000], job_id, worker_id, current),
            )
            connection.commit()
        return status if cursor.rowcount == 1 else "lease_lost"

    def metadata(self) -> dict[str, int]:
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT status, COUNT(*) FROM pipeline_jobs GROUP BY status").fetchall()
        result = {"pending": 0, "running": 0, "completed": 0, "dead": 0}
        result.update({str(status): int(count) for status, count in rows})
        return result
