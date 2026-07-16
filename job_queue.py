"""SQLite-backed durable queue with leases, retries, and a dead-letter state."""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any


class SQLiteJobQueue:
    def __init__(self, path: str = "sentinelgrc-state.db"):
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as connection:
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

    def enqueue(self, payload_path: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        with closing(sqlite3.connect(self.path)) as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO pipeline_jobs(payload_path, status, available_at) VALUES (?, 'pending', ?)",
                (payload_path, current),
            )
            connection.commit()
        return cursor.rowcount == 1

    def claim(self, worker_id: str, lease_seconds: int = 300, now: float | None = None) -> dict[str, Any] | None:
        current = time.time() if now is None else now
        with closing(sqlite3.connect(self.path, timeout=5)) as connection:
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

    def complete(self, job_id: int) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "UPDATE pipeline_jobs SET status = 'completed', locked_until = NULL, last_error = NULL WHERE job_id = ?",
                (job_id,),
            )
            connection.commit()

    def fail(self, job_id: int, error: str, max_attempts: int = 3, retry_delay: int = 60, now: float | None = None) -> str:
        current = time.time() if now is None else now
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute("SELECT attempts FROM pipeline_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if row is None:
                raise ValueError(f"Unknown job {job_id}.")
            status = "dead" if row[0] >= max_attempts else "pending"
            connection.execute(
                "UPDATE pipeline_jobs SET status = ?, available_at = ?, locked_until = NULL, worker_id = NULL, last_error = ? WHERE job_id = ?",
                (status, current + (0 if status == "dead" else retry_delay), error[:2000], job_id),
            )
            connection.commit()
        return status

    def metadata(self) -> dict[str, int]:
        with closing(sqlite3.connect(self.path)) as connection:
            rows = connection.execute("SELECT status, COUNT(*) FROM pipeline_jobs GROUP BY status").fetchall()
        result = {"pending": 0, "running": 0, "completed": 0, "dead": 0}
        result.update({str(status): int(count) for status, count in rows})
        return result
