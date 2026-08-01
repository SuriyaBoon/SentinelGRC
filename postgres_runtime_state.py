"""PostgreSQL replay, queue, and transactional-outbox adapters."""

from __future__ import annotations

import time
import uuid
import re
from contextlib import closing
from typing import Any

from persistence import Database
from outbox_delivery import GovernanceOutboxQueue as GovernanceOutbox


def _postgres(database: Database) -> None:
    if database.dialect != "postgresql":
        raise ValueError("this adapter requires PostgreSQL")


class PostgresConnectorEventStore:
    def __init__(self, database: Database) -> None:
        _postgres(database)
        self.database = database

    def reserve(self, event_id: str, source: str, payload_hash: str) -> bool:
        if (
            not event_id.strip()
            or not source.strip()
            or re.fullmatch(r"[0-9a-f]{64}", payload_hash) is None
        ):
            raise ValueError("source, event_id, and SHA-256 payload_hash are required")
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "INSERT INTO connector_events("
                "source, event_id, payload_hash, accepted_at"
                ") VALUES (?, ?, ?, ?) ON CONFLICT(source, event_id) DO NOTHING",
                (source, event_id, payload_hash, time.time()),
            )
            db.commit()
            return cursor.rowcount == 1


class PostgresJobQueue:
    def __init__(self, database: Database) -> None:
        _postgres(database)
        self.database = database

    def enqueue(self, payload_path: str, now: float | None = None) -> bool:
        if not payload_path.strip():
            raise ValueError("payload_path is required")
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "INSERT INTO pipeline_jobs(payload_path, status, available_at) "
                "VALUES (?, 'pending', ?) "
                "ON CONFLICT(payload_path) DO NOTHING",
                (payload_path, current),
            )
            db.commit()
            return cursor.rowcount == 1

    def claim(
        self,
        worker_id: str,
        lease_seconds: int = 300,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        if not worker_id.strip() or lease_seconds <= 0:
            raise ValueError("worker_id and a positive lease_seconds are required")
        current = time.time() if now is None else now
        token = uuid.uuid4().hex
        with closing(self.database.connect()) as db:
            row = db.execute(
                """
                WITH candidate AS (
                    SELECT job_id FROM pipeline_jobs
                    WHERE (status = 'pending' AND available_at <= ?)
                       OR (status = 'running' AND locked_until <= ?)
                    ORDER BY job_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE pipeline_jobs AS job
                SET status = 'running', attempts = attempts + 1,
                    locked_until = ?, worker_id = ?, lock_token = ?
                FROM candidate
                WHERE job.job_id = candidate.job_id
                RETURNING job.*
                """,
                (
                    current,
                    current,
                    current + lease_seconds,
                    worker_id,
                    token,
                ),
            ).fetchone()
            db.commit()
            return None if row is None else dict(row)

    def renew(
        self,
        job_id: int,
        worker_id: str,
        lock_token: str,
        lease_seconds: int = 300,
        now: float | None = None,
    ) -> bool:
        if not worker_id.strip() or not lock_token or lease_seconds <= 0:
            raise ValueError("worker_id, lock_token, and lease_seconds are required")
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "UPDATE pipeline_jobs SET locked_until = ? "
                "WHERE job_id = ? AND status = 'running' AND worker_id = ? "
                "AND lock_token = ? AND locked_until > ?",
                (
                    current + lease_seconds,
                    job_id,
                    worker_id,
                    lock_token,
                    current,
                ),
            )
            db.commit()
            return cursor.rowcount == 1

    def complete(
        self,
        job_id: int,
        worker_id: str,
        lock_token: str,
        now: float | None = None,
    ) -> bool:
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "UPDATE pipeline_jobs SET status = 'completed', "
                "locked_until = NULL, worker_id = NULL, lock_token = NULL, "
                "last_error = NULL WHERE job_id = ? AND status = 'running' "
                "AND worker_id = ? AND lock_token = ? AND locked_until > ?",
                (job_id, worker_id, lock_token, current),
            )
            db.commit()
            return cursor.rowcount == 1

    def fail(
        self,
        job_id: int,
        worker_id: str,
        lock_token: str,
        error: str,
        max_attempts: int = 3,
        retry_delay: int = 60,
        now: float | None = None,
    ) -> str:
        if max_attempts < 1 or retry_delay < 0:
            raise ValueError("max_attempts and retry_delay are invalid")
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            row = db.execute(
                "SELECT attempts, status, worker_id, lock_token, locked_until "
                "FROM pipeline_jobs WHERE job_id = ? FOR UPDATE",
                (job_id,),
            ).fetchone()
            if (
                row is None
                or row["status"] != "running"
                or row["worker_id"] != worker_id
                or row["lock_token"] != lock_token
                or row["locked_until"] is None
                or row["locked_until"] <= current
            ):
                db.rollback()
                return "lease_lost"
            status = "dead" if row["attempts"] >= max_attempts else "pending"
            db.execute(
                "UPDATE pipeline_jobs SET status = ?, available_at = ?, "
                "locked_until = NULL, worker_id = NULL, lock_token = NULL, "
                "last_error = ? WHERE job_id = ?",
                (
                    status,
                    current + (0 if status == "dead" else retry_delay),
                    str(error)[:2000],
                    job_id,
                ),
            )
            db.commit()
            return status

    def metadata(self) -> dict[str, int]:
        with closing(self.database.connect()) as db:
            rows = db.execute(
                "SELECT status, COUNT(*) AS count FROM pipeline_jobs GROUP BY status"
            ).fetchall()
            db.rollback()
        result = {"pending": 0, "running": 0, "completed": 0, "dead": 0}
        result.update({row["status"]: int(row["count"]) for row in rows})
        return result
