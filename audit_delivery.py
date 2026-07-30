"""Transactional audit-export queue and archive worker."""

from __future__ import annotations

import json
import re
import time
import uuid
from contextlib import closing
from typing import Any

from audit_archive import AuditArchive
from persistence import Database


class AuditExportQueue:
    def __init__(self, database: Database) -> None:
        self.database = database

    def claim(
        self,
        worker_id: str,
        *,
        lease_seconds: int = 60,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        if not worker_id.strip() or lease_seconds <= 0:
            raise ValueError("worker_id and a positive lease_seconds are required")
        current = time.time() if now is None else now
        token = uuid.uuid4().hex
        with closing(self.database.connect()) as db:
            if self.database.dialect == "postgresql":
                row = db.execute(
                    """
                    WITH candidate AS (
                        SELECT item.export_id FROM audit_exports AS item
                        WHERE item.archived_at IS NULL
                          AND item.dead_at IS NULL
                          AND item.available_at <= ?
                          AND (item.locked_until IS NULL OR item.locked_until <= ?)
                          AND NOT EXISTS (
                              SELECT 1 FROM audit_exports AS earlier
                              WHERE earlier.finding_id = item.finding_id
                                AND earlier.event_sequence < item.event_sequence
                                AND earlier.archived_at IS NULL
                          )
                        ORDER BY item.created_at, item.export_id
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE audit_exports AS item
                    SET attempts = attempts + 1, locked_until = ?,
                        worker_id = ?, lock_token = ?
                    FROM candidate
                    WHERE item.export_id = candidate.export_id
                    RETURNING item.*
                    """,
                    (
                        current,
                        current,
                        current + lease_seconds,
                        worker_id,
                        token,
                    ),
                ).fetchone()
            else:
                db.execute("BEGIN IMMEDIATE")
                candidate = db.execute(
                    """
                    SELECT item.export_id FROM audit_exports AS item
                    WHERE item.archived_at IS NULL
                      AND item.dead_at IS NULL
                      AND item.available_at <= ?
                      AND (item.locked_until IS NULL OR item.locked_until <= ?)
                      AND NOT EXISTS (
                          SELECT 1 FROM audit_exports AS earlier
                          WHERE earlier.finding_id = item.finding_id
                            AND earlier.event_sequence < item.event_sequence
                            AND earlier.archived_at IS NULL
                      )
                    ORDER BY item.created_at, item.export_id
                    LIMIT 1
                    """,
                    (current, current),
                ).fetchone()
                row = None
                if candidate is not None:
                    db.execute(
                        "UPDATE audit_exports SET attempts = attempts + 1, "
                        "locked_until = ?, worker_id = ?, lock_token = ? "
                        "WHERE export_id = ?",
                        (
                            current + lease_seconds,
                            worker_id,
                            token,
                            candidate["export_id"],
                        ),
                    )
                    row = db.execute(
                        "SELECT * FROM audit_exports WHERE export_id = ?",
                        (candidate["export_id"],),
                    ).fetchone()
            db.commit()
            return None if row is None else dict(row)

    def acknowledge(
        self,
        item: dict[str, Any],
        archived: Any,
        *,
        now: float | None = None,
    ) -> bool:
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "UPDATE audit_exports SET archived_at = ?, object_key = ?, "
                "sha256 = ?, size_bytes = ?, etag = ?, locked_until = NULL, "
                "worker_id = NULL, lock_token = NULL, last_error = NULL "
                "WHERE export_id = ? AND archived_at IS NULL AND dead_at IS NULL "
                "AND worker_id = ? AND lock_token = ? AND locked_until > ?",
                (
                    current,
                    archived.object_key,
                    archived.sha256,
                    archived.size_bytes,
                    archived.etag,
                    item["export_id"],
                    item["worker_id"],
                    item["lock_token"],
                    current,
                ),
            )
            db.commit()
            return cursor.rowcount == 1

    def fail(
        self,
        item: dict[str, Any],
        *,
        max_attempts: int = 5,
        retry_delay: int = 30,
        now: float | None = None,
    ) -> str:
        if max_attempts < 1 or retry_delay < 0:
            raise ValueError("audit retry policy is invalid")
        current = time.time() if now is None else now
        dead = int(item["attempts"]) >= max_attempts
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "UPDATE audit_exports SET available_at = ?, dead_at = ?, "
                "locked_until = NULL, worker_id = NULL, lock_token = NULL, "
                "last_error = ? WHERE export_id = ? AND archived_at IS NULL "
                "AND dead_at IS NULL AND worker_id = ? AND lock_token = ?",
                (
                    current + retry_delay,
                    current if dead else None,
                    "audit archive delivery failed",
                    item["export_id"],
                    item["worker_id"],
                    item["lock_token"],
                ),
            )
            db.commit()
            if cursor.rowcount != 1:
                return "stale"
            return "dead" if dead else "retry"

    def metrics(self) -> dict[str, int]:
        with closing(self.database.connect()) as db:
            row = db.execute(
                "SELECT "
                "SUM(CASE WHEN archived_at IS NOT NULL THEN 1 ELSE 0 END) AS archived, "
                "SUM(CASE WHEN archived_at IS NULL AND dead_at IS NULL THEN 1 ELSE 0 END) AS pending, "
                "SUM(CASE WHEN dead_at IS NOT NULL THEN 1 ELSE 0 END) AS dead "
                "FROM audit_exports"
            ).fetchone()
            db.rollback()
        return {
            "archived": int(row["archived"] or 0),
            "pending": int(row["pending"] or 0),
            "dead": int(row["dead"] or 0),
        }

    def requeue_dead(
        self,
        export_id: str,
        confirmation: str,
        *,
        now: float | None = None,
    ) -> bool:
        if not re.fullmatch(r"[a-f0-9]{32}", export_id):
            raise ValueError("export_id is invalid")
        if confirmation != f"REQUEUE {export_id}":
            raise PermissionError("exact dead-letter requeue confirmation is required")
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "UPDATE audit_exports SET attempts = 0, available_at = ?, "
                "dead_at = NULL, locked_until = NULL, worker_id = NULL, "
                "lock_token = NULL, last_error = NULL "
                "WHERE export_id = ? AND archived_at IS NULL "
                "AND dead_at IS NOT NULL",
                (current, export_id),
            )
            db.commit()
            return cursor.rowcount == 1


class AuditExportWorker:
    def __init__(
        self,
        queue: AuditExportQueue,
        archive: AuditArchive,
        worker_id: str,
    ) -> None:
        if not worker_id.strip():
            raise ValueError("worker_id is required")
        self.queue = queue
        self.archive = archive
        self.worker_id = worker_id

    def run_once(
        self,
        *,
        lease_seconds: int = 60,
        max_attempts: int = 5,
        retry_delay: int = 30,
        now: float | None = None,
    ) -> str:
        item = self.queue.claim(
            self.worker_id,
            lease_seconds=lease_seconds,
            now=now,
        )
        if item is None:
            return "empty"
        try:
            event = json.loads(item["payload_json"])
            archived = self.archive.persist_event(event)
            acknowledged = self.queue.acknowledge(item, archived, now=now)
            return "archived" if acknowledged else "stale"
        except Exception:
            return self.queue.fail(
                item,
                max_attempts=max_attempts,
                retry_delay=retry_delay,
                now=now,
            )
