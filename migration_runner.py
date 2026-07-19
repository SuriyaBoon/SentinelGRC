"""Versioned SQLite migration runner with checksum protection."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path


class MigrationRunner:
    def __init__(self, db_path: str, migrations_dir: str) -> None:
        self.db_path = str(db_path)
        self.migrations_dir = Path(migrations_dir)
        self.migrations_dir.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=10)
        db.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                migration_id TEXT PRIMARY KEY,
                applied_at REAL NOT NULL,
                checksum TEXT NOT NULL
            )
        """)
        db.commit()
        return db

    def apply(self) -> list[str]:
        applied_now: list[str] = []
        paths = sorted(self.migrations_dir.glob("*.sql"))
        with closing(self._connect()) as db:
            for path in paths:
                migration_id = path.stem
                sql = path.read_text(encoding="utf-8")
                checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
                row = db.execute(
                    "SELECT checksum FROM schema_migrations WHERE migration_id = ?",
                    (migration_id,),
                ).fetchone()
                if row is not None:
                    if row[0] != checksum:
                        raise ValueError(f"migration checksum mismatch: {migration_id}")
                    continue
                try:
                    db.executescript(sql)
                    db.execute(
                        "INSERT INTO schema_migrations(migration_id, applied_at, checksum) VALUES (?, strftime('%s','now'), ?)",
                        (migration_id, checksum),
                    )
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                applied_now.append(migration_id)
        return applied_now

    def status(self) -> list[dict[str, str]]:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT migration_id, applied_at, checksum FROM schema_migrations ORDER BY migration_id"
            ).fetchall()
        return [{"migration_id": row[0], "applied_at": str(row[1]), "checksum": row[2]} for row in rows]
