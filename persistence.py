"""Database adapters for SentinelGRC's canonical runtime state.

SQLite is retained for lab and staging use. PostgreSQL is the shared,
transactional backend for production-shaped deployments.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

POSTGRESQL_PSYCOPG_SCHEME = "postgresql+psycopg://"
POSTGRESQL_SCHEME = "postgresql://"


class DatabaseIntegrityError(RuntimeError):
    """A backend-neutral uniqueness or foreign-key violation."""


def sqlite_path(database_url: str) -> str:
    parsed = urlparse(database_url)
    if parsed.scheme != "sqlite":
        raise ValueError("database URL is not SQLite")
    if parsed.netloc not in {"", "localhost"}:
        raise ValueError("SQLite URL must not include a remote host")
    raw_path = unquote(parsed.path)
    if not raw_path or raw_path == "/":
        raise ValueError("SQLite URL must include a database path")
    if raw_path.startswith("//"):
        return raw_path[1:]
    return raw_path.lstrip("/")


def normalize_postgres_url(database_url: str) -> str:
    if database_url.startswith(POSTGRESQL_PSYCOPG_SCHEME):
        return POSTGRESQL_SCHEME + database_url.removeprefix(
            POSTGRESQL_PSYCOPG_SCHEME
        )
    return database_url


class DatabaseConnection:
    def __init__(self, database: "Database", connection: Any) -> None:
        self.database = database
        self.connection = connection
        self._closed = False

    def execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> Any:
        if self.database.dialect == "postgresql":
            sql = sql.replace("BEGIN IMMEDIATE", "BEGIN").replace("?", "%s")
        try:
            return self.connection.execute(sql, parameters)
        except self.database.integrity_errors as error:
            raise DatabaseIntegrityError(str(error)) from error

    def executescript(self, sql: str) -> Any:
        if self.database.dialect != "sqlite":
            return self.execute(sql)
        try:
            return self.connection.executescript(sql)
        except self.database.integrity_errors as error:
            raise DatabaseIntegrityError(str(error)) from error

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.database.dialect == "postgresql":
            try:
                self.connection.rollback()
            except Exception:
                self.connection.close()
                return
            self.database._pool.putconn(self.connection)
        else:
            self.connection.close()


class Database:
    """Small DB-API boundary shared by governance and identity stores."""

    def __init__(
        self,
        database_url: str,
        *,
        pool_min_size: int = 1,
        pool_max_size: int = 10,
        pool_timeout_seconds: float = 5.0,
    ) -> None:
        self.database_url = database_url
        self._pool = None
        if database_url.startswith("sqlite:"):
            self.dialect = "sqlite"
            self.path = sqlite_path(database_url)
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self.integrity_errors = (sqlite3.IntegrityError,)
            return
        if database_url.startswith((POSTGRESQL_SCHEME, POSTGRESQL_PSYCOPG_SCHEME)):
            self.dialect = "postgresql"
            self.path = None
            try:
                import psycopg
                from psycopg.rows import dict_row
                from psycopg_pool import ConnectionPool
            except ImportError as error:
                raise RuntimeError(
                    "PostgreSQL requires psycopg and psycopg_pool"
                ) from error
            self.integrity_errors = (psycopg.IntegrityError,)
            self._pool = ConnectionPool(
                conninfo=normalize_postgres_url(database_url),
                min_size=pool_min_size,
                max_size=pool_max_size,
                timeout=pool_timeout_seconds,
                kwargs={
                    "row_factory": dict_row,
                    "connect_timeout": int(max(1, pool_timeout_seconds)),
                },
                open=True,
            )
            self._pool.wait(timeout=pool_timeout_seconds)
            return
        raise ValueError("database URL must use sqlite or postgresql")

    @classmethod
    def from_target(cls, target: str) -> "Database":
        if "://" not in target:
            path = Path(target).resolve().as_posix()
            return cls(f"sqlite:///{path}")
        return cls(target)

    def connect(self) -> DatabaseConnection:
        if self.dialect == "sqlite":
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
        else:
            connection = self._pool.getconn()
        return DatabaseConnection(self, connection)

    def ping(self) -> bool:
        connection: DatabaseConnection | None = None
        try:
            connection = self.connect()
            connection.execute("SELECT 1").fetchone()
            return True
        except Exception:
            return False
        finally:
            if connection is not None:
                connection.close()

    def for_update(self, sql: str) -> str:
        return f"{sql} FOR UPDATE" if self.dialect == "postgresql" else sql

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
