"""Agent key metadata and route-scope registry.

Secrets are never stored here. Existing keys migrate fail-closed to posture-only
access; portfolio writers require an explicit reviewed scope at registration.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from path_security import configured_runtime_root, resolve_sqlite_database_under_root, select_storage_root
from state_store import (
    BEGIN_IMMEDIATE_SQL,
    DEFAULT_STATE_DB,
    SQLITE_LOCK_RETRY_SECONDS,
    SQLITE_LOCK_TIMEOUT_SECONDS,
    enable_sqlite_wal,
    is_retryable_sqlite_lock,
)


KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
POSTURE_WRITE_SCOPE = "posture:write"
ASSET_CONTEXT_WRITE_SCOPE = "asset-context:write"
REMEDIATION_TICKET_WRITE_SCOPE = "remediation-ticket:write"
ALLOWED_KEY_SCOPES = frozenset(
    {POSTURE_WRITE_SCOPE, ASSET_CONTEXT_WRITE_SCOPE, REMEDIATION_TICKET_WRITE_SCOPE}
)
LEGACY_SCOPES_SQL_DEFAULT = json.dumps([POSTURE_WRITE_SCOPE])
if "'" in LEGACY_SCOPES_SQL_DEFAULT:
    raise AssertionError(
        "LEGACY_SCOPES_SQL_DEFAULT is embedded in DDL and must not contain a single quote."
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_scopes(scopes: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    # A caller passing None means "no preference, use the default." A caller
    # passing an explicit empty tuple/list means "I want zero route access" -
    # `scopes or (POSTURE_WRITE_SCOPE,)` treated those the same way and
    # silently granted posture-write to a caller that asked for nothing.
    selected = (
        (POSTURE_WRITE_SCOPE,) if scopes is None else tuple(sorted(set(scopes)))
    )
    if not selected or any(scope not in ALLOWED_KEY_SCOPES for scope in selected):
        raise ValueError("agent key scopes must use the approved route-scope allowlist.")
    return selected


class AgentKeyRegistry:
    def __init__(
        self,
        path: str | Path = DEFAULT_STATE_DB,
        *,
        storage_root: str | Path | None = None,
    ):
        supplied = Path(path).expanduser()
        boundary = select_storage_root(supplied, storage_root)
        self.path = str(
            resolve_sqlite_database_under_root(
                supplied,
                boundary,
                purpose="agent-key database",
            )
        )
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(
            sqlite3.connect(database=self.path, timeout=0, uri=False)
        ) as connection:
            connection.execute("PRAGMA busy_timeout=0")
            enable_sqlite_wal(connection)
            self._initialize_schema(connection)

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        """Serialize schema creation and retry only transient SQLite locks."""
        deadline = time.monotonic() + SQLITE_LOCK_TIMEOUT_SECONDS
        legacy_default = LEGACY_SCOPES_SQL_DEFAULT
        while True:
            try:
                connection.execute(BEGIN_IMMEDIATE_SQL)
                connection.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS agent_keys (
                        key_id TEXT PRIMARY KEY,
                        agent_id TEXT NOT NULL,
                        status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                        created_at TEXT NOT NULL,
                        revoked_at TEXT,
                        scopes_json TEXT NOT NULL DEFAULT '{legacy_default}'
                    )
                    """
                )
                columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(agent_keys)"
                    ).fetchall()
                }
                if "scopes_json" not in columns:
                    connection.execute(
                        f"""ALTER TABLE agent_keys ADD COLUMN scopes_json TEXT NOT NULL
                        DEFAULT '{legacy_default}'"""
                    )
                connection.commit()
                return
            except sqlite3.OperationalError as error:
                connection.rollback()
                if (
                    not is_retryable_sqlite_lock(error)
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(SQLITE_LOCK_RETRY_SECONDS)
            except Exception:
                connection.rollback()
                raise

    def register(
        self,
        agent_id: str,
        key_id: str | None = None,
        *,
        scopes: tuple[str, ...] | list[str] | None = None,
    ) -> tuple[str, str]:
        key_id = key_id or f"{agent_id}-{secrets.token_hex(6)}"
        selected_scopes = _canonical_scopes(scopes)
        if not agent_id.strip() or not KEY_ID_PATTERN.fullmatch(key_id):
            raise ValueError("agent_id and key_id must use non-empty safe identifiers.")
        secret = secrets.token_urlsafe(32)
        with closing(
            sqlite3.connect(
                database=self.path, timeout=SQLITE_LOCK_TIMEOUT_SECONDS, uri=False
            )
        ) as connection:
            connection.execute(
                "INSERT INTO agent_keys"
                "(key_id, agent_id, status, created_at, scopes_json) "
                "VALUES (?, ?, 'active', ?, ?)",
                (key_id, agent_id, utc_now(), json.dumps(selected_scopes)),
            )
            connection.commit()
        return key_id, secret

    def revoke(self, key_id: str) -> None:
        with closing(
            sqlite3.connect(
                database=self.path, timeout=SQLITE_LOCK_TIMEOUT_SECONDS, uri=False
            )
        ) as connection:
            connection.execute(
                "UPDATE agent_keys SET status = 'revoked', revoked_at = ? WHERE key_id = ?",
                (utc_now(), key_id),
            )
            connection.commit()

    def is_active(self, key_id: str) -> bool:
        with closing(sqlite3.connect(database=self.path, uri=False)) as connection:
            row = connection.execute(
                "SELECT status FROM agent_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
        return row is not None and row[0] == "active"

    def is_authorized(self, key_id: str, required_scope: str) -> bool:
        if required_scope not in ALLOWED_KEY_SCOPES:
            return False
        with closing(sqlite3.connect(database=self.path, uri=False)) as connection:
            row = connection.execute(
                "SELECT status, scopes_json FROM agent_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
        if row is None or row[0] != "active":
            return False
        try:
            scopes = json.loads(row[1])
        except (TypeError, json.JSONDecodeError):
            return False
        return isinstance(scopes, list) and required_scope in scopes

    def resolve_secret(self, key_id: str, secret_map: dict[str, str]) -> bytes | None:
        if not self.is_active(key_id):
            return None
        secret = secret_map.get(key_id)
        return None if not isinstance(secret, str) or not secret else secret.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage SentinelGRC agent key metadata.")
    parser.add_argument("--db", default=DEFAULT_STATE_DB)
    subparsers = parser.add_subparsers(dest="command", required=True)
    register = subparsers.add_parser("register")
    register.add_argument("--agent-id", required=True)
    register.add_argument("--key-id")
    register.add_argument(
        "--scope", action="append", choices=sorted(ALLOWED_KEY_SCOPES)
    )
    revoke = subparsers.add_parser("revoke")
    revoke.add_argument("--key-id", required=True)
    args = parser.parse_args()
    runtime_root = configured_runtime_root()
    database_path = resolve_sqlite_database_under_root(
        args.db,
        runtime_root,
        purpose="agent-key database",
    )
    registry = AgentKeyRegistry(database_path, storage_root=runtime_root)
    if args.command == "register":
        scopes = _canonical_scopes(args.scope)
        key_id, secret = registry.register(args.agent_id, args.key_id, scopes=scopes)
        print(json.dumps({"key_id": key_id, "scopes": scopes, "secret_once": secret}))
    else:
        registry.revoke(args.key_id)
        print(json.dumps({"key_id": args.key_id, "status": "revoked"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
