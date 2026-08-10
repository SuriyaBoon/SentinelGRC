"""Agent key metadata registry.

Secrets are never stored here. The secret manager owns key material; this registry
stores only key IDs, agent IDs, lifecycle status, and timestamps.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sqlite3
import re
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from path_security import configured_runtime_root, resolve_sqlite_database_under_root
from state_store import DEFAULT_STATE_DB


KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AgentKeyRegistry:
    def __init__(
        self,
        path: str | Path = DEFAULT_STATE_DB,
        *,
        storage_root: str | Path | None = None,
    ):
        supplied = Path(path).expanduser()
        boundary = (
            Path(storage_root)
            if storage_root is not None
            else (supplied.parent if supplied.is_absolute() else Path.cwd())
        )
        self.path = str(
            resolve_sqlite_database_under_root(
                supplied,
                boundary,
                purpose="agent-key database",
            )
        )
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(database=self.path, uri=False)) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_keys (
                    key_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                    created_at TEXT NOT NULL,
                    revoked_at TEXT
                )
                """
            )

    def register(self, agent_id: str, key_id: str | None = None) -> tuple[str, str]:
        key_id = key_id or f"{agent_id}-{secrets.token_hex(6)}"
        if not agent_id.strip() or not KEY_ID_PATTERN.fullmatch(key_id):
            raise ValueError("agent_id and key_id must use non-empty safe identifiers.")
        secret = secrets.token_urlsafe(32)
        with closing(sqlite3.connect(database=self.path, uri=False)) as connection:
            connection.execute(
                "INSERT INTO agent_keys(key_id, agent_id, status, created_at) VALUES (?, ?, 'active', ?)",
                (key_id, agent_id, utc_now()),
            )
            connection.commit()
        return key_id, secret

    def revoke(self, key_id: str) -> None:
        with closing(sqlite3.connect(database=self.path, uri=False)) as connection:
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
        key_id, secret = registry.register(args.agent_id, args.key_id)
        print(json.dumps({"key_id": key_id, "secret_once": secret}))
    else:
        registry.revoke(args.key_id)
        print(json.dumps({"key_id": args.key_id, "status": "revoked"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
