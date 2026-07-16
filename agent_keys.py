"""Agent key metadata registry.

Secrets are never stored here. The secret manager owns key material; this registry
stores only key IDs, agent IDs, lifecycle status, and timestamps.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AgentKeyRegistry:
    def __init__(self, path: str = "sentinelgrc-state.db"):
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as connection:
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
        secret = secrets.token_urlsafe(32)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "INSERT INTO agent_keys(key_id, agent_id, status, created_at) VALUES (?, ?, 'active', ?)",
                (key_id, agent_id, utc_now()),
            )
            connection.commit()
        return key_id, secret

    def revoke(self, key_id: str) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "UPDATE agent_keys SET status = 'revoked', revoked_at = ? WHERE key_id = ?",
                (utc_now(), key_id),
            )
            connection.commit()

    def is_active(self, key_id: str) -> bool:
        with closing(sqlite3.connect(self.path)) as connection:
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
    parser.add_argument("--db", default="sentinelgrc-state.db")
    subparsers = parser.add_subparsers(dest="command", required=True)
    register = subparsers.add_parser("register")
    register.add_argument("--agent-id", required=True)
    register.add_argument("--key-id")
    revoke = subparsers.add_parser("revoke")
    revoke.add_argument("--key-id", required=True)
    args = parser.parse_args()
    registry = AgentKeyRegistry(args.db)
    if args.command == "register":
        key_id, secret = registry.register(args.agent_id, args.key_id)
        print(json.dumps({"key_id": key_id, "secret_once": secret}))
    else:
        registry.revoke(args.key_id)
        print(json.dumps({"key_id": args.key_id, "status": "revoked"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
