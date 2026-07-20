"""Phase 1 human identity and API-key boundary.

Secrets are returned only at issuance and only a SHA-256 digest is persisted.
The authenticated actor is resolved by the server, not supplied by request data.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from governance_core import ActorContext, ROLES


class HumanIdentityStore:
    def __init__(self, path: str = "runtime/identity.db") -> None:
        self.path = str(Path(path))
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS user_api_keys (
                    key_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    secret_hash TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                );
            """)
            db.commit()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys = ON")
        return db

    @staticmethod
    def _hash(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def create_user(self, user_id: str, role: str) -> None:
        if not user_id.strip() or role not in ROLES:
            raise ValueError("user_id and supported role are required")
        with closing(self._connect()) as db:
            try:
                db.execute("INSERT INTO users(user_id, role) VALUES (?, ?)", (user_id, role))
            except sqlite3.IntegrityError as error:
                raise ValueError("user already exists") from error
            db.commit()

    def issue_api_key(self, user_id: str, key_id: str) -> str:
        secret = secrets.token_urlsafe(32)
        with closing(self._connect()) as db:
            user = db.execute("SELECT active FROM users WHERE user_id = ?", (user_id,)).fetchone()
            if user is None or not user[0]:
                raise ValueError("active user is required")
            try:
                db.execute(
                    "INSERT INTO user_api_keys(key_id, user_id, secret_hash) VALUES (?, ?, ?)",
                    (key_id, user_id, self._hash(secret)),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("key already exists") from error
            db.commit()
        return secret

    def revoke_key(self, key_id: str) -> None:
        with closing(self._connect()) as db:
            db.execute("UPDATE user_api_keys SET active = 0 WHERE key_id = ?", (key_id,))
            db.commit()

    def authenticate(self, key_id: str, secret: str) -> ActorContext:
        with closing(self._connect()) as db:
            row = db.execute("""
                SELECT u.user_id, u.role, k.secret_hash
                FROM user_api_keys k JOIN users u ON u.user_id = k.user_id
                WHERE k.key_id = ? AND k.active = 1 AND u.active = 1
            """, (key_id,)).fetchone()
        if row is None or not hmac.compare_digest(row[2], self._hash(secret)):
            raise PermissionError("invalid or revoked human API key")
        return ActorContext(row[0], row[1], auth_method="api_key")
