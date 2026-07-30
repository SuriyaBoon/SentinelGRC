"""Phase 1 human identity and API-key boundary.

Secrets are returned only at issuance and only a SHA-256 digest is persisted.
The authenticated actor is resolved by the server, not supplied by request data.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from contextlib import closing

from governance_core import ActorContext, ROLES
from persistence import Database, DatabaseConnection, DatabaseIntegrityError


class AuthenticationError(PermissionError):
    """Raised only when a supplied credential cannot be authenticated."""


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class HumanIdentityStore:
    def __init__(
        self,
        path: str = "runtime/identity.db",
        *,
        database: Database | None = None,
    ) -> None:
        self.database = database or Database.from_target(path)
        self.path = self.database.path or "postgresql"
        if self.database.dialect != "sqlite":
            return
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

    def _connect(self) -> DatabaseConnection:
        return self.database.connect()

    @staticmethod
    def _hash(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    def create_user(self, user_id: str, role: str) -> None:
        if not _IDENTIFIER_RE.fullmatch(user_id) or role not in ROLES:
            raise ValueError("user_id and supported role are required")
        with closing(self._connect()) as db:
            try:
                db.execute("INSERT INTO users(user_id, role) VALUES (?, ?)", (user_id, role))
            except DatabaseIntegrityError as error:
                raise ValueError("user already exists") from error
            db.commit()

    def issue_api_key(self, user_id: str, key_id: str) -> str:
        if not _IDENTIFIER_RE.fullmatch(key_id):
            raise ValueError("key_id must contain only letters, numbers, dot, underscore or hyphen")
        secret = secrets.token_urlsafe(32)
        with closing(self._connect()) as db:
            user = db.execute(
                "SELECT active AS active FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            if user is None or not user["active"]:
                raise ValueError("active user is required")
            try:
                db.execute(
                    "INSERT INTO user_api_keys(key_id, user_id, secret_hash) VALUES (?, ?, ?)",
                    (key_id, user_id, self._hash(secret)),
                )
            except DatabaseIntegrityError as error:
                raise ValueError("key already exists") from error
            db.commit()
        return secret

    def revoke_key(self, key_id: str) -> None:
        with closing(self._connect()) as db:
            db.execute(
                "UPDATE user_api_keys SET active = FALSE WHERE key_id = ?",
                (key_id,),
            )
            db.commit()

    def authenticate(self, key_id: str, secret: str) -> ActorContext:
        with closing(self._connect()) as db:
            row = db.execute("""
                SELECT u.user_id AS user_id, u.role AS role,
                       k.secret_hash AS secret_hash
                FROM user_api_keys k JOIN users u ON u.user_id = k.user_id
                WHERE k.key_id = ? AND k.active = TRUE AND u.active = TRUE
            """, (key_id,)).fetchone()
        if row is None or not hmac.compare_digest(
            row["secret_hash"], self._hash(secret)
        ):
            raise AuthenticationError("invalid or revoked human API key")
        return ActorContext(
            row["user_id"], row["role"], auth_method="api_key"
        )
