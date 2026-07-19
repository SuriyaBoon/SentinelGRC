"""Production configuration and readiness contract.

The lab can run on SQLite/loopback. Production mode is explicit and fails
closed unless the required external controls are configured.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Settings:
    environment: str = "lab"
    database_url: str = "sqlite:///runtime/sentinelgrc-state.db"
    evidence_dir: str = "runtime/evidence"
    audit_archive_url: str = ""
    oidc_issuer: str = ""
    require_tls: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            environment=os.getenv("SENTINEL_ENV", "lab").lower(),
            database_url=os.getenv("SENTINEL_DATABASE_URL", cls.database_url),
            evidence_dir=os.getenv("SENTINEL_EVIDENCE_DIR", cls.evidence_dir),
            audit_archive_url=os.getenv("SENTINEL_AUDIT_ARCHIVE_URL", ""),
            oidc_issuer=os.getenv("SENTINEL_OIDC_ISSUER", ""),
            require_tls=os.getenv("SENTINEL_REQUIRE_TLS", "false").lower() in {"1", "true", "yes"},
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.environment not in {"lab", "staging", "production"}:
            errors.append("SENTINEL_ENV must be lab, staging, or production")
        if self.environment == "production":
            if self.database_url.startswith("sqlite:"):
                errors.append("production requires PostgreSQL or another shared transactional database")
            if not self.oidc_issuer:
                errors.append("production requires SENTINEL_OIDC_ISSUER")
            if not self.audit_archive_url:
                errors.append("production requires SENTINEL_AUDIT_ARCHIVE_URL")
            if not self.require_tls:
                errors.append("production requires SENTINEL_REQUIRE_TLS=true")
        return errors


def readiness(settings: Settings, state_db: str | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    errors = settings.validate()
    evidence = Path(settings.evidence_dir)
    checks["configuration"] = not errors
    checks["evidence_directory"] = evidence.exists() and evidence.is_dir()
    if state_db:
        try:
            with sqlite3.connect(state_db) as db:
                db.execute("SELECT 1").fetchone()
            checks["state_store"] = True
        except sqlite3.Error:
            checks["state_store"] = False
    else:
        checks["state_store"] = True
    return {
        "status": "ready" if all(checks.values()) else "not_ready",
        "checks": checks,
        "errors": errors,
    }
