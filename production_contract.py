"""Production configuration and readiness contract.

The lab can run on SQLite/loopback. Production mode is explicit and fails
closed unless the required external controls are configured.
"""

from __future__ import annotations

import os
import json
import sqlite3
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _read_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _read_mapping(name: str) -> dict[str, str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return {}
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or len(value) > 100
        or not all(isinstance(key, str) and isinstance(role, str) for key, role in value.items())
    ):
        raise ValueError(f"{name} must be a string-to-string JSON object")
    return value


def _read_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    try:
        value = default if raw is None else int(raw.strip())
    except (AttributeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    environment: str = "lab"
    database_url: str = "sqlite:///runtime/governance.db"
    identity_database_url: str = "sqlite:///runtime/identity.db"
    evidence_dir: str = "runtime/evidence"
    audit_dir: str = "runtime/audit-archive"
    outbox_dir: str = "runtime/outbox"
    evidence_store_url: str = ""
    audit_archive_url: str = ""
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_tenant_id: str = ""
    oidc_jwks_url: str = ""
    oidc_role_map: dict[str, str] = field(default_factory=dict)
    oidc_group_role_map: dict[str, str] = field(default_factory=dict)
    azure_managed_identity_client_id: str = ""
    service_bus_namespace: str = ""
    service_bus_queue: str = ""
    outbox_worker_max_age_seconds: int = 120
    outbox_delivery_lag_max_seconds: int = 300
    require_tls: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            environment=os.getenv("SENTINEL_ENV", "lab").strip().lower(),
            database_url=os.getenv(
                "SENTINEL_DATABASE_URL", cls.database_url
            ).strip(),
            identity_database_url=os.getenv(
                "SENTINEL_IDENTITY_DATABASE_URL", cls.identity_database_url
            ).strip(),
            evidence_dir=os.getenv(
                "SENTINEL_EVIDENCE_DIR", cls.evidence_dir
            ).strip(),
            audit_dir=os.getenv(
                "SENTINEL_AUDIT_DIR", cls.audit_dir
            ).strip(),
            outbox_dir=os.getenv(
                "SENTINEL_OUTBOX_DIR", cls.outbox_dir
            ).strip(),
            evidence_store_url=os.getenv(
                "SENTINEL_EVIDENCE_STORE_URL", ""
            ).strip(),
            audit_archive_url=os.getenv(
                "SENTINEL_AUDIT_ARCHIVE_URL", ""
            ).strip(),
            oidc_issuer=os.getenv("SENTINEL_OIDC_ISSUER", "").strip(),
            oidc_audience=os.getenv("SENTINEL_OIDC_AUDIENCE", "").strip(),
            oidc_tenant_id=os.getenv("SENTINEL_OIDC_TENANT_ID", "").strip(),
            oidc_jwks_url=os.getenv("SENTINEL_OIDC_JWKS_URL", "").strip(),
            oidc_role_map=_read_mapping("SENTINEL_OIDC_ROLE_MAP"),
            oidc_group_role_map=_read_mapping("SENTINEL_OIDC_GROUP_ROLE_MAP"),
            azure_managed_identity_client_id=os.getenv(
                "SENTINEL_AZURE_CLIENT_ID", ""
            ).strip(),
            service_bus_namespace=os.getenv(
                "SENTINEL_SERVICE_BUS_NAMESPACE", ""
            ).strip(),
            service_bus_queue=os.getenv(
                "SENTINEL_SERVICE_BUS_QUEUE", ""
            ).strip(),
            outbox_worker_max_age_seconds=_read_int(
                "SENTINEL_OUTBOX_WORKER_MAX_AGE_SECONDS", 120, 10, 900
            ),
            outbox_delivery_lag_max_seconds=_read_int(
                "SENTINEL_OUTBOX_DELIVERY_LAG_MAX_SECONDS", 300, 30, 86_400
            ),
            require_tls=_read_bool("SENTINEL_REQUIRE_TLS"),
        )

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.environment not in {"lab", "staging", "production"}:
            errors.append("SENTINEL_ENV must be lab, staging, or production")
        if not self.database_url:
            errors.append("SENTINEL_DATABASE_URL is required")
        if not self.identity_database_url:
            errors.append("SENTINEL_IDENTITY_DATABASE_URL is required")
        if not self.evidence_dir:
            errors.append("SENTINEL_EVIDENCE_DIR is required")
        if not self.audit_dir:
            errors.append("SENTINEL_AUDIT_DIR is required")
        if not self.outbox_dir:
            errors.append("SENTINEL_OUTBOX_DIR is required")
        if self.environment in {"staging", "production"}:
            if not self.oidc_issuer:
                errors.append(f"{self.environment} requires SENTINEL_OIDC_ISSUER")
            if not self.oidc_audience:
                errors.append(f"{self.environment} requires SENTINEL_OIDC_AUDIENCE")
            if not self.oidc_tenant_id:
                errors.append(f"{self.environment} requires SENTINEL_OIDC_TENANT_ID")
            if not self.oidc_jwks_url:
                errors.append(f"{self.environment} requires SENTINEL_OIDC_JWKS_URL")
            if not self.evidence_store_url:
                errors.append(
                    f"{self.environment} requires SENTINEL_EVIDENCE_STORE_URL"
                )
            if not self.audit_archive_url:
                errors.append(
                    f"{self.environment} requires SENTINEL_AUDIT_ARCHIVE_URL"
                )
            if not self.azure_managed_identity_client_id:
                errors.append(
                    f"{self.environment} requires SENTINEL_AZURE_CLIENT_ID"
                )
            if re.fullmatch(
                r"[a-z0-9][a-z0-9-]{4,48}[a-z0-9]\.servicebus\.windows\.net",
                self.service_bus_namespace,
            ) is None:
                errors.append(
                    f"{self.environment} requires a valid "
                    "SENTINEL_SERVICE_BUS_NAMESPACE"
                )
            if (
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,259}", self.service_bus_queue)
                is None
                or "//" in self.service_bus_queue
            ):
                errors.append(
                    f"{self.environment} requires a valid SENTINEL_SERVICE_BUS_QUEUE"
                )
        if self.environment == "production":
            if not self.database_url.startswith(("postgresql://", "postgresql+psycopg://")):
                errors.append("production requires PostgreSQL")
            if not self.identity_database_url.startswith(
                ("postgresql://", "postgresql+psycopg://")
            ):
                errors.append("production identity storage requires PostgreSQL")
            if not self.require_tls:
                errors.append("production requires SENTINEL_REQUIRE_TLS=true")
        return errors

    def validate_outbox_worker(self) -> list[str]:
        errors: list[str] = []
        if self.environment not in {"lab", "staging", "production"}:
            errors.append("SENTINEL_ENV must be lab, staging, or production")
        if not self.database_url:
            errors.append("SENTINEL_DATABASE_URL is required")
        if not self.outbox_dir:
            errors.append("SENTINEL_OUTBOX_DIR is required")
        if self.environment in {"staging", "production"}:
            if not self.database_url.startswith(
                ("postgresql://", "postgresql+psycopg://")
            ):
                errors.append(f"{self.environment} outbox requires PostgreSQL")
            if not self.azure_managed_identity_client_id:
                errors.append(
                    f"{self.environment} requires SENTINEL_AZURE_CLIENT_ID"
                )
            if re.fullmatch(
                r"[a-z0-9][a-z0-9-]{4,48}[a-z0-9]\.servicebus\.windows\.net",
                self.service_bus_namespace,
            ) is None:
                errors.append(
                    f"{self.environment} requires a valid "
                    "SENTINEL_SERVICE_BUS_NAMESPACE"
                )
            if (
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,259}", self.service_bus_queue)
                is None
                or "//" in self.service_bus_queue
            ):
                errors.append(
                    f"{self.environment} requires a valid SENTINEL_SERVICE_BUS_QUEUE"
                )
        return errors


def readiness(settings: Settings, state_db: str | None = None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    errors = settings.validate()
    checks["configuration"] = not errors
    evidence = Path(settings.evidence_dir)
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
