"""Production deployment readiness contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DeploymentRequirements:
    database_url: str
    queue_url: str
    secret_manager: str
    audit_archive_url: str
    backup_target: str
    metrics_endpoint: str
    tls_enabled: bool
    oidc_issuer: str

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.database_url.startswith("postgresql://"):
            errors.append("PostgreSQL database URL is required")
        if not self.queue_url:
            errors.append("durable queue URL is required")
        if not self.secret_manager:
            errors.append("secret manager reference is required")
        if not self.audit_archive_url:
            errors.append("immutable audit archive is required")
        if not self.backup_target:
            errors.append("backup target is required")
        if not self.metrics_endpoint:
            errors.append("metrics endpoint is required")
        if not self.tls_enabled:
            errors.append("TLS must be enabled")
        if not self.oidc_issuer:
            errors.append("OIDC issuer is required")
        return errors


def readiness(requirements: DeploymentRequirements) -> dict[str, Any]:
    errors = requirements.validate()
    return {"status": "ready" if not errors else "not_ready", "errors": errors}
