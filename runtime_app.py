"""WSGI runtime composition for the SentinelGRC modular monolith.

SQLite and a content-addressed filesystem support local lab runs. PostgreSQL,
verified OIDC, managed-identity evidence storage, and append-only audit export
support the staging path. Production remains fail closed until the external
retention policy and worker controls are validated.
"""

from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable
from urllib.parse import unquote, urlparse

from audit_archive import (
    AuditArchive,
    AzureBlobAuditArchive,
    LocalAuditArchive,
)
from evidence_store import (
    AzureBlobEvidenceStore,
    EvidenceStore,
    LocalEvidenceStore,
)
from governance_api import GovernanceApi
from governance_core import GovernanceCore
from governance_http import GovernanceHttpApplication, MAX_REQUEST_BODY_BYTES
from human_identity import HumanIdentityStore
from migration_runner import PostgresMigrationRunner
from oidc_contract import ROLE_MAP
from persistence import Database
from production_contract import Settings

if TYPE_CHECKING:
    from oidc_auth import EntraTokenVerifier


STATUS_TEXT = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    413: "Payload Too Large",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def sqlite_path(database_url: str) -> str:
    parsed = urlparse(database_url)
    if parsed.scheme != "sqlite":
        raise RuntimeError("sqlite_path accepts only SQLite URLs")
    if parsed.netloc not in {"", "localhost"}:
        raise ValueError("SQLite URL must not include a remote host")
    raw_path = unquote(parsed.path)
    if not raw_path or raw_path == "/":
        raise ValueError("SQLite URL must include a database path")
    if raw_path.startswith("//"):
        return raw_path[1:]
    return raw_path.lstrip("/")


class SentinelRuntime:
    def __init__(
        self,
        settings: Settings,
        oidc_verifier: EntraTokenVerifier | None = None,
        evidence_store: EvidenceStore | None = None,
        audit_archive: AuditArchive | None = None,
    ) -> None:
        errors = settings.validate()
        if errors:
            raise RuntimeError("invalid Sentinel configuration: " + "; ".join(errors))
        if settings.environment == "production":
            raise RuntimeError(
                "production startup is blocked until immutable-audit retention "
                "and worker delivery are validated in the target environment"
            )
        self.settings = settings
        self.governance_database = Database(settings.database_url)
        self.identity_database = (
            self.governance_database
            if settings.identity_database_url == settings.database_url
            else Database(settings.identity_database_url)
        )
        migrations = Path(__file__).parent / "migrations" / "postgresql"
        migrated: set[int] = set()
        for database in (
            self.governance_database,
            self.identity_database,
        ):
            if database.dialect == "postgresql" and id(database) not in migrated:
                PostgresMigrationRunner(database, str(migrations)).apply()
                migrated.add(id(database))
        self.governance_path = (
            self.governance_database.path
            or "postgresql"
        )
        self.identity_path = (
            self.identity_database.path
            or "postgresql"
        )
        if evidence_store is None:
            if settings.environment == "lab":
                evidence_store = LocalEvidenceStore(settings.evidence_dir)
            else:
                evidence_store = AzureBlobEvidenceStore(
                    settings.evidence_store_url,
                    managed_identity_client_id=(
                        settings.azure_managed_identity_client_id
                    ),
                )
        self.evidence_store = evidence_store
        if audit_archive is None:
            if settings.environment == "lab":
                audit_archive = LocalAuditArchive(settings.audit_dir)
            else:
                audit_archive = AzureBlobAuditArchive(
                    settings.audit_archive_url,
                    managed_identity_client_id=(
                        settings.azure_managed_identity_client_id
                    ),
                )
        self.audit_archive = audit_archive
        if settings.environment != "lab" and oidc_verifier is None:
            try:
                from oidc_auth import EntraTokenVerifier, OidcVerifierConfig
            except ModuleNotFoundError as error:
                raise RuntimeError(
                    "staging OIDC dependencies are not installed"
                ) from error
            oidc_verifier = EntraTokenVerifier(
                OidcVerifierConfig(
                    issuer=settings.oidc_issuer,
                    audience=settings.oidc_audience,
                    tenant_id=settings.oidc_tenant_id,
                    jwks_url=settings.oidc_jwks_url,
                    role_map=settings.oidc_role_map or dict(ROLE_MAP),
                    group_role_map=settings.oidc_group_role_map,
                )
            )
        self.oidc_verifier = oidc_verifier
        self.http = GovernanceHttpApplication(
            GovernanceApi(
                GovernanceCore(
                    database=self.governance_database,
                    evidence_store=self.evidence_store,
                ),
                HumanIdentityStore(database=self.identity_database),
            ),
            authentication_mode=(
                "api_key" if settings.environment == "lab" else "oidc"
            ),
            oidc_verifier=oidc_verifier,
        )

    def readiness(self) -> dict[str, Any]:
        checks: dict[str, bool] = {
            "configuration": not self.settings.validate(),
            "evidence_store": self.evidence_store.ready(),
            "audit_archive": self.audit_archive.ready(),
        }
        for name, database in (
            ("governance_store", self.governance_database),
            ("identity_store", self.identity_database),
        ):
            checks[name] = database.ping()
        if self.settings.environment != "lab":
            checks["identity_provider"] = bool(
                self.oidc_verifier and self.oidc_verifier.ready()
            )
        return {
            "status": "ready" if all(checks.values()) else "not_ready",
            "checks": checks,
        }


class SentinelWsgiApplication:
    def __init__(self, runtime: SentinelRuntime) -> None:
        self.runtime = runtime

    @staticmethod
    def _headers(environ: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                name = "-".join(part.title() for part in key[5:].split("_"))
                headers[name] = str(value)
        if environ.get("CONTENT_TYPE"):
            headers["Content-Type"] = str(environ["CONTENT_TYPE"])
        return headers

    def __call__(
        self,
        environ: dict[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], Any],
    ) -> Iterable[bytes]:
        request_id = str(environ.get("HTTP_X_REQUEST_ID") or uuid.uuid4().hex)
        try:
            raw_length = str(environ.get("CONTENT_LENGTH") or "0")
            content_length = int(raw_length)
            if content_length < 0:
                raise ValueError
            method = str(environ.get("REQUEST_METHOD", "GET"))
            path = str(environ.get("PATH_INFO", "/"))
            if content_length > MAX_REQUEST_BODY_BYTES:
                status, payload = 413, {"error": "request_too_large"}
            elif method.upper() == "GET" and path == "/ready":
                payload = self.runtime.readiness()
                status = 200 if payload["status"] == "ready" else 503
            else:
                body = environ["wsgi.input"].read(content_length)
                status, payload = self.runtime.http.handle(
                    method, path, self._headers(environ), body
                )
        except (KeyError, TypeError, ValueError):
            status, payload = 400, {"error": "invalid_request"}
        except Exception:
            status, payload = 500, {"error": "internal_error"}
        payload["request_id"] = request_id
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        start_response(
            f"{status} {STATUS_TEXT[status]}",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(encoded))),
                ("X-Request-ID", request_id),
                ("Cache-Control", "no-store"),
            ],
        )
        return [encoded]


def create_application(
    settings: Settings | None = None,
    oidc_verifier: EntraTokenVerifier | None = None,
    evidence_store: EvidenceStore | None = None,
    audit_archive: AuditArchive | None = None,
) -> SentinelWsgiApplication:
    return SentinelWsgiApplication(
        SentinelRuntime(
            settings or Settings.from_env(),
            oidc_verifier,
            evidence_store,
            audit_archive,
        )
    )


class LazyApplication:
    """Avoid import-time filesystem and configuration side effects."""

    def __init__(self) -> None:
        self._application: SentinelWsgiApplication | None = None
        self._lock = threading.Lock()

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        if self._application is None:
            with self._lock:
                if self._application is None:
                    self._application = create_application()
        return self._application(environ, start_response)


application = LazyApplication()
