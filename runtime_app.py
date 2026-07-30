"""WSGI runtime composition for the SentinelGRC modular monolith.

The current runtime deliberately supports SQLite only for lab and staging.
Production configuration fails closed until the PostgreSQL, OIDC middleware,
object-storage, and immutable-audit adapters are implemented.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import unquote, urlparse

from governance_api import GovernanceApi
from governance_core import GovernanceCore
from governance_http import GovernanceHttpApplication, MAX_REQUEST_BODY_BYTES
from human_identity import HumanIdentityStore
from production_contract import Settings


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
        raise RuntimeError(
            "this runtime supports SQLite only; PostgreSQL adapter is not implemented"
        )
    if parsed.netloc not in {"", "localhost"}:
        raise ValueError("SQLite URL must not include a remote host")
    raw_path = unquote(parsed.path)
    if not raw_path or raw_path == "/":
        raise ValueError("SQLite URL must include a database path")
    if raw_path.startswith("//"):
        return raw_path[1:]
    return raw_path.lstrip("/")


class SentinelRuntime:
    def __init__(self, settings: Settings) -> None:
        errors = settings.validate()
        if errors:
            raise RuntimeError("invalid Sentinel configuration: " + "; ".join(errors))
        if settings.environment == "production":
            raise RuntimeError(
                "production startup is blocked until PostgreSQL, verified OIDC, "
                "object-storage, and immutable-audit adapters are implemented"
            )
        self.settings = settings
        self.governance_path = sqlite_path(settings.database_url)
        self.identity_path = sqlite_path(settings.identity_database_url)
        Path(settings.evidence_dir).mkdir(parents=True, exist_ok=True)
        self.http = GovernanceHttpApplication(
            GovernanceApi(
                GovernanceCore(self.governance_path),
                HumanIdentityStore(self.identity_path),
            )
        )

    def readiness(self) -> dict[str, Any]:
        checks: dict[str, bool] = {
            "configuration": not self.settings.validate(),
            "evidence_directory": Path(self.settings.evidence_dir).is_dir(),
        }
        for name, path in (
            ("governance_store", self.governance_path),
            ("identity_store", self.identity_path),
        ):
            try:
                with closing(sqlite3.connect(path, timeout=2)) as db:
                    db.execute("SELECT 1").fetchone()
                checks[name] = True
            except (OSError, sqlite3.Error):
                checks[name] = False
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


def create_application(settings: Settings | None = None) -> SentinelWsgiApplication:
    return SentinelWsgiApplication(SentinelRuntime(settings or Settings.from_env()))


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
