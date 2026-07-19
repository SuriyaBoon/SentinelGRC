"""Minimal HTTP application adapter for GovernanceApi.

The application is transport-safe and can be mounted behind a real WSGI/ASGI
server, WAF, TLS termination and rate limiter in production.
"""

from __future__ import annotations

import json
from typing import Any

from governance_api import GovernanceApi


class GovernanceHttpApplication:
    def __init__(self, api: GovernanceApi) -> None:
        self.api = api

    def handle(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        if method.upper() == "GET" and path == "/healthz":
            return 200, {"status": "ok"}
        if method.upper() != "POST" or not path.startswith("/v1/governance/"):
            return 404, {"error": "not_found"}
        action = path.removeprefix("/v1/governance/").strip("/")
        key_id = headers.get("X-API-Key-ID", "")
        authorization = headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return 401, {"error": "missing_bearer_token"}
        try:
            payload = json.loads(body.decode("utf-8"))
            result = self.api.dispatch(action, key_id, authorization[7:], payload)
            return 200, result
        except (PermissionError, ValueError, KeyError) as error:
            status = 401 if isinstance(error, PermissionError) else 400
            return status, {"error": str(error)}
        except json.JSONDecodeError:
            return 400, {"error": "invalid_json"}
