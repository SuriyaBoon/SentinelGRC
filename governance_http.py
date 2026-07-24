"""Minimal HTTP application adapter for GovernanceApi.

The application is transport-safe and can be mounted behind a real WSGI/ASGI
server, WAF, TLS termination and rate limiter in production.
"""

from __future__ import annotations

import json
from typing import Any

from governance_api import GovernanceApi
from human_identity import AuthenticationError


MAX_REQUEST_BODY_BYTES = 256 * 1024


class GovernanceHttpApplication:
    def __init__(self, api: GovernanceApi) -> None:
        self.api = api

    def handle(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        if not isinstance(method, str) or not isinstance(path, str):
            return 400, {"error": "invalid_request"}
        if not isinstance(headers, dict) or not isinstance(body, bytes):
            return 400, {"error": "invalid_request"}
        if len(body) > MAX_REQUEST_BODY_BYTES:
            return 413, {"error": "request_too_large"}
        method = method.upper()
        if method == "GET" and path in {"/health", "/healthz"}:
            return 200, {"status": "ok"}
        if method == "GET" and path == "/ready":
            try:
                self.api.core.export_summary()
                return 200, {"status": "ready"}
            except Exception:
                return 503, {"status": "not_ready"}
        known_get = path == "/findings" or path.startswith("/findings/")
        known_post = path.startswith("/v1/governance/") or path.startswith("/findings/")
        if (method == "GET" and not known_get) or (method == "POST" and not known_post):
            return 404, {"error": "not_found"}
        authorization = headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return 401, {"error": "missing_bearer_token"}
        key_id = headers.get("X-API-Key-ID", "")
        secret = authorization[7:]
        payload: dict[str, Any] = {}
        action = ""
        if method == "GET" and path == "/findings":
            action = "list"
        elif method == "GET" and path.startswith("/findings/"):
            action = "get"
            payload["finding_id"] = path.removeprefix("/findings/").strip("/")
        elif method == "POST" and path.startswith("/v1/governance/"):
            action = path.removeprefix("/v1/governance/").strip("/")
        elif method == "POST" and path.startswith("/findings/"):
            parts = path.strip("/").split("/")
            if len(parts) != 3:
                return 404, {"error": "not_found"}
            payload["finding_id"], action = parts[1], parts[2]
        else:
            return 404, {"error": "not_found"}
        try:
            if method == "POST":
                parsed = json.loads(body.decode("utf-8"))
                if not isinstance(parsed, dict):
                    return 400, {"error": "request body must be an object"}
                payload.update(parsed)
            result = self.api.dispatch(action, key_id, secret, payload)
            return 200, result
        except AuthenticationError as error:
            return 401, {"error": str(error)}
        except PermissionError as error:
            return 403, {"error": str(error)}
        except (ValueError, KeyError) as error:
            status = 400
            return status, {"error": str(error)}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return 400, {"error": "invalid_json"}
