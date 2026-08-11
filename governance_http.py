"""Minimal HTTP application adapter for GovernanceApi.

The application is transport-safe and can be mounted behind a real WSGI/ASGI
server, WAF, TLS termination and rate limiter in production.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from governance_api import GovernanceApi
from governance_core import ActorContext
from human_identity import AuthenticationError


MAX_REQUEST_BODY_BYTES = 256 * 1024
FINDING_PATH_PREFIX = "/findings/"
GOVERNANCE_API_PREFIX = "/v1/governance/"


class OidcVerifier(Protocol):
    def verify(self, token: str) -> ActorContext: ...


class GovernanceHttpApplication:
    def __init__(
        self,
        api: GovernanceApi,
        *,
        authentication_mode: str = "api_key",
        oidc_verifier: OidcVerifier | None = None,
    ) -> None:
        if authentication_mode not in {"api_key", "oidc"}:
            raise ValueError("unsupported authentication mode")
        if authentication_mode == "oidc" and oidc_verifier is None:
            raise ValueError("OIDC verifier is required")
        self.api = api
        self.authentication_mode = authentication_mode
        self.oidc_verifier = oidc_verifier

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
        known_get = path == "/findings" or path.startswith(FINDING_PATH_PREFIX)
        known_post = path.startswith(GOVERNANCE_API_PREFIX) or path.startswith(
            FINDING_PATH_PREFIX
        )
        if (method == "GET" and not known_get) or (method == "POST" and not known_post):
            return 404, {"error": "not_found"}
        normalized_headers = {
            str(name).strip().lower(): str(value) for name, value in headers.items()
        }
        authorization = normalized_headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            return 401, {"error": "missing_bearer_token"}
        bearer = authorization[7:]
        payload: dict[str, Any] = {}
        action = ""
        if method == "GET" and path == "/findings":
            action = "list"
        elif method == "GET" and path.startswith(FINDING_PATH_PREFIX):
            action = "get"
            payload["finding_id"] = path.removeprefix(FINDING_PATH_PREFIX).strip("/")
        elif method == "POST" and path.startswith(GOVERNANCE_API_PREFIX):
            action = path.removeprefix(GOVERNANCE_API_PREFIX).strip("/")
        elif method == "POST" and path.startswith(FINDING_PATH_PREFIX):
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
            if self.authentication_mode == "oidc":
                actor = self.oidc_verifier.verify(bearer)  # type: ignore[union-attr]
                result = self.api.dispatch_actor(action, actor, payload)
            else:
                key_id = normalized_headers.get("x-api-key-id", "")
                result = self.api.dispatch(action, key_id, bearer, payload)
            return 200, result
        except AuthenticationError as error:
            return 401, {"error": str(error)}
        except PermissionError as error:
            return 403, {"error": str(error)}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return 400, {"error": "invalid_json"}
        except (ValueError, KeyError) as error:
            return 400, {"error": str(error)}
