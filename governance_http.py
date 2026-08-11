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


HttpResponse = tuple[int, dict[str, Any]]


def _request_error(
    method: Any,
    path: Any,
    headers: Any,
    body: Any,
) -> HttpResponse | None:
    if not isinstance(method, str) or not isinstance(path, str):
        return 400, {"error": "invalid_request"}
    if not isinstance(headers, dict) or not isinstance(body, bytes):
        return 400, {"error": "invalid_request"}
    if len(body) > MAX_REQUEST_BODY_BYTES:
        return 413, {"error": "request_too_large"}
    return None


def _reject_unknown_route(method: str, path: str) -> bool:
    known_get = path == "/findings" or path.startswith(FINDING_PATH_PREFIX)
    known_post = path.startswith((GOVERNANCE_API_PREFIX, FINDING_PATH_PREFIX))
    return (method == "GET" and not known_get) or (
        method == "POST" and not known_post
    )


def _resolve_route(
    method: str,
    path: str,
) -> tuple[str, dict[str, Any]] | None:
    if method == "GET" and path == "/findings":
        return "list", {}
    if method == "GET" and path.startswith(FINDING_PATH_PREFIX):
        finding_id = path.removeprefix(FINDING_PATH_PREFIX).strip("/")
        return "get", {"finding_id": finding_id}
    if method == "POST" and path.startswith(GOVERNANCE_API_PREFIX):
        return path.removeprefix(GOVERNANCE_API_PREFIX).strip("/"), {}
    if method == "POST" and path.startswith(FINDING_PATH_PREFIX):
        parts = path.strip("/").split("/")
        if len(parts) == 3:
            return parts[2], {"finding_id": parts[1]}
    return None


def _decode_body(body: bytes) -> dict[str, Any]:
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("request body must be an object")
    return parsed


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

    def _public_response(self, method: str, path: str) -> HttpResponse | None:
        if method == "GET" and path in {"/health", "/healthz"}:
            return 200, {"status": "ok"}
        if method != "GET" or path != "/ready":
            return None
        try:
            self.api.core.export_summary()
            return 200, {"status": "ready"}
        except Exception:
            return 503, {"status": "not_ready"}

    def _dispatch(
        self,
        action: str,
        bearer: str,
        headers: dict[str, str],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if self.authentication_mode == "oidc":
            actor = self.oidc_verifier.verify(bearer)  # type: ignore[union-attr]
            return self.api.dispatch_actor(action, actor, payload)
        key_id = headers.get("x-api-key-id", "")
        return self.api.dispatch(action, key_id, bearer, payload)

    def handle(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> HttpResponse:
        request_error = _request_error(method, path, headers, body)
        if request_error is not None:
            return request_error
        method = method.upper()
        public_response = self._public_response(method, path)
        if public_response is not None:
            return public_response
        if _reject_unknown_route(method, path):
            return 404, {"error": "not_found"}
        normalized_headers = {
            str(name).strip().lower(): str(value) for name, value in headers.items()
        }
        authorization = normalized_headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            return 401, {"error": "missing_bearer_token"}
        bearer = authorization[7:]
        route = _resolve_route(method, path)
        if route is None:
            return 404, {"error": "not_found"}
        action, payload = route
        try:
            if method == "POST":
                payload.update(_decode_body(body))
            result = self._dispatch(action, bearer, normalized_headers, payload)
            return 200, result
        except AuthenticationError as error:
            return 401, {"error": str(error)}
        except PermissionError as error:
            return 403, {"error": str(error)}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return 400, {"error": "invalid_json"}
        except (ValueError, KeyError) as error:
            return 400, {"error": str(error)}
