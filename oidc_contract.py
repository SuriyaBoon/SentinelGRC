"""OIDC/SSO claims validation contract.

Signature verification and token retrieval belong to the configured identity
provider middleware. This module validates the already verified claims and
maps them to Sentinel roles.
"""

from __future__ import annotations

import time
from typing import Any

from governance_core import ActorContext, ROLES

ROLE_MAP = {
    "sentinel-admin": "admin",
    "sentinel-analyst": "analyst",
    "sentinel-risk-owner": "risk_owner",
    "sentinel-approver": "approver",
    "sentinel-ciso": "ciso",
    "sentinel-risk-committee": "risk_committee",
}


def actor_from_claims(
    claims: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    now: int | None = None,
) -> ActorContext:
    current = int(time.time()) if now is None else now
    if claims.get("iss") != issuer:
        raise PermissionError("invalid OIDC issuer")
    token_audience = claims.get("aud")
    audiences = token_audience if isinstance(token_audience, list) else [token_audience]
    if audience not in audiences:
        raise PermissionError("invalid OIDC audience")
    if not claims.get("sub") or int(claims.get("exp", 0)) <= current:
        raise PermissionError("expired or incomplete OIDC claims")
    roles = claims.get("roles") or []
    mapped = next((ROLE_MAP[role] for role in roles if role in ROLE_MAP), None)
    if mapped not in ROLES:
        raise PermissionError("OIDC user has no Sentinel role")
    return ActorContext(str(claims["sub"]), mapped, auth_method="oidc")
