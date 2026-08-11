"""Map cryptographically verified OIDC claims to Sentinel actors."""

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


def _validate_trust_claims(
    claims: dict[str, Any],
    issuer: str,
    audience: str,
    tenant_id: str | None,
) -> None:
    if claims.get("iss") != issuer:
        raise PermissionError("invalid OIDC issuer")
    token_audience = claims.get("aud")
    audiences = token_audience if isinstance(token_audience, list) else [token_audience]
    if audience not in audiences:
        raise PermissionError("invalid OIDC audience")
    if tenant_id is not None and claims.get("tid") != tenant_id:
        raise PermissionError("invalid OIDC tenant")


def _validate_token_lifetime(
    claims: dict[str, Any],
    current: int,
    clock_skew_seconds: int,
) -> None:
    if int(claims.get("nbf", 0)) > current + clock_skew_seconds:
        raise PermissionError("OIDC token is not active")
    if (
        not claims.get("sub")
        or int(claims.get("exp", 0)) <= current - clock_skew_seconds
    ):
        raise PermissionError("expired or incomplete OIDC claims")


def _authorization_values(
    claims: dict[str, Any],
    configured_groups: dict[str, str],
) -> tuple[list[Any], list[Any]]:
    roles = claims.get("roles") or []
    groups = claims.get("groups") or []
    if not isinstance(roles, list) or not isinstance(groups, list):
        raise PermissionError("invalid OIDC authorization claims")
    if configured_groups and (claims.get("hasgroups") or "_claim_names" in claims):
        raise PermissionError("OIDC group overage is not supported")
    return roles, groups


def _mapped_role(
    roles: list[Any],
    groups: list[Any],
    configured_roles: dict[str, str],
    configured_groups: dict[str, str],
) -> str:
    mapped_roles = {
        mapping[value]
        for values, mapping in (
            (roles, configured_roles),
            (groups, configured_groups),
        )
        for value in values
        if isinstance(value, str) and value in mapping
    }
    if len(mapped_roles) != 1:
        raise PermissionError("OIDC identity must map to exactly one Sentinel role")
    mapped = mapped_roles.pop()
    if mapped not in ROLES:
        raise PermissionError("OIDC role mapping is invalid")
    return mapped


def actor_from_claims(
    claims: dict[str, Any],
    *,
    issuer: str,
    audience: str,
    tenant_id: str | None = None,
    role_map: dict[str, str] | None = None,
    group_role_map: dict[str, str] | None = None,
    now: int | None = None,
    clock_skew_seconds: int = 0,
) -> ActorContext:
    current = int(time.time()) if now is None else now
    _validate_trust_claims(claims, issuer, audience, tenant_id)
    _validate_token_lifetime(claims, current, clock_skew_seconds)
    configured_roles = ROLE_MAP if role_map is None else role_map
    configured_groups = {} if group_role_map is None else group_role_map
    roles, groups = _authorization_values(claims, configured_groups)
    mapped = _mapped_role(roles, groups, configured_roles, configured_groups)
    return ActorContext(str(claims["sub"]), mapped, auth_method="oidc")
