"""Reusable domain-pack contracts for the Sentinel Enterprise Trust Platform.

Each domain pack emits the same finding shape so the GovernanceCore workflow
does not need separate approval or evidence logic per domain.
"""

from __future__ import annotations

import hashlib
from typing import Any

PACKS = {
    "privacy": ("PRIVACY", "data_owner"),
    "bcm": ("BCM", "service_owner"),
    "itsm": ("ITSM", "service_owner"),
    "vendor": ("VENDOR", "vendor_owner"),
    "cloud": ("CLOUD", "cloud_owner"),
    "data": ("DATA", "data_owner"),
}


def _stable_id(pack: str, observation: dict[str, Any]) -> str:
    identity = "|".join([
        pack,
        str(observation.get("asset_id", "")),
        str(observation.get("control_id", "")),
        str(observation.get("observation_id", "")),
    ])
    return f"{PACKS[pack][0]}-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper()


def normalize_observation(pack: str, observation: dict[str, Any]) -> dict[str, Any] | None:
    """Return a shared finding or None for resolved observations."""
    if pack not in PACKS:
        raise ValueError(f"unsupported domain pack: {pack}")
    if observation.get("status") in {"closed", "resolved", "passed"}:
        return None
    required = ("observation_id", "control_id", "asset_id", "title", "severity")
    missing = [field for field in required if not str(observation.get(field, "")).strip()]
    if missing:
        raise ValueError(f"{pack} observation missing: {', '.join(missing)}")
    owner_field = PACKS[pack][1]
    owner = str(observation.get("owner") or observation.get(owner_field) or "").strip()
    if not owner:
        raise ValueError(f"{pack} observation requires {owner_field}")
    return {
        "finding_id": _stable_id(pack, observation),
        "domain": pack,
        "source": f"{pack}_pack",
        "control_id": str(observation["control_id"]),
        "asset_id": str(observation["asset_id"]),
        "title": str(observation["title"]),
        "risk_owner": owner,
        "severity": str(observation["severity"]).lower(),
        "details": {
            key: value for key, value in observation.items()
            if key not in {"observation_id", "control_id", "asset_id", "title", "severity", "owner"}
        },
    }


def build_domain_findings(pack: str, observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        finding for observation in observations
        if (finding := normalize_observation(pack, observation)) is not None
    ]
