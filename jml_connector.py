"""Normalize closed JML-Automation requests into SentinelGRC findings.

This module deliberately uses only rows read from JML's SQLite database. It
does not import JML code, so the two portfolio repositories remain loosely
coupled across the connector boundary.
"""

from __future__ import annotations

import re
from typing import Any

from contract_validation import is_canonical_text

_CONTROL_BY_REQUEST_TYPE = {
    "joiner": "SEC-IAM-004",
    "mover": "SEC-IAM-005",
    "leaver": "SEC-IAM-006",
}
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", re.ASCII)
_USERNAME = re.compile(r"[A-Za-z0-9._-]{1,64}", re.ASCII)
_JML_REQUEST = "JML request"


def _text(record: dict[str, Any], name: str, maximum: int, label: str) -> str:
    value = record.get(name)
    if not is_canonical_text(value, maximum):
        raise ValueError(f"{label} {name} is invalid")
    return value


def normalize_jml_request(
    request: dict[str, Any],
    verification: dict[str, Any] | None,
    execution_actor_id: str | None,
) -> dict[str, Any] | None:
    """Return a governed finding only for a closed, independently verified request."""
    if not isinstance(request, dict):
        raise ValueError("JML request must be an object")
    if request.get("status") != "closed":
        return None
    if not isinstance(verification, dict) or verification.get("result") != "passed":
        return None

    request_type = _text(request, "request_type", 16, _JML_REQUEST)
    if request_type not in _CONTROL_BY_REQUEST_TYPE:
        raise ValueError(f"unsupported JML request_type: {request_type!r}")
    request_id = _text(request, "request_id", 64, _JML_REQUEST)
    if _REQUEST_ID.fullmatch(request_id) is None:
        raise ValueError("JML request request_id is invalid")
    username = _text(request, "username", 64, _JML_REQUEST)
    if _USERNAME.fullmatch(username) is None:
        raise ValueError("JML request username is invalid")
    department = _text(request, "department", 128, _JML_REQUEST)
    manager_id = _text(request, "manager_id", 128, _JML_REQUEST)
    employee_id = _text(request, "employee_id", 128, _JML_REQUEST)
    requested_by = _text(request, "requested_by", 128, _JML_REQUEST)

    if verification.get("request_id") != request_id:
        raise ValueError("JML verification does not belong to the request")
    verifier_id = _text(verification, "actor_id", 128, "JML verification")
    if execution_actor_id is None:
        return None
    if not is_canonical_text(execution_actor_id, 128):
        raise ValueError("JML execution actor_id is invalid")
    if verifier_id in {requested_by, execution_actor_id}:
        return None

    old_department = request.get("old_department")
    if request_type == "mover" and not is_canonical_text(old_department, 128):
        raise ValueError("JML request old_department is invalid")
    title_by_type = {
        "joiner": f"Access provisioned for new hire {username} ({department})",
        "mover": f"Access changed for {username}: {old_department} -> {department}",
        "leaver": f"Access removed for departing employee {username} ({department})",
    }

    return {
        "finding_id": "SEC-IAM-" + request_id.removeprefix("JML-"),
        "source": "jml_automation",
        "control_id": _CONTROL_BY_REQUEST_TYPE[request_type],
        "asset_id": f"AD:{username}",
        "title": title_by_type[request_type],
        "risk_owner": manager_id,
        "severity": "high" if request_type == "leaver" else "medium",
        "details": {
            "request_type": request_type,
            "jml_request_id": request_id,
            "employee_id": employee_id,
            "department": department,
            "verification_result": verification["result"],
            "verifier_id": verifier_id,
            "execution_actor_id": execution_actor_id,
            "simulated": True,
        },
    }
