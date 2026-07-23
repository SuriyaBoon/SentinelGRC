"""Normalize closed JML-Automation requests into SentinelGRC findings.

This module deliberately uses only rows read from JML's SQLite database. It
does not import JML code, so the two portfolio repositories remain loosely
coupled across the connector boundary.
"""

from __future__ import annotations

from typing import Any

_CONTROL_BY_REQUEST_TYPE = {
    "joiner": "SEC-IAM-004",
    "mover": "SEC-IAM-005",
    "leaver": "SEC-IAM-006",
}


def normalize_jml_request(
    request: dict[str, Any], verification: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Return a governed finding only for a closed, independently verified request."""
    if request.get("status") != "closed":
        return None
    if verification is None or verification.get("result") != "passed":
        return None

    request_type = str(request.get("request_type", "")).strip()
    if request_type not in _CONTROL_BY_REQUEST_TYPE:
        raise ValueError(f"unsupported JML request_type: {request_type!r}")
    request_id = str(request.get("request_id", "")).strip()
    if not request_id:
        raise ValueError("JML request is missing 'request_id'.")

    username = str(request.get("username") or "unknown")
    department = str(request.get("department") or "unknown")
    manager_id = str(request.get("manager_id") or "unassigned")
    employee_id = str(request.get("employee_id") or "unknown")
    title_by_type = {
        "joiner": f"Access provisioned for new hire {username} ({department})",
        "mover": f"Access changed for {username}: {request.get('old_department')} -> {department}",
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
            "simulated": True,
        },
    }
