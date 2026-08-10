"""Staging harness for the real LogWatcher JSONL export."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from governance_core import ActorContext, GovernanceCore
from path_security import (
    configured_runtime_root,
    resolve_existing_file_under_root,
    resolve_sqlite_database_under_root,
)
from security_alert_contract import normalize_security_alert_v1
from security_event_connector import normalize_logwatcher_alert, normalize_security_event


def _select_runtime_root(
    events_path: str,
    governance_db: str,
    runtime_root: str | Path | None,
) -> Path:
    if runtime_root is not None:
        return Path(runtime_root)
    common = os.path.commonpath(
        [str(Path(events_path).resolve()), str(Path(governance_db).resolve())]
    )
    return Path(common)


def _normalize_finding(raw: dict[str, Any], input_kind: str) -> dict[str, Any] | None:
    if input_kind == "contract" or (
        input_kind == "auto" and raw.get("schema_version") == "security_alert.v1"
    ):
        return normalize_security_alert_v1(raw)
    if input_kind == "alert" or (input_kind == "auto" and "kind" in raw):
        return normalize_logwatcher_alert(raw)
    return normalize_security_event(raw)


def _finding_exists(core: GovernanceCore, finding_id: str) -> bool:
    try:
        core.get_finding(finding_id)
    except KeyError:
        return False
    return True


def _empty_result() -> dict[str, Any]:
    return {
        "events_read": 0,
        "findings_created": 0,
        "findings_reassessed": 0,
        "ignored": 0,
        "errors": 0,
        "finding_ids": [],
    }


def run_logwatcher_staging(
    events_path: str,
    governance_db: str,
    input_kind: str = "auto",
    *,
    runtime_root: str | Path | None = None,
) -> dict[str, Any]:
    result = _empty_result()
    try:
        boundary = _select_runtime_root(events_path, governance_db, runtime_root)
        database_path = resolve_sqlite_database_under_root(
            governance_db,
            boundary,
            purpose="governance database",
        )
        source_path = resolve_existing_file_under_root(
            events_path,
            boundary,
            purpose="LogWatcher event input",
        )
        lines = source_path.read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError):
        result["errors"] = 1
        return result

    core = GovernanceCore(str(database_path))
    actor = ActorContext("logwatcher-staging-connector", "analyst", "connector")
    for line in lines:
        if not line.strip():
            continue
        result["events_read"] += 1
        try:
            finding = _normalize_finding(json.loads(line), input_kind)
            if finding is None:
                result["ignored"] += 1
                continue
            existed = _finding_exists(core, finding["finding_id"])
            core.upsert_finding(
                finding["finding_id"],
                finding["control_id"],
                finding["asset_id"],
                finding["title"],
                finding["risk_owner"],
                finding["severity"],
                actor,
            )
            result["finding_ids"].append(finding["finding_id"])
            outcome = "findings_reassessed" if existed else "findings_created"
            result[outcome] += 1
        except (OSError, TypeError, ValueError):
            result["errors"] += 1
    return result


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Validate LogWatcher JSONL into SentinelGRC staging.")
    parser.add_argument("--events", required=True)
    parser.add_argument("--governance-db", required=True)
    parser.add_argument(
        "--input-kind",
        choices={"auto", "event", "alert", "contract"},
        default="auto",
    )
    args = parser.parse_args()
    print(json.dumps(run_logwatcher_staging(
        args.events,
        args.governance_db,
        args.input_kind,
        runtime_root=configured_runtime_root(),
    ), indent=2))
