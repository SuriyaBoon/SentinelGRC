"""Staging harness for the real LogWatcher JSONL export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from governance_core import ActorContext, GovernanceCore
from security_event_connector import normalize_logwatcher_alert, normalize_security_event


def run_logwatcher_staging(events_path: str, governance_db: str, input_kind: str = "auto") -> dict[str, Any]:
    core = GovernanceCore(governance_db)
    actor = ActorContext("logwatcher-staging-connector", "analyst", "connector")
    result = {
        "events_read": 0, "findings_created": 0, "findings_reassessed": 0,
        "ignored": 0, "errors": 0, "finding_ids": [],
    }
    for line in Path(events_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        result["events_read"] += 1
        try:
            raw = json.loads(line)
            if input_kind == "alert" or (input_kind == "auto" and "kind" in raw):
                finding = normalize_logwatcher_alert(raw)
            else:
                finding = normalize_security_event(raw)
            if finding is None:
                result["ignored"] += 1
                continue
            try:
                core.get_finding(finding["finding_id"])
                existed = True
            except KeyError:
                existed = False
            core.upsert_finding(
                finding["finding_id"], finding["control_id"], finding["asset_id"],
                finding["title"], finding["risk_owner"], finding["severity"], actor,
            )
            result["finding_ids"].append(finding["finding_id"])
            result["findings_reassessed" if existed else "findings_created"] += 1
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            result["errors"] += 1
    return result


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Validate LogWatcher JSONL into SentinelGRC staging.")
    parser.add_argument("--events", required=True)
    parser.add_argument("--governance-db", required=True)
    parser.add_argument("--input-kind", choices={"auto", "event", "alert"}, default="auto")
    args = parser.parse_args()
    print(json.dumps(run_logwatcher_staging(args.events, args.governance_db, args.input_kind), indent=2))
