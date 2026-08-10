"""Offline staging-assurance runner and explicit live go/no-go evaluator."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from governance_core import ActorContext, GovernanceCore
from outbox_delivery import GovernanceOutboxQueue, LocalOutboxPublisher, OutboxWorker
from persistence import Database
from scripts.staging_logwatcher import run_logwatcher_staging
from security_alert_contract import normalize_security_alert_v1


POLICY_SCHEMA = "sentinel.staging_assurance.v1"
POLICY_KEYS = {
    "schema_version",
    "environment",
    "source_contract",
    "thresholds",
    "required_offline_gates",
    "required_live_gates",
}
THRESHOLD_KEYS = {
    "outbox_worker_max_age_seconds",
    "outbox_delivery_lag_max_seconds",
    "outbox_retrying_max",
    "outbox_dead_max",
}
SECRET_NAMES = {
    "password",
    "secret",
    "token",
    "connection_string",
    "shared_key",
    "client_secret",
}


def _reject_secret_fields(value: Any, path: str = "policy") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in SECRET_NAMES:
                raise ValueError(f"{path} contains prohibited secret field: {key}")
            _reject_secret_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_fields(item, f"{path}[{index}]")


def load_assurance_policy(path: str) -> dict[str, Any]:
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("staging assurance policy cannot be loaded") from error
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise ValueError("staging assurance policy fields are invalid")
    _reject_secret_fields(policy)
    if policy["schema_version"] != POLICY_SCHEMA or policy["environment"] != "staging":
        raise ValueError("staging assurance policy identity is invalid")
    if policy["source_contract"] != "security_alert.v1":
        raise ValueError("staging assurance source contract is invalid")
    thresholds = policy["thresholds"]
    if not isinstance(thresholds, dict) or set(thresholds) != THRESHOLD_KEYS:
        raise ValueError("staging assurance thresholds are invalid")
    limits = {
        "outbox_worker_max_age_seconds": (10, 900),
        "outbox_delivery_lag_max_seconds": (30, 86_400),
        "outbox_retrying_max": (0, 1000),
        "outbox_dead_max": (0, 1000),
    }
    for name, (minimum, maximum) in limits.items():
        value = thresholds[name]
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"staging assurance threshold is invalid: {name}")
    for name in ("required_offline_gates", "required_live_gates"):
        gates = policy[name]
        if (
            not isinstance(gates, list)
            or not gates
            or any(not isinstance(gate, str) or not gate.strip() for gate in gates)
            or len(set(gates)) != len(gates)
        ):
            raise ValueError(f"staging assurance {name} is invalid")
    if set(policy["required_offline_gates"]) & set(policy["required_live_gates"]):
        raise ValueError("offline and live staging gates must be separate")
    return policy


def _load_contract_fixture(path: str) -> list[dict[str, Any]]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError("security alert fixture cannot be loaded") from error
    alerts: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            normalize_security_alert_v1(payload)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise ValueError(f"security alert fixture line {line_number} is invalid") from error
        alerts.append(payload)
    if not alerts:
        raise ValueError("security alert fixture is empty")
    identities = {
        (item["source"], item["source_event_id"], item["asset_id"], item["kind"])
        for item in alerts
    }
    if len(identities) != len(alerts):
        raise ValueError("security alert fixture contains duplicate logical identities")
    return alerts


def evaluate_live_gates(policy: dict[str, Any], evidence: dict[str, Any] | None) -> dict[str, Any]:
    required = policy["required_live_gates"]
    if evidence is None:
        gates = dict.fromkeys(required, "not_run")
    else:
        if not isinstance(evidence, dict) or set(evidence) != set(required):
            raise ValueError("live evidence must contain exactly the required live gates")
        if any(not isinstance(value, bool) for value in evidence.values()):
            raise ValueError("live evidence gate values must be boolean")
        gates = dict(evidence)
    passed = all(gates[name] is True for name in required)
    return {
        "gates": gates,
        "decision": "GO_LIMITED_STAGING_PILOT" if passed else "NO_GO",
        "all_required_live_gates_passed": passed,
    }


def run_offline_assurance(
    policy_path: str,
    alerts_path: str,
    *,
    live_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run only local deterministic checks; no Azure client is constructed."""

    policy = load_assurance_policy(policy_path)
    alerts = _load_contract_fixture(alerts_path)
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        staged_alerts = root / "alerts.jsonl"
        staged_alerts.write_text(
            "\n".join(json.dumps(item, sort_keys=True) for item in alerts) + "\n",
            encoding="utf-8",
        )
        database_path = str(root / "governance.db")
        first = run_logwatcher_staging(
            str(staged_alerts),
            database_path,
            input_kind="contract",
            runtime_root=root,
        )
        replay = run_logwatcher_staging(
            str(staged_alerts),
            database_path,
            input_kind="contract",
            runtime_root=root,
        )

        finding_id = first["finding_ids"][0] if first["finding_ids"] else ""
        core = GovernanceCore(database_path)
        owner = ActorContext("security-ops", "risk_owner")
        approver = ActorContext("security-manager", "approver")
        verifier = ActorContext("independent-verifier", "analyst")
        lifecycle_closed = False
        chain_valid = False
        if finding_id:
            core.assess_risk(finding_id, owner, "high", "high")
            core.propose_treatment(
                finding_id,
                owner,
                "mitigate",
                "Investigate the synthetic alert and retain reviewed evidence",
                "security-ops",
            )
            core.approve_treatment(finding_id, approver, "approved", "Synthetic staging rehearsal")
            core.start_action(finding_id, owner, "responder-1")
            core.submit_evidence(
                finding_id,
                owner,
                "synthetic-ticket",
                "sample://sentinelgrc/staging-assurance/remediation-001",
            )
            core.verify(finding_id, verifier, True, "Independent synthetic verification passed")
            lifecycle_closed = core.close(finding_id, approver)["status"] == "closed"
            chain_valid = core.verify_event_chain(finding_id)

        database = Database.from_target(database_path)
        queue = GovernanceOutboxQueue(database)
        publish_root = root / "published"
        worker = OutboxWorker(queue, LocalOutboxPublisher(str(publish_root)), "offline-assurance")
        results: list[str] = []
        for _ in range(1000):
            result = worker.run_once()
            results.append(result)
            if result == "empty":
                break
            if result != "delivered":
                break
        metrics = queue.metrics()
        published_files = list(publish_root.glob("*.json"))
        database.close()

    offline_gates = {
        "contract_fixture_valid": len(alerts) > 0,
        "first_ingestion_exact": first == {
            "events_read": len(alerts),
            "findings_created": len(alerts),
            "findings_reassessed": 0,
            "ignored": 0,
            "errors": 0,
            "finding_ids": first["finding_ids"],
        },
        "replay_idempotent": (
            replay["events_read"] == len(alerts)
            and replay["findings_created"] == 0
            and replay["findings_reassessed"] == len(alerts)
            and replay["ignored"] == 0
            and replay["errors"] == 0
            and replay["finding_ids"] == first["finding_ids"]
        ),
        "governance_lifecycle_closed": lifecycle_closed,
        "event_chain_valid": chain_valid,
        "local_outbox_drained": (
            bool(results)
            and results[-1] == "empty"
            and metrics["pending"] == 0
            and metrics["dead"] == 0
            and metrics["delivered"] == len(published_files)
        ),
        "repository_boundary_offline": True,
    }
    required = policy["required_offline_gates"]
    unknown = sorted(set(required) - set(offline_gates))
    if unknown:
        raise ValueError("policy requests unsupported offline gates: " + ", ".join(unknown))
    offline_passed = all(offline_gates[name] for name in required)
    return {
        "schema_version": POLICY_SCHEMA,
        "mode": "offline_no_azure",
        "azure_mutation_performed": False,
        "alert_count": len(alerts),
        "first_ingestion": first,
        "replay": replay,
        "offline_gates": offline_gates,
        "offline_decision": "READY_FOR_MANUAL_AZURE_STAGING" if offline_passed else "NO_GO",
        "live_validation": evaluate_live_gates(policy, live_evidence),
        "production_decision": "NO_GO",
    }
