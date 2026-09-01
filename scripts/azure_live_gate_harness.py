"""Run one bounded Azure live-gate observation and emit sanitized JSON."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from live_gate_harness import (
    AzureServiceBusGateReceiver,
    ExpectedServiceBusMessage,
    LiveGateError,
    PostgresRestoreVerifier,
    verify_restore_snapshot,
)
from persistence import Database


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations" / "postgresql"


def _required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _read_json_env(name: str) -> dict[str, Any]:
    try:
        value = json.loads(_required_env(name))
    except json.JSONDecodeError as error:
        raise ValueError(f"{name} must be valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{name} must contain a JSON object")
    return value


def _boolean_env(name: str, default: str = "false") -> bool:
    value = os.environ.get(name, default).lower()
    if value not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false")
    return value == "true"


def _service_bus(args: argparse.Namespace) -> dict[str, Any]:
    action = args.action or _required_env("SENTINEL_GATE_SETTLEMENT")
    if action not in {"complete", "dead-letter", "abandon"}:
        raise ValueError("SENTINEL_GATE_SETTLEMENT is invalid")
    from_dead_letter = args.from_dead_letter or _boolean_env(
        "SENTINEL_GATE_FROM_DEAD_LETTER"
    )
    receiver = AzureServiceBusGateReceiver(
        _required_env("SENTINEL_SERVICE_BUS_NAMESPACE"),
        _required_env("SENTINEL_SERVICE_BUS_QUEUE"),
        managed_identity_client_id=_required_env("SENTINEL_AZURE_CLIENT_ID"),
        timeout_seconds=args.timeout_seconds,
    )
    expected = ExpectedServiceBusMessage(
        _required_env("SENTINEL_GATE_MESSAGE_ID"),
        _required_env("SENTINEL_GATE_SESSION_ID"),
        _required_env("SENTINEL_GATE_PAYLOAD_SHA256"),
    )
    return receiver.receive_one(
        expected,
        action=action,
        from_dead_letter=from_dead_letter,
    )


def _postgres_snapshot(_: argparse.Namespace) -> dict[str, Any]:
    database = None
    try:
        database = Database(_required_env("SENTINEL_RESTORE_DATABASE_URL"))
        return PostgresRestoreVerifier(
            database,
            MIGRATIONS,
            expected_target_resource_id=_required_env(
                "SENTINEL_GATE_EXPECTED_TARGET_RESOURCE_ID"
            ),
            expected_hostname=_required_env(
                "SENTINEL_GATE_EXPECTED_TARGET_HOSTNAME"
            ),
            evidence_hmac_key=_required_env("SENTINEL_GATE_EVIDENCE_HMAC_KEY"),
        ).snapshot(
            _required_env("SENTINEL_GATE_SYNTHETIC_PREFIX"),
            _required_env("SENTINEL_GATE_FINDING_ID"),
        )
    except (LiveGateError, ValueError):
        raise
    except Exception:
        raise LiveGateError("PostgreSQL restore verifier is unavailable") from None
    finally:
        if database is not None:
            database.close()


def _postgres_compare(_: argparse.Namespace) -> dict[str, Any]:
    return verify_restore_snapshot(
        _read_json_env("SENTINEL_GATE_SOURCE_SNAPSHOT"),
        _read_json_env("SENTINEL_GATE_RESTORED_SNAPSHOT"),
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    service_bus = subparsers.add_parser("service-bus")
    service_bus.add_argument(
        "--action", choices=("complete", "dead-letter", "abandon")
    )
    service_bus.add_argument("--from-dead-letter", action="store_true")
    service_bus.add_argument("--timeout-seconds", type=int, default=15)
    service_bus.set_defaults(handler=_service_bus)
    snapshot = subparsers.add_parser("postgres-snapshot")
    snapshot.set_defaults(handler=_postgres_snapshot)
    compare = subparsers.add_parser("postgres-compare")
    compare.set_defaults(handler=_postgres_compare)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = args.handler(args)
    except (LiveGateError, ValueError) as error:
        print(
            json.dumps(
                {"status": "BLOCKED", "error": str(error)}, sort_keys=True
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
