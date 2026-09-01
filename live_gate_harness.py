"""Fail-closed live-gate probes for Service Bus and PostgreSQL restore evidence."""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from outbox_delivery import MAX_MESSAGE_BYTES, NAMESPACE_PATTERN, QUEUE_PATTERN
from persistence import Database


HEX_32 = re.compile(r"[a-f0-9]{32}")
HEX_64 = re.compile(r"[a-f0-9]{64}")
CORRELATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
SETTLEMENT_ACTIONS = {"complete", "dead-letter", "abandon"}
EXPECTED_TOPIC = "governance.event.v1"
DLQ_REASON = "SentinelGRCSyntheticGateFailure"
DLQ_DESCRIPTION = "Approved synthetic live-gate failure"
REQUIRED_POSTGRES_TABLES = frozenset(
    {
        "action_items",
        "approval_records",
        "audit_exports",
        "closure_records",
        "connector_events",
        "findings",
        "governance_events",
        "governance_evidence",
        "governance_outbox",
        "outbox_worker_heartbeats",
        "pipeline_jobs",
        "risk_records",
        "risk_treatments",
        "schema_migrations",
        "user_api_keys",
        "users",
        "verification_records",
    }
)
SYNTHETIC_TABLE_KEYS = {
    "findings": "finding_id",
    "risk_records": "finding_id",
    "risk_treatments": "finding_id",
    "approval_records": "finding_id",
    "action_items": "finding_id",
    "governance_evidence": "finding_id",
    "verification_records": "finding_id",
    "closure_records": "finding_id",
    "governance_events": "finding_id",
    "governance_outbox": "finding_id",
    "audit_exports": "finding_id",
}


class LiveGateError(RuntimeError):
    """A live-gate observation cannot be trusted or completed safely."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _rfc3339(value: Any, field: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise LiveGateError(f"Service Bus {field} is invalid")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_pattern(value: str, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    return value


def _message_body(message: Any) -> bytes:
    body = message.body
    if isinstance(body, bytes):
        encoded = body
    elif isinstance(body, bytearray):
        encoded = bytes(body)
    else:
        try:
            parts: list[bytes] = []
            size = 0
            for part in body:
                if not isinstance(part, (bytes, bytearray, memoryview)):
                    raise TypeError
                encoded_part = bytes(part)
                size += len(encoded_part)
                if size > MAX_MESSAGE_BYTES:
                    raise LiveGateError("Service Bus message body size is invalid")
                parts.append(encoded_part)
            encoded = b"".join(parts)
        except (TypeError, ValueError) as error:
            raise LiveGateError("Service Bus message body is invalid") from error
    if not encoded or len(encoded) > MAX_MESSAGE_BYTES:
        raise LiveGateError("Service Bus message body size is invalid")
    return encoded


def _properties(message: Any) -> dict[str, Any]:
    raw = message.application_properties or {}
    if not isinstance(raw, dict):
        raise LiveGateError("Service Bus application properties are invalid")
    normalized: dict[str, Any] = {}
    for key, value in raw.items():
        if isinstance(key, bytes):
            try:
                key = key.decode("ascii")
            except UnicodeDecodeError as error:
                raise LiveGateError(
                    "Service Bus application properties are invalid"
                ) from error
        if not isinstance(key, str) or key in normalized:
            raise LiveGateError("Service Bus application properties are invalid")
        if isinstance(value, bytes):
            try:
                value = value.decode("ascii")
            except UnicodeDecodeError as error:
                raise LiveGateError(
                    "Service Bus application properties are invalid"
                ) from error
        normalized[key] = value
    return normalized


@dataclass(frozen=True)
class ExpectedServiceBusMessage:
    message_id: str
    session_id: str
    payload_sha256: str

    def __post_init__(self) -> None:
        _require_pattern(self.message_id, HEX_32, "message_id")
        _require_pattern(self.session_id, CORRELATION_ID, "session_id")
        _require_pattern(self.payload_sha256, HEX_64, "payload_sha256")


def verify_service_bus_message(
    message: Any, expected: ExpectedServiceBusMessage
) -> dict[str, Any]:
    """Verify exact broker metadata and canonical body without returning the body."""
    if str(message.message_id) != expected.message_id:
        raise LiveGateError("Service Bus message identity does not match")
    if str(message.session_id) != expected.session_id:
        raise LiveGateError("Service Bus session identity does not match")
    if str(message.subject) != EXPECTED_TOPIC:
        raise LiveGateError("Service Bus message topic does not match")
    if str(message.content_type) != "application/json":
        raise LiveGateError("Service Bus content type does not match")

    body = _message_body(message)
    if _sha256(body) != expected.payload_sha256:
        raise LiveGateError("Service Bus payload checksum does not match")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LiveGateError("Service Bus payload is not valid JSON") from error
    if not isinstance(payload, dict):
        raise LiveGateError("Service Bus payload is not an object")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if canonical != body:
        raise LiveGateError("Service Bus payload is not canonical JSON")
    if payload.get("finding_id") != expected.session_id:
        raise LiveGateError("Service Bus payload session binding does not match")

    properties = _properties(message)
    if set(properties) != {"event_sequence", "payload_sha256"}:
        raise LiveGateError("Service Bus application properties do not match")
    if properties.get("payload_sha256") != expected.payload_sha256:
        raise LiveGateError("Service Bus checksum property does not match")
    event_sequence = properties.get("event_sequence")
    if isinstance(event_sequence, bool) or not isinstance(event_sequence, int):
        raise LiveGateError("Service Bus event sequence is invalid")
    payload_sequence = payload.get("event_sequence")
    if (
        event_sequence < 1
        or isinstance(payload_sequence, bool)
        or not isinstance(payload_sequence, int)
        or payload_sequence != event_sequence
    ):
        raise LiveGateError("Service Bus event sequence does not match")
    if payload.get("event_id") != str(message.correlation_id):
        raise LiveGateError("Service Bus correlation identity does not match")

    try:
        delivery_count = int(message.delivery_count)
    except (TypeError, ValueError) as error:
        raise LiveGateError("Service Bus delivery count is invalid") from error
    if delivery_count < 0:
        raise LiveGateError("Service Bus delivery count is invalid")
    return {
        "message_id": expected.message_id,
        "session_id": expected.session_id,
        "payload_sha256": expected.payload_sha256,
        "event_sequence": event_sequence,
        "delivery_count": delivery_count,
        "broker_enqueued_at": _rfc3339(message.enqueued_time_utc, "enqueue time"),
    }


class AzureServiceBusGateReceiver:
    """Receive one exact session-bound synthetic message with receiver-only RBAC."""

    PERMANENT_ERRORS = {
        "AuthenticationError",
        "ClientAuthenticationError",
        "MessagingEntityNotFoundError",
        "ServiceBusAuthenticationError",
        "ServiceBusAuthorizationError",
    }

    def __init__(
        self,
        namespace: str,
        queue_name: str,
        *,
        managed_identity_client_id: str,
        timeout_seconds: int = 15,
        retry_attempts: int = 2,
        client_factory: Callable[..., Any] | None = None,
        dead_letter_sub_queue: Any = None,
    ) -> None:
        if NAMESPACE_PATTERN.fullmatch(namespace) is None:
            raise ValueError("Service Bus namespace must be an Azure FQDN")
        if QUEUE_PATTERN.fullmatch(queue_name) is None or "//" in queue_name:
            raise ValueError("Service Bus queue name is invalid")
        _require_pattern(
            managed_identity_client_id, CORRELATION_ID, "managed_identity_client_id"
        )
        if not 1 <= timeout_seconds <= 60 or not 0 <= retry_attempts <= 5:
            raise ValueError("Service Bus timeout or retry policy is invalid")
        if client_factory is None:
            try:
                from azure.identity import ManagedIdentityCredential
                from azure.servicebus import ServiceBusClient, ServiceBusSubQueue
            except ModuleNotFoundError as error:
                raise RuntimeError(
                    "Azure Service Bus dependencies are not installed"
                ) from error
            credential = ManagedIdentityCredential(client_id=managed_identity_client_id)

            def client_factory(**kwargs: Any) -> Any:
                return ServiceBusClient(credential=credential, **kwargs)

            dead_letter_sub_queue = ServiceBusSubQueue.DEAD_LETTER
        self.namespace = namespace
        self.queue_name = queue_name
        self.timeout_seconds = timeout_seconds
        self.retry_attempts = retry_attempts
        self.client_factory = client_factory
        self.dead_letter_sub_queue = dead_letter_sub_queue

    def receive_one(
        self,
        expected: ExpectedServiceBusMessage,
        *,
        action: str,
        from_dead_letter: bool = False,
    ) -> dict[str, Any]:
        if action not in SETTLEMENT_ACTIONS:
            raise ValueError("Service Bus settlement action is invalid")
        if from_dead_letter and action == "dead-letter":
            raise ValueError("a dead-letter message cannot be dead-lettered again")
        receiver_kwargs: dict[str, Any] = {
            "queue_name": self.queue_name,
            "session_id": expected.session_id,
            "max_wait_time": self.timeout_seconds,
        }
        if from_dead_letter:
            receiver_kwargs["sub_queue"] = self.dead_letter_sub_queue
        try:
            with self.client_factory(
                fully_qualified_namespace=self.namespace,
                retry_total=self.retry_attempts,
                retry_backoff_factor=0.25,
                retry_backoff_max=2,
                socket_timeout=self.timeout_seconds,
            ) as client:
                with client.get_queue_receiver(**receiver_kwargs) as receiver:
                    messages = receiver.receive_messages(
                        max_message_count=1,
                        max_wait_time=self.timeout_seconds,
                    )
                    if len(messages) != 1:
                        raise LiveGateError(
                            "the expected Service Bus message was not available"
                        )
                    message = messages[0]
                    try:
                        observation = verify_service_bus_message(message, expected)
                    except Exception:
                        receiver.abandon_message(message)
                        raise
                    if from_dead_letter:
                        reason = getattr(message, "dead_letter_reason", None)
                        description = getattr(
                            message, "dead_letter_error_description", None
                        )
                        if reason != DLQ_REASON or not isinstance(description, str):
                            receiver.abandon_message(message)
                            raise LiveGateError(
                                "Service Bus dead-letter reason does not match"
                            )
                        observation["dead_letter_reason"] = DLQ_REASON
                        observation["dead_letter_description_sha256"] = _sha256(
                            description.encode("utf-8")
                        )
                    if action == "complete":
                        receiver.complete_message(message)
                    elif action == "dead-letter":
                        receiver.dead_letter_message(
                            message,
                            reason=DLQ_REASON,
                            error_description=DLQ_DESCRIPTION,
                        )
                    else:
                        receiver.abandon_message(message)
        except (LiveGateError, ValueError):
            raise
        except Exception as error:
            if type(error).__name__ in self.PERMANENT_ERRORS:
                raise LiveGateError("Service Bus rejected the gate receiver") from None
            raise LiveGateError("Service Bus gate receiver is unavailable") from None

        return {
            "schema_version": "sentinel.live_gate.service_bus.v1",
            "observed_at": _utc_now(),
            "source": "dead-letter" if from_dead_letter else "active",
            "settlement": action,
            **observation,
        }


def expected_migration_checksums(migrations_dir: Path) -> dict[str, str]:
    if not migrations_dir.is_dir():
        raise ValueError("PostgreSQL migrations directory is missing")
    paths = sorted(migrations_dir.glob("*.sql"))
    if not paths:
        raise ValueError("PostgreSQL migrations directory is empty")
    return {
        path.stem: _sha256(path.read_text(encoding="utf-8").encode("utf-8"))
        for path in paths
    }


def _canonical_rows(rows: list[dict[str, Any]]) -> str:
    canonical_rows = sorted(
        json.dumps(
            row,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        for row in rows
    )
    return _sha256(
        json.dumps(
            canonical_rows,
            separators=(",", ":"),
        ).encode("utf-8")
    )


class PostgresRestoreVerifier:
    """Create and compare source-bound, synthetic-only restore snapshots."""

    def __init__(self, database: Database, migrations_dir: Path) -> None:
        if database.dialect != "postgresql":
            raise ValueError("restore verification requires PostgreSQL")
        self.database = database
        self.expected_migrations = expected_migration_checksums(migrations_dir)

    def snapshot(self, synthetic_prefix: str, finding_id: str) -> dict[str, Any]:
        _require_pattern(synthetic_prefix, CORRELATION_ID, "synthetic_prefix")
        _require_pattern(finding_id, CORRELATION_ID, "finding_id")
        if not finding_id.startswith(synthetic_prefix):
            raise ValueError("finding_id is outside the synthetic prefix")
        with closing(self.database.connect()) as db:
            migration_rows = db.execute(
                "SELECT migration_id, checksum FROM schema_migrations "
                "ORDER BY migration_id"
            ).fetchall()
            actual_migrations = {
                str(row["migration_id"]): str(row["checksum"])
                for row in migration_rows
            }
            if actual_migrations != self.expected_migrations:
                raise LiveGateError("PostgreSQL migration checksums do not match")

            table_rows = db.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' ORDER BY table_name"
            ).fetchall()
            actual_tables = {str(row["table_name"]) for row in table_rows}
            missing = REQUIRED_POSTGRES_TABLES - actual_tables
            if missing:
                raise LiveGateError("PostgreSQL required schema objects are missing")

            synthetic: dict[str, dict[str, Any]] = {}
            for table, key in SYNTHETIC_TABLE_KEYS.items():
                rows = [
                    dict(row)
                    for row in db.execute(
                        f"SELECT * FROM {table} "
                        f"WHERE left({key}, length(?)) = ? "
                        f"ORDER BY {key}",
                        (synthetic_prefix, synthetic_prefix),
                    ).fetchall()
                ]
                synthetic[table] = {
                    "count": len(rows),
                    "sha256": _canonical_rows(rows),
                }

            finding = db.execute(
                "SELECT finding_id, status, updated_at FROM findings "
                "WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            db.rollback()
        if finding is None:
            raise LiveGateError("synthetic application read did not find the record")
        application_read_sha256 = _canonical_rows([dict(finding)])
        host = urlparse(self.database.database_url).hostname or ""
        if not host:
            raise LiveGateError("PostgreSQL target identity is invalid")
        return {
            "schema_version": "sentinel.live_gate.postgres_restore.v1",
            "observed_at": _utc_now(),
            "target_sha256": _sha256(host.lower().encode("utf-8")),
            "migration_checksums": self.expected_migrations,
            "required_table_count": len(REQUIRED_POSTGRES_TABLES),
            "synthetic_prefix": synthetic_prefix,
            "synthetic_tables": synthetic,
            "application_read_sha256": application_read_sha256,
        }


def _validate_restore_snapshot(snapshot: dict[str, Any], label: str) -> None:
    required = {
        "schema_version",
        "observed_at",
        "target_sha256",
        "migration_checksums",
        "required_table_count",
        "synthetic_prefix",
        "synthetic_tables",
        "application_read_sha256",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != required:
        raise ValueError(f"{label} restore snapshot schema is invalid")
    if snapshot["schema_version"] != "sentinel.live_gate.postgres_restore.v1":
        raise ValueError(f"{label} restore snapshot version is invalid")
    try:
        observed_at = snapshot["observed_at"]
        if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
            raise ValueError
        parsed = datetime.fromisoformat(observed_at.removesuffix("Z") + "+00:00")
        if parsed.tzinfo is None:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} restore snapshot timestamp is invalid") from error
    _require_pattern(snapshot["target_sha256"], HEX_64, f"{label} target_sha256")
    _require_pattern(
        snapshot["application_read_sha256"],
        HEX_64,
        f"{label} application_read_sha256",
    )
    _require_pattern(
        snapshot["synthetic_prefix"], CORRELATION_ID, f"{label} synthetic_prefix"
    )
    if snapshot["required_table_count"] != len(REQUIRED_POSTGRES_TABLES):
        raise ValueError(f"{label} required_table_count is invalid")
    migrations = snapshot["migration_checksums"]
    if not isinstance(migrations, dict) or not migrations:
        raise ValueError(f"{label} migration_checksums are invalid")
    for migration_id, checksum in migrations.items():
        _require_pattern(migration_id, CORRELATION_ID, f"{label} migration_id")
        _require_pattern(checksum, HEX_64, f"{label} migration checksum")
    tables = snapshot["synthetic_tables"]
    if not isinstance(tables, dict) or set(tables) != set(SYNTHETIC_TABLE_KEYS):
        raise ValueError(f"{label} synthetic_tables are invalid")
    for table, evidence in tables.items():
        if not isinstance(evidence, dict) or set(evidence) != {"count", "sha256"}:
            raise ValueError(f"{label} {table} evidence is invalid")
        count = evidence["count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"{label} {table} count is invalid")
        _require_pattern(evidence["sha256"], HEX_64, f"{label} {table} sha256")


def verify_restore_snapshot(
    source: dict[str, Any], restored: dict[str, Any]
) -> dict[str, Any]:
    _validate_restore_snapshot(source, "source")
    _validate_restore_snapshot(restored, "restored")
    if restored["schema_version"] != source["schema_version"]:
        raise LiveGateError("restore snapshot versions do not match")
    if source["target_sha256"] == restored["target_sha256"]:
        raise LiveGateError("restore target is not isolated from the source")
    for field in (
        "migration_checksums",
        "required_table_count",
        "synthetic_prefix",
        "synthetic_tables",
        "application_read_sha256",
    ):
        if source[field] != restored[field]:
            raise LiveGateError(f"restored PostgreSQL {field} does not match")
    return {
        "schema_version": "sentinel.live_gate.postgres_restore_comparison.v1",
        "verified_at": _utc_now(),
        "source_target_sha256": source["target_sha256"],
        "restored_target_sha256": restored["target_sha256"],
        "synthetic_prefix": source["synthetic_prefix"],
        "verdict": "PASS",
    }
