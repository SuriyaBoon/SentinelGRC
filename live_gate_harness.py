"""Fail-closed live-gate probes for Service Bus and PostgreSQL restore evidence."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
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
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
SETTLEMENT_ACTIONS = {"complete", "dead-letter", "abandon"}
EXPECTED_TOPIC = "governance.event.v1"
DLQ_REASON = "SentinelGRCSyntheticGateFailure"
DLQ_DESCRIPTION = "Approved synthetic live-gate failure"
UTC_OFFSET = "+00:00"
APPLICATION_PROPERTIES_INVALID = "Service Bus application properties are invalid"
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
        UTC_OFFSET, "Z"
    )


def _rfc3339(value: Any, field: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise LiveGateError(f"Service Bus {field} is invalid")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        UTC_OFFSET, "Z"
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hmac_sha256(key: bytes, value: dict[str, Any]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _require_pattern(value: str, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    return value


def _canonical_hostname(value: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 253
        or value != value.lower()
        or value.startswith(".")
        or value.endswith(".")
        or ".." in value
        or any(HOST_LABEL.fullmatch(label) is None for label in value.split("."))
    ):
        raise ValueError(f"{field} is invalid")
    return value


def _azure_resource_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 2048
        or value != value.strip()
        or not value.casefold().startswith("/subscriptions/")
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError("expected_target_resource_id is invalid")
    return value.casefold()


def _evidence_hmac_key(value: str) -> bytes:
    if not isinstance(value, str) or not 32 <= len(value) <= 256:
        raise ValueError("evidence_hmac_key is invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("evidence_hmac_key is invalid") from error
    if any(character < 0x21 or character == 0x7F for character in encoded):
        raise ValueError("evidence_hmac_key is invalid")
    return encoded


def _message_parts(body: Any) -> bytes:
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
        return b"".join(parts)
    except (TypeError, ValueError) as error:
        raise LiveGateError("Service Bus message body is invalid") from error


def _message_body(message: Any) -> bytes:
    body = message.body
    if isinstance(body, bytes):
        encoded = body
    elif isinstance(body, bytearray):
        encoded = bytes(body)
    else:
        encoded = _message_parts(body)
    if not encoded or len(encoded) > MAX_MESSAGE_BYTES:
        raise LiveGateError("Service Bus message body size is invalid")
    return encoded


def _ascii_property_component(value: Any) -> Any:
    if not isinstance(value, bytes):
        return value
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as error:
        raise LiveGateError(APPLICATION_PROPERTIES_INVALID) from error


def _properties(message: Any) -> dict[str, Any]:
    raw = message.application_properties or {}
    if not isinstance(raw, dict):
        raise LiveGateError(APPLICATION_PROPERTIES_INVALID)
    normalized: dict[str, Any] = {}
    for key, value in raw.items():
        key = _ascii_property_component(key)
        if not isinstance(key, str) or key in normalized:
            raise LiveGateError(APPLICATION_PROPERTIES_INVALID)
        normalized[key] = _ascii_property_component(value)
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


def _verify_service_bus_metadata(
    message: Any, expected: ExpectedServiceBusMessage
) -> None:
    if str(message.message_id) != expected.message_id:
        raise LiveGateError("Service Bus message identity does not match")
    if str(message.session_id) != expected.session_id:
        raise LiveGateError("Service Bus session identity does not match")
    if str(message.subject) != EXPECTED_TOPIC:
        raise LiveGateError("Service Bus message topic does not match")
    if str(message.content_type) != "application/json":
        raise LiveGateError("Service Bus content type does not match")


def _verify_service_bus_payload(
    message: Any, expected: ExpectedServiceBusMessage
) -> dict[str, Any]:
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
    return payload


def _verify_service_bus_properties(
    message: Any,
    expected: ExpectedServiceBusMessage,
    payload: dict[str, Any],
) -> int:
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
    return event_sequence


def _delivery_count(message: Any) -> int:
    try:
        delivery_count = int(message.delivery_count)
    except (TypeError, ValueError) as error:
        raise LiveGateError("Service Bus delivery count is invalid") from error
    if delivery_count < 0:
        raise LiveGateError("Service Bus delivery count is invalid")
    return delivery_count


def verify_service_bus_message(
    message: Any, expected: ExpectedServiceBusMessage
) -> dict[str, Any]:
    """Verify exact broker metadata and canonical body without returning the body."""
    _verify_service_bus_metadata(message, expected)
    payload = _verify_service_bus_payload(message, expected)
    event_sequence = _verify_service_bus_properties(message, expected, payload)
    return {
        "message_id": expected.message_id,
        "session_id": expected.session_id,
        "payload_sha256": expected.payload_sha256,
        "event_sequence": event_sequence,
        "delivery_count": _delivery_count(message),
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

    def _receiver_kwargs(
        self, expected: ExpectedServiceBusMessage, from_dead_letter: bool
    ) -> dict[str, Any]:
        receiver_kwargs: dict[str, Any] = {
            "queue_name": self.queue_name,
            "session_id": expected.session_id,
            "max_wait_time": self.timeout_seconds,
        }
        if from_dead_letter:
            receiver_kwargs["sub_queue"] = self.dead_letter_sub_queue
        return receiver_kwargs

    @staticmethod
    def _verified_observation(
        receiver: Any,
        message: Any,
        expected: ExpectedServiceBusMessage,
    ) -> dict[str, Any]:
        try:
            return verify_service_bus_message(message, expected)
        except Exception:
            receiver.abandon_message(message)
            raise

    @staticmethod
    def _dead_letter_observation(receiver: Any, message: Any) -> dict[str, str]:
        reason = getattr(message, "dead_letter_reason", None)
        description = getattr(message, "dead_letter_error_description", None)
        if reason != DLQ_REASON or description != DLQ_DESCRIPTION:
            receiver.abandon_message(message)
            raise LiveGateError("Service Bus dead-letter contract does not match")
        return {
            "dead_letter_reason": DLQ_REASON,
            "dead_letter_description_sha256": _sha256(description.encode("utf-8")),
        }

    @staticmethod
    def _settle(receiver: Any, message: Any, action: str) -> None:
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
        receiver_kwargs = self._receiver_kwargs(expected, from_dead_letter)
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
                    observation = self._verified_observation(
                        receiver, message, expected
                    )
                    if from_dead_letter:
                        observation.update(
                            self._dead_letter_observation(receiver, message)
                        )
                    self._settle(receiver, message, action)
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

    def __init__(
        self,
        database: Database,
        migrations_dir: Path,
        *,
        expected_target_resource_id: str,
        expected_hostname: str,
        evidence_hmac_key: str,
    ) -> None:
        if database.dialect != "postgresql":
            raise ValueError("restore verification requires PostgreSQL")
        hostname = (urlparse(database.database_url).hostname or "").casefold()
        self.expected_hostname = _canonical_hostname(
            expected_hostname, "expected_hostname"
        )
        if hostname != self.expected_hostname:
            raise ValueError("PostgreSQL URL is not bound to the expected target")
        self.database = database
        self.expected_target_resource_id = _azure_resource_id(
            expected_target_resource_id
        )
        self.evidence_hmac_key = _evidence_hmac_key(evidence_hmac_key)
        self.expected_migrations = expected_migration_checksums(migrations_dir)

    @staticmethod
    def _rollback(db: Any) -> None:
        try:
            db.rollback()
        except Exception:
            raise LiveGateError("PostgreSQL snapshot rollback failed") from None

    @staticmethod
    def _begin_snapshot(db: Any) -> None:
        db.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        settings = db.execute(
            "SELECT current_setting('transaction_isolation') AS isolation_level, "
            "current_setting('transaction_read_only') AS read_only"
        ).fetchone()
        if (
            settings is None
            or str(settings["isolation_level"]).casefold() != "repeatable read"
            or str(settings["read_only"]).casefold() not in {"on", "true"}
        ):
            raise LiveGateError("PostgreSQL snapshot transaction is not read-only")

    @staticmethod
    def _validated_target_identity(target: Any) -> tuple[str, int, str, int]:
        if target is None:
            raise LiveGateError("PostgreSQL target identity is unavailable")
        database_name = target["database_name"]
        database_oid = target["database_oid"]
        server_address = target["server_address"]
        server_port = target["server_port"]
        invalid_database_name = (
            not isinstance(database_name, str)
            or not database_name
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in database_name
            )
        )
        invalid_database_oid = (
            isinstance(database_oid, bool)
            or not isinstance(database_oid, int)
            or database_oid <= 0
        )
        invalid_server_port = (
            isinstance(server_port, bool)
            or not isinstance(server_port, int)
            or not 1 <= server_port <= 65535
        )
        if invalid_database_name or invalid_database_oid or invalid_server_port:
            raise LiveGateError("PostgreSQL target identity is invalid")
        try:
            canonical_address = ipaddress.ip_address(str(server_address)).compressed
        except ValueError:
            raise LiveGateError("PostgreSQL target identity is invalid") from None
        return database_name, database_oid, canonical_address, server_port

    def _target_identity_hmac(self, db: Any) -> str:
        target = db.execute(
            "SELECT current_database() AS database_name, "
            "(SELECT oid FROM pg_database WHERE datname = current_database()) "
            "AS database_oid, inet_server_addr()::text AS server_address, "
            "inet_server_port() AS server_port"
        ).fetchone()
        database_name, database_oid, canonical_address, server_port = (
            self._validated_target_identity(target)
        )
        return _hmac_sha256(
            self.evidence_hmac_key,
            {
                "database_name": database_name,
                "database_oid": database_oid,
                "expected_hostname": self.expected_hostname,
                "resource_id": self.expected_target_resource_id,
                "server_address": canonical_address,
                "server_port": server_port,
                "version": "sentinel.postgres.target.v1",
            },
        )

    def _snapshot_in_transaction(
        self, db: Any, synthetic_prefix: str, finding_id: str
    ) -> dict[str, Any]:
        self._begin_snapshot(db)
        target_identity_hmac_sha256 = self._target_identity_hmac(db)
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
        if REQUIRED_POSTGRES_TABLES - actual_tables:
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
        if finding is None:
            raise LiveGateError("synthetic application read did not find the record")
        return {
            "schema_version": "sentinel.live_gate.postgres_restore.v2",
            "observed_at": _utc_now(),
            "target_identity_hmac_sha256": target_identity_hmac_sha256,
            "migration_checksums": self.expected_migrations,
            "required_table_count": len(REQUIRED_POSTGRES_TABLES),
            "synthetic_prefix": synthetic_prefix,
            "synthetic_tables": synthetic,
            "application_read_sha256": _canonical_rows([dict(finding)]),
        }

    def snapshot(self, synthetic_prefix: str, finding_id: str) -> dict[str, Any]:
        _require_pattern(synthetic_prefix, CORRELATION_ID, "synthetic_prefix")
        _require_pattern(finding_id, CORRELATION_ID, "finding_id")
        if not finding_id.startswith(synthetic_prefix):
            raise ValueError("finding_id is outside the synthetic prefix")
        try:
            with closing(self.database.connect()) as db:
                try:
                    snapshot = self._snapshot_in_transaction(
                        db, synthetic_prefix, finding_id
                    )
                except (LiveGateError, ValueError):
                    self._rollback(db)
                    raise
                except Exception:
                    self._rollback(db)
                    raise LiveGateError(
                        "PostgreSQL snapshot verification failed"
                    ) from None
                self._rollback(db)
                return snapshot
        except (LiveGateError, ValueError):
            raise
        except Exception:
            raise LiveGateError("PostgreSQL snapshot verifier is unavailable") from None


def _validate_snapshot_timestamp(observed_at: Any, label: str) -> None:
    try:
        if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
            raise ValueError
        parsed = datetime.fromisoformat(observed_at.removesuffix("Z") + UTC_OFFSET)
        if parsed.tzinfo is None:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} restore snapshot timestamp is invalid") from error


def _validate_snapshot_migrations(migrations: Any, label: str) -> None:
    if not isinstance(migrations, dict) or not migrations:
        raise ValueError(f"{label} migration_checksums are invalid")
    for migration_id, checksum in migrations.items():
        _require_pattern(migration_id, CORRELATION_ID, f"{label} migration_id")
        _require_pattern(checksum, HEX_64, f"{label} migration checksum")


def _validate_snapshot_tables(tables: Any, label: str) -> None:
    if not isinstance(tables, dict) or set(tables) != set(SYNTHETIC_TABLE_KEYS):
        raise ValueError(f"{label} synthetic_tables are invalid")
    for table, evidence in tables.items():
        if not isinstance(evidence, dict) or set(evidence) != {"count", "sha256"}:
            raise ValueError(f"{label} {table} evidence is invalid")
        count = evidence["count"]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"{label} {table} count is invalid")
        _require_pattern(evidence["sha256"], HEX_64, f"{label} {table} sha256")


def _validate_restore_snapshot(snapshot: dict[str, Any], label: str) -> None:
    required = {
        "schema_version",
        "observed_at",
        "target_identity_hmac_sha256",
        "migration_checksums",
        "required_table_count",
        "synthetic_prefix",
        "synthetic_tables",
        "application_read_sha256",
    }
    if not isinstance(snapshot, dict) or set(snapshot) != required:
        raise ValueError(f"{label} restore snapshot schema is invalid")
    if snapshot["schema_version"] != "sentinel.live_gate.postgres_restore.v2":
        raise ValueError(f"{label} restore snapshot version is invalid")
    _validate_snapshot_timestamp(snapshot["observed_at"], label)
    _require_pattern(
        snapshot["target_identity_hmac_sha256"],
        HEX_64,
        f"{label} target_identity_hmac_sha256",
    )
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
    _validate_snapshot_migrations(snapshot["migration_checksums"], label)
    _validate_snapshot_tables(snapshot["synthetic_tables"], label)


def verify_restore_snapshot(
    source: dict[str, Any], restored: dict[str, Any]
) -> dict[str, Any]:
    _validate_restore_snapshot(source, "source")
    _validate_restore_snapshot(restored, "restored")
    if restored["schema_version"] != source["schema_version"]:
        raise LiveGateError("restore snapshot versions do not match")
    if (
        source["target_identity_hmac_sha256"]
        == restored["target_identity_hmac_sha256"]
    ):
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
        "schema_version": "sentinel.live_gate.postgres_restore_comparison.v2",
        "verified_at": _utc_now(),
        "source_target_identity_hmac_sha256": source[
            "target_identity_hmac_sha256"
        ],
        "restored_target_identity_hmac_sha256": restored[
            "target_identity_hmac_sha256"
        ],
        "synthetic_prefix": source["synthetic_prefix"],
        "verdict": "PASS",
    }
