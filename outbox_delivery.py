"""Recoverable transactional-outbox delivery to local or Azure publishers."""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from persistence import Database


MAX_MESSAGE_BYTES = 256 * 1024
ID_PATTERN = re.compile(r"[a-f0-9]{32}")
NAMESPACE_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9-]{4,48}[a-z0-9]\.servicebus\.windows\.net"
)
QUEUE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,259}")


class OutboxError(RuntimeError):
    """Base class for bounded outbox failures."""


class PermanentOutboxError(OutboxError):
    """A retry cannot make this message or configuration valid."""


class TransientOutboxError(OutboxError):
    """The broker may accept a later retry."""


@dataclass(frozen=True)
class OutboxMessage:
    message_id: str
    event_id: str
    finding_id: str
    event_sequence: int
    topic: str
    body: bytes
    sha256: str

    @classmethod
    def from_item(cls, item: dict[str, Any]) -> "OutboxMessage":
        for name in ("outbox_id", "event_id", "finding_id", "topic", "payload_json"):
            if not isinstance(item.get(name), str) or not item[name].strip():
                raise PermanentOutboxError(f"outbox {name} is invalid")
        if ID_PATTERN.fullmatch(item["outbox_id"]) is None:
            raise PermanentOutboxError("outbox message identity is invalid")
        if item["topic"] != "governance.event.v1":
            raise PermanentOutboxError("outbox topic is not an approved contract")
        try:
            event_sequence = int(item["event_sequence"])
            payload = json.loads(item["payload_json"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PermanentOutboxError("outbox payload is invalid") from error
        if event_sequence < 1 or not isinstance(payload, dict):
            raise PermanentOutboxError("outbox event sequence is invalid")
        expected = {
            "event_id": item["event_id"],
            "finding_id": item["finding_id"],
            "event_sequence": event_sequence,
        }
        if any(payload.get(name) != value for name, value in expected.items()):
            raise PermanentOutboxError("outbox metadata does not match its payload")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if canonical != item["payload_json"]:
            raise PermanentOutboxError("outbox payload is not canonical JSON")
        body = canonical.encode("utf-8")
        if not body or len(body) > MAX_MESSAGE_BYTES:
            raise PermanentOutboxError("outbox payload size is invalid")
        return cls(
            item["outbox_id"],
            item["event_id"],
            item["finding_id"],
            event_sequence,
            item["topic"],
            body,
            hashlib.sha256(body).hexdigest(),
        )


@dataclass(frozen=True)
class PublishReceipt:
    message_id: str


class OutboxPublisher(Protocol):
    def publish(self, message: OutboxMessage) -> PublishReceipt: ...

    def ready(self) -> bool: ...


class MemoryOutboxPublisher:
    def __init__(self) -> None:
        self.messages: dict[str, bytes] = {}

    def publish(self, message: OutboxMessage) -> PublishReceipt:
        existing = self.messages.get(message.message_id)
        if existing is not None and existing != message.body:
            raise PermanentOutboxError("message identity collision")
        self.messages[message.message_id] = message.body
        return PublishReceipt(message.message_id)

    def ready(self) -> bool:
        return True


class LocalOutboxPublisher:
    """Create-only local publisher for lab evidence; never used in staging."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def publish(self, message: OutboxMessage) -> PublishReceipt:
        path = self.root / f"{message.message_id}.json"
        try:
            with path.open("xb") as stream:
                stream.write(message.body)
        except FileExistsError:
            if path.read_bytes() != message.body:
                raise PermanentOutboxError("local message identity collision")
        return PublishReceipt(message.message_id)

    def ready(self) -> bool:
        return self.root.is_dir()


class AzureServiceBusPublisher:
    """Managed-identity-only Azure Service Bus publisher."""

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
        timeout_seconds: int = 10,
        retry_attempts: int = 3,
        client_factory: Callable[..., Any] | None = None,
        message_factory: Callable[..., Any] | None = None,
    ) -> None:
        if NAMESPACE_PATTERN.fullmatch(namespace) is None:
            raise ValueError("Service Bus namespace must be an Azure FQDN")
        if QUEUE_PATTERN.fullmatch(queue_name) is None or "//" in queue_name:
            raise ValueError("Service Bus queue name is invalid")
        if not managed_identity_client_id.strip():
            raise ValueError("Service Bus requires a managed identity client ID")
        if not 1 <= timeout_seconds <= 30 or not 0 <= retry_attempts <= 5:
            raise ValueError("Service Bus timeout or retry policy is invalid")
        if (client_factory is None) != (message_factory is None):
            raise ValueError("Service Bus test factories must be supplied together")
        self.namespace = namespace
        self.queue_name = queue_name
        self.timeout_seconds = timeout_seconds
        self.retry_attempts = retry_attempts
        if client_factory is None:
            try:
                from azure.identity import ManagedIdentityCredential
                from azure.servicebus import ServiceBusClient, ServiceBusMessage
            except ModuleNotFoundError as error:
                raise RuntimeError("Azure Service Bus dependencies are not installed") from error
            credential = ManagedIdentityCredential(client_id=managed_identity_client_id)

            def client_factory(**kwargs: Any) -> Any:
                return ServiceBusClient(credential=credential, **kwargs)

            message_factory = ServiceBusMessage
        self.client_factory = client_factory
        self.message_factory = message_factory

    def publish(self, message: OutboxMessage) -> PublishReceipt:
        service_message = self.message_factory(
            message.body,
            message_id=message.message_id,
            content_type="application/json",
            subject=message.topic,
            session_id=message.finding_id,
            partition_key=message.finding_id,
            correlation_id=message.event_id,
            application_properties={
                "event_sequence": message.event_sequence,
                "payload_sha256": message.sha256,
            },
        )
        try:
            with self.client_factory(
                fully_qualified_namespace=self.namespace,
                retry_total=self.retry_attempts,
                retry_backoff_factor=0.25,
                retry_backoff_max=2,
                socket_timeout=self.timeout_seconds,
            ) as client:
                with client.get_queue_sender(self.queue_name) as sender:
                    sender.send_messages(service_message)
        except Exception as error:
            if type(error).__name__ in self.PERMANENT_ERRORS:
                raise PermanentOutboxError("Service Bus rejected the publisher") from None
            raise TransientOutboxError("Service Bus delivery is unavailable") from None
        return PublishReceipt(message.message_id)

    def ready(self) -> bool:
        return True


class GovernanceOutboxQueue:
    def __init__(self, database: Database) -> None:
        self.database = database

    def claim(
        self, worker_id: str, *, lease_seconds: int = 60, now: float | None = None
    ) -> dict[str, Any] | None:
        if not worker_id.strip() or lease_seconds <= 0:
            raise ValueError("worker_id and a positive lease are required")
        current = time.time() if now is None else now
        token = uuid.uuid4().hex
        select = """
            SELECT item.outbox_id FROM governance_outbox AS item
            WHERE item.delivered_at IS NULL AND item.dead_at IS NULL
              AND item.available_at <= ?
              AND (item.locked_until IS NULL OR item.locked_until <= ?)
              AND NOT EXISTS (
                  SELECT 1 FROM governance_outbox AS earlier
                  WHERE earlier.finding_id = item.finding_id
                    AND earlier.event_sequence < item.event_sequence
                    AND earlier.delivered_at IS NULL
              )
            ORDER BY item.created_at, item.outbox_id
        """
        with closing(self.database.connect()) as db:
            if self.database.dialect == "postgresql":
                row = db.execute(
                    f"""WITH candidate AS ({select} FOR UPDATE SKIP LOCKED LIMIT 1)
                    UPDATE governance_outbox AS item
                    SET attempts = attempts + 1, locked_until = ?,
                        worker_id = ?, lock_token = ?
                    FROM candidate WHERE item.outbox_id = candidate.outbox_id
                    RETURNING item.*""",
                    (current, current, current + lease_seconds, worker_id, token),
                ).fetchone()
            else:
                db.execute("BEGIN IMMEDIATE")
                candidate = db.execute(select + " LIMIT 1", (current, current)).fetchone()
                row = None
                if candidate is not None:
                    db.execute(
                        "UPDATE governance_outbox SET attempts = attempts + 1, "
                        "locked_until = ?, worker_id = ?, lock_token = ? "
                        "WHERE outbox_id = ?",
                        (current + lease_seconds, worker_id, token, candidate["outbox_id"]),
                    )
                    row = db.execute(
                        "SELECT * FROM governance_outbox WHERE outbox_id = ?",
                        (candidate["outbox_id"],),
                    ).fetchone()
            db.commit()
            return None if row is None else dict(row)

    def acknowledge(
        self, item: dict[str, Any], receipt: PublishReceipt, *, now: float | None = None
    ) -> bool:
        if receipt.message_id != item["outbox_id"]:
            raise PermanentOutboxError("broker receipt identity mismatch")
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            row = db.execute(
                "SELECT delivered_at, broker_message_id FROM governance_outbox "
                "WHERE outbox_id = ?" + self.database.for_update(""),
                (item["outbox_id"],),
            ).fetchone()
            if row is None:
                db.rollback()
                return False
            if row["delivered_at"] is not None:
                db.rollback()
                return row["broker_message_id"] == receipt.message_id
            cursor = db.execute(
                "UPDATE governance_outbox SET delivered_at = ?, broker_accepted_at = ?, "
                "broker_message_id = ?, locked_until = NULL, worker_id = NULL, "
                "lock_token = NULL, last_error = NULL WHERE outbox_id = ? "
                "AND delivered_at IS NULL AND dead_at IS NULL AND worker_id = ? "
                "AND lock_token = ? AND locked_until > ?",
                (
                    current, current, receipt.message_id, item["outbox_id"],
                    item["worker_id"], item["lock_token"], current,
                ),
            )
            db.commit()
            return cursor.rowcount == 1

    def fail(
        self,
        item: dict[str, Any],
        error: Exception,
        *,
        permanent: bool = False,
        max_attempts: int = 5,
        retry_delay: int = 30,
        now: float | None = None,
    ) -> str:
        if max_attempts < 1 or retry_delay < 0:
            raise ValueError("outbox retry policy is invalid")
        current = time.time() if now is None else now
        dead = permanent or int(item["attempts"]) >= max_attempts
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "UPDATE governance_outbox SET available_at = ?, dead_at = ?, "
                "locked_until = NULL, worker_id = NULL, lock_token = NULL, "
                "last_error = ? WHERE outbox_id = ? AND delivered_at IS NULL "
                "AND dead_at IS NULL AND worker_id = ? AND lock_token = ? "
                "AND locked_until > ?",
                (
                    current + (0 if dead else retry_delay), current if dead else None,
                    str(error)[:2000], item["outbox_id"], item["worker_id"],
                    item["lock_token"], current,
                ),
            )
            db.commit()
            if cursor.rowcount != 1:
                return "stale"
            return "dead" if dead else "retry"

    def heartbeat(
        self, worker_id: str, status: str = "running", *, now: float | None = None
    ) -> None:
        if not worker_id.strip() or status not in {"running", "degraded"}:
            raise ValueError("worker heartbeat is invalid")
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            db.execute(
                "INSERT INTO outbox_worker_heartbeats(worker_id, heartbeat_at, status) "
                "VALUES (?, ?, ?) ON CONFLICT(worker_id) DO UPDATE SET "
                "heartbeat_at = excluded.heartbeat_at, status = excluded.status",
                (worker_id, current, status),
            )
            db.commit()

    def metrics(self, *, now: float | None = None) -> dict[str, int | float]:
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            row = db.execute(
                "SELECT "
                "SUM(CASE WHEN delivered_at IS NOT NULL THEN 1 ELSE 0 END) delivered, "
                "SUM(CASE WHEN delivered_at IS NULL AND dead_at IS NULL THEN 1 ELSE 0 END) pending, "
                "SUM(CASE WHEN dead_at IS NOT NULL THEN 1 ELSE 0 END) dead, "
                "SUM(CASE WHEN delivered_at IS NULL AND dead_at IS NULL "
                "AND last_error IS NOT NULL THEN 1 ELSE 0 END) retrying, "
                "MIN(CASE WHEN delivered_at IS NULL AND dead_at IS NULL THEN created_at END) oldest "
                "FROM governance_outbox"
            ).fetchone()
            db.rollback()
        oldest = row["oldest"]
        return {
            "delivered": int(row["delivered"] or 0),
            "pending": int(row["pending"] or 0),
            "dead": int(row["dead"] or 0),
            "retrying": int(row["retrying"] or 0),
            "oldest_pending_age_seconds": 0.0 if oldest is None else max(0.0, current - float(oldest)),
        }

    def ready(
        self,
        *,
        heartbeat_max_age: int,
        delivery_lag_max_age: int,
        now: float | None = None,
    ) -> bool:
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            heartbeat = db.execute(
                "SELECT heartbeat_at, status FROM outbox_worker_heartbeats "
                "ORDER BY heartbeat_at DESC LIMIT 1"
            ).fetchone()
            db.rollback()
        metrics = self.metrics(now=current)
        return bool(
            heartbeat
            and heartbeat["status"] == "running"
            and float(heartbeat["heartbeat_at"]) > current - heartbeat_max_age
            and metrics["dead"] == 0
            and metrics["retrying"] == 0
            and metrics["oldest_pending_age_seconds"] <= delivery_lag_max_age
        )

    def requeue_dead(
        self, outbox_id: str, confirmation: str, *, now: float | None = None
    ) -> bool:
        if ID_PATTERN.fullmatch(outbox_id) is None:
            raise ValueError("outbox_id is invalid")
        if confirmation != f"REQUEUE OUTBOX {outbox_id}":
            raise PermissionError("exact outbox requeue confirmation is required")
        current = time.time() if now is None else now
        with closing(self.database.connect()) as db:
            cursor = db.execute(
                "UPDATE governance_outbox SET attempts = 0, available_at = ?, "
                "dead_at = NULL, locked_until = NULL, worker_id = NULL, "
                "lock_token = NULL, last_error = NULL WHERE outbox_id = ? "
                "AND delivered_at IS NULL AND dead_at IS NOT NULL",
                (current, outbox_id),
            )
            db.commit()
            return cursor.rowcount == 1


class OutboxWorker:
    def __init__(self, queue: GovernanceOutboxQueue, publisher: OutboxPublisher, worker_id: str) -> None:
        if not worker_id.strip():
            raise ValueError("worker_id is required")
        self.queue = queue
        self.publisher = publisher
        self.worker_id = worker_id

    def run_once(
        self,
        *,
        lease_seconds: int = 60,
        max_attempts: int = 5,
        retry_delay: int = 30,
        now: float | None = None,
    ) -> str:
        self.queue.heartbeat(self.worker_id, now=now)
        item = self.queue.claim(self.worker_id, lease_seconds=lease_seconds, now=now)
        if item is None:
            self.queue.heartbeat(self.worker_id, "running", now=now)
            return "empty"
        try:
            message = OutboxMessage.from_item(item)
            receipt = self.publisher.publish(message)
            result = "delivered" if self.queue.acknowledge(item, receipt, now=now) else "stale"
        except PermanentOutboxError as error:
            result = self.queue.fail(item, error, permanent=True, now=now)
        except Exception as error:
            result = self.queue.fail(
                item, error, max_attempts=max_attempts,
                retry_delay=retry_delay, now=now,
            )
        self.queue.heartbeat(
            self.worker_id,
            "running" if result == "delivered" else "degraded",
            now=now,
        )
        return result
