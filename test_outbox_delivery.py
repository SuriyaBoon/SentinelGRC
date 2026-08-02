import json
import tempfile
import time
import unittest
from pathlib import Path

from governance_core import ActorContext, GovernanceCore
from outbox_delivery import (
    AzureServiceBusPublisher,
    GovernanceOutboxQueue,
    LocalOutboxPublisher,
    MemoryOutboxPublisher,
    OutboxMessage,
    OutboxWorker,
    PermanentOutboxError,
    TransientOutboxError,
)
from persistence import Database


class FailingPublisher:
    def __init__(self, error):
        self.error = error

    def publish(self, message):
        raise self.error

    def ready(self):
        return False


class CountingPublisher(MemoryOutboxPublisher):
    def __init__(self):
        super().__init__()
        self.calls = 0

    def publish(self, message):
        self.calls += 1
        return super().publish(message)


class FakeMessage:
    def __init__(self, body, **kwargs):
        self.body = body
        self.properties = kwargs


class FakeSender:
    def __init__(self):
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def send_messages(self, message):
        self.sent.append(message)


class FakeClient:
    def __init__(self, captured, **kwargs):
        self.captured = captured
        self.captured.update(kwargs)
        self.sender = FakeSender()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get_queue_sender(self, queue):
        self.captured["queue"] = queue
        self.captured["sender"] = self.sender
        return self.sender


class OutboxDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = Database.from_target(str(Path(self.temp.name) / "governance.db"))
        self.core = GovernanceCore(database=self.database)
        self.actor = ActorContext("analyst", "analyst")

    def tearDown(self):
        self.database.close()
        self.temp.cleanup()

    def create(self, finding_id="OUTBOX-1"):
        self.core.create_finding(
            finding_id, "CTRL-1", "ASSET-1", "Outbox delivery", "owner",
            "high", self.actor,
        )

    def test_local_worker_delivers_canonical_message_and_acknowledges(self):
        self.create()
        queue = GovernanceOutboxQueue(self.database)
        publisher = LocalOutboxPublisher(str(Path(self.temp.name) / "published"))
        worker = OutboxWorker(queue, publisher, "worker")
        self.assertEqual(worker.run_once(now=10**10), "delivered")
        self.assertEqual(worker.run_once(now=10**10 + 1), "empty")
        metrics = queue.metrics(now=10**10 + 1)
        self.assertEqual(metrics["delivered"], 1)
        self.assertEqual(metrics["pending"], 0)
        files = list((Path(self.temp.name) / "published").glob("*.json"))
        self.assertEqual(len(files), 1)
        payload = json.loads(files[0].read_text(encoding="utf-8"))
        self.assertEqual(payload["finding_id"], "OUTBOX-1")
        self.assertEqual(payload["event_sequence"], 1)

    def test_crash_after_publish_replays_same_identity_without_duplicate(self):
        self.create("OUTBOX-CRASH")
        queue = GovernanceOutboxQueue(self.database)
        publisher = MemoryOutboxPublisher()
        base = time.time()
        crashed = queue.claim("crashed", lease_seconds=5, now=base)
        first = OutboxMessage.from_item(crashed)
        publisher.publish(first)
        worker = OutboxWorker(queue, publisher, "recovery")
        self.assertEqual(worker.run_once(lease_seconds=5, now=base + 6), "delivered")
        self.assertEqual(len(publisher.messages), 1)

    def test_publisher_interruption_never_acknowledges_and_then_recovers(self):
        self.create("OUTBOX-INTERRUPTED")
        queue = GovernanceOutboxQueue(self.database)
        base = time.time()
        interrupted = OutboxWorker(
            queue,
            FailingPublisher(TransientOutboxError("publisher unavailable")),
            "interrupted",
        )
        self.assertEqual(
            interrupted.run_once(max_attempts=3, retry_delay=1, now=base),
            "retry",
        )
        metrics = queue.metrics(now=base)
        self.assertEqual(metrics["delivered"], 0)
        self.assertEqual(metrics["pending"], 1)
        self.assertEqual(metrics["retrying"], 1)
        recovered_publisher = CountingPublisher()
        recovered = OutboxWorker(queue, recovered_publisher, "recovered")
        self.assertEqual(recovered.run_once(now=base + 1), "delivered")
        self.assertEqual(recovered_publisher.calls, 1)
        self.assertEqual(queue.metrics(now=base + 1)["delivered"], 1)

    def test_database_claim_failure_cannot_publish_or_acknowledge(self):
        self.create("OUTBOX-DB-DOWN")
        queue = GovernanceOutboxQueue(self.database)
        publisher = CountingPublisher()
        worker = OutboxWorker(queue, publisher, "worker")
        original_claim = queue.claim
        queue.claim = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        )
        with self.assertRaisesRegex(RuntimeError, "database unavailable"):
            worker.run_once()
        self.assertEqual(publisher.calls, 0)
        queue.claim = original_claim
        self.assertEqual(worker.run_once(), "delivered")
        self.assertEqual(publisher.calls, 1)

    def test_fencing_ordering_retry_dead_letter_and_exact_requeue(self):
        self.create("OUTBOX-ORDER")
        self.core.assess_risk(
            "OUTBOX-ORDER", ActorContext("owner", "risk_owner"), "high", "high"
        )
        queue = GovernanceOutboxQueue(self.database)
        base = 10**10
        first = queue.claim("old", lease_seconds=5, now=base)
        self.assertEqual(first["event_sequence"], 1)
        self.assertIsNone(queue.claim("blocked", lease_seconds=5, now=base + 1))
        self.assertEqual(
            queue.fail(first, TransientOutboxError("temporary"), max_attempts=2, retry_delay=1, now=base + 1),
            "retry",
        )
        retry = queue.claim("new", lease_seconds=5, now=base + 2)
        self.assertEqual(
            queue.fail(retry, TransientOutboxError("temporary"), max_attempts=2, now=base + 3),
            "dead",
        )
        self.assertIsNone(queue.claim("still-blocked", now=base + 4))
        outbox_id = retry["outbox_id"]
        with self.assertRaises(PermissionError):
            queue.requeue_dead(outbox_id, f"REQUEUE {outbox_id}", now=base + 5)
        self.assertTrue(
            queue.requeue_dead(outbox_id, f"REQUEUE OUTBOX {outbox_id}", now=base + 5)
        )
        replay = queue.claim("latest", lease_seconds=5, now=base + 6)
        self.assertFalse(queue.acknowledge(first, MemoryOutboxPublisher().publish(OutboxMessage.from_item(first)), now=base + 7))
        self.assertEqual(replay["event_sequence"], 1)

    def test_invalid_payload_is_dead_lettered_without_retry(self):
        self.create("OUTBOX-TAMPER")
        db = self.database.connect()
        try:
            db.execute("UPDATE governance_outbox SET payload_json = '{}' ")
            db.commit()
        finally:
            db.close()
        queue = GovernanceOutboxQueue(self.database)
        worker = OutboxWorker(queue, MemoryOutboxPublisher(), "worker")
        self.assertEqual(worker.run_once(now=10**10), "dead")
        self.assertEqual(queue.metrics(now=10**10)["dead"], 1)

    def test_worker_health_is_fail_closed_for_stale_or_dead_delivery(self):
        self.create("OUTBOX-READY")
        queue = GovernanceOutboxQueue(self.database)
        base = time.time()
        self.assertFalse(queue.ready(heartbeat_max_age=60, delivery_lag_max_age=300, now=base))
        queue.heartbeat("worker", now=base)
        self.assertTrue(queue.ready(heartbeat_max_age=60, delivery_lag_max_age=300, now=base))
        self.assertFalse(queue.ready(heartbeat_max_age=60, delivery_lag_max_age=300, now=base + 61))
        item = queue.claim("worker", now=base)
        queue.fail(item, PermanentOutboxError("invalid"), permanent=True, now=base + 1)
        queue.heartbeat("worker", now=base + 1)
        self.assertFalse(queue.ready(heartbeat_max_age=60, delivery_lag_max_age=300, now=base + 1))

    def test_azure_publisher_uses_stable_session_message_and_bounded_client(self):
        self.create("OUTBOX-AZURE")
        item = GovernanceOutboxQueue(self.database).claim("worker", now=10**10)
        message = OutboxMessage.from_item(item)
        captured = {}
        publisher = AzureServiceBusPublisher(
            "sentinel-prod.servicebus.windows.net",
            "governance-outbox",
            managed_identity_client_id="managed-id",
            timeout_seconds=7,
            retry_attempts=2,
            client_factory=lambda **kwargs: FakeClient(captured, **kwargs),
            message_factory=FakeMessage,
        )
        receipt = publisher.publish(message)
        self.assertEqual(receipt.message_id, item["outbox_id"])
        self.assertEqual(captured["retry_total"], 2)
        self.assertEqual(captured["socket_timeout"], 7)
        self.assertEqual(captured["queue"], "governance-outbox")
        sent = captured["sender"].sent[0]
        self.assertEqual(sent.properties["message_id"], item["outbox_id"])
        self.assertEqual(sent.properties["session_id"], "OUTBOX-AZURE")
        self.assertEqual(sent.properties["partition_key"], "OUTBOX-AZURE")

    def test_azure_publisher_rejects_urls_credentials_and_invalid_queue(self):
        for namespace in (
            "https://sentinel.servicebus.windows.net",
            "user:secret@sentinel.servicebus.windows.net",
            "evil.example.com",
        ):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                AzureServiceBusPublisher(
                    namespace, "queue", managed_identity_client_id="managed-id",
                    client_factory=lambda **kwargs: None,
                    message_factory=FakeMessage,
                )


if __name__ == "__main__":
    unittest.main()
