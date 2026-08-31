import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from audit_archive import MemoryAuditArchive
from audit_delivery import AuditExportQueue, AuditExportWorker
from outbox_delivery import OutboxMessage, PublishReceipt
from connectors import ConnectorEventConflictError, ingest_event, sign_event
from governance_core import ActorContext, GovernanceCore
from migration_runner import PostgresMigrationRunner
from persistence import Database
from postgres_runtime_state import (
    GovernanceOutbox,
    PostgresConnectorEventStore,
    PostgresJobQueue,
)


POSTGRES_URL = os.getenv("SENTINEL_TEST_POSTGRES_URL", "")


@unittest.skipUnless(
    POSTGRES_URL, "SENTINEL_TEST_POSTGRES_URL is required"
)
class PostgresRuntimeStateTests(unittest.TestCase):
    def setUp(self):
        self.database = Database(
            POSTGRES_URL, pool_min_size=1, pool_max_size=16
        )
        PostgresMigrationRunner(
            self.database,
            str(Path(__file__).parent / "migrations" / "postgresql"),
        ).apply()
        with closing(self.database.connect()) as db:
            db.execute(
                "TRUNCATE TABLE audit_exports, governance_outbox, pipeline_jobs, "
                "connector_events, closure_records, verification_records, "
                "governance_evidence, action_items, approval_records, "
                "risk_treatments, risk_records, governance_events, findings "
                "CASCADE"
            )
            db.commit()

    def tearDown(self):
        self.database.close()

    def test_authenticated_connector_replay_is_source_scoped_and_concurrent(self):
        store = PostgresConnectorEventStore(self.database)
        with self.assertRaises(ValueError):
            store.reserve("event-invalid", "source", "x" * 64)
        raw = b'{"kind":"alert"}'
        signature = sign_event(raw, "secret")

        def ingest(_):
            return ingest_event(
                raw,
                source="logwatcher",
                event_id="event-1",
                signature=signature,
                secret="secret",
                store=store,
            )["status"]

        with ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(ingest, range(8)))
        self.assertEqual(statuses.count("accepted"), 1)
        self.assertEqual(statuses.count("duplicate"), 7)
        other = ingest_event(
            raw,
            source="siem",
            event_id="event-1",
            signature=signature,
            secret="secret",
            store=store,
        )
        self.assertEqual(other["status"], "accepted")
        changed = b'{"kind":"changed"}'
        changed_signature = sign_event(changed, "secret")
        with self.assertRaises(ConnectorEventConflictError):
            ingest_event(
                changed,
                source="logwatcher",
                event_id="event-1",
                signature=changed_signature,
                secret="secret",
                store=store,
            )
        with self.assertRaises(PermissionError):
            ingest_event(
                raw,
                source="unauthenticated",
                event_id="event-2",
                signature="invalid",
                secret="secret",
                store=store,
            )
        with closing(self.database.connect()) as db:
            count = db.execute(
                "SELECT COUNT(*) AS count FROM connector_events"
            ).fetchone()["count"]
            db.rollback()
        self.assertEqual(count, 2)

    def test_skip_locked_queue_claims_once_and_fences_stale_workers(self):
        queue = PostgresJobQueue(self.database)
        for index in range(12):
            self.assertTrue(queue.enqueue(f"payload-{index}", now=0))

        def process(worker):
            claimed = []
            while True:
                job = queue.claim(worker, lease_seconds=30, now=1)
                if job is None:
                    return claimed
                self.assertTrue(
                    queue.complete(
                        job["job_id"], worker, job["lock_token"], now=2
                    )
                )
                claimed.append(job["payload_path"])

        with ThreadPoolExecutor(max_workers=4) as executor:
            groups = list(executor.map(process, [f"worker-{i}" for i in range(4)]))
        processed = [item for group in groups for item in group]
        self.assertEqual(len(processed), 12)
        self.assertEqual(len(set(processed)), 12)

        self.assertTrue(queue.enqueue("reclaim", now=10))
        first = queue.claim("worker-old", lease_seconds=5, now=10)
        second = queue.claim("worker-new", lease_seconds=5, now=16)
        self.assertFalse(
            queue.complete(
                first["job_id"], "worker-old", first["lock_token"], now=17
            )
        )
        self.assertTrue(
            queue.complete(
                second["job_id"], "worker-new", second["lock_token"], now=17
            )
        )

    def test_queue_retry_dead_letter_and_outbox_ack_are_idempotent(self):
        queue = PostgresJobQueue(self.database)
        queue.enqueue("dead-letter", now=0)
        job = queue.claim("worker", lease_seconds=10, now=1)
        self.assertEqual(
            queue.fail(
                job["job_id"],
                "worker",
                job["lock_token"],
                "failure",
                max_attempts=1,
                now=2,
            ),
            "dead",
        )
        self.assertEqual(queue.metadata()["dead"], 1)

        core = GovernanceCore(database=self.database)
        core.create_finding(
            "OUTBOX-1",
            "CTRL-1",
            "ASSET-1",
            "Outbox proof",
            "owner-1",
            "high",
            ActorContext("analyst-1", "analyst"),
        )
        outbox = GovernanceOutbox(self.database)
        item = outbox.claim("publisher", lease_seconds=30, now=10**10)
        self.assertIsNotNone(item)
        receipt = PublishReceipt(OutboxMessage.from_item(item).message_id)
        self.assertTrue(outbox.acknowledge(item, receipt, now=10**10 + 1))
        self.assertTrue(
            outbox.acknowledge(item, receipt, now=10**10 + 2)
        )

    def test_governance_event_and_outbox_roll_back_atomically(self):
        core = GovernanceCore(database=self.database)
        original = core._event

        def fail_after_outbox(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("forced rollback")

        actor = ActorContext("analyst-2", "analyst")
        with patch.object(core, "_event", side_effect=fail_after_outbox):
            with self.assertRaisesRegex(RuntimeError, "forced rollback"):
                core.create_finding(
                    "ROLLBACK-OUTBOX",
                    "CTRL-2",
                    "ASSET-2",
                    "Atomic rollback",
                    "owner-2",
                    "medium",
                    actor,
                )
        with closing(self.database.connect()) as db:
            finding_count = db.execute(
                "SELECT COUNT(*) AS count FROM findings "
                "WHERE finding_id = ?",
                ("ROLLBACK-OUTBOX",),
            ).fetchone()["count"]
            outbox_count = db.execute(
                "SELECT COUNT(*) AS count FROM governance_outbox"
            ).fetchone()["count"]
            db.rollback()
        self.assertEqual(finding_count, 0)
        self.assertEqual(outbox_count, 0)

    def test_postgres_audit_exports_are_claimed_and_archived_in_order(self):
        core = GovernanceCore(database=self.database)
        actor = ActorContext("analyst-archive", "analyst")
        core.create_finding(
            "AUDIT-PG-1",
            "CTRL-AUDIT",
            "ASSET-AUDIT",
            "PostgreSQL audit archive",
            "owner-audit",
            "high",
            actor,
        )
        core.assess_risk(
            "AUDIT-PG-1",
            ActorContext("owner-audit", "risk_owner"),
            "high",
            "high",
        )
        queue = AuditExportQueue(self.database)
        worker = AuditExportWorker(
            queue,
            MemoryAuditArchive(),
            "postgres-audit-worker",
        )
        self.assertEqual(worker.run_once(now=10**10), "archived")
        self.assertEqual(worker.run_once(now=10**10 + 1), "archived")
        self.assertEqual(worker.run_once(now=10**10 + 2), "empty")
        self.assertEqual(
            queue.metrics(),
            {"archived": 2, "pending": 0, "dead": 0},
        )
