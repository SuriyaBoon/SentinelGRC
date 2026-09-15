import tempfile
import unittest
from pathlib import Path

from audit_archive import AuditArchiveError, LocalAuditArchive
from audit_delivery import AuditExportQueue, AuditExportWorker
from governance_core import ActorContext, GovernanceCore
from persistence import Database


class FailingArchive:
    def persist_event(self, event):
        raise AuditArchiveError("audit archive is unavailable")

    def ready(self):
        return False


class AuditDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = Database.from_target(
            str(Path(self.temp.name) / "governance.db")
        )
        self.core = GovernanceCore(database=self.database)
        self.actor = ActorContext("analyst", "analyst")

    def tearDown(self):
        self.database.close()
        self.temp.cleanup()

    def create(self, finding_id):
        return self.core.create_finding(
            finding_id,
            "CTRL-1",
            "ASSET-1",
            "Audit export",
            "owner",
            "high",
            self.actor,
        )

    def test_governance_event_and_export_record_commit_atomically(self):
        self.create("AUDIT-1")
        events = self.core.list_events("AUDIT-1")
        queue = AuditExportQueue(self.database)
        self.assertEqual(len(events), 1)
        self.assertEqual(queue.metrics(), {"archived": 0, "pending": 1, "dead": 0})

    def test_existing_sqlite_events_are_backfilled_on_upgrade(self):
        self.create("AUDIT-UPGRADE")
        connection = self.database.connect()
        try:
            connection.execute("DELETE FROM audit_exports")
            connection.commit()
        finally:
            connection.close()
        GovernanceCore(database=self.database)
        self.assertEqual(
            AuditExportQueue(self.database).metrics(),
            {"archived": 0, "pending": 1, "dead": 0},
        )

    def test_worker_archives_and_replay_after_crash_is_idempotent(self):
        self.create("AUDIT-2")
        queue = AuditExportQueue(self.database)
        archive = LocalAuditArchive(str(Path(self.temp.name) / "archive"))
        base = 10**10
        crashed = queue.claim("crashed", lease_seconds=5, now=base)
        first = archive.persist_event(__import__("json").loads(crashed["payload_json"]))
        reclaimed = queue.claim("worker", lease_seconds=5, now=base + 6)
        replay = archive.persist_event(__import__("json").loads(reclaimed["payload_json"]))
        self.assertEqual(first, replay)
        self.assertTrue(queue.acknowledge(reclaimed, replay, now=base + 7))
        self.assertEqual(queue.metrics(), {"archived": 1, "pending": 0, "dead": 0})
        self.assertEqual(
            AuditExportWorker(queue, archive, "worker").run_once(now=base + 8),
            "empty",
        )

    def test_failed_delivery_retries_then_dead_letters_without_data_loss(self):
        self.create("AUDIT-3")
        queue = AuditExportQueue(self.database)
        worker = AuditExportWorker(queue, FailingArchive(), "worker")
        base = 10**10
        self.assertEqual(
            worker.run_once(max_attempts=2, retry_delay=1, now=base),
            "retry",
        )
        self.assertEqual(
            worker.run_once(max_attempts=2, retry_delay=1, now=base + 1),
            "dead",
        )
        self.assertEqual(queue.metrics(), {"archived": 0, "pending": 0, "dead": 1})
        dead = self.database.connect()
        try:
            export_id = dead.execute(
                "SELECT export_id FROM audit_exports WHERE dead_at IS NOT NULL"
            ).fetchone()["export_id"]
            dead.rollback()
        finally:
            dead.close()
        with self.assertRaises(PermissionError):
            queue.requeue_dead(export_id, "REQUEUE wrong", now=base + 2)
        self.assertTrue(
            queue.requeue_dead(
                export_id,
                f"REQUEUE {export_id}",
                now=base + 2,
            )
        )
        self.assertEqual(queue.metrics(), {"archived": 0, "pending": 1, "dead": 0})

    def test_later_event_waits_for_prior_event_of_same_finding(self):
        self.create("AUDIT-4")
        self.core.assess_risk(
            "AUDIT-4",
            ActorContext("owner", "risk_owner"),
            "high",
            "high",
        )
        queue = AuditExportQueue(self.database)
        base = 10**10
        first = queue.claim("first", lease_seconds=100, now=base)
        self.assertEqual(first["event_sequence"], 1)
        self.assertIsNone(
            queue.claim("second", lease_seconds=100, now=base + 1)
        )
        archive = LocalAuditArchive(str(Path(self.temp.name) / "ordered"))
        stored = archive.persist_event(__import__("json").loads(first["payload_json"]))
        self.assertTrue(queue.acknowledge(first, stored, now=base + 2))
        second = queue.claim("second", lease_seconds=100, now=base + 3)
        self.assertEqual(second["event_sequence"], 2)


if __name__ == "__main__":
    unittest.main()
