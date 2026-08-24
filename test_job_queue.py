import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import job_queue
from job_queue import SQLiteJobQueue
from state_store import SQLITE_LOCK_TIMEOUT_SECONDS


class JobQueueTests(unittest.TestCase):
    def test_claim_retry_and_dead_letter(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            self.assertTrue(queue.enqueue("bad.json", now=1000))
            self.assertFalse(queue.enqueue("bad.json", now=1001))
            job = queue.claim("worker-a", lease_seconds=30, now=1000)
            self.assertEqual(job["attempts"], 1)
            self.assertTrue(queue.renew(job["job_id"], "worker-a", lease_seconds=300, now=1001))
            self.assertEqual(queue.fail(job["job_id"], "worker-a", "bad payload", max_attempts=2, retry_delay=10, now=1000), "pending")
            retry = queue.claim("worker-b", now=1011)
            self.assertEqual(retry["attempts"], 2)
            self.assertEqual(queue.fail(retry["job_id"], "worker-b", "still bad", max_attempts=2, now=1011), "dead")
            self.assertEqual(queue.metadata()["dead"], 1)

    def test_stale_worker_cannot_complete_or_fail_reclaimed_job(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            queue.enqueue("payload.json", now=1000)
            original = queue.claim("worker-a", lease_seconds=10, now=1000)
            reclaimed = queue.claim("worker-b", lease_seconds=30, now=1011)
            self.assertEqual(original["job_id"], reclaimed["job_id"])
            self.assertFalse(queue.complete(original["job_id"], "worker-a", now=1011))
            self.assertEqual(queue.fail(original["job_id"], "worker-a", "stale", now=1011), "lease_lost")
            self.assertTrue(queue.complete(reclaimed["job_id"], "worker-b", now=1011))

    def test_schema_connection_uses_shared_sqlite_lock_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                job_queue.sqlite3, "connect", wraps=sqlite3.connect
            ) as connect_spy:
                queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            self.assertEqual(
                [call.kwargs.get("timeout") for call in connect_spy.call_args_list],
                [SQLITE_LOCK_TIMEOUT_SECONDS],
            )
            self.assertEqual(
                queue.metadata(),
                {"pending": 0, "running": 0, "completed": 0, "dead": 0},
            )

    def test_enqueue_uses_shared_sqlite_lock_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            with mock.patch.object(
                job_queue.sqlite3, "connect", wraps=sqlite3.connect
            ) as connect_spy:
                enqueued = queue.enqueue("payload.json", now=1000)
            self.assertTrue(enqueued)
            self.assertEqual(
                [call.kwargs.get("timeout") for call in connect_spy.call_args_list],
                [SQLITE_LOCK_TIMEOUT_SECONDS],
            )

    def test_claim_uses_shared_sqlite_lock_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            queue.enqueue("payload.json", now=1000)
            with mock.patch.object(
                job_queue.sqlite3, "connect", wraps=sqlite3.connect
            ) as connect_spy:
                job = queue.claim("worker-a", lease_seconds=30, now=1000)
            self.assertIsNotNone(job)
            self.assertEqual(job["payload_path"], "payload.json")
            self.assertEqual(job["attempts"], 1)
            self.assertEqual(
                [call.kwargs.get("timeout") for call in connect_spy.call_args_list],
                [SQLITE_LOCK_TIMEOUT_SECONDS],
            )


if __name__ == "__main__":
    unittest.main()
