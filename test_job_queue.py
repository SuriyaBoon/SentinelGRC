import sqlite3
import tempfile
import unittest
from contextlib import closing
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

    def test_renew_uses_shared_sqlite_lock_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            queue.enqueue("payload.json", now=1000)
            job = queue.claim("worker-a", lease_seconds=300, now=1000)
            with mock.patch.object(
                job_queue.sqlite3, "connect", wraps=sqlite3.connect
            ) as connect_spy:
                renewed = queue.renew(
                    job["job_id"], "worker-a", lease_seconds=300, now=1001
                )
            self.assertTrue(renewed)
            self.assertEqual(
                [call.kwargs.get("timeout") for call in connect_spy.call_args_list],
                [SQLITE_LOCK_TIMEOUT_SECONDS],
            )

    def test_renew_with_explicit_now_keeps_deterministic_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            queue.enqueue("payload.json", now=1000)
            job = queue.claim("worker-a", lease_seconds=300, now=1000)
            self.assertTrue(
                queue.renew(job["job_id"], "worker-a", lease_seconds=300, now=1299)
            )
            self.assertFalse(
                queue.renew(job["job_id"], "worker-a", lease_seconds=300, now=1599)
            )

    def test_renew_samples_implicit_time_after_write_lock_acquisition(self):
        events = []
        real_connect = sqlite3.connect
        real_time = job_queue.time.time

        def ordering_connect(*args, **kwargs):
            target = real_connect(*args, **kwargs)

            class OrderedConnection:
                def execute(self, statement, *execute_args, **execute_kwargs):
                    if statement.strip().upper().startswith("BEGIN IMMEDIATE"):
                        events.append("begin")
                    return target.execute(statement, *execute_args, **execute_kwargs)

                def commit(self):
                    return target.commit()

                def close(self):
                    return target.close()

            return OrderedConnection()

        def ordering_time():
            events.append("time-sampled")
            return real_time()

        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            # Claim with implicit time so the lease is still valid at the
            # real wall-clock moment the implicit renew sampling uses.
            queue.enqueue("payload.json")
            job = queue.claim("worker-a", lease_seconds=300)
            with mock.patch.object(
                job_queue.sqlite3, "connect", side_effect=ordering_connect
            ), mock.patch.object(
                job_queue.time, "time", side_effect=ordering_time
            ):
                renewed = queue.renew(job["job_id"], "worker-a", lease_seconds=300)
            self.assertTrue(renewed)
        self.assertEqual(events, ["begin", "time-sampled"])

    def test_lease_expired_at_post_lock_time_cannot_be_renewed_or_resurrected(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "queue.db"
            queue = SQLiteJobQueue(str(database))
            queue.enqueue("payload.json", now=1000)
            job = queue.claim("worker-a", lease_seconds=60, now=1000)
            # Without explicit now, ownership is judged by the real wall clock,
            # which is far past the synthetic locked_until of 1060.
            self.assertFalse(
                queue.renew(job["job_id"], "worker-a", lease_seconds=300)
            )
            with closing(sqlite3.connect(database)) as connection:
                row = connection.execute(
                    "SELECT locked_until, worker_id, status FROM pipeline_jobs WHERE job_id = ?",
                    (job["job_id"],),
                ).fetchone()
            self.assertEqual(row[0], 1060)
            self.assertEqual(row[1], "worker-a")
            self.assertEqual(row[2], "running")
            reclaimed = queue.claim("worker-b", lease_seconds=300, now=2000)
            self.assertEqual(reclaimed["job_id"], job["job_id"])


if __name__ == "__main__":
    unittest.main()
