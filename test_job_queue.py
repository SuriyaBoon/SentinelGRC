import tempfile
import unittest
from pathlib import Path

from job_queue import SQLiteJobQueue


class JobQueueTests(unittest.TestCase):
    def test_claim_retry_and_dead_letter(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = SQLiteJobQueue(str(Path(directory) / "queue.db"))
            self.assertTrue(queue.enqueue("bad.json", now=1000))
            self.assertFalse(queue.enqueue("bad.json", now=1001))
            job = queue.claim("worker-a", lease_seconds=30, now=1000)
            self.assertEqual(job["attempts"], 1)
            self.assertTrue(queue.renew(job["job_id"], "worker-a", lease_seconds=300, now=1001))
            self.assertEqual(queue.fail(job["job_id"], "bad payload", max_attempts=2, retry_delay=10, now=1000), "pending")
            retry = queue.claim("worker-b", now=1011)
            self.assertEqual(retry["attempts"], 2)
            self.assertEqual(queue.fail(retry["job_id"], "still bad", max_attempts=2, now=1011), "dead")
            self.assertEqual(queue.metadata()["dead"], 1)


if __name__ == "__main__":
    unittest.main()