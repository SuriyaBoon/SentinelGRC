import tempfile
import unittest
from pathlib import Path

from state_store import SQLiteStateStore


class StateStoreTests(unittest.TestCase):
    def test_nonce_survives_new_store_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            db = str(Path(directory) / "state.db")
            first = SQLiteStateStore(db)
            self.assertTrue(first.reserve_nonce("nonce-123", 300, now=1000))
            second = SQLiteStateStore(db)
            self.assertFalse(second.reserve_nonce("nonce-123", 300, now=1001))

    def test_payload_identity_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteStateStore(str(Path(directory) / "state.db"))
            store.remember_payload("hash-1", "evidence-1", now=1000)
            self.assertEqual(store.get_evidence_id("hash-1"), "evidence-1")
            self.assertIsNone(store.get_evidence_id("hash-2"))


if __name__ == "__main__":
    unittest.main()
