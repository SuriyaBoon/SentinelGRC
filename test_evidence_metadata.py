import tempfile
import unittest
from pathlib import Path

from evidence_metadata import EvidenceMetadataStore


class EvidenceMetadataTests(unittest.TestCase):
    def test_metadata_is_hashed_and_role_gated(self):
        with tempfile.TemporaryDirectory() as temp:
            store = EvidenceMetadataStore(str(Path(temp) / "evidence.db"))
            record = store.register("F-1", "ticket", "sensitive proof", "confidential", "alice")
            self.assertEqual(len(record["sha256"]), 64)
            self.assertNotIn("sensitive proof", str(record))
            self.assertEqual(store.authorize_download(record["evidence_id"], "bob", "analyst")["finding_id"], "F-1")
            with self.assertRaises(PermissionError):
                store.authorize_download(record["evidence_id"], "guest", "viewer")

    def test_review_status_is_constrained(self):
        with tempfile.TemporaryDirectory() as temp:
            store = EvidenceMetadataStore(str(Path(temp) / "evidence.db"))
            record = store.register("F-1", "ticket", "proof", "internal", "alice")
            with self.assertRaises(ValueError):
                store.mark_reviewed(record["evidence_id"], "unknown")
            store.mark_reviewed(record["evidence_id"], "accepted")
