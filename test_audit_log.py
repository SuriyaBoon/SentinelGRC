import tempfile
import unittest
from pathlib import Path

from audit_log import AuditLog


class AuditLogTests(unittest.TestCase):
    def test_hash_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            log = AuditLog(str(Path(directory) / "audit.jsonl"))
            log.append("pipeline.completed", "worker", "PL-001", {"tickets": 2})
            log.append("ticket.created", "worker", "SG-001", {})
            self.assertEqual(log.verify(), (True, "Audit log integrity verified."))
            path = Path(directory) / "audit.jsonl"
            text = path.read_text(encoding="utf-8").replace("SG-001", "SG-TAMPERED")
            path.write_text(text, encoding="utf-8")
            self.assertFalse(log.verify()[0])


if __name__ == "__main__":
    unittest.main()