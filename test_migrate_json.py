import tempfile
import unittest
from pathlib import Path

from governance_core import ActorContext, GovernanceCore
from migrate_json import migrate_queue


class JsonMigrationTests(unittest.TestCase):
    def test_legacy_queue_is_migrated_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            core = GovernanceCore(str(Path(directory) / "governance.db"))
            queue = {"asset_id": "APP-1", "findings": [{
                "finding_id": "APP-1:AC-1",
                "asset": {"asset_id": "APP-1"},
                "control": {"id": "AC-1", "control_name": "MFA", "owner": "IAM", "severity": "high"},
            }]}
            actor = ActorContext("migration", "admin", "api_key")
            self.assertEqual(migrate_queue(queue, core, actor), 1)
            self.assertEqual(migrate_queue(queue, core, actor), 1)
            self.assertEqual(core.export_summary()["total"], 1)
            self.assertEqual(len(core.list_events("APP-1:AC-1")), 2)

    def test_unauthorized_migration_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            core = GovernanceCore(str(Path(directory) / "governance.db"))
            with self.assertRaises(PermissionError):
                migrate_queue({"findings": []}, core, ActorContext("owner", "risk_owner"))
