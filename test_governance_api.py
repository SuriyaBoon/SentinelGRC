import tempfile
import unittest
from pathlib import Path

from governance_api import GovernanceApi
from governance_core import GovernanceCore
from human_identity import HumanIdentityStore


class GovernanceApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.core = GovernanceCore(str(root / "governance.db"))
        self.identities = HumanIdentityStore(str(root / "identity.db"))
        self.identities.create_user("alice", "analyst")
        self.secret = self.identities.issue_api_key("alice", "alice-v1")
        self.api = GovernanceApi(self.core, self.identities)

    def tearDown(self):
        self.temp.cleanup()

    def test_dispatch_resolves_actor_from_key_and_rejects_body_actor(self):
        result = self.api.dispatch("create", "alice-v1", self.secret, {
            "finding_id": "F-API", "control_id": "AC-API", "asset_id": "APP-API",
            "title": "Missing control", "risk_owner": "owner", "severity": "high",
        })
        self.assertEqual(result["status"], "open")
        with self.assertRaises(ValueError):
            self.api.dispatch("create", "alice-v1", self.secret, {
                "finding_id": "F-2", "control_id": "AC", "asset_id": "APP",
                "title": "Bad actor", "risk_owner": "owner", "severity": "low",
                "approved_by": "attacker",
            })

    def test_invalid_key_is_rejected_before_lifecycle(self):
        with self.assertRaises(PermissionError):
            self.api.dispatch("report", "alice-v1", "wrong", {})

    def test_verify_requires_boolean_passed_value(self):
        with self.assertRaises(ValueError):
            self.api.dispatch("verify", "alice-v1", self.secret, {
                "finding_id": "F-API", "passed": "false",
            })
