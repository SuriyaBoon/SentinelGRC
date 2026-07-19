import json
import tempfile
import unittest
from pathlib import Path

from governance_api import GovernanceApi
from governance_core import GovernanceCore
from governance_http import GovernanceHttpApplication
from human_identity import HumanIdentityStore


class GovernanceHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        identities = HumanIdentityStore(str(root / "identity.db"))
        identities.create_user("alice", "analyst")
        self.secret = identities.issue_api_key("alice", "alice-v1")
        self.app = GovernanceHttpApplication(
            GovernanceApi(GovernanceCore(str(root / "governance.db")), identities)
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_health_and_authenticated_governance_route(self):
        self.assertEqual(self.app.handle("GET", "/healthz", {}, b"")[0], 200)
        status, result = self.app.handle(
            "POST", "/v1/governance/create",
            {"X-API-Key-ID": "alice-v1", "Authorization": f"Bearer {self.secret}"},
            json.dumps({
                "finding_id": "F-HTTP", "control_id": "AC-HTTP", "asset_id": "APP-HTTP",
                "title": "Missing control", "risk_owner": "owner", "severity": "high",
            }).encode(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["finding_id"], "F-HTTP")

    def test_invalid_auth_and_route_are_rejected(self):
        self.assertEqual(self.app.handle("GET", "/wrong", {}, b"")[0], 404)
        status, _ = self.app.handle("POST", "/v1/governance/report", {}, b"{}")
        self.assertEqual(status, 401)
