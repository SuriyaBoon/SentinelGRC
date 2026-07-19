import tempfile
import unittest
from pathlib import Path

from governance_core import ActorContext, GovernanceCore


class GovernanceCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.core = GovernanceCore(str(Path(self.temp.name) / "governance.db"))
        self.analyst = ActorContext("alice", "analyst")
        self.owner = ActorContext("owner-1", "risk_owner")
        self.approver = ActorContext("bob", "approver")
        self.verifier = ActorContext("carol", "analyst")

    def tearDown(self):
        self.temp.cleanup()

    def test_definition_of_done_lifecycle_and_chain(self):
        finding = self.core.create_finding("F-001", "AC-01", "APP-01",
                                            "MFA is not enabled", "owner-1", "high", self.analyst)
        self.assertEqual(finding["status"], "open")
        self.core.assess_risk("F-001", self.owner, "high", "high")
        self.core.propose_treatment("F-001", self.owner, "mitigate", "Enable MFA", "team-identity", "2026-08-01")
        self.core.approve_treatment("F-001", self.approver, "approved", "approved by control owner")
        self.core.start_action("F-001", self.owner, "engineer-1")
        self.core.submit_evidence("F-001", self.owner, "change-ticket", "ticket-123")
        self.core.verify("F-001", self.verifier, True, "MFA verified in production")
        self.assertEqual(self.core.close("F-001", self.approver)["status"], "closed")
        self.assertTrue(self.core.verify_event_chain("F-001"))
        self.assertEqual(len(self.core.list_events("F-001")), 8)

    def test_separation_of_duties_and_invalid_closure(self):
        self.core.create_finding("F-002", "AC-02", "APP-02",
                                 "Stale account", "owner-2", "critical", self.analyst)
        with self.assertRaises(ValueError):
            self.core.close("F-002", self.approver)
        self.core.assess_risk("F-002", ActorContext("owner-2", "risk_owner"), "medium", "high")
        self.core.propose_treatment("F-002", ActorContext("owner-2", "risk_owner"), "accept", "temporary exception", "team-id")
        with self.assertRaises(PermissionError):
            self.core.approve_treatment("F-002", ActorContext("owner-2", "approver"), "approved")
        self.core.approve_treatment("F-002", self.approver, "approved")
        self.core.start_action("F-002", ActorContext("owner-2", "risk_owner"), "engineer-2")
        self.core.submit_evidence("F-002", ActorContext("owner-2", "risk_owner"), "ticket", "proof")
        with self.assertRaises(PermissionError):
            self.core.verify("F-002", ActorContext("engineer-2", "analyst"), True)
        self.assertFalse(self.core.verify("F-002", self.verifier, False)["status"] == "closed")

    def test_actor_is_server_side_context(self):
        with self.assertRaises(ValueError):
            ActorContext("", "analyst")
        with self.assertRaises(ValueError):
            ActorContext("alice", "unknown")
