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

    def test_typed_human_agent_and_system_actors_are_authenticated(self):
        from audit_log import AuthenticatedActor
        with tempfile.TemporaryDirectory() as directory:
            log = AuditLog(str(Path(directory) / "audit.jsonl"))
            human = AuthenticatedActor("alice", "human", "approver", "oidc")
            agent = AuthenticatedActor("agent-1", "agent", auth_method="hmac")
            system = AuthenticatedActor("scheduler", "system", auth_method="service")
            human_record = log.append_human_event("approval.granted", human, "F-1")
            agent_record = log.append_agent_event("evidence.ingested", agent, "E-1")
            system_record = log.append_system_event("exception.expired", system, "F-1")
            self.assertEqual(human_record["actor"]["role"], "approver")
            self.assertEqual(agent_record["actor"]["actor_type"], "agent")
            self.assertEqual(system_record["actor"]["auth_method"], "service")
            self.assertTrue(log.verify()[0])

    def test_typed_actor_kind_is_enforced(self):
        from audit_log import AuthenticatedActor
        with tempfile.TemporaryDirectory() as directory:
            log = AuditLog(str(Path(directory) / "audit.jsonl"))
            with self.assertRaises(ValueError):
                log.append_human_event("bad", AuthenticatedActor("agent", "agent", auth_method="hmac"), "x")


if __name__ == "__main__":
    unittest.main()