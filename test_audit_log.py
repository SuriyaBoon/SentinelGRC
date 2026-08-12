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
            invalid_actor = AuthenticatedActor("agent", "agent", auth_method="hmac")
            with self.assertRaises(ValueError):
                log.append_human_event("bad", invalid_actor, "x")

    def test_idempotent_append_reuses_exact_event_and_rejects_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            log = AuditLog(str(path))
            first, first_added = log.append_idempotent(
                "stable-event-1", "finding.created", "connector", "F-1", {"x": 1}
            )
            replay, replay_added = log.append_idempotent(
                "stable-event-1", "finding.created", "connector", "F-1", {"x": 1}
            )

            self.assertTrue(first_added)
            self.assertFalse(replay_added)
            self.assertEqual(first, replay)
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)
            with self.assertRaises(ValueError):
                log.append_idempotent(
                    "stable-event-1", "finding.reassessed", "connector", "F-1", {"x": 1}
                )


if __name__ == "__main__":
    unittest.main()
