import tempfile
import unittest
from pathlib import Path

from human_identity import HumanIdentityStore


class HumanIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = HumanIdentityStore(str(Path(self.temp.name) / "identity.db"))

    def tearDown(self):
        self.temp.cleanup()

    def test_secret_is_issued_once_and_actor_is_server_resolved(self):
        self.store.create_user("alice", "risk_owner")
        secret = self.store.issue_api_key("alice", "alice-v1")
        actor = self.store.authenticate("alice-v1", secret)
        self.assertEqual(actor.actor_id, "alice")
        self.assertEqual(actor.role, "risk_owner")
        self.assertEqual(actor.auth_method, "api_key")

    def test_revocation_and_invalid_secret_are_rejected(self):
        self.store.create_user("bob", "approver")
        secret = self.store.issue_api_key("bob", "bob-v1")
        with self.assertRaises(PermissionError):
            self.store.authenticate("bob-v1", "wrong")
        self.store.revoke_key("bob-v1")
        with self.assertRaises(PermissionError):
            self.store.authenticate("bob-v1", secret)

    def test_secret_material_is_not_stored_as_plaintext(self):
        self.store.create_user("carol", "analyst")
        secret = self.store.issue_api_key("carol", "carol-v1")
        self.assertNotIn(secret, Path(self.store.path).read_bytes().decode("utf-8", errors="ignore"))
