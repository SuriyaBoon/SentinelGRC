import tempfile
import unittest
from pathlib import Path

from agent_keys import AgentKeyRegistry


class AgentKeyTests(unittest.TestCase):
    def test_register_returns_secret_once_and_revoke_disables_key(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            key_id, secret = registry.register("WS-001", "ws-001-v1")
            self.assertEqual(key_id, "ws-001-v1")
            self.assertTrue(secret)
            self.assertTrue(registry.is_active(key_id))
            registry.revoke(key_id)
            self.assertFalse(registry.is_active(key_id))


if __name__ == "__main__":
    unittest.main()
