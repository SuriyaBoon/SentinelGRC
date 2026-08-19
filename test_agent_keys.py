import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from scripts.agent_keys import (
    ASSET_CONTEXT_WRITE_SCOPE,
    POSTURE_WRITE_SCOPE,
    AgentKeyRegistry,
)


class AgentKeyTests(unittest.TestCase):
    def test_register_defaults_to_posture_scope_and_revoke_disables_key(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            key_id, secret = registry.register("WS-001", "ws-001-v1")
            self.assertEqual(key_id, "ws-001-v1")
            self.assertTrue(secret)
            self.assertTrue(registry.is_authorized(key_id, POSTURE_WRITE_SCOPE))
            self.assertFalse(registry.is_authorized(key_id, ASSET_CONTEXT_WRITE_SCOPE))
            registry.revoke(key_id)
            self.assertFalse(registry.is_active(key_id))
            self.assertFalse(registry.is_authorized(key_id, POSTURE_WRITE_SCOPE))

    def test_explicit_portfolio_scope_does_not_grant_posture_access(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            key_id, _ = registry.register(
                "inventory-connector",
                "inventory-v1",
                scopes=(ASSET_CONTEXT_WRITE_SCOPE,),
            )
            self.assertTrue(registry.is_authorized(key_id, ASSET_CONTEXT_WRITE_SCOPE))
            self.assertFalse(registry.is_authorized(key_id, POSTURE_WRITE_SCOPE))

    def test_existing_registry_migrates_to_posture_only(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "keys.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    "CREATE TABLE agent_keys ("
                    "key_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, "
                    "status TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT)"
                )
                connection.execute(
                    "INSERT INTO agent_keys VALUES (?, ?, ?, ?, ?)",
                    ("legacy-v1", "legacy", "active", "2026-01-01T00:00:00Z", None),
                )
                connection.commit()
            registry = AgentKeyRegistry(database)
            self.assertTrue(registry.is_authorized("legacy-v1", POSTURE_WRITE_SCOPE))
            self.assertFalse(
                registry.is_authorized("legacy-v1", ASSET_CONTEXT_WRITE_SCOPE)
            )

    def test_unknown_scope_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            with self.assertRaises(ValueError):
                registry.register("bad", scopes=("admin:all",))


if __name__ == "__main__":
    unittest.main()
