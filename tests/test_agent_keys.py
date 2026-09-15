import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from scripts import agent_keys
from scripts.agent_keys import (
    ASSET_CONTEXT_WRITE_SCOPE,
    POSTURE_WRITE_SCOPE,
    AgentKeyRegistry,
)
from state_store import SQLITE_LOCK_TIMEOUT_SECONDS
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
    def test_concurrent_legacy_migration_is_serialized(self):
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
                    ("legacy-concurrent", "legacy", "active", "2026-01-01T00:00:00Z", None),
                )
                connection.commit()
            barrier = threading.Barrier(2)
            failures = []

            def migrate():
                try:
                    barrier.wait(timeout=5)
                    AgentKeyRegistry(database)
                except Exception as error:
                    failures.append(error)

            workers = [threading.Thread(target=migrate) for _ in range(2)]
            with closing(sqlite3.connect(database, timeout=0)) as blocker:
                blocker.execute("BEGIN EXCLUSIVE")
                for worker in workers:
                    worker.start()
                time.sleep(0.2)
                blocker.rollback()
            for worker in workers:
                worker.join(timeout=10)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assertEqual(failures, [])
            registry = AgentKeyRegistry(database)
            self.assertTrue(
                registry.is_authorized("legacy-concurrent", POSTURE_WRITE_SCOPE)
            )
            self.assertFalse(
                registry.is_authorized("legacy-concurrent", ASSET_CONTEXT_WRITE_SCOPE)
            )

    def test_unknown_scope_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            with self.assertRaises(ValueError):
                registry.register("bad", scopes=("admin:all",))
    def test_explicit_empty_scopes_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            for empty_scopes in ((), []):
                with self.subTest(scopes=empty_scopes):
                    with self.assertRaises(ValueError):
                        registry.register("nobody", scopes=empty_scopes)
    def test_omitted_scopes_still_default_to_posture_write(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            key_id, _ = registry.register("default-agent")
            self.assertTrue(registry.is_authorized(key_id, POSTURE_WRITE_SCOPE))
    def test_register_uses_shared_sqlite_lock_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            with mock.patch.object(
                agent_keys.sqlite3, "connect", wraps=sqlite3.connect
            ) as connect_spy:
                key_id, secret = registry.register("timeout-probe", "timeout-probe-v1")
            self.assertTrue(secret)
            self.assertTrue(registry.is_active(key_id))
            self.assertEqual(
                [call.kwargs.get("timeout") for call in connect_spy.call_args_list],
                [SQLITE_LOCK_TIMEOUT_SECONDS],
            )
    def test_revoke_uses_shared_sqlite_lock_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            key_id, _ = registry.register("timeout-probe", "timeout-probe-v1")
            with mock.patch.object(
                agent_keys.sqlite3, "connect", wraps=sqlite3.connect
            ) as connect_spy:
                registry.revoke(key_id)
            self.assertFalse(registry.is_active(key_id))
            self.assertEqual(
                [call.kwargs.get("timeout") for call in connect_spy.call_args_list],
                [SQLITE_LOCK_TIMEOUT_SECONDS],
            )
    def test_is_active_uses_shared_sqlite_lock_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            key_id, _ = registry.register("timeout-probe", "timeout-probe-v1")
            with mock.patch.object(
                agent_keys, "SQLITE_LOCK_TIMEOUT_SECONDS", 7
            ), mock.patch.object(
                agent_keys.sqlite3, "connect", wraps=sqlite3.connect
            ) as connect_spy:
                active = registry.is_active(key_id)
            self.assertTrue(active)
            self.assertEqual(
                [call.kwargs.get("timeout") for call in connect_spy.call_args_list],
                [7],
            )
    def test_is_authorized_uses_shared_sqlite_lock_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = AgentKeyRegistry(str(Path(directory) / "keys.db"))
            key_id, _ = registry.register("timeout-probe", "timeout-probe-v1")
            with mock.patch.object(
                agent_keys, "SQLITE_LOCK_TIMEOUT_SECONDS", 7
            ), mock.patch.object(
                agent_keys.sqlite3, "connect", wraps=sqlite3.connect
            ) as connect_spy:
                authorized = registry.is_authorized(key_id, POSTURE_WRITE_SCOPE)
            self.assertTrue(authorized)
            self.assertEqual(
                [call.kwargs.get("timeout") for call in connect_spy.call_args_list],
                [7],
            )
if __name__ == "__main__":
    unittest.main()
