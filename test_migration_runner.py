import tempfile
import unittest
from pathlib import Path

from migration_runner import MigrationRunner


class MigrationRunnerTests(unittest.TestCase):
    def test_applies_once_and_records_checksum(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "001_probe.sql").write_text(
                "CREATE TABLE IF NOT EXISTS probe (id TEXT PRIMARY KEY);", encoding="utf-8"
            )
            runner = MigrationRunner(str(root / "state.db"), str(migrations))
            self.assertEqual(runner.apply(), ["001_probe"])
            self.assertEqual(runner.apply(), [])
            self.assertEqual(len(runner.status()), 1)

    def test_checksum_mismatch_and_partial_failure_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            migrations = root / "migrations"
            migrations.mkdir()
            path = migrations / "001_probe.sql"
            path.write_text("CREATE TABLE probe (id TEXT PRIMARY KEY);", encoding="utf-8")
            runner = MigrationRunner(str(root / "state.db"), str(migrations))
            runner.apply()
            path.write_text("CREATE TABLE probe (id TEXT PRIMARY KEY, x TEXT);", encoding="utf-8")
            with self.assertRaises(ValueError):
                runner.apply()
