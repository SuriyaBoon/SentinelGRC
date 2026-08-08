import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class SupplyChainPolicyTests(unittest.TestCase):
    def test_runtime_dependencies_are_hash_locked_in_build_and_ci(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        lock = (ROOT / "requirements-hashed.txt").read_text(encoding="utf-8")
        self.assertIn("--require-hashes --requirement /app/requirements-hashed.txt", dockerfile)
        self.assertEqual(workflow.count("--require-hashes --requirement requirements-hashed.txt"), 2)
        self.assertNotIn("requirements.txt", dockerfile)
        self.assertIn("--hash=sha256:", lock)
        self.assertNotRegex(lock, r"(?m)^[a-zA-Z0-9_.-]+\s*(?:>=|~=|>|<)")

    def test_container_context_uses_explicit_runtime_allowlist(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn("COPY . .", dockerfile)
        self.assertNotRegex(dockerfile, r"(?m)^COPY\s+[^\n]*\*")
        self.assertNotRegex(dockerfile, r"(?m)^COPY\s+(?:tests?|docs|\.git|\.github)(?:/|\s)")
        for required in (
            "runtime_app.py",
            "outbox_worker.py",
            "scripts/azure_staging_validator.py",
            "migrations/postgresql/005_service_bus_outbox.sql",
        ):
            with self.subTest(required=required):
                self.assertIn(required, dockerfile)

if __name__ == "__main__":
    unittest.main()