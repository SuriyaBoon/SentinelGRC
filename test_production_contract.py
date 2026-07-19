import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from production_contract import Settings, readiness


class ProductionContractTests(unittest.TestCase):
    def test_lab_defaults_are_usable_without_production_dependencies(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = Settings(evidence_dir=temp)
            result = readiness(settings)
            self.assertEqual(result["status"], "ready")

    def test_production_fails_closed_without_external_controls(self):
        settings = Settings(environment="production", evidence_dir="missing")
        result = readiness(settings)
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("production requires PostgreSQL or another shared transactional database", result["errors"])
        self.assertIn("production requires SENTINEL_OIDC_ISSUER", result["errors"])
        self.assertIn("production requires SENTINEL_AUDIT_ARCHIVE_URL", result["errors"])
        self.assertIn("production requires SENTINEL_REQUIRE_TLS=true", result["errors"])

    def test_environment_configuration_is_read_from_process(self):
        with patch.dict(os.environ, {
            "SENTINEL_ENV": "staging",
            "SENTINEL_DATABASE_URL": "postgresql://db/sentinel",
            "SENTINEL_REQUIRE_TLS": "true",
        }, clear=False):
            settings = Settings.from_env()
        self.assertEqual(settings.environment, "staging")
        self.assertEqual(settings.database_url, "postgresql://db/sentinel")
        self.assertTrue(settings.require_tls)
