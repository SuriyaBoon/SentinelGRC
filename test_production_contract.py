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
        self.assertIn("production requires PostgreSQL", result["errors"])
        self.assertIn("production identity storage requires PostgreSQL", result["errors"])
        self.assertIn("production requires SENTINEL_OIDC_ISSUER", result["errors"])
        self.assertIn("production requires SENTINEL_OIDC_AUDIENCE", result["errors"])
        self.assertIn("production requires SENTINEL_OIDC_TENANT_ID", result["errors"])
        self.assertIn("production requires SENTINEL_OIDC_JWKS_URL", result["errors"])
        self.assertIn("production requires SENTINEL_EVIDENCE_STORE_URL", result["errors"])
        self.assertIn("production requires SENTINEL_AZURE_CLIENT_ID", result["errors"])
        self.assertIn("production requires SENTINEL_AUDIT_ARCHIVE_URL", result["errors"])
        self.assertIn("production requires SENTINEL_REQUIRE_TLS=true", result["errors"])

    def test_environment_configuration_is_read_from_process(self):
        with patch.dict(os.environ, {
            "SENTINEL_ENV": "staging",
            "SENTINEL_DATABASE_URL": "postgresql://db/sentinel",
            "SENTINEL_OIDC_TENANT_ID": "11111111-1111-1111-1111-111111111111",
            "SENTINEL_OIDC_JWKS_URL": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
            "SENTINEL_REQUIRE_TLS": "true",
        }, clear=False):
            settings = Settings.from_env()
        self.assertEqual(settings.environment, "staging")
        self.assertEqual(settings.database_url, "postgresql://db/sentinel")
        self.assertEqual(
            settings.oidc_tenant_id, "11111111-1111-1111-1111-111111111111"
        )
        self.assertTrue(settings.require_tls)

    def test_staging_requires_complete_oidc_trust_configuration(self):
        errors = Settings(environment="staging").validate()
        for name in ("ISSUER", "AUDIENCE", "TENANT_ID", "JWKS_URL"):
            with self.subTest(name=name):
                self.assertIn(f"staging requires SENTINEL_OIDC_{name}", errors)
        self.assertIn("staging requires SENTINEL_EVIDENCE_STORE_URL", errors)
        self.assertIn("staging requires SENTINEL_AUDIT_ARCHIVE_URL", errors)
        self.assertIn("staging requires SENTINEL_AZURE_CLIENT_ID", errors)
