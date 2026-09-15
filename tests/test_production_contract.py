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
        self.assertIn(
            "production requires a valid SENTINEL_SERVICE_BUS_NAMESPACE",
            result["errors"],
        )
        self.assertIn(
            "production requires a valid SENTINEL_SERVICE_BUS_QUEUE",
            result["errors"],
        )
        self.assertIn("production requires SENTINEL_REQUIRE_TLS=true", result["errors"])

    def test_production_validation_error_order_is_stable(self):
        errors = Settings(environment="production").validate()
        self.assertEqual(
            errors,
            [
                "production requires SENTINEL_OIDC_ISSUER",
                "production requires SENTINEL_OIDC_AUDIENCE",
                "production requires SENTINEL_OIDC_TENANT_ID",
                "production requires SENTINEL_OIDC_JWKS_URL",
                "production requires SENTINEL_EVIDENCE_STORE_URL",
                "production requires SENTINEL_AUDIT_ARCHIVE_URL",
                "production requires SENTINEL_AZURE_CLIENT_ID",
                "production requires a valid SENTINEL_SERVICE_BUS_NAMESPACE",
                "production requires a valid SENTINEL_SERVICE_BUS_QUEUE",
                "production requires PostgreSQL",
                "production identity storage requires PostgreSQL",
                "production requires SENTINEL_REQUIRE_TLS=true",
            ],
        )

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
        self.assertIn(
            "staging requires a valid SENTINEL_SERVICE_BUS_NAMESPACE", errors
        )
        self.assertIn(
            "staging requires a valid SENTINEL_SERVICE_BUS_QUEUE", errors
        )

    def test_outbox_worker_contract_is_narrow_and_fail_closed(self):
        lab = Settings(database_url="sqlite:///runtime/test.db")
        self.assertEqual(lab.validate_outbox_worker(), [])
        staging = Settings(
            environment="staging",
            database_url="postgresql://db/sentinel",
            azure_managed_identity_client_id="managed-id",
            service_bus_namespace="sentinel-staging.servicebus.windows.net",
            service_bus_queue="governance-outbox",
        )
        self.assertEqual(staging.validate_outbox_worker(), [])
        errors = Settings(environment="staging").validate_outbox_worker()
        self.assertIn("staging outbox requires PostgreSQL", errors)
        self.assertIn(
            "staging requires a valid SENTINEL_SERVICE_BUS_NAMESPACE", errors
        )

    def test_outbox_worker_accepts_both_supported_postgres_schemes(self):
        for scheme in ("postgresql://", "postgresql+psycopg://"):
            with self.subTest(scheme=scheme):
                settings = Settings(
                    environment="staging",
                    database_url=f"{scheme}db/sentinel",
                    azure_managed_identity_client_id="managed-id",
                    service_bus_namespace="sentinel-staging.servicebus.windows.net",
                    service_bus_queue="governance-outbox",
                )
                self.assertEqual(settings.validate_outbox_worker(), [])

    def test_outbox_runtime_limits_are_strict(self):
        with patch.dict(
            os.environ,
            {"SENTINEL_OUTBOX_WORKER_MAX_AGE_SECONDS": "unbounded"},
        ):
            with self.assertRaisesRegex(ValueError, "must be an integer"):
                Settings.from_env()
