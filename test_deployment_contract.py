import unittest

from deployment_contract import DeploymentRequirements, readiness


class DeploymentContractTests(unittest.TestCase):
    def test_complete_production_contract_is_ready(self):
        result = readiness(DeploymentRequirements(
            database_url="postgresql://db/sentinel",
            queue_url="redis://queue/0",
            secret_manager="vault://sentinel",
            audit_archive_url="s3://immutable-audit",
            backup_target="s3://sentinel-backups",
            metrics_endpoint="https://metrics",
            tls_enabled=True,
            oidc_issuer="https://idp.example",
        ))
        self.assertEqual(result["status"], "ready")

    def test_missing_production_controls_fail_closed(self):
        result = readiness(DeploymentRequirements(
            database_url="sqlite:///runtime/state.db",
            queue_url="", secret_manager="", audit_archive_url="",
            backup_target="", metrics_endpoint="", tls_enabled=False, oidc_issuer="",
        ))
        self.assertEqual(result["status"], "not_ready")
        self.assertGreaterEqual(len(result["errors"]), 7)
