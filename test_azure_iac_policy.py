import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MAIN = ROOT / "infra" / "azure" / "main.bicep"
PARAMS = ROOT / "infra" / "azure" / "main.staging.bicepparam.example"
PREFLIGHT = ROOT / "scripts" / "Test-AzureStagingInputs.ps1"


class AzureIacPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MAIN.read_text(encoding="utf-8")
        cls.params = PARAMS.read_text(encoding="utf-8")
        cls.preflight = PREFLIGHT.read_text(encoding="utf-8")

    def test_required_staging_topology_is_declared(self):
        required_types = {
            "Microsoft.App/managedEnvironments",
            "Microsoft.App/containerApps",
            "Microsoft.App/jobs",
            "Microsoft.DBforPostgreSQL/flexibleServers",
            "Microsoft.KeyVault/vaults",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.ServiceBus/namespaces",
            "Microsoft.OperationalInsights/workspaces",
            "Microsoft.Network/privateEndpoints",
        }
        for resource_type in required_types:
            with self.subTest(resource_type=resource_type):
                self.assertIn(resource_type, self.source)

    def test_template_is_staging_only_and_application_is_opt_in(self):
        self.assertRegex(
            self.source,
            r"@allowed\(\[\s*'staging'\s*\]\)[\s\S]*?param environmentName",
        )
        self.assertIn("param deployApplication bool = false", self.source)
        self.assertIn(
            "if (deployApplication && imageDigestPinned)",
            self.source,
        )
        self.assertIn("application-blocked-invalid-image", self.source)
        self.assertIn("value: 'staging'", self.source)

    def test_secret_and_image_inputs_fail_closed(self):
        self.assertRegex(
            self.source,
            r"@secure\(\)[\s\S]*?param databaseAdministratorPassword string",
        )
        self.assertNotRegex(
            self.params,
            r"param\s+databaseAdministratorPassword\s*=",
        )
        self.assertIn("@sha256:[a-f0-9]{64}", self.preflight)
        self.assertNotIn("az deployment", self.preflight.lower())

    def test_complete_oidc_trust_boundary_is_wired_to_runtime(self):
        for parameter, environment_name in (
            ("oidcIssuer", "SENTINEL_OIDC_ISSUER"),
            ("oidcAudience", "SENTINEL_OIDC_AUDIENCE"),
            ("oidcTenantId", "SENTINEL_OIDC_TENANT_ID"),
            ("oidcJwksUrl", "SENTINEL_OIDC_JWKS_URL"),
        ):
            with self.subTest(parameter=parameter):
                self.assertIn(f"param {parameter} string", self.source)
                self.assertIn(f"name: '{environment_name}'", self.source)
        self.assertIn("[Guid]::TryParse($OidcTenantId", self.preflight)
        self.assertIn("[Guid]::TryParse($OidcAudience", self.preflight)
        self.assertIn("$jwks.Scheme -ne \"https\"", self.preflight)
        self.assertIn(
            "param oidcAudience = 'REPLACE_SENTINEL_APP_ID'",
            self.params,
        )
        self.assertNotIn(
            "param oidcAudience = 'api://REPLACE_SENTINEL_APP_ID'",
            self.params,
        )
        self.assertIn("@maxLength(36)", self.source)
        self.assertIn("name: 'SENTINEL_AZURE_CLIENT_ID'", self.source)
        self.assertIn("value: appIdentity.properties.clientId", self.source)

    def test_managed_identity_and_resource_scoped_roles_are_used(self):
        self.assertIn("Microsoft.ManagedIdentity/userAssignedIdentities", self.source)
        for role_id in (
            "7f951dda-4ed3-4680-a7ca-43fe172d538d",
            "4633458b-17de-408a-b874-0445c86b69e6",
            "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
            "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39",
        ):
            with self.subTest(role_id=role_id):
                self.assertTrue(
                    role_id in self.source
                    or role_id
                    in (ROOT / "infra" / "azure" / "acr-pull-role.bicep").read_text(
                        encoding="utf-8"
                    )
                )
        self.assertIn("allowSharedKeyAccess: false", self.source)
        self.assertIn("disableLocalAuth: true", self.source)
        self.assertIn("name: 'Premium'", self.source)
        self.assertNotIn("listKeys(", self.source)

    def test_outbox_worker_is_sender_only_and_ordered(self):
        self.assertIn("name: 'outbox-publisher'", self.source)
        self.assertIn("'outbox_worker.py'", self.source)
        self.assertIn("requiresDuplicateDetection: true", self.source)
        self.assertIn("requiresSession: true", self.source)
        self.assertIn("enablePartitioning: false", self.source)
        self.assertNotIn("enablePartitioning: true", self.source)
        self.assertIn("serviceBusSender", self.source)
        self.assertNotIn("serviceBusReceiver", self.source)

    def test_live_validation_job_is_separated_and_private(self):
        self.assertIn("param deployValidationJob bool = false", self.source)
        self.assertIn("param deployMonitoringAlerts bool = false", self.source)
        self.assertIn("validationAnalystIdentity", self.source)
        self.assertIn("validationApproverIdentity", self.source)
        self.assertIn("SENTINEL_VALIDATION_ANALYST_CLIENT_ID", self.source)
        self.assertIn("SENTINEL_VALIDATION_APPROVER_CLIENT_ID", self.source)
        self.assertIn("scripts.azure_staging_validator", self.source)
        self.assertIn("triggerType: 'Manual'", self.source)
        self.assertIn("replicaRetryLimit: 0", self.source)
        self.assertIn(
            "value: 'https://${containerApp!.properties.configuration.ingress.fqdn}'",
            self.source,
        )
        self.assertNotIn("external: true", self.source)
        self.assertIn("image: containerImage", self.source)
        self.assertIn("validationAcrPull", self.source)

    def test_live_monitoring_alerts_are_explicit_and_opt_in(self):
        self.assertIn("Microsoft.Insights/diagnosticSettings", self.source)
        self.assertIn("category: 'ContainerAppConsoleLogs'", self.source)
        self.assertIn("category: 'ContainerAppSystemLogs'", self.source)
        self.assertIn("workspaceId: logAnalytics.id", self.source)
        self.assertIn("Microsoft.Insights/metricAlerts", self.source)
        self.assertIn("metricName: 'Replicas'", self.source)
        self.assertIn("Microsoft.Insights/scheduledQueryRules", self.source)
        self.assertIn("ContainerAppConsoleLogs_CL", self.source)
        self.assertIn('ContainerName_s == "outbox-publisher"', self.source)
        self.assertIn("toint(payload.dead) > 0", self.source)
        self.assertIn("monitoringActionGroupResourceId", self.source)
        self.assertIn("containerEnvironmentDiagnostics", self.source)
        self.assertEqual(self.source.count("autoMitigate: true"), 2)
        self.assertNotIn("autoMitigate: false", self.source)
        self.assertIn("param deployMonitoringAlerts = false", self.params)

    def test_stateful_services_are_private_and_encrypted(self):
        self.assertGreaterEqual(
            self.source.count("publicNetworkAccess: 'Disabled'"),
            4,
        )
        self.assertIn("supportsHttpsTrafficOnly: true", self.source)
        self.assertIn("minimumTlsVersion: 'TLS1_2'", self.source)
        self.assertIn("immutableStorageWithVersioning", self.source)
        self.assertIn("immutabilityPolicies", self.source)
        self.assertIn("immutabilityPeriodSinceCreationInDays", self.source)
        self.assertNotIn("state: 'Locked'", self.source)
        self.assertIn("allowProtectedAppendWrites: true", self.source)
        self.assertIn("enablePurgeProtection: true", self.source)
        self.assertIn("privateDnsZones", self.source)

    def test_no_plausible_embedded_cloud_secret(self):
        combined = f"{self.source}\n{self.params}"
        suspicious = (
            r"AccountKey=[A-Za-z0-9+/=]{20,}",
            r"SharedAccessKey=[A-Za-z0-9+/=]{20,}",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        )
        for pattern in suspicious:
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, combined))


if __name__ == "__main__":
    unittest.main()
