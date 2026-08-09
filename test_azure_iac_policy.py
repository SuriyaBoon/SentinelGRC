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
        self.assertIn("param validationContainerImage string", self.source)
        self.assertIn("validationImageDigestPinned", self.source)
        self.assertIn(
            "if (deployValidatedApplication)",
            self.source,
        )
        self.assertNotIn("application-blocked-invalid-image", self.source)
        self.assertIn("deployApplication requires a lowercase digest-pinned", self.source)
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
        self.assertIn("ValidationContainerImage", self.preflight)
        self.assertIn("validation_image_is_digest_pinned", self.preflight)
        self.assertIn("param validationContainerImage", self.params)
        self.assertNotIn("az deployment", self.preflight.lower())
        self.assertIn("length(containerImageParts) == 2", self.source)
        self.assertIn("length(validationImageParts) == 2", self.source)
        self.assertIn("empty(containerImageInvalidDigestCharacters)", self.source)
        self.assertIn("empty(validationImageInvalidDigestCharacters)", self.source)

    def test_requested_application_jobs_and_monitoring_fail_instead_of_omitting(self):
        for contract in (
            "var deployValidatedApplication = !deployApplication",
            "var deployValidatedJobs = !deployValidationJobs",
            "var deployValidatedMonitoring = !deployMonitoringAlerts",
            "deployValidationJobs requires deployApplication=true",
            "deployValidationJobs requires a lowercase digest-pinned",
            "deployMonitoringAlerts requires deployApplication=true",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, self.source)
        self.assertEqual(self.source.count("= if (deployValidatedJobs)"), 6)
        self.assertEqual(self.source.count("= if (deployValidatedMonitoring)"), 5)
        self.assertEqual(self.source.count("= if (deployValidatedApplication)"), 1)
        self.assertNotIn("deployApplication && deployValidationJobs", self.source)
        self.assertNotIn("deployApplication && deployMonitoringAlerts", self.source)
        self.assertNotIn("deployApplication && imageDigestPinned", self.source)

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

    def test_validation_jobs_isolate_role_bearing_identities(self):
        self.assertIn("param deployValidationJobs bool = false", self.source)
        self.assertEqual(self.source.count("image: validationContainerImage"), 2)
        self.assertNotIn(
            "image: containerImage\n          name: 'sentinel-validation'",
            self.source,
        )
        analyst_job = self.source.split(
            "resource validationAnalystJob", 1
        )[1].split("resource validationApproverJob", 1)[0]
        approver_job = self.source.split(
            "resource validationApproverJob", 1
        )[1].split("resource availabilityAlert", 1)[0]
        self.assertIn("validationImagePullIdentity.id", analyst_job)
        self.assertIn("validationAnalystIdentity.id", analyst_job)
        self.assertNotIn("validationApproverIdentity.id", analyst_job)
        self.assertIn("value: 'analyst'", analyst_job)
        self.assertIn("validationImagePullIdentity.id", approver_job)
        self.assertIn("validationApproverIdentity.id", approver_job)
        self.assertNotIn("validationAnalystIdentity.id", approver_job)
        self.assertIn("value: 'approver'", approver_job)
        self.assertEqual(
            self.source.count("name: 'SENTINEL_VALIDATION_CLIENT_ID'"), 2
        )
        self.assertNotIn(
            "SENTINEL_VALIDATION_ANALYST_CLIENT_ID", self.source
        )
        self.assertNotIn(
            "SENTINEL_VALIDATION_APPROVER_CLIENT_ID", self.source
        )
        self.assertIn(
            "principalId: validationImagePullIdentity!.properties.principalId",
            self.source,
        )
        self.assertIn("value: 'REQUIRED_AT_START'", analyst_job)
        self.assertIn("value: 'REQUIRED_AT_START'", approver_job)
        self.assertIn(
            "name: 'SENTINEL_VALIDATION_EXPECTED_SUBJECT'", analyst_job
        )
        self.assertIn(
            "value: validationAnalystIdentity!.properties.principalId",
            analyst_job,
        )
        self.assertIn(
            "name: 'SENTINEL_VALIDATION_PEER_SUBJECT'", analyst_job
        )
        self.assertIn(
            "value: validationApproverIdentity!.properties.principalId",
            analyst_job,
        )
        self.assertIn(
            "value: validationApproverIdentity!.properties.principalId",
            approver_job,
        )
        self.assertIn(
            "value: validationAnalystIdentity!.properties.principalId",
            approver_job,
        )
        self.assertNotIn("external: true", self.source)

    def test_live_monitoring_has_log_source_and_auto_resolution(self):
        self.assertIn("param deployMonitoringAlerts bool = false", self.source)
        self.assertIn("Microsoft.Insights/diagnosticSettings", self.source)
        self.assertIn("category: 'ContainerAppConsoleLogs'", self.source)
        self.assertIn("category: 'ContainerAppSystemLogs'", self.source)
        self.assertIn("workspaceId: logAnalytics.id", self.source)
        self.assertIn("Microsoft.Insights/metricAlerts", self.source)
        self.assertIn("metricName: 'Replicas'", self.source)
        self.assertIn("Microsoft.Insights/scheduledQueryRules", self.source)
        self.assertIn("monitoringQueryIdentityName", self.source)
        self.assertIn("purpose: 'outbox-health-query'", self.source)
        self.assertIn(
            "'73c42c96-874c-492b-b04d-ab87d138a893'", self.source
        )
        self.assertIn("resource monitoringQueryReader", self.source)
        self.assertIn("scope: logAnalytics", self.source)
        self.assertIn(
            "principalId: monitoringQueryIdentity!.properties.principalId",
            self.source,
        )
        outbox_alert = self.source.split(
            "resource outboxHealthAlert", 1
        )[1].split("output deploymentMode", 1)[0]
        self.assertIn("type: 'UserAssigned'", outbox_alert)
        self.assertIn("monitoringQueryIdentity!.id", outbox_alert)
        self.assertIn("kind: 'LogAlert'", outbox_alert)
        self.assertIn("monitoringQueryReader", outbox_alert)
        self.assertNotIn("appIdentity", outbox_alert)
        self.assertNotIn("validationAnalystIdentity", outbox_alert)
        self.assertNotIn("validationApproverIdentity", outbox_alert)
        self.assertNotIn("validationImagePullIdentity", outbox_alert)
        self.assertNotIn("dimensions: []", outbox_alert)
        self.assertIn("ContainerAppConsoleLogs_CL", self.source)
        self.assertIn('ContainerName_s == "outbox-publisher"', self.source)
        self.assertIn("toint(payload.dead) > 0", self.source)
        self.assertEqual(self.source.count("autoMitigate: true"), 2)
        self.assertNotIn("autoMitigate: false", self.source)
        self.assertIn("monitoringActionGroupResourceId", self.source)
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
