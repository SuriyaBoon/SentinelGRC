import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MAIN = ROOT / "infra" / "azure" / "main.bicep"
PARAMS = ROOT / "infra" / "azure" / "main.staging.bicepparam.example"
PREFLIGHT = ROOT / "scripts" / "Test-AzureStagingInputs.ps1"
STAGING_ASSURANCE = ROOT / "docs" / "staging-assurance.md"
SECURITY_REMEDIATION = ROOT / "docs" / "sonar-security-remediation.md"
RESOURCE_ELEMENT_ORDER = {
    "parent": 0,
    "scope": 20,
    "name": 50,
    "location": 50,
    "sku": 80,
    "kind": 90,
    "identity": 120,
    "dependson": 140,
    "tags": 150,
    "properties": 1000,
}
TOP_LEVEL_DECLARATION_ORDER = {
    "targetscope": 0,
    "metadata": 1,
    "param": 2,
    "func": 3,
    "var": 4,
    "resource_existing": 5,
    "resource": 6,
    "module": 7,
    "output": 8,
}


def _without_bicep_strings(line):
    return re.sub(r"'(?:[^']|'')*'", "''", line.split("//", 1)[0])


def _resource_element_sequences(source):
    current_name = None
    depth = 0
    elements = []
    for line in source.splitlines():
        code = _without_bicep_strings(line)
        if current_name is None:
            match = re.match(r"\s*resource\s+([A-Za-z][A-Za-z0-9_]*)\b.*=\s*(?:if\s*\([^)]*\)\s*)?\{", code)
            if match is None:
                continue
            current_name = match.group(1)
            depth = code.count("{") - code.count("}")
            elements = []
            continue
        if depth == 1:
            match = re.match(r"\s*([A-Za-z][A-Za-z0-9_]*)\s*:", code)
            if match is not None:
                elements.append(match.group(1))
        depth += code.count("{") - code.count("}")
        if depth == 0:
            yield current_name, elements
            current_name = None


def _first_resource_order_violation(elements):
    previous = 0
    for element in elements:
        current = RESOURCE_ELEMENT_ORDER.get(element.lower(), 200)
        if current < previous:
            return element
        previous = current
    return None


def _top_level_declaration_sequence(source):
    declarations = []
    for line in source.splitlines():
        code = _without_bicep_strings(line)
        match = re.match(
            r"^(targetScope|metadata|param|func|var|resource|module|output)\b",
            code,
            re.IGNORECASE,
        )
        if match is None:
            continue
        kind = match.group(1).lower()
        if kind == "resource" and re.search(r"\bexisting\s*=", code):
            kind = "resource_existing"
        declarations.append(kind)
    return declarations


def _first_top_level_order_violation(declarations):
    previous = 0
    for declaration in declarations:
        current = TOP_LEVEL_DECLARATION_ORDER[declaration]
        if current < previous:
            return declaration
        previous = current
    return None


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

    def test_resource_elements_follow_sonar_recommended_order(self):
        violations = []
        for resource_name, elements in _resource_element_sequences(self.source):
            violating_element = _first_resource_order_violation(elements)
            if violating_element is not None:
                violations.append(f"{resource_name}: {violating_element} in {elements}")
        self.assertEqual(violations, [])

    def test_top_level_declarations_follow_sonar_recommended_order(self):
        declarations = _top_level_declaration_sequence(self.source)
        violation = _first_top_level_order_violation(declarations)
        self.assertIsNone(violation, declarations)

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
        self.assertIn("@sha256:(?<digest>[a-f0-9]{64})", self.preflight)
        self.assertIn("ValidationContainerImage", self.preflight)
        self.assertIn("validation_image_is_digest_pinned", self.preflight)
        self.assertIn("param validationContainerImage", self.params)
        self.assertNotIn("az deployment", self.preflight.lower())
        self.assertIn("length(containerImageParts) == 2", self.source)
        self.assertIn("length(validationImageParts) == 2", self.source)
        self.assertIn("empty(containerImageInvalidDigestCharacters)", self.source)
        self.assertIn("empty(validationImageInvalidDigestCharacters)", self.source)

    def test_images_are_bound_to_the_acr_receiving_pull_permissions(self):
        self.assertIn("expectedRegistryHost = toLower('${containerRegistryName}.azurecr.io')", self.source)
        self.assertIn("expectedRuntimeImageRepository = '${expectedRegistryHost}/sentinelgrc'", self.source)
        self.assertIn("expectedValidationImageRepository = '${expectedRegistryHost}/sentinelgrc-assurance'", self.source)
        self.assertIn("containerImageRepository == expectedRuntimeImageRepository", self.source)
        self.assertIn("validationImageRepository == expectedValidationImageRepository", self.source)
        self.assertIn("containerImageHost == expectedRegistryHost", self.source)
        self.assertIn("validationImageHost == expectedRegistryHost", self.source)
        self.assertNotIn("monitoringImage", self.source)
        self.assertIn("image_registry_bound = $true", self.preflight)
        self.assertIn("validation_image_registry_bound = $true", self.preflight)

    def _run_preflight(
        self,
        container_image,
        validation_image,
        *,
        issuer=None,
        jwks=None,
        tenant="11111111-1111-1111-1111-111111111111",
        audience="22222222-2222-2222-2222-222222222222",
    ):
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is unavailable")
        if issuer is None:
            issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
        if jwks is None:
            jwks = f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
        command = [
            powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(PREFLIGHT),
            "-ContainerImage", container_image,
            "-ValidationContainerImage", validation_image,
            "-RegistrySubscriptionId", "11111111-1111-1111-1111-111111111111",
            "-RegistryResourceGroup", "sentinel-staging", "-RegistryName", "expectedacr",
            "-OidcIssuer", issuer,
            "-OidcAudience", audience,
            "-OidcTenantId", tenant,
            "-OidcJwksUrl", jwks,
        ]
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_preflight_accepts_only_separate_repository_bound_images(self):
        runtime_digest = "a" * 64
        validation_digest = "b" * 64
        runtime = f"expectedacr.azurecr.io/sentinelgrc@sha256:{runtime_digest}"
        validation = f"expectedacr.azurecr.io/sentinelgrc-assurance@sha256:{validation_digest}"
        accepted = self._run_preflight(runtime, validation)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        evidence = json.loads(accepted.stdout)
        for field in (
            "runtime_repository_bound",
            "validation_repository_bound",
            "image_separation_enforced",
            "tenant_bound_endpoints",
        ):
            with self.subTest(field=field):
                self.assertIs(evidence[field], True)
        same_digest_validation = (
            f"expectedacr.azurecr.io/sentinelgrc-assurance@sha256:{runtime_digest}"
        )
        for rejected_runtime, rejected_validation in (
            (runtime, runtime),
            (validation, validation),
            (validation, runtime),
            (f"expectedacr.azurecr.io/arbitrary@sha256:{runtime_digest}", validation),
            (runtime, f"expectedacr.azurecr.io/arbitrary@sha256:{validation_digest}"),
            (f"otheracr.azurecr.io/sentinelgrc@sha256:{runtime_digest}", validation),
            (runtime, f"otheracr.azurecr.io/sentinelgrc-assurance@sha256:{validation_digest}"),
            ("expectedacr.azurecr.io/sentinelgrc:latest", validation),
            (runtime, "expectedacr.azurecr.io/sentinelgrc-assurance:latest"),
            (runtime, same_digest_validation),
            (f"expectedacr.azurecr.io/SentinelGRC@sha256:{runtime_digest}", validation),
        ):
            with self.subTest(runtime=rejected_runtime, validation=rejected_validation):
                rejected = self._run_preflight(rejected_runtime, rejected_validation)
                self.assertNotEqual(rejected.returncode, 0)

    def test_preflight_rejects_noncanonical_entra_inputs(self):
        runtime = f"expectedacr.azurecr.io/sentinelgrc@sha256:{'a' * 64}"
        validation = (
            f"expectedacr.azurecr.io/sentinelgrc-assurance@sha256:{'b' * 64}"
        )
        tenant = "aaaaaaaa-1111-1111-1111-111111111111"
        audience = "bbbbbbbb-2222-2222-2222-222222222222"
        other_tenant = "cccccccc-3333-3333-3333-333333333333"
        empty_guid = "00000000-0000-0000-0000-000000000000"
        issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
        jwks = f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"
        empty_guid_issuer = f"https://login.microsoftonline.com/{empty_guid}/v2.0"
        empty_guid_jwks = (
            f"https://login.microsoftonline.com/{empty_guid}/discovery/v2.0/keys"
        )
        cases = (
            ("attacker pair", {"issuer": "https://attacker.invalid/v2.0", "jwks": "https://attacker.invalid/keys"}),
            ("wrong issuer host", {"issuer": f"https://attacker.invalid/{tenant}/v2.0", "jwks": jwks}),
            ("wrong jwks host", {"issuer": issuer, "jwks": f"https://attacker.invalid/{tenant}/keys"}),
            ("cross-tenant issuer", {"issuer": f"https://login.microsoftonline.com/{other_tenant}/v2.0", "jwks": jwks}),
            ("cross-tenant jwks", {"issuer": issuer, "jwks": f"https://login.microsoftonline.com/{other_tenant}/discovery/v2.0/keys"}),
            ("issuer port", {"issuer": f"https://login.microsoftonline.com:443/{tenant}/v2.0", "jwks": jwks}),
            ("jwks port", {"issuer": issuer, "jwks": f"https://login.microsoftonline.com:443/{tenant}/discovery/v2.0/keys"}),
            ("issuer query", {"issuer": f"{issuer}?x=1", "jwks": jwks}),
            ("jwks fragment", {"issuer": issuer, "jwks": f"{jwks}#x"}),
            ("issuer trailing slash", {"issuer": f"{issuer}/", "jwks": jwks}),
            ("jwks trailing slash", {"issuer": issuer, "jwks": f"{jwks}/"}),
            ("noncanonical tenant", {"issuer": issuer, "jwks": jwks, "tenant": tenant.upper()}),
            ("noncanonical audience", {"issuer": issuer, "jwks": jwks, "audience": audience.upper()}),
            ("empty tenant GUID", {"issuer": empty_guid_issuer, "jwks": empty_guid_jwks, "tenant": empty_guid}),
            ("empty audience GUID", {"issuer": issuer, "jwks": jwks, "audience": empty_guid}),
        )
        for name, overrides in cases:
            with self.subTest(case=name):
                rejected = self._run_preflight(runtime, validation, **overrides)
                self.assertNotEqual(rejected.returncode, 0)

    def test_bicep_consumes_repository_digest_and_oidc_guards(self):
        runtime_predicate = self.source.split(
            "var imageDigestPinned =", 1
        )[1].split("var validationImageParts", 1)[0]
        validation_predicate = self.source.split(
            "var validationImageDigestPinned =", 1
        )[1].split("var canonicalOidcIssuer", 1)[0]
        self.assertIn(
            "containerImageRepository == expectedRuntimeImageRepository",
            runtime_predicate,
        )
        self.assertIn(
            "validationImageRepository == expectedValidationImageRepository",
            validation_predicate,
        )
        application = self.source.split(
            "var deployValidatedApplication", 1
        )[1].split("var deployValidatedJobs", 1)[0]
        self.assertIn("validationImageDigest == containerImageDigest", application)
        self.assertIn("!oidcTrustInputsCanonical", application)
        self.assertLess(
            application.index("validationImageDigest == containerImageDigest"),
            application.index("!deployApplication"),
        )
        self.assertLess(
            application.index("!oidcTrustInputsCanonical"),
            application.index("!deployApplication"),
        )
        trust_inputs = self.source.split(
            "var oidcTenantIdWithoutHyphens", 1
        )[1].split("var deployValidatedApplication", 1)[0]
        for contract in (
            "var oidcTenantIdCanonical =",
            "var oidcAudienceCanonical =",
            "length(oidcTenantIdWithoutHyphens) == 32",
            "length(oidcAudienceWithoutHyphens) == 32",
            "substring(oidcTenantId, 23, 1) == '-'",
            "substring(oidcAudience, 23, 1) == '-'",
            "oidcTenantId != emptyGuid",
            "oidcAudience != emptyGuid",
            "oidcTenantIdCanonical && oidcAudienceCanonical",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, trust_inputs)
        jobs = self.source.split("var deployValidatedJobs", 1)[1].split(
            "var deployValidatedMonitoring", 1
        )[0]
        self.assertNotIn("validationImageDigest == containerImageDigest", jobs)

    def test_staging_assurance_documents_both_required_images(self):
        assurance = STAGING_ASSURANCE.read_text(encoding="utf-8")
        self.assertRegex(
            assurance,
            r'-ContainerImage\s+"example\.azurecr\.io/sentinelgrc@sha256:<64-hex-digest>"',
        )
        self.assertRegex(
            assurance,
            r'-ValidationContainerImage\s+"example\.azurecr\.io/sentinelgrc-assurance@sha256:<64-hex-digest>"',
        )

    def test_requested_application_jobs_and_monitoring_fail_instead_of_omitting(self):
        for contract in (
            "var deployValidatedApplication = validationImageDigest == containerImageDigest",
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
        self.assertIn("$OidcIssuer -cne $canonicalIssuer", self.preflight)
        self.assertIn("$OidcJwksUrl -cne $canonicalJwksUrl", self.preflight)
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

    def test_client_certificate_decision_does_not_claim_unimplemented_mtls(self):
        container_app = self.source.split(
            "resource containerApp 'Microsoft.App/containerApps@2025-01-01'", 1
        )[1].split("resource analystValidationJob", 1)[0]
        decision = SECURITY_REMEDIATION.read_text(encoding="utf-8")
        self.assertIn("allowInsecure: false", container_app)
        self.assertIn("external: false", container_app)
        self.assertNotIn("clientCertificateMode: 'require'", container_app)
        self.assertIn(
            "mTLS is intentionally not asserted without certificate issuance",
            container_app,
        )
        self.assertIn("Container Apps client certificate", decision)
        self.assertIn("Entra OIDC", decision)
        self.assertIn("private-network boundary", decision)

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
        )[1].split("module acrPull", 1)[0]
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

    def test_stateful_services_declare_identity_and_storage_encryption(self):
        postgres = self.source.split(
            "resource postgres 'Microsoft.DBforPostgreSQL", 1
        )[1].split("resource governanceDatabase", 1)[0]
        storage = self.source.split(
            "resource storage 'Microsoft.Storage/storageAccounts", 1
        )[1].split("resource blobService", 1)[0]
        service_bus = self.source.split(
            "resource serviceBus 'Microsoft.ServiceBus/namespaces", 1
        )[1].split("resource governanceQueue", 1)[0]
        for name, resource in (
            ("postgres", postgres),
            ("storage", storage),
            ("service_bus", service_bus),
        ):
            with self.subTest(resource=name):
                self.assertIn("type: 'SystemAssigned'", resource)
        self.assertIn("requireInfrastructureEncryption: true", storage)
        self.assertIn("keySource: 'Microsoft.Storage'", storage)
        self.assertIn("keyType: 'Account'", storage)

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
