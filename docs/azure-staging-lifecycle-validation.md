# Azure staging lifecycle validation

This runner is a staging-only validation tool. It proves selected SentinelGRC
runtime and governance controls from inside the private Azure Container Apps
environment. It is not part of the server process and does not claim that the
system is production-ready.

## Trust boundary

The runner requires two separate user-assigned managed identities:

- an identity assigned the `sentinel-analyst` application role;
- an identity assigned the `sentinel-approver` application role.

It requests short-lived tokens from the managed identity endpoint. Tokens are
kept in memory, are never accepted as command-line arguments, and are never
included in the report. The server derives each actor from the verified OIDC
token.

The validation container must run inside an approved private-network execution
point that can resolve the internal Container App FQDN. Do not enable public
ingress to run this test.

## Provisioned validation boundary

The reviewed Azure template keeps this boundary opt-in. Set both
`deployApplication = true` and `deployValidationJob = true` to create two
separate user-assigned identities and a manual-trigger Container Apps Job in
the same internal managed environment. The analyst identity alone receives
`AcrPull`; neither validation identity receives storage, database, Service Bus,
or Key Vault RBAC from the template.

Azure Resource Manager cannot assign a Microsoft Entra application role to a
managed identity through these resource-scoped Bicep declarations. A tenant
operator must therefore assign exactly one API role to each identity after
review. Use object IDs returned by the deployment; never paste access tokens:

```powershell
$api = az ad sp show --id "<sentinel-application-client-id>" | ConvertFrom-Json
$analyst = az identity show -g "<resource-group>" -n "<validation-analyst-identity>" | ConvertFrom-Json
$approver = az identity show -g "<resource-group>" -n "<validation-approver-identity>" | ConvertFrom-Json

$analystRole = $api.appRoles | Where-Object value -eq "sentinel-analyst"
$approverRole = $api.appRoles | Where-Object value -eq "sentinel-approver"

az ad sp app-role assignment create `
  --assignee-object-id $analyst.principalId `
  --assignee-principal-type ServicePrincipal `
  --resource-object-id $api.id `
  --app-role-id $analystRole.id

az ad sp app-role assignment create `
  --assignee-object-id $approver.principalId `
  --assignee-principal-type ServicePrincipal `
  --resource-object-id $api.id `
  --app-role-id $approverRole.id
```

Fail the change if the client IDs or principal IDs are equal, either identity
has both roles, or either identity has resource-plane RBAC other than the
analyst identity's image-pull role.

## Required settings

```text
SENTINEL_VALIDATION_API_URL
SENTINEL_VALIDATION_AUDIENCE
SENTINEL_VALIDATION_ANALYST_CLIENT_ID
SENTINEL_VALIDATION_APPROVER_CLIENT_ID
```

The API URL must be a root HTTPS `.azurecontainerapps.io` URL. The two client
IDs must be different GUIDs. `SENTINEL_VALIDATION_AUDIENCE` is the
`api://<application-client-id>` resource URI used to request
`api://<application-client-id>/.default`. The API runtime separately verifies
the bare application client ID GUID carried in the `aud` claim of the returned
Entra v2 access token.

Start the digest-pinned private validation job manually:

```powershell
az containerapp job start `
  --name "<validation-job-name>" `
  --resource-group "<resource-group>"

az containerapp job execution list `
  --name "<validation-job-name>" `
  --resource-group "<resource-group>" `
  --output table
```

For a local fixture-only check, the same module remains runnable as
`python -m scripts.azure_staging_validator --pretty`.

Store the JSON output in the approved private evidence location. Do not commit
live reports, tokens, tenant identifiers, subscription identifiers, resource
IDs, database values, or operator filesystem paths.

## Gates proved by one successful run

- `/healthz` and `/ready` return HTTP 200;
- an unauthenticated request is rejected;
- caller-supplied actor identity is rejected;
- a risk owner cannot approve the same finding;
- a finding cannot close before verification;
- a duplicate finding is rejected;
- an implementer/evidence submitter cannot self-verify;
- a separate approver can approve, verify, and close;
- the final finding is read back in `closed` state.

The report contains only finding IDs, hashed actor fingerprints, the submitted
evidence SHA-256, HTTP gate statuses, and the final state. A passing report does
not prove backup restore, disaster recovery, sustained load, alert delivery,
external SIEM/ITSM integration, or production readiness.

## Monitoring validation

Set `deployMonitoringAlerts = true` to create two staging alerts: a
`Replicas < 1` metric alert on the internal Container App and a Log Analytics
query alert when the outbox publisher emits a positive `dead`, `retry`, or
`stale` count. Both rules use automatic mitigation so Azure can resolve the
alert after its recovery condition remains healthy. `monitoringActionGroupResourceId` is optional so no personal or
secret notification address is stored in the template. The same opt-in switch
creates a diagnostic setting that routes `ContainerAppConsoleLogs` and
`ContainerAppSystemLogs` from the managed environment to the declared Log
Analytics workspace; without that route, the outbox query alert has no evidence
source and must not be counted as deployed successfully.

The `monitoring_alerts_observed` live gate requires an approved rehearsal:
record the alert rule resource ID and pre-test state, trigger a bounded staging
condition, observe Azure set the alert to fired, restore the healthy condition,
observe resolution, and retain sanitized timestamps plus operator/reviewer
identity in the private evidence location. Merely provisioning a rule is not a
passing result.
