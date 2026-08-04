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

Run the validator from the digest-pinned validation image:

```powershell
python -m scripts.azure_staging_validator --pretty
```

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
