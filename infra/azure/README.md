# Azure staging infrastructure

This directory defines a manual, private-networked Azure staging topology for
SentinelGRC. It does not deploy automatically and does not enable the
application's deliberately blocked production mode.

The template provisions:

- an internal Azure Container Apps environment;
- PostgreSQL Flexible Server on a delegated subnet;
- encrypted Blob Storage with versioning and an immutable audit container;
- Key Vault in RBAC mode;
- Service Bus with a duplicate-detecting, session-enabled queue and
  dead-letter behavior;
- Log Analytics and Application Insights;
- private endpoints and private DNS for Blob, Key Vault, Service Bus, and the
  existing Azure Container Registry;
- a user-assigned managed identity with resource-scoped RBAC.

The application revision contains an API container and a supervised outbox
publisher sidecar. The sidecar has sender-only Service Bus RBAC; consumers must
use session-aware, idempotent processing and have their own receiver identity.

`main.staging.bicepparam.example` contains identifiers only. The PostgreSQL
bootstrap password is intentionally absent and must be supplied securely at
deployment time.

See [the deployment runbook](../../docs/azure-staging-deployment.md) before
running any Azure mutation.
