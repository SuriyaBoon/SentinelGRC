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
- a user-assigned application identity with resource-scoped RBAC;
- opt-in analyst and approver validation jobs with isolated role identities;
- a digest-pinned assurance image for validation jobs, separate from the
  production runtime image;
- a separate validation image-pull identity with `AcrPull` only;
- a dedicated outbox-query identity with `Log Analytics Reader` on only the
  deployment workspace;
- opt-in availability and outbox-health alerts with automatic resolution.

The Service Bus Premium namespace owns partitioning through
`premiumMessagingPartitions`. The child queue explicitly keeps
`enablePartitioning: false` because Azure reports that effective value after
creation and queue partitioning is immutable. Do not change the child flag to
`true`: an infrastructure-first deployment followed by an application-enabled
redeployment would fail instead of converging idempotently.

The application revision contains an API container and a supervised outbox
publisher sidecar. The sidecar has sender-only Service Bus RBAC; consumers must
use session-aware, idempotent processing and have their own receiver identity.

`main.staging.bicepparam.example` contains identifiers only. The PostgreSQL
bootstrap password is intentionally absent and must be supplied securely at
deployment time.

See [the deployment runbook](../../docs/azure-staging-deployment.md) before
running any Azure mutation.

The analyst and approver jobs never share a role-bearing identity. Each job
also attaches an image-pull identity that has no Sentinel API application role.
The canonical governance state is the handoff between four manually triggered
phases; `SENTINEL_VALIDATION_RUN_ID` and `SENTINEL_VALIDATION_PHASE` must be
overridden for every execution. Entra API role assignment remains an explicit
tenant-operator step. Every phase can resume after a committed mutation whose
response was lost, but rejects states outside its explicit allowlist. The jobs
bind each verified token subject to the corresponding managed-identity object
ID, compare it with the peer identity, and exercise server-side self-approval
rejection during the live rehearsal.
