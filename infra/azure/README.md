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
- an opt-in session-aware Service Bus validation job whose workload identity
  has `Azure Service Bus Data Receiver` only on the governance queue;
- a source PostgreSQL snapshot job whose workload identity can read only the
  versioned source database-URL secret, plus a separately opt-in restored job
  with a different identity and no source-secret role;
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

The API and supervised outbox publisher are separate Container Apps. The API
uses the application identity; the publisher uses a different identity with
queue-scoped sender RBAC and secret-scoped access to the database URL. A third
identity performs runtime image pulls only. Consumers must use session-aware,
idempotent processing and have their own receiver identity.
The assurance receiver is separate from the application and publisher. It
settles only one exact synthetic message after validating the stable message
ID, finding-scoped session ID, canonical body, correlation ID, event sequence,
and payload SHA-256. Its output excludes the message body and endpoint names.

`main.staging.bicepparam.example` contains identifiers only. The PostgreSQL
bootstrap password, restored URL, and per-run evidence HMAC key are
intentionally absent and must be supplied securely at deployment time.

The offline IaC preflight binds the runtime image to the digest-pinned
`<acr-name>.azurecr.io/sentinelgrc` repository and the validation image to the
digest-pinned `<acr-name>.azurecr.io/sentinelgrc-assurance` repository. Their
digests must differ. The Microsoft Entra issuer and JWKS URL must be the exact
tenant-derived v2 endpoints. Same, swapped, arbitrary, wrong-ACR, noncanonical,
or mutable inputs fail closed. These repository controls perform no Azure
mutation and grant no Azure live-validation credit.

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

The PostgreSQL jobs call `scripts.azure_live_gate_harness`. They compare the
repository migration IDs and checksums, required schema objects, synthetic-only
row counts and canonical row hashes, and one application-level finding read.
Every snapshot runs all identity, migration, schema, row, and application reads
inside one read-only repeatable-read transaction. Target identity is a per-run
HMAC over the Bicep-bound Azure server resource, canonical server FQDN, and
database-observed name, OID, address, and port. The source and restored HMACs
must differ while integrity evidence remains equal. The restored job rejects a
URL whose host is not the canonical FQDN of the declared existing restored
server. `deployRestoreValidationJob` defaults to `false`; these jobs do not
create a restore or grant live-gate credit without approved Azure execution.
