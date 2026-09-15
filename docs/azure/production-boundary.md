# Production acceptance boundary

See [current status](../STATUS.md) before interpreting this requirements checklist. Historical deployment observations do not prove the current revision.

## Production boundary

This repository is **not** a production deployment. Before even a limited internal pilot, it would need at least:

- A reviewed Azure staging deployment and operational validation. The repository
  now includes manual Bicep for an internal Container Apps environment,
  private PostgreSQL, Key Vault, encrypted Blob containers, Service Bus,
  monitoring, private endpoints, managed identity, and resource-scoped RBAC.
  The template compiles in CI. Sanitized historical staging evidence is retained
  under `docs/evidence/historical-azure-staging-202608`, but it is tied to an
  older source revision and cannot validate current `main` or satisfy a current
  live gate.
- A real Microsoft Entra tenant/app registration, role assignments, Conditional Access/MFA policy, and lifecycle-managed service identities. The staging code verifies OIDC signatures and trust claims; local hashed API keys are lab-only.
- A secrets manager, TLS termination, network policy, rate limiting, and a hardened WSGI or ASGI server around the HTTP adapter.
- Validation of the managed-identity Azure Blob adapter against a private
  staging container, plus orphan reconciliation and retention/restore
  operations. Local JSON, JSONL, and SQLite files are not an evidence vault.
- Validation of the managed-identity audit adapter and worker against the real
  private audit container. The IaC declares an **unlocked** retention policy so
  it can be tested safely; an authorised operator must validate it, lock it,
  monitor delivery lag/dead letters, and retain proof.
- Validation of the implemented managed-identity Service Bus publisher and
  separately isolated outbox publisher app against the real private queue. Repository tests
  cover stable message IDs, sessions, duplicate-safe replay, fencing,
  heartbeat/readiness, retry and dead-letter recovery. Historical synthetic
  Azure messaging observations are retained only as old-revision evidence and
  grant no current live-gate credit.
- The assurance image now includes a fail-closed, session-aware Service Bus
  receiver probe and PostgreSQL source/restore snapshot verifier. Their Bicep
  jobs use separate queue-receiver, source-database, restored-database, and
  image-pull identities. PostgreSQL snapshots use one read-only repeatable-read
  transaction and emit only a resource-bound HMAC for target identity. The
  jobs expose no message body or database URL, default runtime inputs to
  `REQUIRED_AT_START`, and remain manual evidence tools rather than current
  Azure proof.
- Live centralized logging, metrics, tracing, alert observation and resolution,
  backup/restore rehearsal, and disaster-recovery procedures. The offline
  repository security assessment is complete; target-environment assessment
  and go-live review remain mandatory.
- A real connector test against an authorised Windows and SIEM environment, including failure recovery and access-control validation.

The repository includes an offline staging-assurance package and explicit live
go/no-go gates. Passing it means the reviewed code is prepared for a manual
staging attempt; it is not evidence that Azure controls work. The threat model,
monitoring signals, incident procedures, rollback criteria and required private
evidence are documented in
[`docs/azure/staging-assurance.md`](staging-assurance.md).

The PostgreSQL adapters are repository-tested for canonical governance, human
identity, connector replay, fenced job claims, and transactional outbox
delivery. Legacy pipeline stores remain SQLite-specific, and no external
message broker or outbox destination is credited as a validated current-version deployment. Azure deployment and observability
contracts are not proof that their external controls have been deployed.
