# Integration status

These are offline/synthetic boundaries, not live production connectivity.

## Planned integration

The source revisions and fail-closed rules behind these offline claims are
recorded in [`docs/integrations/connector-contracts.md`](connector-contracts.md).
Changing any supporting repository revision requires a new boundary audit.

| Integration | Current status |
| --- | --- |
| LogWatcher | **Connected and validated at synthetic-lab level.** The tracked fixture demonstrates 20 source events, 3 alerts, and idempotent finding replay. A strict `security_alert.v1` staging contract and offline lifecycle rehearsal are also included; no live source transport has been validated. |
| JML-Automation | **Implemented as a read-only portfolio bridge and covered by repository tests.** It requires a closed request, a passing verification record bound to that request, and a verifier distinct from the requester and executor. No live directory changes are made. |
| Mini-SOAR | **Implemented as a synthetic-evidence bridge and covered by repository tests.** It authenticates the bundle manifest against an externally supplied digest, binds alert, finding, and verification identities across a `synthetic-lab` bundle, and requires a verifier distinct from the executor by default. |
| Windows, Elastic, SIEM, ITSM, Azure Blob, and SSO | **Adapters or contracts exist, but they have not been validated as live integrations in an organisation-owned environment.** |

For the Azure IaC boundary, exact manual deployment steps, rollback, and
remaining user-owned prerequisites, see
[`docs/azure/azure-staging-deployment.md`](../azure/azure-staging-deployment.md).
For the wider production requirements, see
[`docs/operations/production-runbook.md`](../operations/production-runbook.md) and
[`docs/azure/enterprise-deployment.md`](../azure/enterprise-deployment.md).
