# Enterprise deployment boundary

SentinelGRC is a security governance reference implementation. The code is designed to be extended into an enterprise service, but a GitHub repository alone cannot provide production identity, network, storage, or operational ownership.

## Required production controls

| Area | Required implementation | Current baseline |
|---|---|---|
| Identity | SSO/OIDC, RBAC, service identities, MFA | Not bundled; adapter boundary required |
| Transport | TLS everywhere; mTLS for agents and workers | Loopback HTTP lab mode |
| Secrets | Vault/Key Vault/Secrets Manager; rotation and revocation | External secret map plus metadata registry |
| State | PostgreSQL or equivalent shared transactional store | SQLite with leases and idempotency |
| Queue | Redis/RabbitMQ/SQS with DLQ and metrics | SQLite durable queue and polling worker |
| Evidence | WORM/object-lock retention, encryption, access logs | Local hash-chain JSONL |
| ITSM | Jira/ServiceNow API with approval/change IDs | Reviewable JSON tickets |
| SIEM | Signed event forwarding and correlation | Planned connector boundary |
| Operations | Windows service/container, health checks, metrics, alerts | CLI worker |
| Recovery | Backup/restore test, RPO/RTO evidence, key recovery | Documented future requirement |

## Security acceptance gates

Before production approval, require:

1. No public bind without TLS/mTLS and authentication.
2. No secrets in repository, local evidence, or logs.
3. Shared state store with tested transaction isolation and backup restore.
4. Queue metrics for pending, running, retry, and dead-letter jobs.
5. Immutable evidence retention and auditable access.
6. SSO/RBAC approval for exceptions and remediation closure.
7. SAST, dependency, secret, SBOM, and image scans in CI.
8. Incident response, key compromise, and disaster recovery exercises.

ISO/IEC 27001/27002 and NIST CSF mappings are control-evidence references; they do not constitute certification. CompTIA certifications describe practitioner knowledge and are not substitutes for organisational controls.
