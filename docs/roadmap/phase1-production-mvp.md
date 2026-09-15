# Phase 1 Production MVP status

## Locked scope

Security control findings only:

Finding -> Risk -> Treatment -> Approval -> Action
        -> Evidence -> Verification -> Closure

Privacy, BCM, full ITSM, multi-tenant, committee quorum and full framework implementations remain outside this phase.

## Production-MVP repository capabilities

- Versioned SQLite migrations with checksums in schema_migrations.
- Relational workflow records for findings, risks, treatments, approvals, actions, evidence, verification and closure.
- SENTINEL_STORAGE=governance makes GovernanceCore the primary pipeline write path.
- Legacy JSON is retained as compatibility export, not the governance source of truth.
- JSON queue migration is idempotent and authorization-gated.
- Authenticated human API-key/OIDC actor resolution.
- Typed audit actors and fail-closed canonicalization.
- Health/readiness and authenticated finding/lifecycle routes.
- Five-page governance console shell.
- Connector HMAC authentication and replay protection.
- Full regression and negative authorization coverage.

## Cutover

Lab/compatibility mode:

$env:SENTINEL_STORAGE = "legacy"
python -m scripts.pipeline run ...

Production-MVP SQLite mode:

$env:SENTINEL_STORAGE = "governance"
$env:SENTINEL_GOVERNANCE_DB = "runtime/governance.db"
python -m scripts.pipeline run ...

The JSON files remain export artifacts for compatibility. A failed GovernanceCore write fails the pipeline; it is not silently downgraded to JSON-only success.

## Exit boundary

This is a repository-level Production MVP. A real production release still requires external PostgreSQL, OIDC/SSO and MFA, WAF/TLS, durable queue, encrypted evidence/object storage, immutable audit archive, monitoring, backup/restore and security assessment.
