# Implemented safety controls

## Safety model

The following guardrails are implemented in code and covered by tests:

- **Server-derived human actor:** `GovernanceApi` rejects actor fields in request bodies. Lab mode resolves hashed API keys through `HumanIdentityStore`; staging verifies OIDC tokens before mapping claims to an actor.
- **OIDC fail-closed verification:** staging accepts only RS256 bearer tokens with a trusted `kid`, valid signature, issuer, audience, tenant, time claims, and exactly one configured Sentinel role. JWKS retrieval is HTTPS-only, bounded, cached, and protected from unknown-key refresh flooding.
- **Role-gated workflow:** only specified roles can assess, approve, verify, or close a finding; self-approval and self-verification are rejected in `GovernanceCore`.
- **Agent authentication and replay protection:** `scripts/ingestion_api.py`, `scripts/agent_keys.py`, and `state_store.py` validate HMAC-backed agent identity, nonces, and payload hashes.
- **Idempotent finding identity:** repeated LogWatcher alerts and bridged evidence reassess the same finding rather than creating duplicates.
- **Integrity records:** governance events are hash chained in a deterministic per-finding sequence; submitted evidence is SHA-256 hashed.
- **Evidence object boundary:** lab evidence uses server-generated content-addressed paths. Staging uses create-only Azure Blob writes through a user-assigned managed identity and commits governance metadata only after read-after-write integrity verification.
- **Recoverable immutable-audit boundary:** every governance event creates an
  audit-export record transactionally. A fenced worker archives canonical
  events in order with create-only writes, read-back verification, bounded
  retry, and explicit dead-letter state.
- **Recoverable broker-outbox boundary:** a single queue implementation covers
  SQLite lab and PostgreSQL staging. It validates canonical event metadata,
  fences stale publishers, preserves per-finding order, retries transient
  failures, dead-letters permanent failures, and requires exact operator
  confirmation before requeue. Azure publishing uses managed identity only,
  stable message/session IDs, TLS, bounded retries, and no connection-string
  fallback.
- **Bounded lab automation:** the repository collects and evaluates data. It does not automatically remediate endpoints or modify Active Directory.
- **Worker lease fencing:** a stale queue worker cannot complete or fail a job after its lease is no longer valid.
