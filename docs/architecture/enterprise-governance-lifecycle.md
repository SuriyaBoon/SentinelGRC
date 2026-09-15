# Enterprise governance lifecycle

SentinelGRC is organized as one governance core with domain packs. The current security pack evaluates Windows posture and AD access review; `governance_core.py` supplies the common finding lifecycle that future privacy, BCM, vendor, cloud, and data packs can reuse.

## Definition of done

```text
Define control
  -> detect finding
  -> assess risk
  -> propose treatment
  -> authorized approval
  -> track remediation action
  -> collect evidence
  -> independent verification
  -> close or reopen risk
  -> report
```

The Phase 1 implementation provides:

- relational findings, evidence, and governance events;
- server-side actor context with roles: admin, analyst, risk_owner, approver, ciso, risk_committee;
- separation of duties for approval and verification;
- explicit state-transition guards;
- SHA-256 event chaining per finding;
- accepted-risk closure only after authorized approval;
- evidence SHA-256 fingerprints.

## Framework alignment

The implementation is designed to support control mapping and audit readiness for ISO/IEC 27001/27002, NIST CSF 2.0, CIS Controls, and future ISO 27701, ISO 22301, ISO 20000-1, PDPA/GDPR packs. It is not a certification or a claim of full compliance.

## Production exit criteria

Before production, replace the lab boundary with OIDC/SSO and MFA, short-lived tokens, PostgreSQL migrations, a managed queue, a secret manager, encrypted evidence storage, immutable/WORM or SIEM audit export, backups and restore tests, health/readiness endpoints, metrics/tracing, rate limiting, dependency scanning, incident response, and an independent security assessment.
