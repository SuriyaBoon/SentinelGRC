# Production deployment runbook

SentinelGRC is production-ready only after the following gates are satisfied in the target environment:

1. Apply the PostgreSQL migrations with a controlled migration runner.
2. Configure a durable queue and verify worker lease/retry behavior.
3. Configure OIDC/SSO, MFA, role mapping and short-lived token validation.
4. Put the HTTP adapter behind TLS, WAF, rate limiting and structured access logs.
5. Store API/connector secrets in a secret manager with rotation and revocation.
6. Export governance events to immutable/WORM storage or SIEM.
7. Configure encrypted evidence storage and retention/deletion policy.
8. Test backup restore and disaster recovery, including RTO/RPO evidence.
9. Enable metrics, traces, health/readiness probes and alerting.
10. Run dependency, vulnerability, security and penetration tests.

The repository's `deployment_contract.py` fails readiness when required controls are absent. The lab SQLite implementation remains useful for repeatable tests and portfolio demonstration; it is not a substitute for the production controls above.
