# SonarCloud Overall Security Remediation

Task: `DEV-ef35c4440e32b1f8`

Source baseline: `8e0bd5e14fe1000db4e02437a393c99dfdfd8ca4`

This document records the security treatment for the 20 open vulnerability
findings reported on the `main` branch before this change. A candidate fix is
not called resolved until SonarCloud analyses the reviewed branch. No rule is
suppressed and no issue is marked accepted without an explicit architecture
decision and evidence.

## Baseline

| Category | Count | Treatment |
|---|---:|---|
| Filesystem path injection (`pythonsecurity:S8707`) | 11 | Central root confinement, symlink resolution, URI rejection, and existing-file checks before filesystem access |
| CLI-controlled SQLite connection (`pythonsecurity:S8706`) | 2 | Local filename-only database policy, fixed suffix allowlist, confined resolution, and `uri=False` |
| SSRF (`pythonsecurity:S8703`) | 1 | HTTPS requirement, exact hostname allowlist, credential rejection, and loopback-only HTTP opt-in |
| Plain HTTP (`python:S5332`) | 1 | TLS required by default; explicit lab-only HTTP is loopback-bound |
| Missing Azure resource identity (`azureresourcemanager:S6378`) | 3 | System-assigned identities declared for PostgreSQL, Storage, and Service Bus |
| Missing explicit Storage encryption (`azureresourcemanager:S6388`) | 1 | Account encryption and infrastructure encryption declared explicitly |
| Container Apps client certificate (`azureresourcemanager:S6382`) | 1 | Architecture decision required; see below |

## Trust-boundary changes

- `path_security.py` is the single source of truth for local path, SQLite,
  and outbound URL validation.
- Command-line values cannot select their own trust root. CLI entry points use
  the working directory established by the operator or orchestrator.
- Relative traversal, absolute escape, symlink escape, null bytes, SQLite URI
  parameters, unexpected database suffixes, non-allowlisted hosts, URL
  credentials, and non-loopback HTTP fail closed.
- The lab ingestion server is loopback-only and requires TLS by default.
  Plain HTTP needs the explicit `--allow-loopback-http` lab flag.
- The production image includes the shared policy module and its manifest
  remains import-closed.

## Client-certificate finding

The Container App is internal-only and authenticates humans with Entra OIDC.
The analyst and approver validation jobs use separate managed identities. A
blind change to `clientCertificateMode: 'require'` would break those clients
because no client-certificate issuance, rotation, revocation, or job-side
certificate delivery contract currently exists.

This finding must be handled in one of two reviewed ways:

1. implement a complete mTLS lifecycle and prove both role-isolated jobs can
   authenticate without sharing certificate material; or
2. record it as not applicable to this OIDC and private-network boundary, with
   security-owner approval and Azure live evidence proving public ingress is
   unavailable.

It must not be silenced in source code merely to change a scanner score.

## Rating-A gate

Security Rating A requires all true vulnerabilities to be fixed and the single
client-certificate decision to be reviewed with evidence. The branch must then
be re-analysed by SonarCloud. A green new-code Quality Gate alone is not proof
that the overall rating has reached A.
