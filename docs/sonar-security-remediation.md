# SonarCloud Overall Security Remediation

Task: `DEV-ef35c4440e32b1f8`
Residual review task: `DEV-2fd9aa7ccd0d85f8`

Source baseline: `8e0bd5e14fe1000db4e02437a393c99dfdfd8ca4`
Residual review baseline: `d1063800b044815acfa892417c9cc626b10d2fb9`

The residual review starts from three open security findings on `main`. Source
suppression is prohibited. Scanner acceptance is allowed only after the
security owner approves the documented boundary and its required evidence.

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

## Residual path and transport treatment

- `sentinelgrc.load_json` now resolves every input through the configured
  runtime root immediately before reading. Traversal, absolute escape, symlink
  escape, unreadable files, invalid UTF-8, and invalid JSON fail closed.
- `--allow-loopback-http` remains a lab interoperability exception. The server
  rejects it in `staging` and `production` before creating directories,
  databases, or listening sockets. TLS remains the default in every
  environment.
- Sonar rule `python:S5332` cannot distinguish the TLS-wrapped server socket
  from the explicitly isolated lab branch. It may be accepted only for the
  exact loopback `serve_forever` call after tests prove the environment and
  host gates. The acceptance must be revisited if the server implementation,
  bind policy, or TLS setup changes.

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
   unavailable, `allowInsecure` is false, Entra role assignments are distinct,
   and no client-certificate identity is claimed by the application.

It must not be silenced in source code merely to change a scanner score.
Microsoft documents that `accept` only forwards an optional certificate and
that `require` rejects clients without one. Neither setting provides a complete
authorization control unless the application validates the forwarded
certificate chain and identity. The current design therefore keeps Entra OIDC
as the human identity boundary and managed identities as the workload boundary.
This exception expires if ingress becomes public, a non-OIDC client is added,
or an approved certificate lifecycle and application-side validation are
implemented.

## Rating-A gate

Security Rating A requires all true vulnerabilities to be fixed and the single
client-certificate decision to be reviewed with evidence. The branch must then
be re-analysed by SonarCloud. A green new-code Quality Gate alone is not proof
that the overall rating has reached A.
