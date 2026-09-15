# Project status

As of 2026-09-15. Baseline: `3bdfc881d0f0e8d4a2c22f827816bb328fe69514` (PR #153).
This is a dated evidence snapshot; reverify after code, dependency or infrastructure changes.

**Local delivery: complete. Cloud acceptance: externally blocked. Production: NO_GO_PENDING_LIVE_EVIDENCE.**

| Workstream | State | Evidence / next condition |
| --- | --- | --- |
| Governance, identity, evidence, queue/replay and connector code | Implemented and repository-tested | Not a claim of live integration |
| IaC preflight and image qualification contracts | Implemented | Current cloud prerequisites must be reverified |
| Local synthetic demo | PASS at baseline | Seven offline checks, 3 alerts, replay without duplicate findings, governed closure and local outbox |
| Local hermetic load/soak | PASS at baseline | 80 reassessments; 160 events; no missing, unexpected or mismatched deliveries; not production capacity |
| Full local baseline suite | OK | 576 tests, 555 non-skipped, 21 skipped, 81.243s on 2026-09-15 |
| Main CI at baseline | Success | Test, container-smoke, security-assessment and SonarCloud; historical result for exact SHA |
| Fresh local Docker verification | Unavailable at delivery checkpoint | Remote container CI is separate evidence |
| Independent Azure expiry/cleanup guardian | BLOCKED_EXTERNAL | Recovered Automation account was readable but update returned HTTP 400: Could not find the account; no successful guardian/notification proof |
| Current-version Azure live validation | 0/8 credited | No new live validation in local delivery; old observations cannot be carried forward automatically |
| Target-environment security/access/DR review | Pending live evidence | Required before pilot |
| Limited pilot | Not started | Requires live gates, approved workload and operational acceptance |
| Production GO | Not granted | Explicit human decision after all prerequisites |

## Azure blocker and resume conditions

The HTTP 400 is an observed cloud-operation failure, not a proven diagnosis of Microsoft's backend.
Support resolution or another independently reviewed solution is pending. A cleanup script run by the same process is not an independent guardian.
Failure notification is also unverified. Do not repeatedly create accounts or silently bypass the protection requirement.

Local code/documentation work may continue. Do not deploy or begin a paid live test while cleanup protection and a fresh spending/time window are unavailable.
No old budget is extended; no subscription upgrade or PAYG is authorized.
Resume only after verifying the guardian and notification path, credit/expiry, exact scope, absolute deadline, resource allowlist, evidence export and cleanup ownership.

## Eight live acceptance gates

1. Separate Entra identities and role enforcement.
2. Private-network execution.
3. Service Bus delivery.
4. Restart/replay without duplicate logical effects.
5. Dead-letter recovery.
6. PostgreSQL backup/restore verification.
7. Monitoring alerts observed and resolved.
8. Rollback to a verified digest-pinned revision.

All eight require current-image, sanitized, source-bound evidence. Then complete security/access/DR review, a bounded pilot and explicit human GO.

## Evidence and history

- [PR #153](https://github.com/SuriyaBoon/SentinelGRC/pull/153)
- [Baseline CI run](https://github.com/SuriyaBoon/SentinelGRC/actions/runs/34451079604)
- [Retained historical Azure evidence](evidence/historical-azure-staging-202608/README.md)
- [Synthetic fixture evidence](evidence/concept-validation/README.md)
- [Repository reorganization record](maintenance/repository-organization.md)

The local delivery log/ZIP is not committed here. Its dated summary is not a replacement for raw test output or an attestation.
A passing cleanup/documentation PR will not change the production verdict.
