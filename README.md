# SentinelGRC

Security observations become traceable findings, governed remediation, verified evidence and accountable closure.

**Status (2026-09-15): local demonstration delivered; Azure acceptance blocked.**
**Production verdict: `NO_GO_PENDING_LIVE_EVIDENCE`.**

This is a Python governance portfolio/concept MVP, not a production service, certified ISMS, or automatic endpoint remediation system.

## Start here

- [Project status and remaining acceptance gates](docs/STATUS.md)
- [Local quickstart](docs/getting-started/local-demo.md)
- [Documentation index](docs/README.md)
- [Architecture and trust boundaries](docs/architecture/system-overview.md)
- [Connector contracts](docs/integrations/connector-contracts.md)

## Current evidence

The inspected main baseline is `3bdfc881d0f0e8d4a2c22f827816bb328fe69514` (merged PR #153).
On 2026-09-15 the packaged-source local run completed 576 tests: 555 non-skipped and 21 skipped, with no failures.
The synthetic lifecycle, replay, local outbox and bounded load/soak demonstration passed.
These are baseline results, not CI approval of subsequent changes or Azure production evidence.

The independent Azure cleanup guardian remains blocked after an Automation account update returned HTTP 400.
It is a tracked external blocker, not a reason to repeat deployments, weaken cleanup requirements or claim a pass.
New Azure execution is paused pending safe cleanup protection and fresh budget/time approval. No PAYG.

## Repository map

| Location | Responsibility |
| --- | --- |
| Root `*.py` | Runtime/domain modules; existing public imports and image manifest preserved |
| `scripts/` | CLI entry points, bounded workers and evidence collectors |
| `tests/` | Unit, regression and optional integration suites |
| `agent/` | Read-only Windows/AD collectors |
| `config/`, `schemas/`, `fixtures/` | Non-secret policy, contracts and test fixtures |
| `migrations/` | Ordered SQLite/PostgreSQL migrations; never delete to roll back |
| `infra/azure/` | Reviewed infrastructure templates, not deployment permission |
| `ui/` | Static workflow interface |
| `docs/` | Categorized guides, status and retained evidence |
| `.github/` | CI and explicitly dispatched image qualification/publication |

Root JSON examples and policy inputs remain in place because documented commands and runtime defaults use them.
Runtime modules are not relocated as part of this documentation/test-layout cleanup.
Generated databases, secrets, caches and `runtime/` outputs are excluded from Git.
Other portfolio repositories and local worker/task artifacts do not belong in this repository.

## Verify locally

Use Python 3.12 and the hash-locked dependencies described in the quickstart.

```powershell
python -m unittest discover -v
python -m scripts.staging_assurance --policy config/staging-assurance.example.json --alerts docs/evidence/staging-readiness/logwatcher-security-alert.v1.jsonl
```

Skipped tests grant no integration credit. PostgreSQL, Docker, Bicep and cloud checks have distinct prerequisites.
See [status](docs/STATUS.md) for the exact separation of implemented code, local evidence, historical CI and unverified live controls.

## Scope and safety

SentinelGRC governs findings, risks, approvals, evidence and closure.
LogWatcher, JML and Mini-SOAR are separately bounded inputs; their concept documents are in
[portfolio references](docs/reference/portfolio/README.md), not additional SentinelGRC product commitments.

No production launch, new cloud budget, automatic deployment or merge is authorized by this README.
Historical evidence is retained with its original revision boundary.

