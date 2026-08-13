# Pre-Live Security Assessment

This assessment is a repository and CI security gate. It does not claim that
deployed Azure controls work and it is not a penetration test or certification.

## Scope and ownership

| Area | Evidence | Owner | Failure treatment |
|---|---|---|---|
| CI supply chain | Every external GitHub Action uses a full commit SHA | Platform owner | Remediate before release |
| Dependency integrity | Exact versions and artifact hashes | Dependency owner | Regenerate and review lock |
| Dependency vulnerabilities | Pinned PyPA `pip-audit` outcome and source/run-bound receipt digest | Dependency owner | Upgrade, remove, or formally accept with expiry |
| Container boundary | Digest-pinned runtime base, effective final-stage non-root user in both images, explicit COPY sources | Platform owner | Remediate before image publication |
| Security decisions | Owner, rationale, expiry, production boundary | Security owner | Re-review or expire closed |
| Regression boundary | Auth, path, crypto, IaC and supply-chain suites | Repository owner | Restore required tests |
| Secret hygiene | High-confidence patterns; locations only | Security owner | Revoke first, then remove and investigate |

Workflow action declarations are parsed structurally with the exact PyYAML
version and artifact hashes in `requirements-assessment-hashed.txt`. Invalid,
ambiguous, duplicate-key, non-scalar, custom-tag, oversized, or recursive YAML
fails the action-pinning control closed. The assessment dependency lock is
installed only by unit-test and assessment jobs; it is not copied into the
production runtime image. The pinned dependency-audit action scans both the
runtime and assessment lock in one required outcome.

Every failed or unavailable required offline control creates an open finding
with severity, owner, and `REMEDIATE_OR_FORMALLY_ACCEPT`. An accepted risk needs
a named owner, rationale, expiry date, compensating controls, and explicit human
approval. The collector itself never accepts risk.

## CI execution

The CI job runs a commit-pinned PyPA `pip-audit` action against both hash-locked
requirements files, then writes the fixed artifact:

```text
runtime/staging-assurance/security-assessment-evidence.json
```

The raw scanner output is not retained in the sanitized assessment. If the
action exposes a nonempty report, only its SHA-256 digest is recorded. When a
successful action exposes no report body, the collector creates a deterministic
receipt bound to the pinned action, source SHA, GitHub run ID, and trusted step
outcome. This is CI orchestration metadata, not cryptographic attestation of the
runner, operator, or vulnerability database.

Exit codes are `0` for `PASS_OFFLINE`, `1` for a valid `NO_GO` assessment, and
`2` for invalid input or evidence. Artifact upload still runs after a valid
scanner failure so the reason for `NO_GO` is retained.

A skipped or cancelled dependency audit is recorded as `UNAVAILABLE`, creates
a fail-closed finding, and retains a valid `NO_GO` assessment artifact. CI must
not silently omit evidence when the scanner does not run.

## Mandatory live boundary

The following remain `NOT_TESTED_LIVE` in every offline document:

- Entra analyst and approver role separation;
- Managed Identity access to actual Azure resources;
- private-network exposure from an external and private execution point;
- any complete mTLS issuance, rotation, revocation and application-validation lifecycle;
- deployed Azure resource configuration; and
- independent penetration validation.

Therefore even `PASS_OFFLINE` grants no Azure live-gate credit and preserves
`NO_GO_PENDING_LIVE_EVIDENCE`.

## Handoff

```text
Pre-Live Security Assessment
-> remediate or formally accept every offline finding
-> IaC preflight and what-if
-> Azure Live Validation
-> independent security/access review
-> limited production pilot verdict
```

## Qualification dependency boundary

The production runtime image intentionally excludes PyYAML. The manual staging
publication workflow builds an ephemeral `Dockerfile.qualification` overlay
from the exact runtime layer, installs the hash-locked assessment dependency,
and runs the repository suite there. Only the runtime and assurance images are
saved and published. If assessment dependency setup fails in CI, the standard
library evidence path still writes a `NO_GO` artifact; it never grants live
validation credit.
