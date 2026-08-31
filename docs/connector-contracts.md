# Connector contract assurance

This document binds SentinelGRC's offline connector claims to the exact source
revisions audited on 31 August 2026. It is repository evidence only. It does
not prove a live transport, production identity, organisation-owned source,
Azure deployment, or operational service-level objective.

## Audited source revisions

| Boundary | Audited upstream revision | SentinelGRC contract |
| --- | --- | --- |
| LogWatcher | `SuriyaBoon/LogWatcher@0622bba18df602d079e227d7033f3a26e0c807f1` | `security_alert.v1` schema and runtime normalizer |
| JML-Automation | `SuriyaBoon/JML-Automation@07e82ba8f178fcf7d2e28534ed1d486e0edda0b3` (`agent/jml-mvp`) | read-only SQLite bridge for closed, independently verified requests |
| Mini-SOAR | `SuriyaBoon/Mini-SOAR@49f49931c6be3561a78628a2ceb353cb71e3e573` | bounded synthetic export-profile bridge with payload and cross-record identity checks |

Any upstream revision change makes this source-bound audit stale until the
boundary is reviewed again. SentinelGRC does not import code from these
repositories at runtime.

## Fail-closed contracts

### Signed connector events

The generic HMAC boundary accepts canonical lowercase source identifiers and
canonical event identifiers only. The replay key is `(source, event_id)`. An
exact byte replay is idempotent, while the same key with a different SHA-256
payload digest is an identity conflict and is rejected. SQLite and PostgreSQL
implement the same rule.

### LogWatcher security alerts

`schemas/security-alert.v1.schema.json` and `security_alert_contract.py` share
the same canonical text, RFC3339 timestamp, evidence-reference, identifier,
kind, severity, and event-code rules. Runtime normalization converts valid
offset timestamps to UTC. Control characters, boundary whitespace, malformed
evidence authorities, noncanonical source aliases, and mismatched
`kind`/`event_code` pairs fail closed.

The audited LogWatcher revision emits a simpler detector alert. The existing
staging adapter converts that output into `security_alert.v1`; no direct live
transport from LogWatcher has been asserted.

### JML-Automation

The bridge opens the source SQLite database with `mode=ro`. It accepts only a
closed request whose latest verification passed, belongs to the same request,
and was performed by neither the requester nor the latest execution actor.
Source request IDs, usernames, owners, departments, and actor fields are
validated again at the SentinelGRC trust boundary.

### Mini-SOAR

The bridge accepts `synthetic-lab` evidence only. It recomputes both the
upstream alert identity hash and the SHA-256 digest of the bounded canonical
producer-input profile represented by the export, then preserves the verified
source digest in governed finding evidence. It binds the alert ID, finding ID,
verification record, title, owner, severity, and evidence reference across the
bundle, rejects unsupported kinds, and requires the verifier to differ from the
execution actor by default.

Mini-SOAR identifiers are treated as bounded canonical source text rather than
SentinelGRC identifiers, so producer-valid values such as path-like asset IDs
remain importable without being reinterpreted. Mini-SOAR's timezone-aware ISO
timestamp profile is accepted at this boundary and normalized to UTC RFC3339
for governed evidence. Inputs whose original producer representation cannot be
reconstructed from that canonical export profile fail closed; this is not a
claim that every value accepted by Mini-SOAR's broader input normalizer is an
accepted connector payload. The explicit unverified demonstration switch
remains a local concept-only override and grants no production or live-gate
credit.

## Verification

The focused offline contract suite is:

```powershell
python -m unittest `
  test_connectors.py `
  test_security_alert_contract.py `
  test_bridge_jml.py `
  test_bridge_minisoar.py `
  test_postgres_runtime_state.py `
  test_staging_assurance.py
```

PostgreSQL tests require `SENTINEL_TEST_POSTGRES_URL`. Schema semantic-format
assertions use the repository's hash-locked assessment dependencies. The full
CI and container qualification paths remain the publication gate.

## Readiness boundary

This closes only the audited repository/offline connector-profile workstream.
Azure Live Validation remains `0 of 8`, and the product verdict remains
`NO_GO_PENDING_LIVE_EVIDENCE` until fresh live evidence, a limited pilot, and
an explicit human GO decision exist.
