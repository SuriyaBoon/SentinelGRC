# Security model

## Collection boundary

The Windows agent is intentionally read-only. It collects operating-system security posture facts and writes one JSON record to a caller-selected path.

It does not:

- collect passwords, tokens, private keys, user files, or file contents;
- make network calls;
- modify firewall, Defender, BitLocker, users, services, or registry;
- auto-remediate a failed control;
- accept a remote computer name by default.

## Fail-closed behaviour

If a required check cannot be collected, its value is exported as false/null with an error entry. The governance layer must treat missing or failed evidence as non-compliant until a controlled re-check succeeds.

## Evidence trust

Posture JSON is an observation, not proof of identity by itself. A production integration must add:

- authenticated transport;
- agent identity and key rotation;
- signed payloads or mutually authenticated ingestion;
- replay protection using collection timestamp and nonce;
- server-side schema validation;
- immutable retention and access logging.

The Phase 1 hash chain protects the evidence ledger from unnoticed local edits. It is not a substitute for a trusted ingestion service or a cryptographic signature.

## Governance separation

Detection and evidence collection do not grant remediation authority. Any future remediation action must be:

1. explicitly approved by policy;
2. scoped to a named asset;
3. logged with actor and change identifier;
4. reversible where possible;
5. verified by a post-change control check.

Never place secrets in this repository. Use a secret manager or CI secret store for future integrations.
