# Offline staging-readiness fixture

`logwatcher-security-alert.v1.jsonl` contains three sanitized, synthetic
LogWatcher alerts conforming to the strict `security_alert.v1` boundary. The
offline staging-assurance command uses this fixture to prove exact first
ingestion, replay idempotency, one complete finding lifecycle, event-chain
integrity and local transactional-outbox drainage.

This folder is input evidence only. Generated reports belong under ignored
`runtime/staging-assurance/` because they may include local execution details.
Nothing here proves Azure, Windows, Elastic, Entra, Service Bus, PostgreSQL or
private-network operation.
