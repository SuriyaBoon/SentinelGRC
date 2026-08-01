ALTER TABLE governance_outbox
    ADD COLUMN IF NOT EXISTS finding_id TEXT,
    ADD COLUMN IF NOT EXISTS event_sequence INTEGER,
    ADD COLUMN IF NOT EXISTS dead_at DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS broker_message_id TEXT,
    ADD COLUMN IF NOT EXISTS broker_accepted_at DOUBLE PRECISION;

UPDATE governance_outbox AS item
SET finding_id = event.finding_id,
    event_sequence = event.event_sequence
FROM governance_events AS event
WHERE item.event_id = event.event_id
  AND (item.finding_id IS NULL OR item.event_sequence IS NULL);

ALTER TABLE governance_outbox
    ALTER COLUMN finding_id SET NOT NULL,
    ALTER COLUMN event_sequence SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_governance_outbox_finding_sequence
    ON governance_outbox(finding_id, event_sequence);

CREATE INDEX IF NOT EXISTS idx_governance_outbox_delivery
    ON governance_outbox(
        delivered_at, dead_at, available_at, locked_until, created_at
    );

CREATE TABLE IF NOT EXISTS outbox_worker_heartbeats (
    worker_id TEXT PRIMARY KEY,
    heartbeat_at DOUBLE PRECISION NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running', 'degraded'))
);
