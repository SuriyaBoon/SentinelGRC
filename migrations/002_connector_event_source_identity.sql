-- PostgreSQL production migration. The SQLite lab schema self-migrates in code.
-- Apply with a PostgreSQL-compatible migration runner; do not use migration_runner.py.

ALTER TABLE governance_events ADD COLUMN IF NOT EXISTS event_sequence BIGINT;

WITH ordered_events AS (
    SELECT event_id,
           row_number() OVER (PARTITION BY finding_id ORDER BY occurred_at, event_id) AS sequence
    FROM governance_events
)
UPDATE governance_events AS event
SET event_sequence = ordered_events.sequence
FROM ordered_events
WHERE event.event_id = ordered_events.event_id
  AND event.event_sequence IS NULL;

ALTER TABLE governance_events ALTER COLUMN event_sequence SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_governance_events_finding_sequence
    ON governance_events(finding_id, event_sequence);

ALTER TABLE connector_events DROP CONSTRAINT IF EXISTS connector_events_pkey;
ALTER TABLE connector_events ADD PRIMARY KEY (source, event_id);
