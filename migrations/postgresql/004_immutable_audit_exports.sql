CREATE TABLE IF NOT EXISTS audit_exports (
    export_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE REFERENCES governance_events(event_id),
    finding_id TEXT NOT NULL,
    event_sequence INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    available_at DOUBLE PRECISION NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    locked_until DOUBLE PRECISION,
    worker_id TEXT,
    lock_token TEXT,
    archived_at DOUBLE PRECISION,
    dead_at DOUBLE PRECISION,
    object_key TEXT,
    sha256 TEXT,
    size_bytes INTEGER,
    etag TEXT,
    last_error TEXT,
    UNIQUE(finding_id, event_sequence),
    CHECK(size_bytes IS NULL OR size_bytes > 0)
);

CREATE INDEX IF NOT EXISTS idx_audit_exports_claim
    ON audit_exports(
        archived_at,
        dead_at,
        available_at,
        locked_until,
        created_at
    );

INSERT INTO audit_exports(
    export_id,
    event_id,
    finding_id,
    event_sequence,
    payload_json,
    created_at,
    available_at
)
SELECT
    md5('audit-export:' || event_id),
    event_id,
    finding_id,
    event_sequence,
    jsonb_build_object(
        'finding_id', finding_id,
        'event_type', event_type,
        'actor_id', actor_id,
        'actor_role', actor_role,
        'auth_method', auth_method,
        'occurred_at', occurred_at,
        'details', details_json::jsonb,
        'previous_hash', previous_hash,
        'event_id', event_id,
        'event_sequence', event_sequence,
        'event_hash', event_hash
    )::text,
    occurred_at,
    occurred_at
FROM governance_events
ON CONFLICT(event_id) DO NOTHING;
