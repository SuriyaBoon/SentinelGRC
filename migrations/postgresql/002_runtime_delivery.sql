CREATE TABLE IF NOT EXISTS connector_events (
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    accepted_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (source, event_id)
);

CREATE TABLE IF NOT EXISTS pipeline_jobs (
    job_id BIGSERIAL PRIMARY KEY,
    payload_path TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'running', 'completed', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at DOUBLE PRECISION NOT NULL,
    locked_until DOUBLE PRECISION,
    worker_id TEXT,
    lock_token TEXT,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_claim
    ON pipeline_jobs(status, available_at, locked_until, job_id);

CREATE TABLE IF NOT EXISTS governance_outbox (
    outbox_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE REFERENCES governance_events(event_id),
    topic TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    available_at DOUBLE PRECISION NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    locked_until DOUBLE PRECISION,
    worker_id TEXT,
    lock_token TEXT,
    delivered_at DOUBLE PRECISION,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_governance_outbox_claim
    ON governance_outbox(delivered_at, available_at, locked_until, created_at);
