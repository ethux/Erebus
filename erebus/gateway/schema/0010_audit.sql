-- 0010_audit: tamper-evident, append-only, per-scope hash-chained audit (FR-028/030/041).
-- entry_hash = sha256(prev_hash || canonical serialization of the row); the first
-- entry per scope chains a genesis constant. seq is dense and monotonic per scope.
-- Depends only on 0001_core's scopes(id) table.

CREATE TABLE IF NOT EXISTS audit_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id      UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    seq           BIGINT NOT NULL,
    event_type    TEXT NOT NULL,
    actor_id      TEXT,
    actor_role    TEXT,
    request_id    TEXT,
    masked_value  TEXT,
    category      TEXT,
    outcome       TEXT,
    metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
    ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash     BYTEA NOT NULL,
    entry_hash    BYTEA NOT NULL,
    UNIQUE (scope_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_audit_events_scope_type ON audit_events (scope_id, event_type);

-- Defense-in-depth: rows are filtered to the scope set on the session. The hash
-- chain remains the primary tamper-evidence guarantee.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_events_scope ON audit_events
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
