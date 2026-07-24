-- 0013_retention: per-category retention deletion evidence (FR-033).
-- Records only non-PII counts/windows; never plaintext token values. Depends
-- solely on 0001_core's scopes/token_maps. gen_random_uuid() is built in.

CREATE TABLE IF NOT EXISTS retention_deletions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id      UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    category      TEXT NOT NULL,
    deleted_count INT NOT NULL,
    "window"      TEXT NOT NULL,  -- quoted: WINDOW is a reserved SQL keyword
    ts            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_retention_deletions_scope
    ON retention_deletions (scope_id, ts);

-- Tenant isolation: evidence rows are filtered to the scope set on the session,
-- and writes are forced through RLS like every other tenant table (FR-005).
ALTER TABLE retention_deletions ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_deletions FORCE ROW LEVEL SECURITY;

CREATE POLICY retention_deletions_scope ON retention_deletions
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
