-- 0017_catalog: per-scope known-value catalog (T009; FR-009 known-value enforcement).
-- Org-curated values (project names, internal IDs, etc.) the generic detector
-- misses, stored encrypted at rest under the scope key. Lookup/dedupe is via a
-- scope-keyed blind index; no plaintext is ever persisted. Depends only on
-- 0001_core's scopes. gen_random_uuid() is built into PostgreSQL 13+.

CREATE TABLE IF NOT EXISTS catalog_entries (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id          UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    label             TEXT NOT NULL,
    value_ciphertext  BYTEA NOT NULL,
    value_nonce       BYTEA NOT NULL,
    value_blind_index BYTEA NOT NULL,
    key_version       INT NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_id, value_blind_index)
);

CREATE INDEX IF NOT EXISTS idx_catalog_entries_scope
    ON catalog_entries (scope_id, value_blind_index);

-- Tenant isolation: a request only ever sees its own scope's known values, and
-- the per-scope encryption key remains the primary isolation guarantee (FR-005).
ALTER TABLE catalog_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalog_entries FORCE ROW LEVEL SECURITY;

CREATE POLICY catalog_entries_scope ON catalog_entries
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
