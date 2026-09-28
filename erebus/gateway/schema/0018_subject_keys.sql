-- 0018_subject_keys: per-subject DEK sub-tier for surgical GDPR erasure (T007/FR-031/032/040).
-- Each subject inside a scope gets its own DEK, wrapped under a per-subject KEK held only
-- in the KeyProvider (composite key id "scope_id:subject_id"). Only the wrapped DEK is
-- persisted; crypto-erasing one subject's KEK renders that subject's data irrecoverable
-- across every backup/replica without touching the scope or other subjects (FR-040).
-- Depends only on 0001_core (scopes). Same per-tenant RLS posture as the core tables.

CREATE TABLE IF NOT EXISTS subject_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id    UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    subject_id  TEXT NOT NULL,
    wrapped_dek BYTEA NOT NULL,
    key_version INT NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_id, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_subject_keys_scope ON subject_keys (scope_id);

-- Per-tenant isolation: same RLS posture as the core tenant tables (defense-in-depth;
-- the per-subject encryption key remains the primary isolation/erasure guarantee).
ALTER TABLE subject_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY subject_keys_scope ON subject_keys
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
