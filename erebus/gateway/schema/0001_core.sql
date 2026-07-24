-- 0001_core: scope registry, per-scope keys, and the encrypted token map (FR-005/006/036).
-- gen_random_uuid() is built into PostgreSQL 13+.

CREATE TABLE IF NOT EXISTS scopes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_key   TEXT UNIQUE NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_keys (
    scope_id    UUID PRIMARY KEY REFERENCES scopes(id) ON DELETE CASCADE,
    wrapped_dek BYTEA NOT NULL,
    key_version INT NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS token_maps (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id          UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    token             TEXT NOT NULL,
    label             TEXT NOT NULL,
    value_nonce       BYTEA NOT NULL,
    value_ciphertext  BYTEA NOT NULL,
    value_blind_index BYTEA NOT NULL,
    key_version       INT NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_id, token)
);

CREATE INDEX IF NOT EXISTS idx_token_maps_blind ON token_maps (scope_id, value_blind_index);

-- Defense-in-depth: rows are filtered to the scope set on the session; the
-- per-scope encryption key remains the primary isolation guarantee.
ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE token_maps  ENABLE ROW LEVEL SECURITY;
ALTER TABLE token_maps  FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_keys_scope ON tenant_keys
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);

CREATE POLICY token_maps_scope ON token_maps
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
