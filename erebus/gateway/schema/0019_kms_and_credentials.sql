-- 0019_kms_and_credentials: restart-safe key custody + dynamic credential->scope (008 R2/R3).
-- gen_random_uuid() is built into PostgreSQL 13+.

-- Per-scope KEK wrapped by the operator master key. This is what makes key custody
-- survive a process restart (007 held KEKs only in memory). The raw KEK and the
-- master key never appear here; only the master-key-wrapped KEK is stored.
CREATE TABLE IF NOT EXISTS scope_keks (
    scope_id     UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    key_version  INT  NOT NULL,
    wrapped_kek  BYTEA NOT NULL,
    wrap_nonce   BYTEA NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',   -- active | rotated | crypto_erased
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_id, key_version)
);

-- Credential -> scope directory for dynamic, restart-free tenant resolution. Looked
-- up before a scope is known, so it is NOT row-confined by per-scope RLS; it stores
-- only a salted hash of the API credential, never the plaintext.
CREATE TABLE IF NOT EXISTS scope_credentials (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_hash  BYTEA NOT NULL UNIQUE,
    credential_salt  BYTEA NOT NULL,
    scope_id         UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    scope_key        TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'active',   -- active | revoked
    label            TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scope_credentials_active
    ON scope_credentials (credential_hash) WHERE status = 'active';

-- Defense-in-depth on the wrapped KEKs (the master-key wrap is the primary guarantee):
-- confine rows to the scope bound on the session, like tenant_keys/token_maps.
ALTER TABLE scope_keks ENABLE ROW LEVEL SECURITY;
ALTER TABLE scope_keks FORCE ROW LEVEL SECURITY;

CREATE POLICY scope_keks_scope ON scope_keks
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
