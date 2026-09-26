-- 0014_providers: centralized provider credentials + approved egress routes (FR-020/021/022).
-- Depends only on 0001_core (scopes). Credentials are encrypted at rest under the
-- per-scope DEK (ciphertext + nonce + key_version); routes carry an allowlist and an
-- explicit approval gate so egress is denied unless a route is approved.

CREATE TABLE IF NOT EXISTS provider_credentials (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id              UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    provider              TEXT NOT NULL,
    credential_ciphertext BYTEA NOT NULL,
    value_nonce           BYTEA NOT NULL,
    key_version           INT NOT NULL DEFAULT 1,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_id, provider)
);

CREATE TABLE IF NOT EXISTS provider_routes (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id          UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    base_url          TEXT NOT NULL,
    model_allowlist   JSONB NOT NULL DEFAULT '[]'::jsonb,
    approved          BOOLEAN NOT NULL DEFAULT false,
    residency_region  TEXT,
    priority          INT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_id, provider, base_url)
);

CREATE INDEX IF NOT EXISTS idx_provider_routes_select
    ON provider_routes (scope_id, provider, approved, priority);

-- Defense-in-depth: rows are filtered to the scope set on the session; the
-- per-scope encryption key remains the primary isolation guarantee for credentials.
ALTER TABLE provider_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE provider_routes      ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_routes      FORCE ROW LEVEL SECURITY;

CREATE POLICY provider_credentials_scope ON provider_credentials
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);

CREATE POLICY provider_routes_scope ON provider_routes
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
