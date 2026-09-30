-- 0021_connectors: data sources, their field mapping, sync jobs and known-value links (015).
-- Tenant tables carry scope_id under FORCE row-level security. sync_jobs and
-- catalog_versions hold only ids, counters and times and have NO RLS: the sync worker
-- and the gateway replicas read them across tenants before any scope is bound.
-- A "source FK" is (scope_id, source_id) -> sources(scope_id, id) ON DELETE CASCADE:
-- FK checks bypass RLS, so the composite key is what stops a row in one tenant from
-- naming another tenant's source, and a write racing a source delete fails.

CREATE TABLE IF NOT EXISTS sources (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id              UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    connector_type        TEXT NOT NULL,
    settings              JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Encrypted under the scope DEK with AAD bound to the source id. Written by the
    -- gateway, decrypted only by the sync worker.
    secrets_ciphertext    BYTEA NOT NULL,
    secrets_nonce         BYTEA NOT NULL,
    secrets_key_version   INT NOT NULL DEFAULT 1,
    credentials_expire_at TIMESTAMPTZ,
    cursor                JSONB NOT NULL DEFAULT '{}'::jsonb,
    status                TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active', 'paused', 'needs_attention')),
    max_values            INT NOT NULL DEFAULT 1000000 CHECK (max_values > 0),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_id, id)
);

-- One row per field or name tuple (field = 'first_name+last_name'), written by the
-- sample job. decided_by = 'admin' keeps an admin decision across re-samples;
-- confirmable = false marks fields the rules never let an admin confirm.
CREATE TABLE IF NOT EXISTS source_fields (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id    UUID NOT NULL,
    source_id   UUID NOT NULL,
    collection  TEXT NOT NULL,
    field       TEXT NOT NULL,
    db_type     TEXT NOT NULL DEFAULT '',
    label       TEXT,
    decision    TEXT NOT NULL CHECK (decision IN ('auto', 'pending', 'confirmed', 'ignored')),
    reason      TEXT NOT NULL DEFAULT '',
    confirmable BOOLEAN NOT NULL DEFAULT true,
    decided_by  TEXT NOT NULL DEFAULT 'rule' CHECK (decided_by IN ('rule', 'admin')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_id, source_id, collection, field),
    FOREIGN KEY (scope_id, source_id) REFERENCES sources (scope_id, id) ON DELETE CASCADE
);

-- Existing rows take the defaults (manual, active); no backfill. One entry per
-- (normalized value, label): the label is inside value_blind_index.
ALTER TABLE catalog_entries ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'manual'
    CHECK (origin IN ('manual', 'source'));
ALTER TABLE catalog_entries ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'retired'));
ALTER TABLE catalog_entries ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;

-- Target of the composite entry FK below.
CREATE UNIQUE INDEX IF NOT EXISTS idx_catalog_entries_scope_id ON catalog_entries (scope_id, id);
CREATE INDEX IF NOT EXISTS idx_catalog_entries_status ON catalog_entries (scope_id, status);

-- Value-level links (databases, warehouses): which source last saw an entry, in which sync.
CREATE TABLE IF NOT EXISTS catalog_entry_sources (
    scope_id          UUID NOT NULL,
    entry_id          UUID NOT NULL,
    source_id         UUID NOT NULL,
    last_seen_sync_id UUID NOT NULL,
    PRIMARY KEY (scope_id, entry_id, source_id),
    FOREIGN KEY (scope_id, source_id) REFERENCES sources (scope_id, id) ON DELETE CASCADE,
    FOREIGN KEY (scope_id, entry_id) REFERENCES catalog_entries (scope_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_catalog_entry_sources_sync
    ON catalog_entry_sources (scope_id, source_id, last_seen_sync_id);

-- Erased values. value_index = blind_index(value, '') is label-free, so an erased
-- value is refused under every label.
CREATE TABLE IF NOT EXISTS catalog_suppressions (
    scope_id    UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    value_index BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_id, value_index)
);

-- The job queue. id is the sync id. No RLS (claimed across tenants); every API query
-- filters scope_id itself. lease_token fences a worker whose lease expired;
-- limited_since is when a job first waited on a source's rate limit (it fails after
-- EREBUS_SYNC_LIMIT_WAIT_S). attempts counts failed attempts, never limit waits.
CREATE TABLE IF NOT EXISTS sync_jobs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id       UUID NOT NULL,
    source_id      UUID NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('sample', 'full', 'incremental', 'oauth_exchange')),
    status         TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    attempts       INT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    not_before     TIMESTAMPTZ NOT NULL DEFAULT now(),
    heartbeat_at   TIMESTAMPTZ,
    leased_until   TIMESTAMPTZ,
    lease_token    UUID,
    limited_since  TIMESTAMPTZ,
    started_at     TIMESTAMPTZ,
    finished_at    TIMESTAMPTZ,
    rows_seen      BIGINT NOT NULL DEFAULT 0,
    values_added   BIGINT NOT NULL DEFAULT 0,
    values_retired BIGINT NOT NULL DEFAULT 0,
    error          TEXT,
    FOREIGN KEY (scope_id, source_id) REFERENCES sources (scope_id, id) ON DELETE CASCADE
);

-- At most one queued or running job per source: two syncs would overwrite each
-- other's last_seen_sync_id and retire what the other one saw.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_jobs_one_active
    ON sync_jobs (source_id) WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS idx_sync_jobs_claim ON sync_jobs (created_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_sync_jobs_lease ON sync_jobs (leased_until) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_sync_jobs_source ON sync_jobs (scope_id, source_id, created_at);

-- Bumped whenever a tenant's active known values change; replicas poll it to rebuild.
CREATE TABLE IF NOT EXISTS catalog_versions (
    scope_id   UUID PRIMARY KEY REFERENCES scopes(id) ON DELETE CASCADE,
    version    BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE sources               ENABLE ROW LEVEL SECURITY;
ALTER TABLE sources               FORCE ROW LEVEL SECURITY;
ALTER TABLE source_fields         ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_fields         FORCE ROW LEVEL SECURITY;
ALTER TABLE catalog_entry_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalog_entry_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE catalog_suppressions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalog_suppressions  FORCE ROW LEVEL SECURITY;

CREATE POLICY sources_scope ON sources
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);

CREATE POLICY source_fields_scope ON source_fields
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);

CREATE POLICY catalog_entry_sources_scope ON catalog_entry_sources
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);

CREATE POLICY catalog_suppressions_scope ON catalog_suppressions
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
