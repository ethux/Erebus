-- 0012_erasure: subject erasure requests + crypto-erase certificates (FR-031/032/040).
-- Depends only on 0001_core (scopes). Records masked subjects only; the certificate
-- is a tamper-evident proof of what was deleted and which key versions were destroyed,
-- never a recovery channel (FR-041..043).

CREATE TABLE IF NOT EXISTS erasure_requests (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id           UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    subject_masked     TEXT NOT NULL,
    requested_by       TEXT NOT NULL,
    requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolution_method  TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'completed'
);

CREATE TABLE IF NOT EXISTS erasure_certificates (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    erasure_request_id     UUID NOT NULL REFERENCES erasure_requests(id) ON DELETE CASCADE,
    scope_id               UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    stores_acted_on        JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes_acted_on        JSONB NOT NULL DEFAULT '[]'::jsonb,
    key_versions_destroyed JSONB NOT NULL DEFAULT '[]'::jsonb,
    residual_scan          INT NOT NULL,
    completed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    certificate_hash       BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_erasure_requests_scope ON erasure_requests (scope_id);
CREATE INDEX IF NOT EXISTS idx_erasure_certificates_scope ON erasure_certificates (scope_id);

-- Per-tenant isolation: same RLS posture as the core tenant tables.
ALTER TABLE erasure_requests      ENABLE ROW LEVEL SECURITY;
ALTER TABLE erasure_requests      FORCE ROW LEVEL SECURITY;
ALTER TABLE erasure_certificates  ENABLE ROW LEVEL SECURITY;
ALTER TABLE erasure_certificates  FORCE ROW LEVEL SECURITY;

CREATE POLICY erasure_requests_scope ON erasure_requests
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);

CREATE POLICY erasure_certificates_scope ON erasure_certificates
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
