-- 0016_attestation: no-raw-egress attestation + tokenization-escape incidents (FR-003).
-- Depends only on 0001_core.scopes. Each row attests, per request turn, whether the
-- egress leaving the gateway was token-only or whether a raw protected value escaped
-- (a flagged incident). Rows are CONTENT-FREE: they record only categories/counts and
-- boolean verdicts, never the raw value that was scanned for (FR-003, FR-041..043).

CREATE TABLE IF NOT EXISTS egress_attestations (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id           UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    request_id         TEXT,
    token_only         BOOLEAN NOT NULL,
    escape_detected    BOOLEAN NOT NULL,
    escaped_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    ts                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_egress_attestations_scope
    ON egress_attestations (scope_id, escape_detected);

-- Defense-in-depth: an attestation is only visible to a session bound to its scope.
ALTER TABLE egress_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE egress_attestations FORCE ROW LEVEL SECURITY;

CREATE POLICY egress_attestations_scope ON egress_attestations
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
