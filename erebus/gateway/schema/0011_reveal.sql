-- 0011_reveal: privileged reveal grants (FR-015/016/019).
-- Default-deny break-glass: a reveal of token->value is allowed only when an
-- active, unexpired grant issued to the requester covers the requested tokens.
-- Single-use grants are consumed on the first authorized reveal. Depends only on
-- 0001_core.scopes. No plaintext token/value is stored here (FR-041); the grant
-- merely references token ids, and consumption state is not a recovery channel
-- (FR-042) nor a process-global (FR-043).

CREATE TABLE IF NOT EXISTS reveal_grants (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id      UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    grantee_id    TEXT NOT NULL,
    grantee_role  TEXT NOT NULL,
    purpose       TEXT NOT NULL,
    token_refs    JSONB NOT NULL DEFAULT '[]'::jsonb,
    request_id    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    single_use    BOOLEAN NOT NULL DEFAULT false,
    consumed_at   TIMESTAMPTZ,
    status        TEXT NOT NULL DEFAULT 'active'
);

CREATE INDEX IF NOT EXISTS idx_reveal_grants_lookup
    ON reveal_grants (scope_id, grantee_id, status);

-- Defense-in-depth: a grant is only visible to a session bound to its own scope.
ALTER TABLE reveal_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE reveal_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY reveal_grants_scope ON reveal_grants
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
