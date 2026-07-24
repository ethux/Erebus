-- 0015_quota: per-tenant quota config + windowed usage counters (FR-039).
-- Fail-closed enforcement of rate_limit and spend_budget per scope. Depends only
-- on the 0001_core scopes table. RLS confines every row to its own scope.

CREATE TABLE IF NOT EXISTS quotas (
    scope_id        UUID PRIMARY KEY REFERENCES scopes(id) ON DELETE CASCADE,
    rate_limit      INT NOT NULL DEFAULT 0,
    concurrency_cap INT NOT NULL DEFAULT 0,
    spend_budget    NUMERIC NOT NULL DEFAULT 0,
    window_seconds  INT NOT NULL DEFAULT 60,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usage_counters (
    scope_id     UUID NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    window_start TIMESTAMPTZ NOT NULL,
    requests     INT NOT NULL DEFAULT 0,
    spend        NUMERIC NOT NULL DEFAULT 0,
    PRIMARY KEY (scope_id, window_start)
);

-- Defense-in-depth: every read/write is filtered to the scope set on the session.
ALTER TABLE quotas         ENABLE ROW LEVEL SECURITY;
ALTER TABLE quotas         FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_counters FORCE ROW LEVEL SECURITY;

CREATE POLICY quotas_scope ON quotas
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);

CREATE POLICY usage_counters_scope ON usage_counters
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
