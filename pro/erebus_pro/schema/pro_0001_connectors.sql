-- SPDX-License-Identifier: Elastic-2.0
-- pro_0001_connectors: scheduled syncs (Erebus Pro). Applied by core after its own
-- migrations. No RLS: the rows hold ids, intervals and times only, and the scheduler
-- reads them across tenants. The composite source FK keeps a row from naming another
-- tenant's source and drops it with the source.

CREATE TABLE IF NOT EXISTS source_schedules (
    source_id           UUID PRIMARY KEY,
    scope_id            UUID NOT NULL,
    -- NULL means never. Bounds are checked here and by the schedule route.
    incremental_minutes INT CHECK (incremental_minutes BETWEEN 15 AND 1440),
    full_minutes        INT CHECK (full_minutes BETWEEN 60 AND 43200),
    next_incremental_at TIMESTAMPTZ,
    next_full_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (scope_id, source_id) REFERENCES sources (scope_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_source_schedules_full ON source_schedules (next_full_at)
    WHERE next_full_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_source_schedules_incremental ON source_schedules (next_incremental_at)
    WHERE next_incremental_at IS NOT NULL;
