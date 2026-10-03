-- 0022_source_pending_job: work a source is owed (015). A change no active job covers
-- (a sample for new settings or credentials, a full sync for a field decision) is
-- recorded here and queued when the active job ends or the source is resumed.
ALTER TABLE sources ADD COLUMN IF NOT EXISTS pending_job TEXT
    CHECK (pending_job IN ('sample', 'full'));
