-- 0023_record_links: known values linked to the app record they came from (015).
-- An app source (Odoo, Salesforce, ...) links each value to (collection, record_id).
-- A changed record's links are replaced, a deleted record's removed, and a complete
-- full sync drops the links it did not renew; an entry left with no link of either
-- kind (this table or catalog_entry_sources) retires. Source and entry FKs are
-- composite, as in 0021, so a row never names another tenant's source or entry.

CREATE TABLE IF NOT EXISTS catalog_entry_records (
    scope_id          UUID NOT NULL,
    source_id         UUID NOT NULL,
    collection        TEXT NOT NULL,
    record_id         TEXT NOT NULL,
    entry_id          UUID NOT NULL,
    last_seen_sync_id UUID NOT NULL,
    PRIMARY KEY (scope_id, source_id, collection, record_id, entry_id),
    FOREIGN KEY (scope_id, source_id) REFERENCES sources (scope_id, id) ON DELETE CASCADE,
    FOREIGN KEY (scope_id, entry_id) REFERENCES catalog_entries (scope_id, id) ON DELETE CASCADE
);

-- The retire check looks links up by entry; a full sync's cleanup by sync id.
CREATE INDEX IF NOT EXISTS idx_catalog_entry_records_entry ON catalog_entry_records (scope_id, entry_id);
CREATE INDEX IF NOT EXISTS idx_catalog_entry_records_sync
    ON catalog_entry_records (scope_id, source_id, last_seen_sync_id);

ALTER TABLE catalog_entry_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalog_entry_records FORCE ROW LEVEL SECURITY;

CREATE POLICY catalog_entry_records_scope ON catalog_entry_records
    USING (scope_id = current_setting('erebus.scope_id', true)::uuid);
