-- 0020_credential_privilege: bind authorization to the credential (010).
-- The privilege is set at issuance and is the only input to the admin gate. Existing rows
-- become 'tenant' (no admin privilege), so upgrading grants nothing: the first operator
-- comes from erebus-gateway create-operator. A constant DEFAULT is metadata-only on PG 11+.
-- Kept to ONE statement so a tolerant re-apply (IF NOT EXISTS) is a no-op.
ALTER TABLE scope_credentials
    ADD COLUMN IF NOT EXISTS privilege TEXT NOT NULL DEFAULT 'tenant'
    CHECK (privilege IN ('operator', 'tenant'));
