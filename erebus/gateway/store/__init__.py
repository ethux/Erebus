"""Tenant-scoped, Postgres-backed state layer for the gateway.

Replaces the per-user local SQLite KnownValueDB with a multi-tenant store where
every value is encrypted under the per-scope key and rows are RLS-filtered to the
owning scope (FR-005/036/037). Never uses the audit log as a recovery path or a
process-global mirror (FR-041..043).
"""
