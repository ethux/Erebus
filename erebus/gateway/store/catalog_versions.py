"""Per-tenant catalog version (spec 015: ``catalog_versions``, no RLS).

Bumped whenever a tenant's active known values may have changed; gateway replicas poll
``read_all`` and rebuild a tenant's matcher when its number moves. Holds only ids,
counters and times, so it is read across tenants without a scope binding.
"""
from __future__ import annotations

import uuid

import psycopg


def bump(conn: psycopg.Connection, scope_id: uuid.UUID) -> int:
    """Increment the scope's version (creating it at 1); return the new number."""
    with conn.transaction():
        row = conn.execute(
            "INSERT INTO catalog_versions (scope_id, version) VALUES (%s, 1) "
            "ON CONFLICT (scope_id) DO UPDATE SET version = catalog_versions.version + 1, updated_at = now() "
            "RETURNING version",
            (scope_id,),
        ).fetchone()
    return row[0]


def read(conn: psycopg.Connection, scope_id: uuid.UUID) -> int:
    """The scope's version; 0 when it was never bumped."""
    with conn.transaction():
        row = conn.execute("SELECT version FROM catalog_versions WHERE scope_id = %s", (scope_id,)).fetchone()
    return row[0] if row else 0


def read_all(conn: psycopg.Connection) -> dict[uuid.UUID, int]:
    """Every tenant's version, for the replica poll."""
    with conn.transaction():
        rows = conn.execute("SELECT scope_id, version FROM catalog_versions").fetchall()
    return {sid: version for sid, version in rows}
