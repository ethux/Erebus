"""Per-category retention with deletion evidence (FR-033).

Enforces a time-based retention window over a scope's ``token_maps`` rows: rows
older than ``now() - older_than_seconds`` are deleted, and a single non-PII
evidence row is written to ``retention_deletions`` (category, count, window, ts).
The evidence is a count and a human-readable window string only; it never mirrors
token text or plaintext values, so it cannot double as a recovery channel
(FR-041..043). All reads/writes are RLS-bound to the scope via ``scoped`` (FR-005).
"""
from __future__ import annotations

import uuid

import psycopg

from ..store.scope_context import scoped


def purge_expired(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    older_than_seconds: int,
    label: str | None = None,
) -> int:
    """Delete this scope's ``token_maps`` rows older than the window; log evidence.

    Deletes rows whose ``created_at`` is older than ``now() - older_than_seconds``
    (optionally restricted to a single ``label``), records a non-PII
    ``retention_deletions`` row, and returns the number of rows deleted (FR-033).
    """
    window = f"{older_than_seconds}s"
    category = label if label is not None else "*"
    with scoped(conn, scope_id):
        if label is None:
            deleted = conn.execute(
                "DELETE FROM token_maps "
                "WHERE scope_id = %s "
                "AND created_at < now() - make_interval(secs => %s) "
                "RETURNING id",
                (scope_id, older_than_seconds),
            ).fetchall()
        else:
            deleted = conn.execute(
                "DELETE FROM token_maps "
                "WHERE scope_id = %s AND label = %s "
                "AND created_at < now() - make_interval(secs => %s) "
                "RETURNING id",
                (scope_id, label, older_than_seconds),
            ).fetchall()
        count = len(deleted)
        conn.execute(
            "INSERT INTO retention_deletions "
            '(scope_id, category, deleted_count, "window") '  # "window" is a reserved keyword
            "VALUES (%s, %s, %s, %s)",
            (scope_id, category, count, window),
        )
    return count
