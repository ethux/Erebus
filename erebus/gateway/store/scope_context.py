"""Bind a Postgres session to a scope so RLS filters every query to it (FR-005).

Uses ``set_config(..., is_local => true)`` inside a transaction, so the binding is
scoped to that transaction and cannot leak to the next request on a pooled
connection.
"""
from __future__ import annotations

import contextlib
import uuid

import psycopg


@contextlib.contextmanager
def scoped(conn: psycopg.Connection, scope_id: uuid.UUID):
    """Open a transaction with ``erebus.scope_id`` set for RLS."""
    with conn.transaction():
        conn.execute("SELECT set_config('erebus.scope_id', %s, true)", (str(scope_id),))
        yield conn
