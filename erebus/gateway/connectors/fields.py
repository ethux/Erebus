"""Field mapping of a source (spec 015 "Data model": ``source_fields``).

The sample job writes one row per field or name tuple (``field = 'first_name+last_name'``)
with the gateway rules' decision. An admin may confirm or ignore a field; that decision
survives re-samples, except a confirm of a field the rules now call unconfirmable.
"""
from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

import psycopg

from ..store import catalog_versions
from ..store.scope_context import scoped

_RULE_DECISIONS = ("auto", "pending", "ignored")
_ADMIN_DECISIONS = ("confirmed", "ignored")
_COLUMNS = "id, source_id, collection, field, db_type, label, decision, reason, confirmable, decided_by"
# An admin decision is kept unless it confirms a field the new sample calls unconfirmable.
_KEEP_ADMIN = "(source_fields.decided_by = 'admin' AND (EXCLUDED.confirmable OR source_fields.decision = 'ignored'))"


class FieldNotConfirmable(Exception):
    """The rules never let this field be confirmed (binary type, lone name part, free text)."""

    def __init__(self) -> None:
        super().__init__("this field cannot be confirmed")


@dataclass(frozen=True)
class FieldSample:
    """What the gateway rules decided for one field of a sampled collection."""

    collection: str
    field: str
    db_type: str
    label: str | None
    decision: str  # auto, pending or ignored
    reason: str = ""
    confirmable: bool = True


@dataclass(frozen=True)
class SourceField:
    """A stored field row."""

    id: uuid.UUID
    source_id: uuid.UUID
    collection: str
    field: str
    db_type: str
    label: str | None
    decision: str
    reason: str
    confirmable: bool
    decided_by: str


def record_sample(
    conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID, samples: Iterable[FieldSample]
) -> int:
    """Write a sample's field decisions; return how many fields are now accepted.

    Rule rows the sample no longer has are removed; admin rows are kept (their column
    may come back, and a sync that cannot read them fails incomplete, retiring nothing).
    """
    rows: dict[tuple[str, str], FieldSample] = {}
    for s in samples:
        if s.decision not in _RULE_DECISIONS:
            raise ValueError("a sample decides auto, pending or ignored")
        rows[(s.collection, s.field)] = s
    batch = list(rows.values())
    with scoped(conn, scope_id):
        conn.execute(
            "INSERT INTO source_fields "
            "(scope_id, source_id, collection, field, db_type, label, decision, reason, confirmable) "
            "SELECT %s, %s, t.c, t.f, t.d, t.l, t.dec, t.r, t.cf FROM unnest("
            "%s::text[], %s::text[], %s::text[], %s::text[], %s::text[], %s::text[], %s::bool[]"
            ") AS t(c, f, d, l, dec, r, cf) "
            "ON CONFLICT (scope_id, source_id, collection, field) DO UPDATE SET "
            "db_type = EXCLUDED.db_type, confirmable = EXCLUDED.confirmable, updated_at = now(), "
            f"label = CASE WHEN {_KEEP_ADMIN} THEN source_fields.label ELSE EXCLUDED.label END, "
            f"decision = CASE WHEN {_KEEP_ADMIN} THEN source_fields.decision ELSE EXCLUDED.decision END, "
            f"reason = CASE WHEN {_KEEP_ADMIN} THEN source_fields.reason ELSE EXCLUDED.reason END, "
            f"decided_by = CASE WHEN {_KEEP_ADMIN} THEN 'admin' ELSE 'rule' END",
            (scope_id, source_id, [s.collection for s in batch], [s.field for s in batch],
             [s.db_type for s in batch], [s.label for s in batch], [s.decision for s in batch],
             [s.reason for s in batch], [s.confirmable for s in batch]),
        )
        conn.execute(
            "DELETE FROM source_fields WHERE scope_id = %s AND source_id = %s AND decided_by = 'rule' "
            "AND (collection, field) NOT IN (SELECT * FROM unnest(%s::text[], %s::text[]))",
            (scope_id, source_id, [s.collection for s in batch], [s.field for s in batch]),
        )
        return conn.execute(
            "SELECT count(*) FROM source_fields WHERE scope_id = %s AND source_id = %s "
            "AND decision IN ('auto', 'confirmed')",
            (scope_id, source_id),
        ).fetchone()[0]


def list_fields(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID) -> list[SourceField]:
    """Every field row of the source, by collection and field."""
    with scoped(conn, scope_id):
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM source_fields WHERE scope_id = %s AND source_id = %s "
            "ORDER BY collection, field",
            (scope_id, source_id),
        ).fetchall()
    return [SourceField(*r) for r in rows]


def accepted_fields(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID) -> list[SourceField]:
    """The fields a full sync reads: auto-accepted or confirmed."""
    return [f for f in list_fields(conn, scope_id, source_id) if f.decision in ("auto", "confirmed")]


def decide_field(
    conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID, field_id: uuid.UUID, decision: str
) -> SourceField | None:
    """Record an admin's confirm or ignore; ``None`` when the field is not in this scope.

    A field without a label or marked unconfirmable raises ``FieldNotConfirmable`` on
    confirm. Bumps the catalog version (the full sync it queues changes values).
    """
    if decision not in _ADMIN_DECISIONS:
        raise ValueError("a field is confirmed or ignored")
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT confirmable, label FROM source_fields WHERE scope_id = %s AND source_id = %s AND id = %s "
            "FOR UPDATE",
            (scope_id, source_id, field_id),
        ).fetchone()
        if row is None:
            return None
        if decision == "confirmed" and (not row[0] or row[1] is None):
            raise FieldNotConfirmable()
        updated = conn.execute(
            "UPDATE source_fields SET decision = %s, decided_by = 'admin', updated_at = now() "
            f"WHERE scope_id = %s AND id = %s RETURNING {_COLUMNS}",
            (decision, scope_id, field_id),
        ).fetchone()
        catalog_versions.bump(conn, scope_id)
    return SourceField(*updated)
