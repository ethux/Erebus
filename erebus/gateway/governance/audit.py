"""Tamper-evident, append-only, per-scope hash-chained audit (FR-028/030/041).

Each scope owns an independent hash chain over its ``audit_events`` rows. A new
entry's ``entry_hash`` is ``sha256(prev_hash || canonical(row))`` where the first
entry per scope chains a fixed genesis constant; this makes any retroactive edit,
deletion, or reordering detectable by recomputing the chain (FR-030). The API is
strictly append-only: it never issues UPDATE or DELETE against audit rows, so the
audit cannot be quietly rewritten and is not itself a recovery path for token
values (FR-041). Only already-masked values are recorded, never raw PII (FR-028).

Reads and writes are wrapped in ``scoped(...)`` so Postgres RLS confines every
query to the caller's scope, and no process-global mutable state is used.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import psycopg

from ..store.scope_context import scoped

# Genesis constant chained as the prev_hash of the first entry in every scope.
_GENESIS = hashlib.sha256(b"erebus.audit.genesis.v1").digest()

# Row fields covered by the hash chain, in canonical order. ``id``/``prev_hash``/
# ``entry_hash`` are excluded: id is random and prev_hash/entry_hash are the chain
# itself. ``ts`` is included as an ISO-8601 string so tampering with it is caught.
_CHAINED_FIELDS = (
    "scope_id",
    "seq",
    "event_type",
    "actor_id",
    "actor_role",
    "request_id",
    "masked_value",
    "category",
    "outcome",
    "metadata",
    "ts",
)


def _canonical(row: dict[str, Any]) -> bytes:
    """Deterministically serialize the chained fields of a row to bytes."""
    payload = {k: row[k] for k in _CHAINED_FIELDS}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("utf-8")


def _entry_hash(prev_hash: bytes, row: dict[str, Any]) -> bytes:
    return hashlib.sha256(bytes(prev_hash) + _canonical(row)).digest()


def append(
    conn: psycopg.Connection, scope_id: uuid.UUID, event: dict[str, Any]
) -> dict[str, Any]:
    """Append one audit entry to ``scope_id``'s chain; return the stored row.

    ``event`` carries the application fields (event_type, actor_id, actor_role,
    request_id, masked_value, category, outcome, metadata). Only masked values
    must be passed; raw PII must never reach this function (FR-028). The seq,
    prev_hash, ts, and entry_hash are assigned here so the chain stays dense and
    correct. A per-scope transaction advisory lock serializes concurrent appenders
    to the SAME scope (a hash chain is inherently sequential), so dense seq and
    prev_hash chaining hold under load; different scopes append in parallel.
    """
    with scoped(conn, scope_id):
        # Bound the wait on the per-scope advisory lock (FR-007): a stalled or slow
        # transaction holding this scope's lock must not block other appenders to
        # the same chain indefinitely. SET LOCAL (scoped to this transaction by
        # ``scoped``) makes a contended pg_advisory_xact_lock fail fast with a clean
        # lock-timeout error (psycopg LockNotAvailable), to be retried/failed-closed,
        # rather than hanging. Appends to OTHER scopes are unaffected.
        conn.execute("SET LOCAL lock_timeout = '3s'")
        # Serialize same-scope appends without blocking other scopes: this lock is
        # held until the transaction commits, so the read-then-insert of the next
        # seq/prev_hash cannot interleave with a concurrent append to this chain.
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (str(scope_id),))
        tail = conn.execute(
            "SELECT seq, entry_hash FROM audit_events "
            "WHERE scope_id = %s ORDER BY seq DESC LIMIT 1",
            (scope_id,),
        ).fetchone()
        if tail is None:
            seq = 1
            prev_hash = _GENESIS
        else:
            seq = tail[0] + 1
            prev_hash = bytes(tail[1])

        row = {
            "scope_id": str(scope_id),
            "seq": seq,
            "event_type": str(event["event_type"]),
            "actor_id": event.get("actor_id"),
            "actor_role": event.get("actor_role"),
            "request_id": event.get("request_id"),
            "masked_value": event.get("masked_value"),
            "category": event.get("category"),
            "outcome": event.get("outcome"),
            "metadata": event.get("metadata") or {},
        }
        inserted = conn.execute(
            "INSERT INTO audit_events "
            "(scope_id, seq, event_type, actor_id, actor_role, request_id, "
            " masked_value, category, outcome, metadata, prev_hash, entry_hash) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "RETURNING id, ts",
            (
                scope_id,
                seq,
                row["event_type"],
                row["actor_id"],
                row["actor_role"],
                row["request_id"],
                row["masked_value"],
                row["category"],
                row["outcome"],
                json.dumps(row["metadata"]),
                prev_hash,
                prev_hash,  # placeholder; overwritten below once ts is known
            ),
        ).fetchone()
        entry_id, ts = inserted[0], inserted[1]

        # ts is server-assigned; fold its canonical form into the hash, then store
        # the final entry_hash. This UPDATE only fills the just-inserted row's
        # placeholder hash within the same transaction (not a mutation of history).
        row["ts"] = ts.isoformat()
        entry_hash = _entry_hash(prev_hash, row)
        conn.execute(
            "UPDATE audit_events SET entry_hash = %s WHERE id = %s",
            (entry_hash, entry_id),
        )

    return {
        "id": entry_id,
        "scope_id": scope_id,
        "seq": seq,
        "event_type": row["event_type"],
        "actor_id": row["actor_id"],
        "actor_role": row["actor_role"],
        "request_id": row["request_id"],
        "masked_value": row["masked_value"],
        "category": row["category"],
        "outcome": row["outcome"],
        "metadata": row["metadata"],
        "ts": ts,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    }


def verify_chain(conn: psycopg.Connection, scope_id: uuid.UUID) -> bool:
    """Recompute the scope's hash chain; return True iff it is intact (FR-030).

    Walks the scope's entries in seq order and checks that (a) seq is dense from 1,
    (b) each stored prev_hash equals the prior entry_hash (genesis for the first),
    and (c) each stored entry_hash equals ``sha256(prev_hash || canonical(row))``.
    Any tamper (edited field, deleted/reordered row, forged hash) fails one check.
    """
    with scoped(conn, scope_id):
        rows = conn.execute(
            "SELECT seq, event_type, actor_id, actor_role, request_id, "
            " masked_value, category, outcome, metadata, ts, prev_hash, entry_hash "
            "FROM audit_events WHERE scope_id = %s ORDER BY seq ASC",
            (scope_id,),
        ).fetchall()

    expected_prev = _GENESIS
    expected_seq = 1
    for r in rows:
        (
            seq, event_type, actor_id, actor_role, request_id,
            masked_value, category, outcome, metadata, ts, prev_hash, entry_hash,
        ) = r
        if seq != expected_seq:
            return False
        if bytes(prev_hash) != expected_prev:
            return False
        row = {
            "scope_id": str(scope_id),
            "seq": seq,
            "event_type": event_type,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "request_id": request_id,
            "masked_value": masked_value,
            "category": category,
            "outcome": outcome,
            "metadata": metadata or {},
            "ts": ts.isoformat(),
        }
        if _entry_hash(prev_hash, row) != bytes(entry_hash):
            return False
        expected_prev = bytes(entry_hash)
        expected_seq += 1
    return True


def query(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    """Return the scope's audit entries (RLS-confined), newest-last, optionally
    filtered by ``event_type``. Read-only; never crosses a scope boundary."""
    sql = (
        "SELECT id, scope_id, seq, event_type, actor_id, actor_role, request_id, "
        " masked_value, category, outcome, metadata, ts, prev_hash, entry_hash "
        "FROM audit_events WHERE scope_id = %s"
    )
    params: tuple[Any, ...] = (scope_id,)
    if event_type is not None:
        sql += " AND event_type = %s"
        params += (event_type,)
    sql += " ORDER BY seq ASC"
    with scoped(conn, scope_id):
        rows = conn.execute(sql, params).fetchall()
    cols = (
        "id", "scope_id", "seq", "event_type", "actor_id", "actor_role",
        "request_id", "masked_value", "category", "outcome", "metadata",
        "ts", "prev_hash", "entry_hash",
    )
    return [dict(zip(cols, r, strict=True)) for r in rows]
