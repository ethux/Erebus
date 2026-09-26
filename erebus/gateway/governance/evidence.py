"""Scoped, integrity-verifiable compliance evidence pack export (FR-035).

A regulator or auditor periodically needs a single, self-contained proof bundle
for exactly one tenant scope. :func:`export_pack` assembles, for that scope only,
the four governance artifacts already maintained elsewhere in the gateway:

  * the tamper-evident audit chain (``governance.audit.query``),
  * the privileged reveal grants (``reveal_grants``),
  * the crypto-erase certificates (``erasure_certificates``),
  * the retention deletion evidence (``retention_deletions``),

and binds them together with a ``pack_hash`` = ``sha256`` over a canonical
serialization of the whole pack. Recomputing that hash over the returned pack
detects any later alteration, so the export is integrity-verifiable on its own.

Strict scope isolation (FR-005): every read is wrapped in ``scoped(...)`` so
Postgres RLS confines it to the caller's scope, and a parallel scope's rows can
never appear in the pack. The pack mirrors only the already-masked values these
tables hold (masked subjects, token references, counts, hashes); it never adds a
raw-PII field, so it is not a recovery channel and holds no plaintext mirror
(FR-041..043). No process-global mutable state is used.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

import psycopg

from ..store.scope_context import scoped
from . import audit


def _jsonable(value: Any) -> Any:
    """Canonicalize one value for stable, cross-process hashing/serialization.

    ``bytes`` (hash columns) become lowercase hex, ``datetime``/``uuid`` become
    ISO-8601 / string, and containers recurse. This makes the pack deterministic
    regardless of psycopg's native Python types so the hash is reproducible.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _rows(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    sql: str,
    cols: tuple[str, ...],
    *,
    since: datetime | None,
    until: datetime | None,
    ts_col: str,
) -> list[dict[str, Any]]:
    """RLS-confined SELECT returning canonicalized dict rows, time-windowed.

    The query is already scoped to ``scope_id`` and we add an optional inclusive
    lower / exclusive upper bound on ``ts_col`` so the pack can cover a window.
    """
    params: list[Any] = [scope_id]
    where = "WHERE scope_id = %s"
    if since is not None:
        where += f" AND {ts_col} >= %s"
        params.append(since)
    if until is not None:
        where += f" AND {ts_col} < %s"
        params.append(until)
    with scoped(conn, scope_id):
        rows = conn.execute(f"{sql} {where} ORDER BY {ts_col} ASC, id ASC", params).fetchall()
    return [
        {c: _jsonable(v) for c, v in zip(cols, r, strict=True)} for r in rows
    ]


def _pack_hash(pack: dict[str, Any]) -> str:
    """sha256 over a canonical JSON serialization of the pack's contents (FR-035).

    Excludes the ``pack_hash`` key itself (it is the output) and serializes with
    sorted keys and tight separators so the digest is byte-for-byte stable across
    runs and processes. Returns lowercase hex.
    """
    payload = {k: v for k, v in pack.items() if k != "pack_hash"}
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def export_pack(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict[str, Any]:
    """Export an integrity-verifiable compliance evidence pack for one scope (FR-035).

    Assembles, for ``scope_id`` only (RLS-confined, never cross-tenant), the audit
    chain, reveal grants, erasure certificates, and retention deletions optionally
    restricted to ``[since, until)``, then adds a ``pack_hash`` binding them all.
    The pack carries only already-masked values; it introduces no raw PII (FR-041).
    """
    # Audit chain: reuse the canonical reader, then window + canonicalize locally.
    audit_events: list[dict[str, Any]] = []
    for ev in audit.query(conn, scope_id):
        ts = ev["ts"]
        if since is not None and ts < since:
            continue
        if until is not None and ts >= until:
            continue
        audit_events.append({k: _jsonable(v) for k, v in ev.items()})

    reveal_grants = _rows(
        conn,
        scope_id,
        "SELECT id, scope_id, grantee_id, grantee_role, purpose, token_refs, "
        "request_id, created_at, expires_at, single_use, consumed_at, status "
        "FROM reveal_grants",
        (
            "id", "scope_id", "grantee_id", "grantee_role", "purpose", "token_refs",
            "request_id", "created_at", "expires_at", "single_use", "consumed_at",
            "status",
        ),
        since=since,
        until=until,
        ts_col="created_at",
    )

    erasure_certificates = _rows(
        conn,
        scope_id,
        "SELECT id, erasure_request_id, scope_id, stores_acted_on, scopes_acted_on, "
        "key_versions_destroyed, residual_scan, completed_at, certificate_hash "
        "FROM erasure_certificates",
        (
            "id", "erasure_request_id", "scope_id", "stores_acted_on",
            "scopes_acted_on", "key_versions_destroyed", "residual_scan",
            "completed_at", "certificate_hash",
        ),
        since=since,
        until=until,
        ts_col="completed_at",
    )

    retention_deletions = _rows(
        conn,
        scope_id,
        'SELECT id, scope_id, category, deleted_count, "window", ts '
        "FROM retention_deletions",
        ("id", "scope_id", "category", "deleted_count", "window", "ts"),
        since=since,
        until=until,
        ts_col="ts",
    )

    pack: dict[str, Any] = {
        "scope_id": str(scope_id),
        "since": since.isoformat() if since is not None else None,
        "until": until.isoformat() if until is not None else None,
        "audit_events": audit_events,
        "reveal_grants": reveal_grants,
        "erasure_certificates": erasure_certificates,
        "retention_deletions": retention_deletions,
    }
    pack["pack_hash"] = _pack_hash(pack)
    return pack
