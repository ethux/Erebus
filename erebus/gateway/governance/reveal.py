"""Privileged reveal grants: default-deny break-glass authorization (FR-015/016/019).

A reveal exposes the plaintext behind a placeholder token, so it is gated. By
default every reveal is denied (FR-016): a request succeeds only when the caller
holds the ``reveal-authorized`` role, supplies a non-empty business purpose
(FR-019), and an active, unexpired grant issued to them covers every requested
token (FR-015). Single-use grants are consumed on the first authorized reveal and
deny every subsequent attempt.

The grant stores only token *references* (placeholder ids), never the plaintext
values they hide, so this table is not a plaintext mirror (FR-041) and its
consumption state is not a value-recovery channel (FR-042). All state lives in
Postgres under row-level security; nothing is held in process-global mutable
state (FR-043).
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Iterable

import psycopg

from ..store.scope_context import scoped

REVEAL_ROLE = "reveal-authorized"


def grant(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    grantee_id: str,
    role: str,
    purpose: str,
    tokens: Iterable[str],
    ttl_seconds: int = 3600,
    single_use: bool = False,
    request_id: str | None = None,
) -> uuid.UUID:
    """Issue a reveal grant to ``grantee_id`` covering ``tokens``; return its id.

    ``purpose`` must be non-empty (FR-019) and ``tokens`` must list at least one
    placeholder the grant authorizes. ``expires_at`` is ``now() + ttl_seconds``.
    """
    purpose = purpose.strip()
    if not purpose:
        raise ValueError("a non-empty purpose is required to issue a reveal grant (FR-019)")
    token_refs = sorted({t for t in tokens})
    if not token_refs:
        raise ValueError("a reveal grant must cover at least one token")
    with scoped(conn, scope_id):
        row = conn.execute(
            "INSERT INTO reveal_grants "
            "(scope_id, grantee_id, grantee_role, purpose, token_refs, request_id, "
            " expires_at, single_use) "
            "VALUES (%s, %s, %s, %s, %s::jsonb, %s, now() + make_interval(secs => %s), %s) "
            "RETURNING id",
            (
                scope_id,
                grantee_id,
                role,
                purpose,
                json.dumps(token_refs),
                request_id,
                ttl_seconds,
                single_use,
            ),
        ).fetchone()
    return row[0]


def authorize_reveal(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    grantee_id: str,
    role: str,
    tokens: Iterable[str],
) -> bool:
    """Return True iff this reveal is permitted; default-deny otherwise (FR-016).

    Requires ``role == REVEAL_ROLE``, a non-empty requested token set, and a
    single active, unexpired grant for ``grantee_id`` whose ``token_refs`` cover
    every requested token while carrying a non-empty purpose (FR-015/019). A
    matching ``single_use`` grant is marked consumed within the same transaction,
    so a replay finds no usable grant and is denied.
    """
    if role != REVEAL_ROLE:
        return False
    requested = {t for t in tokens}
    if not requested:
        return False
    with scoped(conn, scope_id):
        rows = conn.execute(
            "SELECT id, token_refs, single_use FROM reveal_grants "
            "WHERE scope_id = %s AND grantee_id = %s AND status = 'active' "
            "  AND grantee_role = %s "
            "  AND char_length(btrim(purpose)) > 0 "
            "  AND (expires_at IS NULL OR expires_at > now()) "
            "  AND consumed_at IS NULL "
            "ORDER BY created_at DESC "
            "FOR UPDATE",
            (scope_id, grantee_id, REVEAL_ROLE),
        ).fetchall()
        for grant_id, token_refs, single_use in rows:
            covered = set(token_refs or [])
            if not requested.issubset(covered):
                continue
            if single_use:
                conn.execute(
                    "UPDATE reveal_grants "
                    "SET consumed_at = now(), status = 'consumed' WHERE id = %s",
                    (grant_id,),
                )
            return True
    return False
