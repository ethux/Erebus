# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""``PUT /v1/admin/scopes/{scope_id}/sources/{source_id}/schedule`` (Erebus Pro).

Built only on the core facade (``app.state.erebus``). The operator check comes first, so
a tenant learns nothing, then the ``sync.schedule`` feature, then the target scope and
source. The body is parsed by hand: ``incremental_minutes`` and ``full_minutes``, each an
integer or ``null`` (never); a missing key takes the family default. Errors are fixed
text and never echo the body.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

from .scheduler import DEFAULTS, FEATURE

PATH = "/v1/admin/scopes/{scope_id}/sources/{source_id}/schedule"
_BOUNDS = {"incremental_minutes": (15, 1440), "full_minutes": (60, 43200)}
_INCREMENTAL_FAMILIES = frozenset({"app"})


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def parse_schedule(raw: Any, family: str) -> tuple[int | None, int | None]:
    """``(incremental_minutes, full_minutes)`` from a PUT body; ``HTTPException`` 400 otherwise."""
    if not isinstance(raw, dict):
        raise _bad("request body must be a JSON object")
    if any(key not in _BOUNDS for key in raw):
        raise _bad("unknown field in schedule")
    values = dict(zip(_BOUNDS, DEFAULTS[family], strict=True))
    for key, (low, high) in _BOUNDS.items():
        if key not in raw:
            continue
        value = raw[key]
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise _bad(f"{key} must be an integer number of minutes")
        if value is not None and not low <= value <= high:
            raise _bad(f"{key} must be between {low} and {high}")
        values[key] = value
    if values["incremental_minutes"] is not None and family not in _INCREMENTAL_FAMILIES:
        raise _bad("incremental sync is not available for this source type")
    return values["incremental_minutes"], values["full_minutes"]


def _store(conn, scope_id: uuid.UUID, source_id: uuid.UUID, inc: int | None, full: int | None) -> dict:
    with conn.transaction():
        row = conn.execute(
            "INSERT INTO source_schedules (source_id, scope_id, incremental_minutes, full_minutes, "
            "next_incremental_at, next_full_at) VALUES (%(src)s, %(scope)s, %(inc)s, %(full)s, "
            "now() + make_interval(mins => %(inc)s), now() + make_interval(mins => %(full)s)) "
            "ON CONFLICT (source_id) DO UPDATE SET incremental_minutes = EXCLUDED.incremental_minutes, "
            "full_minutes = EXCLUDED.full_minutes, next_incremental_at = EXCLUDED.next_incremental_at, "
            "next_full_at = EXCLUDED.next_full_at, updated_at = now() "
            "RETURNING next_incremental_at, next_full_at",
            {"src": source_id, "scope": scope_id, "inc": inc, "full": full}).fetchone()
    return {"source_id": str(source_id), "incremental_minutes": inc, "full_minutes": full,
            "next_incremental_at": row[0].isoformat() if row[0] else None,
            "next_full_at": row[1].isoformat() if row[1] else None}


def register(app: FastAPI, erebus: Any, entitlements: Any) -> None:
    """Add the schedule route to ``app`` through the core facade ``erebus``."""

    @app.put(PATH)
    async def put_schedule(scope_id: str, source_id: str, request: Request,
                           authorization: str | None = Header(default=None)) -> dict:
        ident = await erebus.require_operator(authorization, event="source_schedule")
        if not entitlements.has(FEATURE):
            raise HTTPException(status_code=403, detail=f"requires Erebus Pro (feature {FEATURE})")
        target = await erebus.target_scope(scope_id)
        if target is None:
            raise HTTPException(status_code=404, detail="scope not found")
        ref = await erebus.source(target, source_id)
        if ref is None:
            raise HTTPException(status_code=404, detail="source not found")
        if ref.family not in DEFAULTS:
            raise _bad("unknown connector type")
        try:
            raw = await request.json()
        except Exception:
            raise _bad("request body must be a JSON object") from None
        inc, full = parse_schedule(raw, ref.family)
        schedule = await erebus.db(lambda c: _store(c, target, ref.id, inc, full))
        await erebus.audit(target, "source_schedule", "ok", ident,
                           {"source_id": str(ref.id), "incremental_minutes": inc, "full_minutes": full})
        return {"schedule": schedule}
