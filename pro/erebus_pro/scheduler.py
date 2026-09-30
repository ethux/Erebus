# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Scheduled sync: a sync worker extension (``erebus.worker.extensions``).

Every tick, while the license carries ``sync.schedule``: give each source without a
schedule the defaults for its family, then claim due schedule rows (``SKIP LOCKED``, so
several workers share the work), queue a full or incremental job for each active,
idle source and advance its next run in the same transaction. A busy source stays due
and is tried again next tick; a paused or flagged one is advanced without a job. Without
the feature nothing is scheduled; values already synced keep matching and "sync now"
keeps working.
"""
from __future__ import annotations

import logging
from typing import Any

from .license import Entitlements, from_env

log = logging.getLogger("erebus_pro.scheduler")

FEATURE = "sync.schedule"
TICK_S = 60
_CLAIM_LIMIT = 100
# (incremental minutes, full minutes) per family; None means never.
DEFAULTS: dict[str, tuple[int | None, int | None]] = {
    "app": (60, 1440),
    "database": (None, 1440),
    "warehouse": (None, 1440),
    "file": (None, 1440),
}


class Scheduler:
    """Queues scheduled syncs through the worker hooks."""

    def __init__(self, hooks: Any, entitlements: Entitlements) -> None:
        self._hooks = hooks
        self._entitlements = entitlements
        self._licensed: bool | None = None

    def _allowed(self) -> bool:
        allowed = self._entitlements.has(FEATURE)
        if allowed is not self._licensed:
            self._licensed = allowed
            if not allowed:
                log.warning("scheduled sync is off: requires Erebus Pro (feature %s)", FEATURE)
        return allowed

    def tick(self) -> dict[str, int]:
        """One pass; returns counts (added, queued, skipped). Does nothing unlicensed."""
        counts = {"added": 0, "queued": 0, "skipped": 0}
        if not self._allowed():
            return counts
        with self._hooks.state.pool.connection() as conn:
            conn.autocommit = True
            counts["added"] = self._add_missing(conn)
            self._run_due(conn, counts)
        return counts

    def _add_missing(self, conn) -> int:
        added = 0
        scopes = [r[0] for r in conn.execute("SELECT id FROM scopes WHERE status = 'active'").fetchall()]
        for scope_id in scopes:
            with self._hooks.scoped(conn, scope_id):
                rows = conn.execute(
                    "SELECT id, connector_type FROM sources s WHERE scope_id = %s AND NOT EXISTS "
                    "(SELECT 1 FROM source_schedules ss WHERE ss.source_id = s.id)", (scope_id,)).fetchall()
                for source_id, connector_type in rows:
                    family = self._hooks.connector_family(connector_type)
                    if family not in DEFAULTS:
                        continue  # a type this worker does not know: never scheduled
                    inc, full = DEFAULTS[family]
                    cur = conn.execute(
                        "INSERT INTO source_schedules (source_id, scope_id, incremental_minutes, full_minutes, "
                        "next_incremental_at, next_full_at) VALUES (%s, %s, %s, %s, "
                        "now() + make_interval(mins => %s), now() + make_interval(mins => %s)) "
                        "ON CONFLICT (source_id) DO NOTHING", (source_id, scope_id, inc, full, inc, full))
                    added += cur.rowcount
        return added

    def _run_due(self, conn, counts: dict[str, int]) -> None:
        with conn.transaction():
            due = conn.execute(
                "SELECT source_id, scope_id, incremental_minutes, full_minutes, next_full_at <= now() "
                "FROM source_schedules WHERE next_full_at <= now() OR next_incremental_at <= now() "
                "ORDER BY LEAST(next_full_at, next_incremental_at) FOR UPDATE SKIP LOCKED LIMIT %s",
                (_CLAIM_LIMIT,)).fetchall()
            for source_id, scope_id, inc, full, full_due in due:
                kind = "full" if full_due else "incremental"
                if self._busy(conn, source_id):
                    counts["skipped"] += 1
                    continue  # stays due: tried again next tick
                if self._status(conn, scope_id, source_id) == "active":
                    try:
                        self._hooks.enqueue_job(conn, scope_id, source_id, kind)
                        counts["queued"] += 1
                    except KeyError:  # deleted since the claim; the cascade drops the row
                        counts["skipped"] += 1
                else:
                    counts["skipped"] += 1
                # A full sync also covers the incremental window.
                conn.execute(
                    "UPDATE source_schedules SET updated_at = now(), "
                    "next_full_at = CASE WHEN %(full)s THEN now() + make_interval(mins => %(fm)s) "
                    "                    ELSE next_full_at END, "
                    "next_incremental_at = now() + make_interval(mins => %(im)s) "
                    "WHERE source_id = %(id)s",
                    {"full": kind == "full", "fm": full, "im": inc, "id": source_id})

    @staticmethod
    def _busy(conn, source_id) -> bool:
        return conn.execute("SELECT 1 FROM sync_jobs WHERE source_id = %s AND status IN ('queued', 'running')",
                            (source_id,)).fetchone() is not None

    def _status(self, conn, scope_id, source_id) -> str | None:
        with self._hooks.scoped(conn, scope_id):
            row = conn.execute("SELECT status FROM sources WHERE scope_id = %s AND id = %s",
                               (scope_id, source_id)).fetchone()
        return row[0] if row else None


def register(hooks: Any) -> None:
    """Worker extension entry point: tick every ``TICK_S`` seconds."""
    scheduler = Scheduler(hooks, from_env())
    hooks.add_periodic(scheduler.tick, TICK_S)
