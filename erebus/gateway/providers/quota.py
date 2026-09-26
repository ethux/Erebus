"""Per-tenant quota and spend enforcement, fail-closed (FR-039).

Each scope has a ``quotas`` row (rate_limit, concurrency_cap, spend_budget,
window_seconds). ``usage_counters`` accumulates the request count and spend per
fixed time window. ``check_and_reserve`` atomically reserves one request slot in
the current window and refuses (raising :class:`QuotaExceeded`) the moment the
scope is at or over its rate limit or spend budget; it never returns a
"send anyway" path. If no quota is configured, the call also fails closed.
``record_spend`` attributes cost to the current window so spend enforcement sees
it on the next reservation.

State lives only in Postgres under RLS (no process-global mutable counters,
FR-043); raw values are not involved here, so there is nothing to encrypt.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal

import psycopg

from ..store.scope_context import scoped


class QuotaExceeded(Exception):
    """Raised when a scope is at/over its rate limit or spend budget (FR-039).

    ``retryable`` is True: the limit is windowed, so a later attempt may succeed.
    """

    retryable = True

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.retryable = True


def set_quota(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    rate_limit: int,
    spend_budget: Decimal | float | int | str,
    window_seconds: int,
    concurrency_cap: int = 0,
) -> None:
    """Create or replace the quota configuration for a scope."""
    with scoped(conn, scope_id):
        conn.execute(
            "INSERT INTO quotas "
            "(scope_id, rate_limit, concurrency_cap, spend_budget, window_seconds) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT (scope_id) DO UPDATE SET "
            "rate_limit = EXCLUDED.rate_limit, "
            "concurrency_cap = EXCLUDED.concurrency_cap, "
            "spend_budget = EXCLUDED.spend_budget, "
            "window_seconds = EXCLUDED.window_seconds",
            (scope_id, rate_limit, concurrency_cap, Decimal(str(spend_budget)), window_seconds),
        )


def _window_start(now: datetime, window_seconds: int) -> datetime:
    """Floor ``now`` to the start of its fixed window (UTC)."""
    epoch = int(now.timestamp())
    floored = epoch - (epoch % max(window_seconds, 1))
    return datetime.fromtimestamp(floored, tz=UTC)


def check_and_reserve(conn: psycopg.Connection, scope_id: uuid.UUID) -> None:
    """Reserve one request in the current window; fail closed if over quota (FR-039).

    Raises :class:`QuotaExceeded` (retryable) when no quota is configured, when the
    rate limit for the window is reached, or when accrued spend has met/exceeded
    the budget. On success the window's request count is incremented and committed.
    """
    with scoped(conn, scope_id):
        cfg = conn.execute(
            "SELECT rate_limit, spend_budget, window_seconds FROM quotas WHERE scope_id = %s",
            (scope_id,),
        ).fetchone()
        if cfg is None:
            # Fail closed: an unconfigured scope is denied, not waved through.
            raise QuotaExceeded(f"no quota configured for scope {scope_id}")
        rate_limit, spend_budget, window_seconds = cfg[0], cfg[1], cfg[2]
        window = _window_start(datetime.now(UTC), window_seconds)

        # Atomically claim a slot: lock/insert the window row, then bump requests.
        conn.execute(
            "INSERT INTO usage_counters (scope_id, window_start, requests, spend) "
            "VALUES (%s, %s, 0, 0) ON CONFLICT (scope_id, window_start) DO NOTHING",
            (scope_id, window),
        )
        row = conn.execute(
            "SELECT requests, spend FROM usage_counters "
            "WHERE scope_id = %s AND window_start = %s FOR UPDATE",
            (scope_id, window),
        ).fetchone()
        requests, spend = row[0], Decimal(row[1])

        if requests >= rate_limit:
            raise QuotaExceeded(
                f"rate limit reached for scope {scope_id}: {requests}/{rate_limit}"
            )
        if spend >= Decimal(spend_budget):
            raise QuotaExceeded(
                f"spend budget exceeded for scope {scope_id}: {spend}/{spend_budget}"
            )

        conn.execute(
            "UPDATE usage_counters SET requests = requests + 1 "
            "WHERE scope_id = %s AND window_start = %s",
            (scope_id, window),
        )


def record_spend(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    amount: Decimal | float | int | str,
) -> None:
    """Attribute ``amount`` of spend to the scope's current usage window (FR-039)."""
    with scoped(conn, scope_id):
        cfg = conn.execute(
            "SELECT window_seconds FROM quotas WHERE scope_id = %s",
            (scope_id,),
        ).fetchone()
        window_seconds = cfg[0] if cfg is not None else 60
        window = _window_start(datetime.now(UTC), window_seconds)
        conn.execute(
            "INSERT INTO usage_counters (scope_id, window_start, requests, spend) "
            "VALUES (%s, %s, 0, %s) "
            "ON CONFLICT (scope_id, window_start) DO UPDATE SET "
            "spend = usage_counters.spend + EXCLUDED.spend",
            (scope_id, window, Decimal(str(amount))),
        )
