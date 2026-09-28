"""Per-tenant quota + spend enforcement tests (FR-039) against a live Postgres.

Creates its own database (erebus_gw_quota) and applies ONLY 0001_core.sql and
0015_quota.sql (other gateway modules migrate concurrently, so we must not run the
whole schema dir). Verifies fail-closed enforcement: requests pass up to the rate
limit, the next is denied with a retryable QuotaExceeded, spend over budget is
denied, and spend is attributed in usage_counters. Self-skips without Postgres.
"""
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers.quota import (
    QuotaExceeded,
    check_and_reserve,
    record_spend,
    set_quota,
)
from erebus.gateway.store.db import _statements
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped

_DBNAME = "erebus_gw_quota"
_DSN = os.environ.get("EREBUS_PG_DSN", f"postgresql:///{_DBNAME}")
_SCHEMA = Path(__file__).resolve().parent.parent.parent / "erebus" / "gateway" / "schema"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _apply(conn, filename):
    """Apply a migration's statements idempotently (tolerate objects from a prior run)."""
    for stmt in _statements((_SCHEMA / filename).read_text()):
        try:
            with conn.transaction():
                conn.execute(stmt)
        except psycopg.errors.DuplicateObject:
            pass  # policy/table already created by an earlier run of this test


def main():
    print("\n=== Gateway per-tenant quota enforcement (FR-039) ===\n")
    subprocess.run(["createdb", _DBNAME], capture_output=True)  # ignore "already exists"
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres -> self-skip (matches suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        _apply(conn, "0001_core.sql")
        _apply(conn, "0015_quota.sql")
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org1/quota/a")
        b_id = provision_scope(conn, kms, "org1/quota/b")

        # Generous spend budget so the rate-limit path is isolated first.
        set_quota(conn, a_id, rate_limit=3, spend_budget="100.00", window_seconds=3600)

        # Requests pass up to the limit.
        for i in range(3):
            check(f"reserve {i + 1}/3 within rate limit", check_and_reserve(conn, a_id) is None)

        # The next reservation fails closed (no "send anyway").
        try:
            check_and_reserve(conn, a_id)
            over_ok, exc = False, None
        except QuotaExceeded as e:
            over_ok, exc = True, e
        check("over rate limit raises QuotaExceeded (fail closed, FR-039)", over_ok)
        check("QuotaExceeded.retryable is True", exc is not None and exc.retryable is True)

        # Unconfigured scope is denied, not waved through (fail closed).
        try:
            check_and_reserve(conn, b_id)
            unconfigured_ok = False
        except QuotaExceeded:
            unconfigured_ok = True
        check("unconfigured scope fails closed (FR-039)", unconfigured_ok)

        # Spend over budget also raises. Fresh window via a tiny budget on a new scope.
        c_id = provision_scope(conn, kms, "org1/quota/c")
        set_quota(conn, c_id, rate_limit=1000, spend_budget="5.00", window_seconds=3600)
        check("reserve OK before any spend", check_and_reserve(conn, c_id) is None)
        record_spend(conn, c_id, "6.50")
        try:
            check_and_reserve(conn, c_id)
            spend_over_ok = False
        except QuotaExceeded as e:
            spend_over_ok = e.retryable is True
        check("over spend budget raises retryable QuotaExceeded (FR-039)", spend_over_ok)

        # Spend is attributed in usage_counters (and survives multiple records).
        record_spend(conn, c_id, "1.50")
        with scoped(conn, c_id):
            total = conn.execute(
                "SELECT COALESCE(SUM(spend), 0) FROM usage_counters WHERE scope_id = %s",
                (c_id,),
            ).fetchone()[0]
        check("spend attributed in usage_counters", Decimal(total) == Decimal("8.00"))

        # Per-scope isolation: scope A's request count is its own, capped at the limit.
        with scoped(conn, a_id):
            a_reqs = conn.execute(
                "SELECT COALESCE(SUM(requests), 0) FROM usage_counters WHERE scope_id = %s",
                (a_id,),
            ).fetchone()[0]
        check("only successful reservations counted (3, not the denied 4th)", a_reqs == 3)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
