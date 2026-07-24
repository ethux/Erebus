"""Tamper-evident per-scope audit chain tests (FR-028/030/041) against live Postgres.

Creates its own database (erebus_gw_audit), applies ONLY 0001_core + 0010_audit
(other modules are written concurrently, so we never run the whole schema dir),
and verifies: append builds a dense per-scope hash chain; verify_chain is True for
an intact chain and False after an in-place row tamper; RLS confines query/verify
so scope B cannot see scope A's entries; the API records masked values only and
performs no UPDATE/DELETE of history. Set EREBUS_PG_DSN=postgresql:///erebus_gw_audit.
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.governance import audit
from erebus.gateway.store.db import _statements
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped

_DBNAME = "erebus_gw_audit"
_DSN = os.environ.get("EREBUS_PG_DSN", f"postgresql:///{_DBNAME}")
_SCHEMA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..",
    "erebus", "gateway", "schema",
)
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _apply(conn, filename):
    """Apply a migration statement-by-statement, tolerating objects that already
    exist from a prior run (CREATE POLICY/ALTER TABLE have no IF NOT EXISTS, and
    we must not edit the shared 0001_core.sql)."""
    path = os.path.join(_SCHEMA_DIR, filename)
    with open(path, encoding="utf-8") as fh:
        sql = fh.read()
    for stmt in _statements(sql):
        try:
            with conn.transaction():
                conn.execute(stmt)
        except (psycopg.errors.DuplicateObject, psycopg.errors.DuplicateTable):
            pass  # idempotent re-run: this object is already present


def main():
    print("\n=== Gateway tamper-evident audit (FR-028/030/041) ===\n")
    subprocess.run(["createdb", _DBNAME], capture_output=True)  # ignore "already exists"
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres -> self-skip (suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        # Apply only the two relevant migrations (avoid racing concurrent modules).
        _apply(conn, "0001_core.sql")
        _apply(conn, "0010_audit.sql")
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org1/payments/oncall")
        b_id = provision_scope(conn, kms, "org1/payments/billing")

        # Append several events to scope A.
        e1 = audit.append(conn, a_id, {
            "event_type": "tokenize", "actor_id": "u1", "actor_role": "agent",
            "request_id": "req-1", "masked_value": "[PERSON_1]", "category": "PII",
            "outcome": "ok", "metadata": {"count": 1},
        })
        e2 = audit.append(conn, a_id, {
            "event_type": "reveal", "actor_id": "u2", "actor_role": "admin",
            "request_id": "req-2", "masked_value": "[PERSON_1]", "category": "PII",
            "outcome": "granted", "metadata": {"reason": "support"},
        })
        e3 = audit.append(conn, a_id, {
            "event_type": "tokenize", "actor_id": "u1", "actor_role": "agent",
            "request_id": "req-3", "masked_value": "[EMAIL_2]", "outcome": "ok",
        })

        check("seq is dense and monotonic per scope", (e1["seq"], e2["seq"], e3["seq"]) == (1, 2, 3))
        check("first entry chains the genesis constant", e1["prev_hash"] == audit._GENESIS)
        check("each prev_hash links to the prior entry_hash", e2["prev_hash"] == e1["entry_hash"])
        check("chain advances across the third entry", e3["prev_hash"] == e2["entry_hash"])
        check("entry_hash is a 32-byte sha256 digest", len(e1["entry_hash"]) == 32)

        # Independent scope B chain.
        b1 = audit.append(conn, b_id, {"event_type": "tokenize", "outcome": "ok"})
        check("scope B starts its own chain at seq 1 from genesis",
              b1["seq"] == 1 and b1["prev_hash"] == audit._GENESIS)

        check("verify_chain True for intact scope A", audit.verify_chain(conn, a_id) is True)
        check("verify_chain True for intact scope B", audit.verify_chain(conn, b_id) is True)

        # query() is scope-confined and filterable.
        all_a = audit.query(conn, a_id)
        check("query returns all scope A entries in seq order",
              [r["seq"] for r in all_a] == [1, 2, 3])
        tok_a = audit.query(conn, a_id, event_type="tokenize")
        check("query filters by event_type", [r["seq"] for r in tok_a] == [1, 3])
        check("query records masked values only (no raw PII)",
              all(r["masked_value"] in (None, "[PERSON_1]", "[EMAIL_2]") for r in all_a))

        # RLS: scope B cannot see scope A's entries (and vice versa).
        b_view = audit.query(conn, b_id)
        check("RLS confines scope B's query to its own entry only",
              [r["seq"] for r in b_view] == [1] and all(r["scope_id"] == b_id for r in b_view))
        check("scope A query never returns scope B rows",
              all(r["scope_id"] == a_id for r in all_a))

        # Tamper a scope A row in place (a raw UPDATE outside the audit API) and
        # confirm the chain is now detected as broken.
        with scoped(conn, a_id):
            with conn.transaction():
                conn.execute(
                    "UPDATE audit_events SET masked_value = %s "
                    "WHERE scope_id = %s AND seq = %s",
                    ("[PERSON_999]", a_id, 2),
                )
        check("verify_chain False after an in-place field tamper (FR-030)",
              audit.verify_chain(conn, a_id) is False)
        check("untampered scope B chain still verifies True",
              audit.verify_chain(conn, b_id) is True)

        # FR-007: append takes a per-scope advisory lock that previously waited
        # unboundedly. A stalled transaction holding a scope's lock must NOT block
        # an appender forever: append SET LOCAL lock_timeout so a contended append
        # fails fast with a clean error instead of hanging. We hold scope C's lock
        # on a separate connection and confirm a contending append raises promptly.
        c_id = provision_scope(conn, kms, "org1/payments/audit-lock")
        # Normal serialization on a fresh scope still appends correctly (seq dense).
        cl1 = audit.append(conn, c_id, {"event_type": "tokenize", "outcome": "ok"})
        cl2 = audit.append(conn, c_id, {"event_type": "tokenize", "outcome": "ok"})
        check("appends still serialize on the lock-timeout scope (seq 1,2)",
              (cl1["seq"], cl2["seq"]) == (1, 2))

        blocker = psycopg.connect(_DSN)
        blocker.autocommit = False
        try:
            # Hold scope C's advisory xact lock on a SEPARATE session, using the
            # exact key append derives, so a concurrent append must wait on it.
            with scoped(blocker, c_id):
                blocker.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (str(c_id),),
                )
                # The main connection's append now contends for the held lock. It
                # must surface a clean lock-timeout error within a bounded wait,
                # not hang. (psycopg maps lock_timeout to LockNotAvailable.)
                conn.rollback()  # release any in-progress txn before the contended append
                started = time.monotonic()
                timed_out = False
                try:
                    audit.append(conn, c_id, {"event_type": "tokenize", "outcome": "ok"})
                except psycopg.errors.LockNotAvailable:
                    timed_out = True
                    conn.rollback()
                waited = time.monotonic() - started
                check("contended append fails fast with a clean lock-timeout (FR-007)", timed_out)
                check("contended append did not hang (bounded wait, well under 30s)", waited < 30)
            # Once the blocker's transaction ends the lock is freed; appends resume.
            blocker.rollback()
        finally:
            blocker.close()

        resumed = audit.append(conn, c_id, {"event_type": "tokenize", "outcome": "ok"})
        check("appends resume once the lock is released (seq advances to 3)",
              resumed["seq"] == 3)
        check("lock-timeout scope chain still verifies intact",
              audit.verify_chain(conn, c_id) is True)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
