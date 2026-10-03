"""Migrations under a Postgres advisory lock (spec 015 "Architecture": replicas and the
sync worker migrate together).

Live Postgres on its own, empty database. Several processes' worth of connections run
``run_migrations`` at the same moment: every one succeeds, each file is recorded once,
and a migrator on a connection with an open transaction holds the others off until it
commits (they never see a half-applied schema).
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.store import db

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_migrations_lock")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _reset(conn):
    conn.execute("DROP SCHEMA public CASCADE")
    conn.execute("CREATE SCHEMA public")


def _race(n):
    barrier = threading.Barrier(n)
    errors, applied = [], []

    def run():
        try:
            with psycopg.connect(_DSN, autocommit=True) as conn:
                barrier.wait()
                applied.append(db.run_migrations(conn))
        except Exception as exc:
            errors.append(type(exc).__name__)

    threads = [threading.Thread(target=run) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    return errors, applied


def _check_race(admin):
    files = sorted(p.name for p in db.migration_files())  # core plus installed extensions
    errors, applied = _race(6)
    check("six concurrent migrators all succeed", not errors)
    check("exactly one migrator applied the files", sorted(len(a) for a in applied) == [0] * 5 + [len(files)])
    rows = admin.execute("SELECT name, count(*) FROM _migrations GROUP BY name ORDER BY name").fetchall()
    check("each file is recorded once", [r[0] for r in rows] == files and all(r[1] == 1 for r in rows))


def _check_open_transaction_holds_lock(admin):
    _reset(admin)
    holder = psycopg.connect(_DSN)  # not autocommit, and a transaction already open:
    holder.execute("SELECT 1")  # run_migrations nests in it; the caller commits later
    db.run_migrations(holder)
    done = threading.Event()
    result = {}

    def other():
        with psycopg.connect(_DSN, autocommit=True) as conn:
            result["applied"] = db.run_migrations(conn)
        done.set()

    t = threading.Thread(target=other)
    t.start()
    time.sleep(1.0)
    check("a second migrator waits while the first has not committed", not done.is_set())
    holder.commit()
    t.join(30)
    check("after the commit the second migrator finds nothing to apply", result.get("applied") == [])
    holder.close()


def main():
    print("\n=== Advisory-locked migrations (spec 015) ===\n")
    with psycopg.connect(_DSN, autocommit=True) as admin:
        _reset(admin)
        _check_race(admin)
        _check_open_transaction_holds_lock(admin)
        _reset(admin)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
