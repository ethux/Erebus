# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Scheduled sync, a sync worker extension (spec 015 D8, "Architecture": worker extensions).

Live Postgres on a throwaway database. Without the ``sync.schedule`` feature the scheduler
does nothing. Licensed, each tick gives every source without a schedule the defaults
(databases: full daily, never incremental; apps: incremental hourly, full daily), queues
the due syncs of active sources and advances their next run in the same transaction. A
busy source stays due; a paused one is advanced without a job; a row another worker holds
is skipped; deleting a source removes its schedule. The extension registers one periodic
callback and no schedule row holds a setting or credential.
"""
import base64
import os
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _pg import temp_database

_passed = 0
_SECRET = "Zq-sched-secret-4"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _licensed(features):
    from erebus_pro.license import Entitlements, License
    return Entitlements(License("lic-1", "Acme", frozenset(features), 0, int(time.time()) + 86400))


def _schedule(conn, source_id):
    return conn.execute(
        "SELECT incremental_minutes, full_minutes, next_incremental_at, next_full_at, "
        "next_full_at - now() FROM source_schedules WHERE source_id = %s", (source_id,)).fetchone()


def _jobs(conn, source_id):
    return [r[0] for r in conn.execute(
        "SELECT kind FROM sync_jobs WHERE source_id = %s ORDER BY created_at", (source_id,)).fetchall()]


def _make_due(conn, source_id, column="next_full_at"):
    conn.execute(f"UPDATE source_schedules SET {column} = now() - interval '1 minute' WHERE source_id = %s",
                 (source_id,))


def _check_register(hooks):
    from erebus_pro import scheduler
    added = []
    fake = SimpleNamespace(state=hooks.state, add_periodic=lambda fn, s: added.append((fn, s)),
                           enqueue_job=hooks.enqueue_job, scoped=hooks.scoped, connector_family=hooks.connector_family)
    scheduler.register(fake)
    check("the extension registers one periodic tick", len(added) == 1 and added[0][1] == scheduler.TICK_S)
    check("the feature is sync.schedule", scheduler.FEATURE == "sync.schedule")


def _check_unlicensed(conn, hooks, source_id):
    from erebus_pro import license as lic
    from erebus_pro.scheduler import Scheduler
    for label, ent in (("no license", lic.Entitlements(None)), ("a license without the feature", _licensed(["kms"]))):
        Scheduler(hooks, ent).tick()
        check(f"{label}: no schedule is added and nothing queued",
              _schedule(conn, source_id) is None and _jobs(conn, source_id) == [])


def _check_defaults(conn, hooks, db_source, app_source):
    from erebus_pro.scheduler import Scheduler
    fam = {"postgres": "database", "zendesk": "app"}
    app_hooks = SimpleNamespace(state=hooks.state, add_periodic=hooks.add_periodic, enqueue_job=hooks.enqueue_job,
                                scoped=hooks.scoped, connector_family=fam.get)
    counts = Scheduler(app_hooks, _licensed(["sync.schedule"])).tick()
    inc, full, next_inc, _next_full, until_full = _schedule(conn, db_source)
    check("a database gets a daily full sync and no incremental one",
          inc is None and full == 1440 and next_inc is None)
    check("its first scheduled full sync is a day away (the sample queues the first one)",
          86000 < until_full.total_seconds() <= 86400)
    inc, full, next_inc, _next_full, _ = _schedule(conn, app_source)
    check("an app gets an hourly incremental and a daily full sync", inc == 60 and full == 1440 and next_inc)
    check("adding schedules queues nothing", _jobs(conn, db_source) == [] and counts["added"] == 3)
    check("a second tick adds nothing", Scheduler(app_hooks, _licensed(["sync.schedule"])).tick()["added"] == 0)


def _check_due(conn, hooks, source_id, app_source):
    from erebus_pro.scheduler import Scheduler
    sched = Scheduler(hooks, _licensed(["sync.schedule"]))
    _make_due(conn, source_id)
    counts = sched.tick()
    check("a due full sync is queued", _jobs(conn, source_id) == ["full"] and counts["queued"] >= 1)
    until = _schedule(conn, source_id)[4].total_seconds()
    check("the next full sync moves a day ahead", 86000 < until <= 86400)
    sched.tick()
    check("a sync is not queued twice", _jobs(conn, source_id) == ["full"])

    conn.execute("UPDATE source_schedules SET next_incremental_at = now() - interval '1 minute', "
                 "next_full_at = now() + interval '1 day' WHERE source_id = %s", (app_source,))
    Scheduler(hooks, _licensed(["sync.schedule"])).tick()
    check("a due incremental sync is queued as incremental", _jobs(conn, app_source) == ["incremental"])


def _check_busy_and_paused(conn, hooks, source_id, paused_source):
    from erebus_pro.scheduler import Scheduler
    sched = Scheduler(hooks, _licensed(["sync.schedule"]))
    _make_due(conn, source_id)  # its full job from before is still queued: busy
    sched.tick()
    check("a busy source queues nothing and stays due",
          _jobs(conn, source_id) == ["full"] and _schedule(conn, source_id)[4].total_seconds() < 0)
    conn.execute("UPDATE sources SET status = 'paused' WHERE id = %s", (paused_source,))
    _make_due(conn, paused_source)
    sched.tick()
    check("a paused source queues nothing and is advanced",
          _jobs(conn, paused_source) == [] and _schedule(conn, paused_source)[4].total_seconds() > 86000)


def _check_locked(conn, dsn, hooks, source_id):
    import psycopg
    from erebus_pro.scheduler import Scheduler
    Scheduler(hooks, _licensed(["sync.schedule"])).tick()  # gives the new source its schedule
    _make_due(conn, source_id)
    with psycopg.connect(dsn) as other:
        other.execute("SELECT 1 FROM source_schedules WHERE source_id = %s FOR UPDATE", (source_id,))
        Scheduler(hooks, _licensed(["sync.schedule"])).tick()
        check("a row another worker holds is skipped", _jobs(conn, source_id) == [])
        other.rollback()
    Scheduler(hooks, _licensed(["sync.schedule"])).tick()
    check("once released it is queued", _jobs(conn, source_id) == ["full"])


def main():
    print("\n=== Scheduled sync (Erebus Pro, spec 015 D8) ===\n")
    with temp_database("scheduler") as dsn:
        if dsn is None:
            print("  (skipped: EREBUS_PG_DSN is not set)")
            return
        import psycopg
        from psycopg_pool import ConnectionPool

        from erebus.gateway.connectors import sources
        from erebus.gateway.crypto.keyprovider import MasterKeyKms
        from erebus.gateway.store import db
        from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
        from erebus.sync.config import SyncConfig
        from erebus.sync.worker import Worker

        key = base64.b64encode(os.urandom(32)).decode()
        conn = psycopg.connect(dsn, autocommit=True)
        db.run_migrations(conn)
        check("core applied the Pro schema", conn.execute(
            "SELECT to_regclass('public.source_schedules') IS NOT NULL").fetchone()[0])
        kms = MasterKeyKms(dsn, key)
        pool = ConnectionPool(dsn, min_size=1, max_size=2, open=True)
        try:
            scope = provision_scope(conn, kms, "org/a")
            crypto = open_scope_crypto(conn, kms, scope)

            def source(name, ctype="postgres"):
                return sources.create_source(conn, crypto, scope, name=name, connector_type=ctype,
                                             settings={"host": "db.example"}, secrets={"password": _SECRET})

            db_source, app_source, paused = source("crm"), source("desk", "zendesk"), source("old")
            config = SyncConfig.from_env({"EREBUS_PG_DSN": dsn, "EREBUS_GATEWAY_MASTER_KEY": key,
                                          "EREBUS_DISABLE_GLINER": "1"})
            hooks = Worker(config, pool=pool, provider=kms, connectors=lambda _t: None, model=None).hooks()
            _check_register(hooks)
            _check_unlicensed(conn, hooks, db_source)
            _check_defaults(conn, hooks, db_source, app_source)
            _check_due(conn, hooks, db_source, app_source)
            _check_busy_and_paused(conn, hooks, db_source, paused)
            _check_locked(conn, dsn, hooks, source("late"))
            rows = conn.execute("SELECT row_to_json(s)::text FROM source_schedules s").fetchall()
            check("schedule rows hold no setting or credential",
                  rows and not any(_SECRET in r[0] or "db.example" in r[0] for r in rows))
            sources.delete_source(conn, scope, db_source)
            check("deleting a source removes its schedule", _schedule(conn, db_source) is None)
        finally:
            pool.close()
            kms.close()
            conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
