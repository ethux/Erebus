# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""A Pro warehouse source through the real sync worker.

Live Postgres on a throwaway database; the Snowflake connector on fakesnow. Licensed,
the sample maps the warehouse columns (email and full name auto-accepted, the name parts
paired, integers, dates and flags ignored) and the full sync stores the distinct values.
When the license lapses the next sync fails unretried with the license text and flags the
source, and every value already synced stays active: filtering never weakens. A
``collections`` entry matches as Snowflake reads an unquoted name (``crm.customers`` is
``CRM.customers``); one the warehouse does not have fails the sample as bad settings.
Needs erebus-pro installed (its connector types come from the entry point).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _pg import temp_database
from warehouse_backends import SnowflakeBackend, licensed

from erebus.cataloging import connector_types

_passed = 0
_FEATURE = "connectors.snowflake"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _values(conn, kms, scope_id):
    from erebus.gateway import catalog
    from erebus.gateway.store.known_value_store import open_scope_crypto
    crypto = open_scope_crypto(conn, kms, scope_id)
    return {v for v, _label in catalog.iter_active_values(conn, crypto, scope_id)}


def _drain(worker):
    ran = []
    while len(ran) < 10 and (job_id := worker.run_once()) is not None:
        ran.append(job_id)
    return ran


def _check_collections(conn, worker, scope_id, kms, b):
    from erebus.gateway.connectors import fields, jobs, sources
    from erebus.gateway.store.known_value_store import open_scope_crypto

    def sample(collections):
        source_id = sources.create_source(conn, open_scope_crypto(conn, kms, scope_id), scope_id, name="dwh-only",
                                          connector_type="snowflake",
                                          settings=b.settings(collections=collections), secrets=b.secrets())
        job, _ = jobs.enqueue(conn, scope_id, source_id, "sample")
        conn.commit()
        worker.run_once()
        _drain(worker)  # the full sync a done sample queues
        return jobs.get_job(conn, scope_id, job.id), source_id

    job, source_id = sample(["crm.customers"])
    mapped = {f.collection for f in fields.list_fields(conn, scope_id, source_id)}
    check("a lower-case collections entry matches the warehouse's upper-case (unquoted) schema",
          job.status == "done" and mapped == {"CRM.customers"})
    job, source_id = sample(["crm.customers", "crm.no_such_table_zq"])
    check("a collections entry the warehouse does not have fails the sample as bad settings, unretried",
          job.status == "failed" and job.attempts == 1 and job.error == "source settings are not valid"
          and sources.get_source(conn, scope_id, source_id).status == "needs_attention")


def _run(dsn, b):
    import psycopg
    from psycopg_pool import ConnectionPool
    from sync_fakes import config

    from erebus.gateway.connectors import fields, jobs, sources
    from erebus.gateway.crypto.keyprovider import LocalKms
    from erebus.gateway.store import db
    from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
    from erebus.sync.worker import Worker

    conn = psycopg.connect(dsn)
    db.run_migrations(conn)
    conn.commit()
    kms = LocalKms()
    pool = ConnectionPool(dsn, min_size=1, max_size=3, open=True)
    try:
        scope_id = provision_scope(conn, kms, "tenant-warehouse")
        source_id = sources.create_source(conn, open_scope_crypto(conn, kms, scope_id), scope_id, name="dwh",
                                          connector_type="snowflake", settings=b.settings(), secrets=b.secrets())
        jobs.enqueue(conn, scope_id, source_id, "sample")
        conn.commit()
        current = {"connector": b.connector(licensed([_FEATURE]))}
        worker = Worker(config(dsn), pool=pool, provider=kms,
                        connectors=lambda t: current["connector"] if t == "snowflake" else None)
        ran = _drain(worker)
        done = [jobs.get_job(conn, scope_id, j) for j in ran]
        check("licensed, the sample and the full sync it queued both finish",
              [(j.kind, j.status) for j in done] == [("sample", "done"), ("full", "done")])
        decided = {(f.collection, f.field): f.decision for f in fields.list_fields(conn, scope_id, source_id)}
        check("the warehouse columns are mapped by the gateway rules",
              decided[("CRM.customers", "email")] == "auto" and decided[("CRM.customers", "full_name")] == "auto"
              and decided[("CRM.customers", "first_name+last_name")] == "auto"
              and decided[("CRM.customers", "id")] == "ignored" and decided[("CRM.customers", "signup")] == "ignored")
        before = _values(conn, kms, scope_id)
        check("the full sync stores the distinct values, name parts as full names",
              {"Zyx Qorbel", "Anna Visser", "Zyx Qorbël", "mila.brandt@acme.example"} <= before
              and "zyx.qorbel@acme.example" in {v.casefold() for v in before}  # case variants are one value
              and "Zyx" not in before and "Qorbel" not in before)

        _check_collections(conn, worker, scope_id, kms, b)

        current["connector"] = b.connector(licensed([_FEATURE], expires_in=-30 * 86400))
        job, _ = jobs.enqueue(conn, scope_id, source_id, "full")
        conn.commit()
        worker.run_once()
        failed = jobs.get_job(conn, scope_id, job.id)
        check("after the license lapses a sync fails unretried with the license text",
              failed.status == "failed" and failed.attempts == 1
              and failed.error == f"requires Erebus Pro (feature {_FEATURE})")
        check("... and flags the source for an admin",
              sources.get_source(conn, scope_id, source_id).status == "needs_attention")
        check("every value already synced keeps matching", _values(conn, kms, scope_id) == before)
    finally:
        pool.close()
        conn.close()


def main():
    print("\n=== Pro warehouse source through the sync worker ===\n")
    b = SnowflakeBackend()
    reason = b.unavailable()
    if reason is None and connector_types.get("snowflake") is None:
        reason = "erebus-pro is not installed (pip install -e './pro[test]')"
    with temp_database("warehouse_sync") as dsn:
        if reason is None and dsn is None:
            reason = "EREBUS_PG_DSN is not set"
        if reason:
            if os.environ.get("EREBUS_REQUIRE_SNOWFLAKE") == "1":
                raise AssertionError(reason)
            print(f"  - skipped ({reason})")
            return
        b.setup()
        try:
            _run(dsn, b)
        finally:
            b.teardown()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
