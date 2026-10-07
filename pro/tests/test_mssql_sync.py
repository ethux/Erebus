# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""An MSSQL source through the real sync worker and its network policy.

SQL Server is a self-hosted database, so the worker treats it like Postgres and MySQL: it
resolves the source's host once, refuses an address on its deny list (by default
loopback, link-local, cloud metadata and its own database host) or off its allow list,
and hands the connector only the checked ``hostaddr``. Allowed, the sample maps the
columns and the full sync stores the distinct values; refused, the job fails with the
policy's fixed text before the connector is ever called.

Live Postgres on a throwaway database (``EREBUS_PG_DSN``) and the SQL Server named by
``EREBUS_TEST_MSSQL_DSN`` (skipped without either unless ``EREBUS_REQUIRE_MSSQL=1``).
Needs erebus-pro installed (its connector types come from the entry point).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _pg import temp_database
from mssql_backend import MssqlBackend

from erebus.cataloging import connector_types

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _Recording:
    """The real MSSQL connector, noting the settings the worker handed it."""

    def __init__(self, inner):
        self.inner = inner
        self.handed = []

    def connector_id(self):
        return self.inner.connector_id()

    def connect(self, settings, secrets):
        self.handed.append(dict(settings))
        return self.inner.connect(settings, secrets)


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
        scope_id = provision_scope(conn, kms, "tenant-mssql")
        stored = {k: v for k, v in b.settings(schemas=["crm"]).items() if k != "hostaddr"}
        source_id = sources.create_source(conn, open_scope_crypto(conn, kms, scope_id), scope_id, name="erp",
                                          connector_type="mssql", settings=stored, secrets=b.secrets())
        jobs.enqueue(conn, scope_id, source_id, "sample")
        conn.commit()
        connector = _Recording(b.connector())
        lookup = {"mssql": connector}.get
        worker = Worker(config(dsn), pool=pool, provider=kms, connectors=lookup)
        done = [jobs.get_job(conn, scope_id, j) for j in _drain(worker)]
        check("with loopback allowed, the sample and the full sync it queued both finish",
              [(j.kind, j.status) for j in done] == [("sample", "done"), ("full", "done")])
        check("the worker resolved the host and handed the connector the checked address and port",
              connector.handed and all(s["hostaddr"] == "127.0.0.1" and s["host"] == "localhost"
                                       and s["port"] == stored["port"] for s in connector.handed))
        decided = {(f.collection, f.field): f.decision for f in fields.list_fields(conn, scope_id, source_id)}
        coll = "crm.customers"
        check("the SQL Server columns are mapped by the gateway rules",
              decided[(coll, "email")] == "auto" and decided[(coll, "full_name")] == "auto"
              and decided[(coll, "first_name+last_name")] == "auto" and decided[(coll, "id")] == "ignored"
              and decided[(coll, "signup")] == "ignored")
        before = _values(conn, kms, scope_id)
        check("the full sync stores the distinct values, name parts as full names",
              {"Zyx Qorbel", "Anna Visser", "Zyx Qorbël", "mila.brandt@acme.example"} <= before
              and "Zyx" not in before)

        for case, env in (("the default deny list (loopback)", {"EREBUS_SYNC_DENIED_HOSTS": ""}),
                          ("an allow list without the host", {"EREBUS_SYNC_ALLOWED_HOSTS": "10.0.0.0/8"})):
            connector.handed.clear()
            refusing = Worker(config(dsn, **env), pool=pool, provider=kms, connectors=lookup)
            job, _ = jobs.enqueue(conn, scope_id, source_id, "full")
            conn.commit()
            refusing.run_once()
            failed = jobs.get_job(conn, scope_id, job.id)
            check(f"{case}: the sync fails with the policy's fixed text",
                  failed.status == "failed" and failed.attempts == 1
                  and failed.error == "source address is not allowed")
            check(f"{case}: ... before the connector is called", not connector.handed)
        check("values already synced keep matching", _values(conn, kms, scope_id) == before)
    finally:
        pool.close()
        conn.close()


def main():
    print("\n=== MSSQL source through the sync worker and its network policy ===\n")
    b = MssqlBackend()
    reason = b.unavailable()
    if reason is None and connector_types.get("mssql") is None:
        reason = "erebus-pro is not installed (pip install -e ./pro)"
    with temp_database("mssql_sync") as dsn:
        if reason is None and dsn is None:
            reason = "EREBUS_PG_DSN is not set"
        if reason:
            if os.environ.get("EREBUS_REQUIRE_MSSQL") == "1":
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
