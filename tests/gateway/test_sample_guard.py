"""A re-sample never silently drops a collection that holds accepted fields.

Live Postgres on its own database; an in-memory connector. When a source is read without
a ``collections`` setting and a re-sample no longer lists a collection whose fields were
accepted (a listing that lost it to an error, or a dropped table), the sample fails as
``incomplete`` and flags the source: its field rows stay and no full sync retires their
values. Dropping the collection on purpose through ``collections`` is allowed, and the
next full sync retires what only it held.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers import fresh_db
from psycopg_pool import ConnectionPool
from sync_fakes import FakeConnector, Field, Table, config, customers, lookup

from erebus.gateway import catalog
from erebus.gateway.connectors import fields, jobs, sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
from erebus.sync.worker import Worker

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_sample_guard")
_SETTINGS = {"host": "127.0.0.1", "dbname": "crm", "user": "reader"}
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _values(conn, kms, scope_id):
    return {v for v, _l in catalog.iter_active_values(conn, open_scope_crypto(conn, kms, scope_id), scope_id)}


def _run(conn, worker, scope_id, source_id, kind):
    job, _ = jobs.enqueue(conn, scope_id, source_id, kind)
    conn.commit()
    worker.run_once()
    return jobs.get_job(conn, scope_id, job.id)


def main():
    print("\n=== Re-sample guard for collections with accepted fields ===\n")
    conn = fresh_db("erebus_gw_sample_guard")
    kms = LocalKms()
    pool = ConnectionPool(_DSN, min_size=1, max_size=3, open=True)
    contacts = Table([Field("id", "integer", True), Field("email")],
                     [{"id": 1, "email": "wendeline@ostrakova.example"}])
    pg = FakeConnector("postgres", {"customers": customers(), "contacts": contacts})
    worker = Worker(config(_DSN), pool=pool, provider=kms, connectors=lookup(pg))
    try:
        scope_id = provision_scope(conn, kms, "tenant-guard")
        source_id = sources.create_source(conn, open_scope_crypto(conn, kms, scope_id), scope_id, name="crm",
                                          connector_type="postgres", settings=dict(_SETTINGS),
                                          secrets={"password": "Pw-Zq-12"})
        conn.commit()
        _run(conn, worker, scope_id, source_id, "sample")
        worker.run_once()
        before = _values(conn, kms, scope_id)
        check("the first sample and full sync store both collections' values",
              {"Zyx Qorbel", "wendeline@ostrakova.example"} <= before)

        del pg.tables["contacts"]
        resample = _run(conn, worker, scope_id, source_id, "sample")
        check("a re-sample that no longer lists a collection with accepted fields fails as incomplete",
              resample.status == "failed" and resample.error == "sync incomplete")
        check("... and flags the source for an admin",
              sources.get_source(conn, scope_id, source_id).status == "needs_attention")
        kept = {(f.collection, f.field) for f in fields.accepted_fields(conn, scope_id, source_id)}
        check("... keeping that collection's field rules", ("contacts", "email") in kept)
        check("... queuing no full sync and retiring nothing",
              jobs.list_jobs(conn, scope_id, source_id=source_id)[0].id == resample.id
              and _values(conn, kms, scope_id) == before)

        sources.update_source(conn, None, scope_id, source_id, settings={**_SETTINGS, "collections": ["customers"]},
                              status="active")
        conn.commit()
        dropped = _run(conn, worker, scope_id, source_id, "sample")
        kept = {(f.collection, f.field) for f in fields.accepted_fields(conn, scope_id, source_id)}
        check("dropping the collection through the collections setting is allowed",
              dropped.status == "done" and not any(c == "contacts" for c, _f in kept))
        worker.run_once()
        values = _values(conn, kms, scope_id)
        check("... and the next full sync retires what only it held",
              "wendeline@ostrakova.example" not in values and "Zyx Qorbel" in values)
    finally:
        pool.close()
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
