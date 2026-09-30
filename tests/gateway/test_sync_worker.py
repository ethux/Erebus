"""The sync worker's jobs on Postgres (spec 015 "Architecture": worker; "Sync behaviour").

Live Postgres on its own database; in-memory connectors stand in for sources. Jobs of
several tenants are claimed oldest first and each runs under its own tenant's key; a
sample reads at most 1,000 rows per collection and writes the field decisions, then
queues the full sync; a full sync reads distinct values per accepted field (name tuples
joined), upserts and links them under the job id, retires what a complete sync no
longer saw and bumps the catalog version; the loop heartbeats a long job and stops
cleanly. No value reaches a job row or an audit event.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers import fresh_db
from psycopg_pool import ConnectionPool
from sync_fakes import FakeConnector, config, customers, lookup

from erebus.gateway import catalog
from erebus.gateway.connectors import fields, jobs, sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store import catalog_versions
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
from erebus.gateway.store.scope_context import scoped
from erebus.sync.worker import Worker

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_sync_worker")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _source(conn, kms, scope_id, name="crm", connector_type="postgres"):
    crypto = open_scope_crypto(conn, kms, scope_id)
    sid = sources.create_source(conn, crypto, scope_id, name=name, connector_type=connector_type,
                                settings={"host": "127.0.0.1", "dbname": "crm", "user": "reader"},
                                secrets={"password": "Pw-Zq-77"})
    conn.commit()
    return sid


def _values(conn, kms, scope_id):
    crypto = open_scope_crypto(conn, kms, scope_id)
    return {v for v, _label in catalog.iter_active_values(conn, crypto, scope_id)}


def _job(conn, scope_id, job_id):
    return jobs.get_job(conn, scope_id, job_id)


def _drain(worker, limit=20):
    ran = []
    while len(ran) < limit and (job_id := worker.run_once()) is not None:
        ran.append(job_id)
    return ran


def _check_tenants(conn, kms, worker, pg_a, pg_b):
    a = provision_scope(conn, kms, "tenant-a")
    b = provision_scope(conn, kms, "tenant-b")
    sa, sb = _source(conn, kms, a), _source(conn, kms, b, connector_type="mysql")
    ja, _ = jobs.enqueue(conn, a, sa, "sample")
    conn.commit()
    time.sleep(0.01)
    jb, _ = jobs.enqueue(conn, b, sb, "sample")
    conn.commit()
    first = worker.run_once()
    check("the oldest job is claimed first, whatever its tenant", first == ja.id)
    check("the second tenant's job is claimed next", worker.run_once() == jb.id)
    check("both samples are done", _job(conn, a, ja.id).status == "done" and _job(conn, b, jb.id).status == "done")
    check("each tenant's connector received its own settings and credentials",
          pg_a.connects[0][1] == {"password": "Pw-Zq-77"} and pg_a.connects[0][0]["hostaddr"] == "127.0.0.1")
    fulls = _drain(worker)
    check("each sample queued a full sync, and both ran", len(fulls) == 2)
    va, vb = _values(conn, kms, a), _values(conn, kms, b)
    check("tenant A holds its own values", "Zyx Qorbel" in va and "Ann Other" not in va)
    check("tenant B holds its own values", "Ann Other" in vb and "Zyx Qorbel" not in vb)
    check("sources are closed after each job", pg_a.closed == 2 and pg_b.closed == 2)
    return a, sa


def _check_sample(conn, kms, scope_id, source_id, pg):
    rows = {f.field: f for f in fields.list_fields(conn, scope_id, source_id)}
    check("a sample reads at most 1,000 rows per collection",
          next(c for c in pg.calls if c[0] == "records") == ("records", "customers", 1000))
    check("the email field is auto-accepted",
          rows["email"].decision == "auto" and rows["email"].label == "EMAIL_ADDRESS")
    check("the full name is auto-accepted", rows["full_name"].decision == "auto")
    check("the name parts form one tuple",
          rows["first_name+tussenvoegsel+last_name"].decision == "auto" and rows["first_name"].decision == "ignored")
    check("an integer primary key is ignored", rows["id"].decision == "ignored")
    check("a product name waits for review", rows["product_name"].decision == "pending")


def _check_full(conn, kms, scope_id, source_id, pg):
    values = _values(conn, kms, scope_id)
    check("a full sync stores the accepted values", {"Zyx Qorbel", "zyx.qorbel@acme.example"} <= values)
    check("name tuples are stored as full names", "Jan de Vries" in values and "Mila Brandt" in values)
    check("single name parts are never stored", "Jan" not in values and "Vries" not in values)
    check("pending fields are not synced", "Widget" not in values)
    distinct = [c for c in pg.calls if c[0] == "distinct"]
    check("values are read as distinct values per accepted field",
          ("distinct", "customers", ("email",), 1_000_001) in distinct)
    check("name parts are read as one distinct tuple",
          any(c[2] == ("first_name", "tussenvoegsel", "last_name") for c in distinct))
    done = jobs.list_jobs(conn, scope_id, source_id=source_id)[0]
    check("the job row carries counts and no error",
          done.kind == "full" and done.status == "done" and done.values_added >= 5 and done.error is None)
    check("the catalog version moved", catalog_versions.read(conn, scope_id) >= 1)
    with scoped(conn, scope_id):
        rows = conn.execute("SELECT actor_id, outcome, metadata::text FROM audit_events "
                            "WHERE scope_id = %s AND event_type = 'sync'", (scope_id,)).fetchall()
    check("the worker audits each job as sync-worker", len(rows) == 2 and all(r[0] == "sync-worker" for r in rows))
    check("audit events hold ids and counts only", all("Qorbel" not in r[2] and "Pw-Zq" not in r[2] for r in rows))


def _check_retire(conn, kms, worker, scope_id, source_id, pg):
    before = catalog_versions.read(conn, scope_id)
    pg.tables["customers"].rows = [r for r in pg.tables["customers"].rows if r["full_name"] != "Zyx Qorbel"]
    job, _ = jobs.enqueue(conn, scope_id, source_id, "full")
    conn.commit()
    worker.run_once()
    values = _values(conn, kms, scope_id)
    check("a complete full sync retires what the source no longer holds",
          "Zyx Qorbel" not in values and "Jan de Vries" not in values)
    check("what the source still holds stays", "Mila Brandt" in values)
    check("the job counts the retired values", _job(conn, scope_id, job.id).values_retired >= 3)
    check("retiring bumps the catalog version", catalog_versions.read(conn, scope_id) > before)
    with scoped(conn, scope_id):
        stale = conn.execute("SELECT count(*) FROM catalog_entry_sources WHERE scope_id = %s AND source_id = %s "
                             "AND last_seen_sync_id <> %s", (scope_id, source_id, job.id)).fetchone()[0]
    check("every remaining link carries this sync's id", stale == 0)


def _check_heartbeat_and_loop(conn, kms, pool, pg):
    cfg = config(_DSN, EREBUS_SYNC_HEARTBEAT_S=1, EREBUS_SYNC_LEASE_S=3, EREBUS_SYNC_POLL_S=1)
    scope_id = provision_scope(conn, kms, "tenant-slow")
    source_id = _source(conn, kms, scope_id, "slow")
    pg.on_distinct = lambda _c: time.sleep(4.5)
    job, _ = jobs.enqueue(conn, scope_id, source_id, "full")
    conn.commit()
    with scoped(conn, scope_id):
        conn.execute("INSERT INTO source_fields (scope_id, source_id, collection, field, db_type, label, decision) "
                     "VALUES (%s, %s, 'customers', 'email', 'varchar', 'EMAIL_ADDRESS', 'confirmed')",
                     (scope_id, source_id))
    conn.commit()
    worker = Worker(cfg, pool=pool, provider=kms, connectors=lookup(pg))
    stop = threading.Event()
    loop = threading.Thread(target=worker.run_forever, args=(stop,))
    loop.start()
    deadline = time.time() + 30
    while time.time() < deadline and _job(conn, scope_id, job.id).status != "done":
        time.sleep(0.2)
    stop.set()
    loop.join(15)
    pg.on_distinct = None
    finished = _job(conn, scope_id, job.id)
    check("a job running past its lease is kept alive by the heartbeat",
          finished.status == "done" and finished.attempts == 0)
    check("the loop stops when asked", not loop.is_alive())


def main():
    print("\n=== Sync worker jobs (spec 015) ===\n")
    conn = fresh_db("erebus_gw_sync_worker")
    kms = LocalKms()
    pg_a = FakeConnector("postgres", {"customers": customers()})
    pg_b = FakeConnector("mysql", {"customers": customers([
        {"id": 7, "email": "ann.other@beta.example", "full_name": "Ann Other", "first_name": "Ann",
         "tussenvoegsel": "", "last_name": "Other", "product_name": "Thing"}])})

    pool = ConnectionPool(_DSN, min_size=1, max_size=4, open=True)
    worker = Worker(config(_DSN), pool=pool, provider=kms, connectors=lookup(pg_a, pg_b))
    try:
        a, sa = _check_tenants(conn, kms, worker, pg_a, pg_b)
        _check_sample(conn, kms, a, sa, pg_a)
        _check_full(conn, kms, a, sa, pg_a)
        _check_retire(conn, kms, worker, a, sa, pg_a)
        _check_heartbeat_and_loop(conn, kms, pool, FakeConnector("postgres", {"customers": customers()}))
    finally:
        pool.close()
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
