"""Record syncs of app sources through the sync worker: full, incremental, retire.

Live Postgres on its own database; an in-memory app connector (``app_fakes``). A full
sync links every value to its record, retires what no record holds any more and stores
the cursor each collection's read started at. An incremental sync reads only the
records changed since that cursor, replaces their links (a renamed contact's old name
retires) and stores the new cursor after it commits; a deletion feed retires a deleted
record's values; without one a deleted record keeps its values until the next full
sync. An expired cursor, or none, makes the job a full sync. A failed incremental
retires nothing and keeps the old cursor. The credential expiry a connector reports is
stored on the source. Every record read counts toward ``max_values``, values or not, and
a long read of records without values still checks the job's lease, so a source that
keeps returning records cannot run forever. Nothing a record holds reaches a job row or
an audit event.
"""
import os
import sys
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app_fakes import APP_TYPE, FakeApp, install_app_type
from helpers import fresh_db
from psycopg_pool import ConnectionPool
from sync_fakes import config

from erebus.gateway import catalog
from erebus.gateway.connectors import fields, jobs, sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
from erebus.gateway.store.scope_context import scoped
from erebus.sync import runner
from erebus.sync.worker import Worker

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_sync_records")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _contacts():
    return {"contacts": {
        "1": {"id": 1, "name": "Zyx Qorbel", "email": "zyx.qorbel@acme.example", "company": None},
        "2": {"id": 2, "name": "Ilsabet Vranckx", "email": "ilsabet.vranckx@acme.example", "company": None},
        "3": {"id": 3, "name": None, "email": None, "company": "Qorbel Holding BV"},
    }}


def _values(conn, kms, scope_id):
    crypto = open_scope_crypto(conn, kms, scope_id)
    return {v: label for v, label in catalog.iter_active_values(conn, crypto, scope_id)}


def _run(conn, worker, scope_id, source_id, kind):
    job, _ = jobs.enqueue(conn, scope_id, source_id, kind)
    conn.commit()
    worker.run_once()
    return jobs.get_job(conn, scope_id, job.id)


def _setup(conn, kms, pool, app, name):
    scope_id = provision_scope(conn, kms, name)
    source_id = sources.create_source(conn, open_scope_crypto(conn, kms, scope_id), scope_id, name="crm",
                                      connector_type=APP_TYPE.id, settings={"url": "https://crm.example"},
                                      secrets={"api_key": "Key-Zq-31"})
    conn.commit()
    worker = Worker(config(_DSN), pool=pool, provider=kms, connectors=lambda t: app if t == APP_TYPE.id else None)
    return scope_id, source_id, worker


def _check_full(conn, kms, worker, scope_id, source_id, app):
    _run(conn, worker, scope_id, source_id, "sample")
    decided = {f.field: (f.decision, f.label) for f in fields.list_fields(conn, scope_id, source_id)}
    check("the app's field hints map name, email and company",
          decided["name"] == ("auto", "PERSON") and decided["email"] == ("auto", "EMAIL_ADDRESS")
          and decided["company"] == ("auto", "ORGANIZATION") and decided["id"][0] == "ignored")
    full = jobs.list_jobs(conn, scope_id, source_id=source_id)[0]
    worker.run_once()
    full = jobs.get_job(conn, scope_id, full.id)
    values = _values(conn, kms, scope_id)
    check("the full sync the sample queued stores every record's values under their labels",
          full.kind == "full" and full.status == "done" and values.get("Zyx Qorbel") == "PERSON"
          and values.get("Qorbel Holding BV") == "ORGANIZATION" and "ilsabet.vranckx@acme.example" in values)
    check("... reading records, not distinct values", ("records", "contacts", None) in app.calls)
    check("... counting the records read", full.rows_seen == 3)
    with scoped(conn, scope_id):
        links = conn.execute("SELECT count(*) FROM catalog_entry_records WHERE scope_id = %s AND source_id = %s",
                             (scope_id, source_id)).fetchone()[0]
    check("each value is linked to its record", links == 5)
    check("the cursor the read started at is stored per collection",
          sources.get_source(conn, scope_id, source_id).cursor == {"contacts": "1"})
    return full


def _check_incremental(conn, kms, worker, scope_id, source_id, app):
    app.change("contacts", "1", name="Zyx Qorbel-Vranckx")
    job = _run(conn, worker, scope_id, source_id, "incremental")
    values = _values(conn, kms, scope_id)
    check("an incremental sync reads the changes since the stored cursor",
          app.calls[-1] == ("changes", "contacts", "1") and job.status == "done")
    check("... picks up the new name", "Zyx Qorbel-Vranckx" in values)
    check("... and retires the old one through the record's links", "Zyx Qorbel" not in values
          and job.values_retired == 1)
    check("... reading only the changed record", job.rows_seen == 1)
    check("records it did not read keep their values", "Ilsabet Vranckx" in values)
    check("the new cursor is stored", sources.get_source(conn, scope_id, source_id).cursor == {"contacts": "2"})

    app.delete("contacts", "2")
    job = _run(conn, worker, scope_id, source_id, "incremental")
    check("without a deletion feed an incremental sync keeps a deleted record's values",
          job.status == "done" and "Ilsabet Vranckx" in _values(conn, kms, scope_id))
    job = _run(conn, worker, scope_id, source_id, "full")
    check("... and the next full sync retires them",
          job.status == "done" and "Ilsabet Vranckx" not in _values(conn, kms, scope_id))

    app.feed = True
    app.delete("contacts", "3")
    job = _run(conn, worker, scope_id, source_id, "incremental")
    check("a deletion feed retires a deleted record's values in an incremental sync",
          job.status == "done" and "Qorbel Holding BV" not in _values(conn, kms, scope_id))


def _check_fallback(conn, kms, worker, scope_id, source_id, app):
    app.expired = True
    app.change("contacts", "1", email="zyx@qorbel.example")
    job = _run(conn, worker, scope_id, source_id, "incremental")
    values = _values(conn, kms, scope_id)
    check("an expired cursor makes the incremental job a full sync",
          job.status == "done" and [c[0] for c in app.calls[-2:]] == ["changes", "records"])
    check("... which retires what the source no longer holds", "zyx@qorbel.example" in values
          and "zyx.qorbel@acme.example" not in values)
    check("... and stores a fresh cursor", sources.get_source(conn, scope_id, source_id).cursor == {
        "contacts": str(app.tick)})
    app.expired = False

    sources.set_cursor(conn, scope_id, source_id, {})
    conn.commit()
    before = len(app.calls)
    job = _run(conn, worker, scope_id, source_id, "incremental")
    check("an incremental job without a cursor reads everything",
          job.status == "done" and ("records", "contacts", None) in app.calls[before:]
          and not any(c[0] == "changes" for c in app.calls[before:]))


def _check_failure(conn, kms, worker, scope_id, source_id, app):
    cursor = sources.get_source(conn, scope_id, source_id).cursor
    app.change("contacts", "1", name="Zyx Qorbel-Brandt")
    app.change("contacts", "4", id=4, name="Mila Brandt", email=None, company=None)
    app.fail_after = 1
    job = _run(conn, worker, scope_id, source_id, "incremental")
    values = _values(conn, kms, scope_id)
    check("a failed incremental sync is retried later", job.status == "queued" and job.attempts == 1)
    check("... retires nothing (the old name of a record it already read stays)",
          "Zyx Qorbel-Vranckx" in values)
    check("... and keeps the old cursor", sources.get_source(conn, scope_id, source_id).cursor == cursor)
    app.fail_after = None
    with conn.transaction():
        conn.execute("UPDATE sync_jobs SET not_before = now() WHERE id = %s", (job.id,))
    worker.run_once()
    values = _values(conn, kms, scope_id)
    check("the retry completes the incremental sync",
          jobs.get_job(conn, scope_id, job.id).status == "done" and "Zyx Qorbel-Brandt" in values
          and "Mila Brandt" in values and "Zyx Qorbel-Vranckx" not in values)


def _check_expiry_and_audit(conn, kms, worker, scope_id, source_id, app):
    app.expiry = datetime(2027, 1, 2, tzinfo=UTC)
    _run(conn, worker, scope_id, source_id, "incremental")
    check("the credential expiry the connector reports is stored on the source",
          sources.get_source(conn, scope_id, source_id).credentials_expire_at == app.expiry)
    app.expiry = None
    _run(conn, worker, scope_id, source_id, "incremental")
    check("an unknown expiry leaves the stored one",
          sources.get_source(conn, scope_id, source_id).credentials_expire_at == datetime(2027, 1, 2, tzinfo=UTC))
    with scoped(conn, scope_id):
        rows = conn.execute("SELECT metadata::text FROM audit_events WHERE scope_id = %s AND event_type = 'sync'",
                            (scope_id,)).fetchall()
        errors = conn.execute("SELECT coalesce(string_agg(error, ' '), '') FROM sync_jobs WHERE scope_id = %s",
                              (scope_id,)).fetchone()[0]
    check("audit events and job rows hold no record value or credential",
          rows and not any(s in r[0] + errors for r in rows for s in ("Qorbel", "Vranckx", "Key-Zq")))


def _check_cap(conn, kms, pool):
    app = FakeApp(_contacts())
    scope_id, source_id, worker = _setup(conn, kms, pool, app, "tenant-app-cap")
    _run(conn, worker, scope_id, source_id, "sample")
    sources.update_source(conn, None, scope_id, source_id, max_values=2)
    conn.commit()
    full = jobs.list_jobs(conn, scope_id, source_id=source_id)[0]
    worker.run_once()
    check("an app sync past max_values fails as incomplete",
          jobs.get_job(conn, scope_id, full.id).error == "sync incomplete")


def _accept_name(conn, scope_id, source_id):
    with scoped(conn, scope_id):
        conn.execute("INSERT INTO source_fields (scope_id, source_id, collection, field, db_type, label, decision) "
                     "VALUES (%s, %s, 'contacts', 'name', 'char', 'PERSON', 'confirmed')", (scope_id, source_id))
    conn.commit()


class _CountingLease:
    """A lease that is lost at its ``limit``-th check."""

    def __init__(self, limit):
        self.limit = limit
        self.calls = 0

    def check(self):
        self.calls += 1
        if self.calls >= self.limit:
            raise runner.LeaseLost()


def _empty(count):
    return {"contacts": {str(i): {"id": i, "name": None, "email": None, "company": None}
                         for i in range(1, count + 1)}}


def _check_progress(conn, kms, pool):
    rows = _empty(10)
    rows["contacts"]["11"] = {"id": 11, "name": "Zyx Qorbel", "email": None, "company": None}
    app = FakeApp(rows)
    scope_id, source_id, worker = _setup(conn, kms, pool, app, "tenant-app-progress")
    _accept_name(conn, scope_id, source_id)
    sources.update_source(conn, None, scope_id, source_id, max_values=5)
    conn.commit()
    job = _run(conn, worker, scope_id, source_id, "full")
    check("records without values count toward max_values (an endless read stops)",
          job.status == "failed" and job.error == "sync incomplete")

    app = FakeApp(_empty(5000))
    scope_id, source_id, _worker = _setup(conn, kms, pool, app, "tenant-app-lease")
    _accept_name(conn, scope_id, source_id)
    queued, _ = jobs.enqueue(conn, scope_id, source_id, "full")
    conn.commit()
    cfg = config(_DSN)
    with pool.connection() as job_conn:
        job_conn.autocommit = True
        job = jobs.claim(job_conn, timings=cfg.timings)
        lease = _CountingLease(4)
        ctx = runner.Context(job_conn, kms, cfg, lambda t: app if t == APP_TYPE.id else None, lease)
        try:
            runner.execute(ctx, job)
            lost = False
        except runner.LeaseLost:
            lost = True
    check("a long read of records without values still checks the lease",
          job.id == queued.id and lost and lease.calls == 4)


def main():
    print("\n=== Record syncs of app sources ===\n")
    install_app_type()
    conn = fresh_db("erebus_gw_sync_records")
    kms = LocalKms()
    pool = ConnectionPool(_DSN, min_size=1, max_size=3, open=True)
    app = FakeApp(_contacts())
    try:
        scope_id, source_id, worker = _setup(conn, kms, pool, app, "tenant-app")
        _check_full(conn, kms, worker, scope_id, source_id, app)
        _check_incremental(conn, kms, worker, scope_id, source_id, app)
        _check_fallback(conn, kms, worker, scope_id, source_id, app)
        _check_failure(conn, kms, worker, scope_id, source_id, app)
        _check_expiry_and_audit(conn, kms, worker, scope_id, source_id, app)
        _check_cap(conn, kms, pool)
        _check_progress(conn, kms, pool)
    finally:
        pool.close()
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
