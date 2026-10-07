"""Sync worker failures on Postgres.

Live Postgres on its own database; in-memory connectors stand in for sources. A full
sync that fails midway, passes max_values or the tenant cap, misses an accepted column,
reports a capped query or loses its lease retires nothing; only the next complete sync
does. Failures follow the policy: unreachable retries with backoff and fails after the
last step, auth and license fail unretried and flag the source, a limit waits for its
reset without counting an attempt, anything else is an internal error. The worker
refuses a denied host, bad settings and an unknown type before any connector runs, and
skips a paused source. A ``collections`` entry the source does not list fails the sample
as bad settings; an entry matches as written or as the source reads an unquoted name. A
connector that dials anything but the checked address (a redirect, say) fails the job as
denied; model review and the worker's own database connections are never refused. Job
rows and logs carry fixed text only.
"""
import contextlib
import io
import logging
import os
import socket
import sys
import tempfile
import threading
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers import fresh_db
from psycopg_pool import ConnectionPool
from sync_fakes import FakeConnector, Field, Table, config, customers, lookup

from erebus.cataloging.connector_types import ConnectorType
from erebus.cataloging.sources import ConnectorError, DriverMissing, LicenseRequired
from erebus.gateway import catalog
from erebus.gateway.connectors import fields, jobs, sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store import catalog_versions
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
from erebus.gateway.store.scope_context import scoped
from erebus.sync import runner
from erebus.sync.worker import Worker

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_sync_failures")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _Env:
    def __init__(self, conn, kms, pool):
        self.conn, self.kms, self.pool = conn, kms, pool
        lead = {"id": 9, "email": "lara.lead@acme.example", "full_name": "Lara Lead", "first_name": "Lara",
                "tussenvoegsel": "", "last_name": "Lead", "product_name": "Kit"}
        self.pg = FakeConnector("postgres", {"customers": customers(), "leads": Table(customers().fields, [lead])})
        self.scope = provision_scope(conn, kms, "tenant-f")
        self.crypto = open_scope_crypto(conn, kms, self.scope)
        self.source = self.new_source({"host": "127.0.0.1", "dbname": "crm"})

    def new_source(self, settings, connector_type="postgres"):
        sid = sources.create_source(self.conn, self.crypto, self.scope, name="s", connector_type=connector_type,
                                    settings=settings, secrets={"password": "Pw-Zq-77"})
        self.conn.commit()
        return sid

    def worker(self, **env):
        return Worker(config(_DSN, **env), pool=self.pool, provider=self.kms, connectors=lookup(self.pg))

    def run(self, kind="full", source=None, worker=None, **env):
        job, _ = jobs.enqueue(self.conn, self.scope, source or self.source, kind)
        self.conn.commit()
        (worker or self.worker(**env)).run_once()
        return jobs.get_job(self.conn, self.scope, job.id)

    def values(self):
        return {v for v, _l in catalog.iter_active_values(self.conn, self.crypto, self.scope)}

    def status(self, source=None):
        return sources.get_source(self.conn, self.scope, source or self.source).status

    def set_status(self, status, source=None):
        with scoped(self.conn, self.scope):
            self.conn.execute("UPDATE sources SET status = %s WHERE id = %s", (status, source or self.source))
        self.conn.commit()

    def settle(self, job_id):
        """Close a job left queued so the next check can enqueue."""
        with self.conn.transaction():
            self.conn.execute("UPDATE sync_jobs SET status = 'failed' WHERE id = %s AND status = 'queued'", (job_id,))


def _prime(env):
    sample = env.run("sample")
    full = jobs.list_jobs(env.conn, env.scope, source_id=env.source)[0]
    env.worker().run_once()
    check("setup: sample and full sync ran", sample.status == "done"
          and jobs.get_job(env.conn, env.scope, full.id).status == "done")
    check("setup: Zyx Qorbel is a known value", "Zyx Qorbel" in env.values())
    env.pg.tables["customers"].rows = [r for r in env.pg.tables["customers"].rows if r["full_name"] != "Zyx Qorbel"]


def _check_no_retire(env):
    env.pg.fail[("distinct", "leads")] = ConnectorError("unreachable")
    job = env.run()
    check("a source failing midway re-queues the job", job.status == "queued" and job.attempts == 1)
    check("the retry waits for the first backoff step",
          job.not_before > datetime.now(UTC) + timedelta(seconds=30) and job.error == "source unreachable")
    check("a failed sync retires nothing", "Zyx Qorbel" in env.values())
    env.settle(job.id)
    del env.pg.fail[("distinct", "leads")]

    with scoped(env.conn, env.scope):
        env.conn.execute("UPDATE sources SET max_values = 2 WHERE id = %s", (env.source,))
    env.conn.commit()
    job = env.run()
    check("passing max_values fails the sync as incomplete", job.status == "failed" and job.error == "sync incomplete")
    check("an incomplete sync flags the source", env.status() == "needs_attention")
    check("a capped sync retires nothing", "Zyx Qorbel" in env.values())
    with scoped(env.conn, env.scope):
        env.conn.execute("UPDATE sources SET max_values = 1000000 WHERE id = %s", (env.source,))
    env.conn.commit()

    rows = env.pg.tables["customers"].rows
    rows.append({"id": 3, "email": "new.person@acme.example", "full_name": "Nova Person"})
    job = env.run(EREBUS_SYNC_TENANT_MAX_VALUES=3)
    check("passing the tenant cap fails the sync as incomplete", job.error == "sync incomplete")
    check("a tenant-capped sync retires nothing", "Zyx Qorbel" in env.values())
    rows.pop()

    env.pg.fail[("distinct", "customers")] = ConnectorError("incomplete")
    job = env.run()
    check("a connector's capped query fails the sync as incomplete", job.error == "sync incomplete")
    check("a capped query retires nothing", "Zyx Qorbel" in env.values())
    del env.pg.fail[("distinct", "customers")]

    fields_before = env.pg.tables["customers"].fields
    env.pg.tables["customers"].fields = [f for f in fields_before if f.name != "email"]
    job = env.run()
    check("an accepted column the source no longer has makes the sync incomplete", job.error == "sync incomplete")
    check("a skipped column retires nothing", "Zyx Qorbel" in env.values())
    env.pg.tables["customers"].fields = fields_before

    def steal(_collection):
        with env.conn.transaction():
            env.conn.execute("UPDATE sync_jobs SET lease_token = gen_random_uuid() WHERE status = 'running'")

    env.pg.on_distinct = steal
    job = env.run()
    env.pg.on_distinct = None
    check("a worker that lost its lease writes no result", job.status == "running")
    check("a lost lease retires nothing", "Zyx Qorbel" in env.values())
    with env.conn.transaction():
        env.conn.execute("UPDATE sync_jobs SET status = 'failed', lease_token = NULL WHERE id = %s", (job.id,))

    job = env.run()
    check("the next complete sync retires the value", job.status == "done" and "Zyx Qorbel" not in env.values())
    check("a successful sync clears needs_attention", env.status() == "active")


def _check_bump(env):
    """Values an attempt committed reach the replicas even when that attempt failed."""
    batch = runner.UPSERT_BATCH
    runner.UPSERT_BATCH = 1  # commit each value as its own batch
    rows = env.pg.tables["customers"].rows
    rows.append({"id": 4, "email": "qyra.novell@acme.example", "full_name": "Qyra Novell"})
    env.pg.fail[("distinct", "leads")] = ConnectorError("unreachable")
    try:
        v0 = catalog_versions.read(env.conn, env.scope)
        job = env.run()
        check("setup: the attempt failed after committing a batch",
              job.status == "queued" and "Qyra Novell" in env.values())
        check("a failed attempt that added values bumps the catalog version",
              catalog_versions.read(env.conn, env.scope) > v0)
        del env.pg.fail[("distinct", "leads")]
        v1 = catalog_versions.read(env.conn, env.scope)
        with env.conn.transaction():
            env.conn.execute("UPDATE sync_jobs SET not_before = now() WHERE id = %s", (job.id,))
        env.worker().run_once()
        job = jobs.get_job(env.conn, env.scope, job.id)
        check("the retry of that job completes", job.status == "done" and job.values_added == 0)
        check("a retried sync bumps the catalog version though it added nothing new",
              catalog_versions.read(env.conn, env.scope) > v1)

        job, _ = jobs.enqueue(env.conn, env.scope, env.source, "full")
        env.conn.commit()
        claimed = jobs.claim(env.conn, timings=env.worker().config.timings)
        with env.conn.transaction():
            env.conn.execute("UPDATE sync_jobs SET leased_until = now() - interval '1 second' WHERE id = %s",
                             (claimed.id,))
        v2 = catalog_versions.read(env.conn, env.scope)
        jobs.expire_leases(env.conn, timings=env.worker().config.timings)
        check("an expired full sync (worker killed) bumps the catalog version",
              catalog_versions.read(env.conn, env.scope) > v2)
        env.settle(job.id)
    finally:
        runner.UPSERT_BATCH = batch
        env.pg.fail.pop(("distinct", "leads"), None)
        rows.pop()


def _check_capped_tuples(env):
    """A name tuple the query returned but that gives no value still counts toward max_values."""
    saved = env.pg.tables
    fields = [Field("id", "integer", True), Field("first_name"), Field("last_name")]
    people = [{"id": i, "first_name": f, "last_name": last}
              for i, (f, last) in enumerate([("Ann", "Arbor"), ("Bob", "Baker"), ("Cyd", "Cole")])]
    env.pg.tables = {"people": Table(fields, people)}
    try:
        src = env.new_source({"host": "127.0.0.1", "dbname": "hr"})
        env.run("sample", source=src)
        env.worker().run_once()
        check("setup: the people tuples are known values", {"Ann Arbor", "Bob Baker", "Cyd Cole"} <= env.values())
        with scoped(env.conn, env.scope):
            env.conn.execute("UPDATE sources SET max_values = 2 WHERE id = %s", (src,))
        env.conn.commit()
        people.insert(0, {"id": 9, "first_name": "Solo", "last_name": None})
        job = env.run(source=src)
        check("a capped query with a skipped tuple fails the sync as incomplete",
              job.status == "failed" and job.error == "sync incomplete")
        check("a tuple past the limit is not retired", "Cyd Cole" in env.values())
    finally:
        env.pg.tables = saved


def _check_retries(env):
    env.pg.fail[("connect", "*")] = ConnectorError("unreachable")
    worker = env.worker(EREBUS_SYNC_BACKOFF_S="1,1")
    job, _ = jobs.enqueue(env.conn, env.scope, env.source, "full")
    env.conn.commit()
    seen = []
    for _ in range(3):
        with env.conn.transaction():
            env.conn.execute("UPDATE sync_jobs SET not_before = now() WHERE id = %s", (job.id,))
        worker.run_once()
        seen.append(jobs.get_job(env.conn, env.scope, job.id))
    check("unreachable retries once per backoff step",
          [(j.status, j.attempts) for j in seen] == [("queued", 1), ("queued", 2), ("failed", 3)])
    check("retries do not flag the source", env.status() == "active")

    env.pg.fail[("connect", "*")] = ConnectorError("auth")
    job = env.run()
    check("auth fails unretried", job.status == "failed" and job.attempts == 1 and job.error == "authentication failed")
    check("auth flags the source", env.status() == "needs_attention")
    env.set_status("active")

    env.pg.fail[("connect", "*")] = LicenseRequired("connectors.postgres")
    job = env.run()
    check("LicenseRequired is stored verbatim and unretried",
          job.status == "failed" and job.error == "requires Erebus Pro (feature connectors.postgres)")
    env.set_status("active")

    env.pg.fail[("connect", "*")] = DriverMissing("erebus-pro[mssql-entra]")
    job = env.run()
    check("a missing optional driver is stored by name, unretried, and flags the source",
          job.status == "failed" and job.attempts == 1 and job.error == "requires the erebus-pro[mssql-entra] extra"
          and env.status() == "needs_attention")
    env.set_status("active")

    reset = datetime.now(UTC) + timedelta(minutes=20)
    env.pg.fail[("connect", "*")] = ConnectorError("limit", reset_at=reset)
    job = env.run()
    check("a limit waits for the source's reset and is no attempt",
          job.status == "queued" and job.attempts == 0 and abs((job.not_before - reset).total_seconds()) < 1)
    env.settle(job.id)

    env.pg.fail[("connect", "*")] = RuntimeError("boom for Zyx Qorbel at postgresql://u:Pw-Zq-77@h/db")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logging.getLogger("erebus.sync").addHandler(handler)
    logging.getLogger("erebus.sync").setLevel(logging.DEBUG)
    try:
        job = env.run()
    finally:
        logging.getLogger("erebus.sync").removeHandler(handler)
    check("any other error is an internal error, retried", job.status == "queued" and job.error == "internal error")
    log = stream.getvalue()
    check("the worker logged the failure", "internal" in log)
    check("the log holds no value, password or DSN",
          "Qorbel" not in log and "Pw-Zq-77" not in log and "postgresql://" not in log)
    env.settle(job.id)
    del env.pg.fail[("connect", "*")]


def _check_policy(env):
    worker = env.worker(EREBUS_SYNC_DENIED_HOSTS="")  # the defaults: loopback and the DB host
    before = len(env.pg.connects)
    job = env.run(worker=worker)
    check("the worker refuses a loopback source by default",
          job.status == "failed" and job.error == "source address is not allowed")
    check("no connector ran for a denied host", len(env.pg.connects) == before)
    check("a denied host flags the source", env.status() == "needs_attention")
    env.set_status("active")

    bad = env.new_source({"host": "127.0.0.1", "passfile": "/etc/pgpass"})
    job = env.run(source=bad)
    check("settings outside the type's keys are refused", job.error == "source settings are not valid")
    check("no connector ran for bad settings", len(env.pg.connects) == before)

    lite = env.new_source({"path": "crm.db"}, connector_type="sqlite")
    job = env.run(source=lite)
    check("SQLite is refused while EREBUS_SYNC_SQLITE_DIR is unset", job.error == "source address is not allowed")

    odd = env.new_source({}, connector_type="no_such_type_zq")
    job = env.run(source=odd)
    check("an unknown connector type fails", job.status == "failed" and job.error == "unknown connector type")

    env.set_status("paused")
    job = env.run()
    check("a paused source's job is skipped", job.status == "failed" and job.error == "source paused")
    check("skipping keeps the source paused", env.status() == "paused")
    env.set_status("active")

    with scoped(env.conn, env.scope):
        rows = env.conn.execute("SELECT error FROM sync_jobs WHERE scope_id = %s", (env.scope,)).fetchall()
    check("no job row holds a value or credential",
          all(r[0] is None or ("Qorbel" not in r[0] and "Pw-Zq" not in r[0]) for r in rows))


def _check_collections(env):
    calls = len(env.pg.calls)
    src = env.new_source({"host": "127.0.0.1", "dbname": "crm", "collections": ["Customers"]})
    job = env.run("sample", source=src)
    read = {c[1] for c in env.pg.calls[calls:] if c[0] == "records"}
    check("a collections entry matches as Postgres reads an unquoted name (lower case)",
          job.status == "done" and read == {"customers"})
    env.settle(jobs.list_jobs(env.conn, env.scope, source_id=src)[0].id)  # the full sync it queued

    bad = env.new_source({"host": "127.0.0.1", "dbname": "crm", "collections": ["customers", "no_such_table_zq"]})
    job = env.run("sample", source=bad)
    check("a collections entry the source does not list fails the sample as bad settings, unretried",
          job.status == "failed" and job.attempts == 1 and job.error == "source settings are not valid")
    check("... flags the source and maps no field",
          env.status(bad) == "needs_attention" and fields.list_fields(env.conn, env.scope, bad) == [])

    def pick(rule, listed, wanted):
        try:
            return runner.selected(ConnectorType("zq", "warehouse", "pro", frozenset(), identifiers=rule),
                                   listed, wanted)
        except runner.JobFailed as exc:
            return exc.error_class
    upper = ["CRM.customers", "CRM.CUSTOMERS", "PUBLIC.ORDERS"]
    check("upper: an entry matches as written, or as Snowflake and Oracle read it unquoted",
          pick("upper", upper, ["public.orders"]) == ["PUBLIC.ORDERS"]
          and pick("upper", upper, ["crm.customers"]) == ["CRM.customers", "CRM.CUSTOMERS"])
    check("... an exact match wins", pick("upper", upper, ["CRM.customers"]) == ["CRM.customers"])
    check("... an upper-case entry never matches a quoted lower-case name",
          pick("upper", ["CRM.customers"], ["CRM.CUSTOMERS"]) == "settings")
    check("insensitive (SQLite): any case matches", pick("insensitive", ["Customers"], ["CUSTOMERS"]) == ["Customers"])
    check("exact (MySQL, BigQuery, MSSQL): only the name as written",
          pick("exact", ["crm.customers"], ["crm.Customers"]) == "settings")
    check("collections keep the source's order", pick("exact", ["a.x", "a.y"], ["a.y", "a.x"]) == ["a.x", "a.y"])


@contextlib.contextmanager
def _listener():
    """A local TCP listener; yields (port, number of connections accepted so far as a list)."""
    srv = socket.create_server(("127.0.0.1", 0))
    accepted = []

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            accepted.append(1)
            conn.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1], accepted
    finally:
        srv.close()
        thread.join(2)


class _Dialing(FakeConnector):
    """A postgres connector that also dials ``target`` while connecting, as a driver
    following a server's redirect would."""

    def __init__(self, tables, target):
        super().__init__("postgres", tables)
        self.target = target

    def connect(self, settings, secrets):
        try:
            socket.create_connection(self.target, timeout=1).close()
        except OSError:
            raise ConnectorError("unreachable") from None
        return super().connect(settings, secrets)


def _check_connect_guard(env):
    notes = Table([Field("id", "integer", True), Field("notes")], [{"id": 1, "notes": "called Zyx about the kit"}])
    with _listener() as (port, accepted), _listener() as (other, redirected), \
            tempfile.TemporaryDirectory(dir="/tmp") as root:
        daemon_path = os.path.join(root, "gliner.sock")
        daemon = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        daemon.bind(daemon_path)
        daemon.listen(4)
        src = env.new_source({"host": "127.0.0.1", "port": port, "dbname": "crm"})
        asked = []

        def model(text):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(daemon_path)  # the GLiNER daemon's socket, outside connector work
            asked.append(text)
            return []

        def run(connector, kind):
            job, _ = jobs.enqueue(env.conn, env.scope, src, kind)
            env.conn.commit()
            Worker(config(_DSN), pool=env.pool, provider=env.kms, connectors=lookup(connector), model=model).run_once()
            return jobs.get_job(env.conn, env.scope, job.id)
        try:
            job = run(_Dialing({"notes": notes}, ("127.0.0.1", port)), "sample")
            check("a connector dialling the checked address and port works (and the worker's own DB connections)",
                  job.status == "done" and len(accepted) == 1)
            check("model review reaches the GLiNER daemon's Unix socket during a sample job", bool(asked))
            job = run(_Dialing({"notes": notes}, ("127.0.0.1", other)), "full")
            check("a connector dialling another address (a redirect) fails the job as denied",
                  job.status == "failed" and job.attempts == 1 and job.error == "source address is not allowed")
            check("... the redirect target is never reached", not redirected)
            check("... and the source is flagged", env.status(src) == "needs_attention")
        finally:
            daemon.close()


def main():
    print("\n=== Sync worker failures ===\n")
    conn = fresh_db("erebus_gw_sync_failures")
    pool = ConnectionPool(_DSN, min_size=1, max_size=4, open=True)
    try:
        env = _Env(conn, LocalKms(), pool)
        _prime(env)
        _check_no_retire(env)
        _check_bump(env)
        _check_capped_tuples(env)
        _check_retries(env)
        _check_policy(env)
        _check_collections(env)
        _check_connect_guard(env)
    finally:
        pool.close()
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
