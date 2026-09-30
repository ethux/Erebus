"""Sync job queue on Postgres (spec 015 "Architecture": worker; "Sync behaviour": failure, lease).

Live Postgres on its own database. One queued or running job per source (a second
enqueue returns the first, also under a race); claims skip rows another worker holds
(FOR UPDATE SKIP LOCKED), wait for not_before and take the oldest; the lease token
fences a worker whose lease expired; expiry re-queues as an attempt and the third fails
the job and flags the source; failures follow the policy with fixed-text errors; a
finished sample can queue its full sync in the same transaction; reads filter scope.
"""
import os
import sys
import threading
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
from helpers import fresh_db, restricted_role

from erebus.gateway.connectors import jobs, policy, sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store.known_value_store import open_store, provision_scope

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_sync_jobs")
_T = policy.JobTimings()
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _raises(exc_type, fn):
    try:
        fn()
    except exc_type:
        return True
    return False


def _src(conn, crypto, scope_id, name):
    return sources.create_source(conn, crypto, scope_id, name=name, connector_type="postgres", settings={},
                                 secrets={"password": "Zq-secret-9"})


def _age(conn, job_id, *, created=None, lease_past=False, not_before_now=False):
    with conn.transaction():
        if created is not None:
            conn.execute("UPDATE sync_jobs SET created_at = now() - make_interval(secs => %s) WHERE id = %s",
                         (created, job_id))
        if lease_past:
            conn.execute("UPDATE sync_jobs SET leased_until = now() - interval '1 second' WHERE id = %s", (job_id,))
        if not_before_now:
            conn.execute("UPDATE sync_jobs SET not_before = now() WHERE id = %s", (job_id,))


def _drain(conn):
    """Claim and finish everything claimable, so each check starts from an empty queue."""
    while (job := jobs.claim(conn, timings=_T)) is not None:
        jobs.finish(conn, job)


def _check_enqueue(conn, crypto, a_id, b_id, s1, s2):
    job, created = jobs.enqueue(conn, a_id, s1, "sample")
    check("enqueue queues a job", created and job.status == "queued" and job.kind == "sample")
    again, created2 = jobs.enqueue(conn, a_id, s1, "full")
    check("a second enqueue returns the job already queued", not created2 and again.id == job.id)
    other, created3 = jobs.enqueue(conn, a_id, s2, "full")
    check("another source gets its own job", created3 and other.id != job.id)
    check("enqueue for another scope's source raises KeyError",
          _raises(KeyError, lambda: jobs.enqueue(conn, b_id, s1, "full")))
    check("an unknown kind is refused", _raises(ValueError, lambda: jobs.enqueue(conn, a_id, s1, "export")))

    s3 = _src(conn, crypto, a_id, "race")
    conn.commit()
    results = []
    barrier = threading.Barrier(4)

    def racer():
        c = psycopg.connect(_DSN, autocommit=True)
        barrier.wait()
        results.append(jobs.enqueue(c, a_id, s3, "full"))
        c.close()

    threads = [threading.Thread(target=racer) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    check("four concurrent enqueues make one job", len({j.id for j, _ in results}) == 1
          and sum(1 for _j, c in results if c) == 1)
    return job, other


def _check_claim(conn, a_id, first, second):
    _age(conn, first.id, created=60)
    holder = psycopg.connect(_DSN)
    with holder.transaction():
        held = jobs.claim(holder, timings=_T)
        check("claim takes the oldest queued job", held.id == first.id and held.status == "running")
        check("a claimed job carries a lease token and lease", held.lease_token is not None
              and held.leased_until > held.started_at)
        other = psycopg.connect(_DSN, autocommit=True)
        mine = jobs.claim(other, timings=_T)
        check("a concurrent claim skips the locked row instead of waiting", mine is not None and mine.id != held.id)
        other.close()
    holder.close()
    check("claiming does not count an attempt", held.attempts == 0)
    _drain(conn)
    check("claim returns None on an empty queue", jobs.claim(conn, timings=_T) is None)
    return held, mine


def _check_lease(conn, crypto, a_id):
    src = _src(conn, crypto, a_id, "lease")
    jobs.enqueue(conn, a_id, src, "full")
    job = jobs.claim(conn, timings=_T)
    check("heartbeat with the lease token extends the lease", jobs.heartbeat(conn, job, timings=_T))
    stale = job
    for n in (1, 2):
        _age(conn, job.id, lease_past=True)
        expired = jobs.expire_leases(conn, timings=_T)
        check(f"expiry {n} re-queues the job as an attempt",
              expired == [(job.id, "queued")] and jobs.get_job(conn, a_id, job.id).attempts == n)
        check(f"after expiry {n} the old token is fenced", not jobs.heartbeat(conn, stale, timings=_T)
              and not jobs.finish(conn, stale) and jobs.fail(conn, stale, "query", timings=_T) is None)
        stale = jobs.claim(conn, timings=_T)
        check(f"the re-queued job is claimable again with a new token (round {n})",
              stale.id == job.id and stale.lease_token != job.lease_token)
    _age(conn, job.id, lease_past=True)
    check("the third expiry fails the job", jobs.expire_leases(conn, timings=_T) == [(job.id, "failed")])
    row = jobs.get_job(conn, a_id, job.id)
    check("the failed job has the fixed lease text", row.error == policy.ERROR_TEXT["lease"] and row.finished_at)
    check("the third expiry flags the source", sources.get_source(conn, a_id, src).status == "needs_attention")
    check("a live lease is not expired", jobs.expire_leases(conn, timings=_T) == [])


def _check_failures(conn, crypto, a_id):
    src = _src(conn, crypto, a_id, "fail")
    jobs.enqueue(conn, a_id, src, "full")
    job = jobs.claim(conn, timings=_T)
    out = jobs.fail(conn, job, "unreachable", timings=_T)
    row = jobs.get_job(conn, a_id, job.id)
    check("a retryable failure re-queues with backoff", out.status == "queued" and row.status == "queued"
          and row.attempts == 1 and row.not_before > row.created_at + timedelta(seconds=50))
    check("a backed-off job is not claimable yet", jobs.claim(conn, timings=_T) is None)
    check("the stored error is the fixed text", row.error == "source unreachable")
    _age(conn, job.id, not_before_now=True)

    job = jobs.claim(conn, timings=_T)
    reset = row.created_at + timedelta(hours=1)
    out = jobs.fail(conn, job, "limit", timings=_T, reset_at=reset)
    row = jobs.get_job(conn, a_id, job.id)
    check("a limit waits for the reset and is no attempt", row.status == "queued" and row.attempts == 1
          and row.not_before == reset and row.limited_since is not None)
    _age(conn, job.id, not_before_now=True)

    job = jobs.claim(conn, timings=_T)
    jobs.fail(conn, job, "auth", timings=_T)
    row = jobs.get_job(conn, a_id, job.id)
    check("auth fails unretried", row.status == "failed" and row.error == "authentication failed")
    check("auth flags the source", sources.get_source(conn, a_id, src).status == "needs_attention")
    check("no job row carries the credential", "Zq-secret" not in repr(jobs.list_jobs(conn, a_id)))


def _check_finish(conn, crypto, a_id, b_id):
    src = _src(conn, crypto, a_id, "finish")
    jobs.enqueue(conn, a_id, src, "sample")
    job = jobs.claim(conn, timings=_T)
    check("finish with a follow-up succeeds", jobs.finish(conn, job, rows_seen=10, then="full"))
    done = jobs.get_job(conn, a_id, job.id)
    check("finish stores done and its counts", done.status == "done" and done.rows_seen == 10 and done.finished_at)
    queued = [j for j in jobs.list_jobs(conn, a_id, source_id=src) if j.status == "queued"]
    check("the sample's transaction queued the full sync", [j.kind for j in queued] == ["full"])
    full = jobs.claim(conn, timings=_T)
    jobs.finish(conn, full, rows_seen=5, values_added=3, values_retired=1)
    row = jobs.get_job(conn, a_id, full.id)
    check("finish stores added and retired counts", (row.values_added, row.values_retired) == (3, 1))
    check("list_jobs filters on scope (another scope sees none)", jobs.list_jobs(conn, b_id, source_id=src) == [])
    check("get_job filters on scope", jobs.get_job(conn, b_id, full.id) is None)
    check("list_jobs returns newest first", jobs.list_jobs(conn, a_id, source_id=src)[0].id == full.id)


def _check_restricted(kms, a_id, b_id):
    """The worker path under a role that does not bypass RLS: claims cross tenants, the
    source flag lands in each job's own scope."""
    with restricted_role(_DSN) as role:
        role.commit()
        role.autocommit = True
        _drain(role)
        made = {}
        for scope_id in (a_id, b_id):
            crypto = open_store(role, kms, scope_id)._crypto
            made[scope_id] = _src(role, crypto, scope_id, "rls")
            jobs.enqueue(role, scope_id, made[scope_id], "full")
        claimed = [jobs.claim(role, timings=_T) for _ in range(2)]
        check("an unbound worker claims jobs of both tenants", {j.scope_id for j in claimed if j} == {a_id, b_id})
        for job in claimed:
            jobs.fail(role, job, "permission", timings=_T)
        check("each failure flags the source in its own scope",
              all(sources.get_source(role, sid, src).status == "needs_attention" for sid, src in made.items()))


def main():
    print("\n=== Sync job queue (spec 015 worker, lease, failure) ===\n")
    try:
        conn = fresh_db("erebus_gw_sync_jobs")
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.commit()
    conn.autocommit = True
    try:
        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/jobs/a")
        b_id = provision_scope(conn, kms, "org/jobs/b")
        crypto = open_store(conn, kms, a_id)._crypto
        s1 = _src(conn, crypto, a_id, "crm")
        s2 = _src(conn, crypto, a_id, "erp")
        first, second = _check_enqueue(conn, crypto, a_id, b_id, s1, s2)
        _check_claim(conn, a_id, first, second)
        _check_lease(conn, crypto, a_id)
        _check_failures(conn, crypto, a_id)
        _check_finish(conn, crypto, a_id, b_id)
        _check_restricted(kms, a_id, b_id)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
