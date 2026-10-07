"""The sync job queue (spec 015 "Data model": ``sync_jobs``, no RLS).

At most one queued or running job per source (partial unique index); ``enqueue``
returns that job instead of adding a second. Workers ``claim`` with FOR UPDATE SKIP
LOCKED, oldest first, once ``not_before`` has passed; each claim mints a lease token
that fences every later write, so a worker whose lease expired cannot finish or fail
the job it lost. Retry, wait and failure follow ``policy``. The table has no RLS, so
every read here filters ``scope_id`` itself; only the sources update is scoped.

A change the active job does not cover is owed (``request``): ``sources.pending_job``
holds it until that job ends (``finish``, a final ``fail`` or lease expiry queue it in
the same transaction) or the paused source resumes. Those paths lock the source row
before they change the job row, the order the admin API takes, so they cannot deadlock.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

import psycopg
from psycopg import errors as pg_errors

from ..store import catalog_versions
from ..store.scope_context import scoped
from . import policy

KINDS = ("sample", "full", "incremental", "oauth_exchange")
_COLUMNS = (
    "id, scope_id, source_id, kind, status, attempts, created_at, not_before, heartbeat_at, leased_until, "
    "lease_token, limited_since, started_at, finished_at, rows_seen, values_added, values_retired, error"
)
_FENCE = "id = %s AND lease_token = %s AND status = 'running'"


@dataclass(frozen=True)
class Job:
    """A ``sync_jobs`` row; ``lease_token`` is set while a worker holds it."""

    id: uuid.UUID
    scope_id: uuid.UUID
    source_id: uuid.UUID
    kind: str
    status: str
    attempts: int
    created_at: datetime
    not_before: datetime
    heartbeat_at: datetime | None
    leased_until: datetime | None
    lease_token: uuid.UUID | None
    limited_since: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    rows_seen: int
    values_added: int
    values_retired: int
    error: str | None


def enqueue(
    conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID, kind: str, *, not_before=None
) -> tuple[Job, bool]:
    """Queue a ``kind`` job, or return the source's queued or running one.

    Returns ``(job, created)``. ``KeyError`` when the source is not in this scope.
    Safe under concurrent calls: the loser of the insert reads the winner's job.
    """
    if kind not in KINDS:
        raise ValueError("unknown job kind")
    try:
        with scoped(conn, scope_id):
            # The partial unique index would answer for any scope's source, so check
            # ownership first; KEY SHARE also holds off a concurrent delete.
            if conn.execute(
                "SELECT 1 FROM sources WHERE scope_id = %s AND id = %s FOR KEY SHARE", (scope_id, source_id)
            ).fetchone() is None:
                raise KeyError("source not found")
            for _ in range(3):
                row = conn.execute(
                    "INSERT INTO sync_jobs (scope_id, source_id, kind, not_before) "
                    "VALUES (%s, %s, %s, COALESCE(%s, now())) "
                    "ON CONFLICT (source_id) WHERE status IN ('queued', 'running') DO NOTHING "
                    f"RETURNING {_COLUMNS}",
                    (scope_id, source_id, kind, not_before),
                ).fetchone()
                if row:
                    return Job(*row), True
                row = conn.execute(
                    f"SELECT {_COLUMNS} FROM sync_jobs WHERE scope_id = %s AND source_id = %s "
                    "AND status IN ('queued', 'running')",
                    (scope_id, source_id),
                ).fetchone()
                if row:
                    return Job(*row), False
    except pg_errors.ForeignKeyViolation:
        raise KeyError("source not found") from None
    raise RuntimeError("job queue contended")


def claim(conn: psycopg.Connection, *, timings: policy.JobTimings) -> Job | None:
    """Take the oldest due queued job, skipping rows other workers hold; ``None`` if none."""
    with conn.transaction():
        row = conn.execute(
            "UPDATE sync_jobs SET status = 'running', lease_token = gen_random_uuid(), started_at = now(), "
            "heartbeat_at = now(), leased_until = now() + make_interval(secs => %s) "
            "WHERE id = (SELECT id FROM sync_jobs WHERE status = 'queued' AND not_before <= now() "
            "            ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT 1) "
            f"RETURNING {_COLUMNS}",
            (timings.lease_s,),
        ).fetchone()
    return Job(*row) if row else None


def heartbeat(conn: psycopg.Connection, job: Job, *, timings: policy.JobTimings) -> bool:
    """Extend the lease; ``False`` when the lease was lost (stop working on the job)."""
    with conn.transaction():
        row = conn.execute(
            "UPDATE sync_jobs SET heartbeat_at = now(), leased_until = now() + make_interval(secs => %s) "
            f"WHERE {_FENCE} RETURNING 1",
            (timings.lease_s, job.id, job.lease_token),
        ).fetchone()
    return row is not None


def hold_lease(conn: psycopg.Connection, job: Job) -> bool:
    """Inside the caller's transaction, lock the job row if this worker still holds its lease.

    ``False`` when the lease was lost; the caller must then write nothing. Holding the row
    lock keeps the lease from expiring under a result being committed.
    """
    return conn.execute(f"SELECT 1 FROM sync_jobs WHERE {_FENCE} FOR UPDATE", (job.id, job.lease_token)).fetchone() \
        is not None


def finish(
    conn: psycopg.Connection,
    job: Job,
    *,
    rows_seen: int = 0,
    values_added: int = 0,
    values_retired: int = 0,
    then: str | None = None,
) -> bool:
    """Mark the job done with its counts and, in the same transaction, queue ``then``.

    ``False`` (and nothing written) when the lease was lost. Runs as a savepoint when the
    caller already holds a transaction, so value writes can commit with it.
    """
    with conn.transaction():
        owed = _lock_source(conn, job.scope_id, job.source_id)
        row = conn.execute(
            "UPDATE sync_jobs SET status = 'done', finished_at = now(), rows_seen = %s, values_added = %s, "
            "values_retired = %s, error = NULL, lease_token = NULL, leased_until = NULL "
            f"WHERE {_FENCE} RETURNING 1",
            (rows_seen, values_added, values_retired, job.id, job.lease_token),
        ).fetchone()
        if row is None:
            return False
        _settle_owed(conn, job.scope_id, job.source_id, owed, _merge(then, owed[0] if owed else None))
    return True


def _merge(a: str | None, b: str | None) -> str | None:
    """One job for two needs: a sample (it queues the full sync itself) over a full."""
    return "sample" if "sample" in (a, b) else (a or b)


def _lock_source(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID
                 ) -> tuple[str | None, str] | None:
    """Lock the source row; ``(pending_job, status)``, or ``None`` when it is gone."""
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT pending_job, status FROM sources WHERE scope_id = %s AND id = %s FOR UPDATE", (scope_id, source_id)
        ).fetchone()
    return (row[0], row[1]) if row else None


def _set_owed(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID, kind: str | None) -> None:
    with scoped(conn, scope_id):
        conn.execute("UPDATE sources SET pending_job = %s WHERE scope_id = %s AND id = %s", (kind, scope_id, source_id))


def _settle_owed(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID,
                 locked: tuple[str | None, str] | None, kind: str | None) -> None:
    """After the active job ended: queue ``kind``, or keep it owed while the source is paused."""
    if locked is None or kind is None:
        return
    if locked[1] == "paused":
        if kind != locked[0]:
            _set_owed(conn, scope_id, source_id, kind)
        return
    if locked[0] is not None:
        _set_owed(conn, scope_id, source_id, None)
    enqueue(conn, scope_id, source_id, kind)


def request(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID, kind: str | None = None
            ) -> Job | None:
    """Queue ``kind`` (``sample`` or ``full``) plus anything owed; return the active job.

    A queued job of that kind covers it. Otherwise, when a job is running or queued for
    another kind, or the source is paused, the need is owed on the source and queued when
    that job ends or the source resumes. ``kind=None`` queues only what is owed (a
    resume). ``None`` when nothing is active. ``KeyError`` when the source is not here.
    """
    with conn.transaction():
        locked = _lock_source(conn, scope_id, source_id)
        if locked is None:
            raise KeyError("source not found")
        owed, status = locked
        want = _merge(kind, owed)
        if want is None:
            return None
        if status == "paused":
            if want != owed:
                _set_owed(conn, scope_id, source_id, want)
            return None
        job, created = enqueue(conn, scope_id, source_id, want)
        left = None if created or (job.status == "queued" and job.kind == want) else want
        if left != owed:
            _set_owed(conn, scope_id, source_id, left)
    return job


def _flag_source(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID) -> None:
    with scoped(conn, scope_id):
        conn.execute(
            "UPDATE sources SET status = 'needs_attention', updated_at = now() WHERE scope_id = %s AND id = %s",
            (scope_id, source_id),
        )


def _apply(conn: psycopg.Connection, job_id: uuid.UUID, out: policy.Outcome) -> None:
    conn.execute(
        "UPDATE sync_jobs SET status = %s, attempts = %s, error = %s, "
        "not_before = COALESCE(%s, not_before), limited_since = COALESCE(%s, limited_since), "
        "lease_token = NULL, leased_until = NULL, heartbeat_at = NULL, "
        "finished_at = CASE WHEN %s = 'failed' THEN now() END "
        "WHERE id = %s",
        (out.status, out.attempts, out.error, out.not_before, out.limited_since, out.status, job_id),
    )


def fail(
    conn: psycopg.Connection,
    job: Job,
    error_class: str,
    *,
    timings: policy.JobTimings,
    reset_at: datetime | None = None,
    detail: str | None = None,
) -> policy.Outcome | None:
    """Record a failed attempt per ``policy.failure_outcome``; ``None`` if the lease was lost.

    Stores only fixed text. A fatal class also marks the source ``needs_attention``.
    """
    with conn.transaction():
        row = conn.execute(
            f"SELECT attempts, limited_since, now() FROM sync_jobs WHERE {_FENCE} FOR UPDATE",
            (job.id, job.lease_token),
        ).fetchone()
        if row is None:
            return None
        out = policy.failure_outcome(error_class, attempts=row[0], limited_since=row[1], now=row[2],
                                     timings=timings, reset_at=reset_at, detail=detail)
        _end(conn, job.id, job.scope_id, job.source_id, out)
    return out


def _end(conn: psycopg.Connection, job_id: uuid.UUID, scope_id: uuid.UUID, source_id: uuid.UUID,
         out: policy.Outcome) -> None:
    """Record a failed attempt; a job that failed for good queues what the source is owed."""
    final = out.status == "failed"
    locked = _lock_source(conn, scope_id, source_id) if final or out.needs_attention else None
    _apply(conn, job_id, out)
    if out.needs_attention:
        _flag_source(conn, scope_id, source_id)
    if final:
        _settle_owed(conn, scope_id, source_id, locked, locked[0] if locked else None)


def expire_leases(conn: psycopg.Connection, *, timings: policy.JobTimings) -> list[tuple[uuid.UUID, str]]:
    """Re-queue running jobs whose lease ran out (an attempt each); the last one fails.

    Returns ``(job id, new status)`` per expired job. Skips rows another sweeper holds.
    An expired sync may have committed value batches, so it bumps the catalog version.
    """
    done = []
    with conn.transaction():
        rows = conn.execute(
            "SELECT id, scope_id, source_id, attempts, kind FROM sync_jobs "
            "WHERE status = 'running' AND leased_until < now() ORDER BY leased_until FOR UPDATE SKIP LOCKED"
        ).fetchall()
        for job_id, scope_id, source_id, attempts, kind in rows:
            out = policy.lease_outcome(attempts=attempts, timings=timings)
            _end(conn, job_id, scope_id, source_id, out)
            if kind in ("full", "incremental"):
                catalog_versions.bump(conn, scope_id)
            done.append((job_id, out.status))
    return done


def get_job(conn: psycopg.Connection, scope_id: uuid.UUID, job_id: uuid.UUID) -> Job | None:
    """One job of this scope, or ``None``."""
    with conn.transaction():
        row = conn.execute(
            f"SELECT {_COLUMNS} FROM sync_jobs WHERE scope_id = %s AND id = %s", (scope_id, job_id)
        ).fetchone()
    return Job(*row) if row else None


def list_jobs(
    conn: psycopg.Connection, scope_id: uuid.UUID, *, source_id: uuid.UUID | None = None, limit: int = 50
) -> list[Job]:
    """This scope's jobs, newest first, optionally for one source."""
    with conn.transaction():
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM sync_jobs WHERE scope_id = %s AND (%s::uuid IS NULL OR source_id = %s) "
            "ORDER BY created_at DESC, id DESC LIMIT %s",
            (scope_id, source_id, source_id, limit),
        ).fetchall()
    return [Job(*r) for r in rows]
