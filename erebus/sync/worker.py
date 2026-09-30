"""The sync worker's job loop (spec 015 "Architecture": worker).

Each poll expires lapsed leases, runs due extension callbacks, then claims queued jobs
(``FOR UPDATE SKIP LOCKED``, oldest first, across tenants) up to ``concurrency`` and runs
each on a thread with its own pooled connection. A running job heartbeats on a separate
connection every ``heartbeat_s``; a job whose heartbeat finds the lease gone stops
writing. Failures are recorded as fixed text through ``jobs.fail``; logs name the job,
its kind and the error class, never a message a driver or source produced.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

import psycopg

from ..cataloging import sources as contract
from ..gateway.connectors import jobs
from ..gateway.crypto.keyprovider import KeyProvider
from . import runner
from .config import SyncConfig

log = logging.getLogger("erebus.sync")
_DEFAULT: Any = object()


class Lease:
    """Heartbeat a claimed job on its own connection until closed."""

    def __init__(self, dsn: str, job: jobs.Job, timings) -> None:
        self._dsn = dsn
        self._job = job
        self._timings = timings
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(target=self._beat, name=f"erebus-sync-lease-{job.id}", daemon=True)

    def __enter__(self) -> Lease:
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()
        self._thread.join()

    def _beat(self) -> None:
        conn = None
        while not self._stop.wait(self._timings.heartbeat_s):
            try:
                if conn is None or conn.closed:
                    conn = psycopg.connect(self._dsn, autocommit=True)
                alive = jobs.heartbeat(conn, self._job, timings=self._timings)
            except Exception as exc:  # a DB hiccup: retry; the fence still guards every write
                log.warning("job %s: heartbeat failed (%s)", self._job.id, type(exc).__name__)
                conn = None
                continue
            if not alive:
                self._lost.set()
                break
        if conn is not None:
            conn.close()

    def check(self) -> None:
        """Raise ``LeaseLost`` once a heartbeat found the lease gone."""
        if self._lost.is_set():
            raise runner.LeaseLost()


class Worker:
    """Claims and runs sync jobs. ``connectors`` maps a type id to a connector (default:
    the ``erebus.sources`` registry); ``model`` reviews sampled text (default: GLiNER
    unless detection is disabled)."""

    def __init__(
        self,
        config: SyncConfig,
        *,
        pool: Any,
        provider: KeyProvider,
        connectors: Callable[[str], Any] | None = None,
        model: Any = _DEFAULT,
        resolve: Callable[..., list] = socket.getaddrinfo,
    ) -> None:
        self.config = config
        self.pool = pool
        self.provider = provider
        self.connectors = connectors or contract.get_connector
        if model is _DEFAULT:
            model = None
            if not config.detection_disabled:
                from ..gateway.detection import build_model_reviewer
                model = build_model_reviewer()
        self.model = model
        self.resolve = resolve
        self._periodic: list[list] = []  # [fn, seconds, next due (monotonic)]

    def add_periodic(self, fn: Callable[[], Any], seconds: float) -> None:
        """Call ``fn()`` every ``seconds`` from the loop (worker extensions)."""
        if seconds <= 0:
            raise ValueError("a periodic callback needs a positive interval")
        self._periodic.append([fn, float(seconds), time.monotonic()])

    def enqueue_job(self, conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID, kind: str,
                    *, not_before=None) -> tuple[jobs.Job, bool]:
        """Queue a job (worker extensions); see ``jobs.enqueue``."""
        return jobs.enqueue(conn, scope_id, source_id, kind, not_before=not_before)

    def _connection(self):
        return self.pool.connection()

    def _claim(self) -> jobs.Job | None:
        with self._connection() as conn:
            conn.autocommit = True
            for job_id, status in jobs.expire_leases(conn, timings=self.config.timings):
                log.warning("job %s: lease expired, now %s", job_id, status)
            return jobs.claim(conn, timings=self.config.timings)

    def run_once(self) -> uuid.UUID | None:
        """Claim one due job and run it here; return its id, or ``None`` if none was due."""
        job = self._claim()
        if job is None:
            return None
        self._run(job)
        return job.id

    def _run(self, job: jobs.Job) -> None:
        log.info("job %s: %s started", job.id, job.kind)
        with self._connection() as conn, Lease(self.config.dsn, job, self.config.timings) as lease:
            conn.autocommit = True
            ctx = runner.Context(conn, self.provider, self.config, self.connectors, lease, self.model, self.resolve)
            try:
                counts = runner.execute(ctx, job)
            except runner.LeaseLost:
                log.warning("job %s: lease lost, result dropped", job.id)
                return
            except Exception as exc:
                self._record_failure(conn, job, exc)
                return
        log.info("job %s: %s done %s", job.id, job.kind, counts)

    def _record_failure(self, conn: psycopg.Connection, job: jobs.Job, exc: BaseException) -> None:
        failure = runner.classify(exc)
        if failure.error_class == "internal":
            # The type only: a message could quote a value or a DSN (SC-4).
            log.warning("job %s: %s failed: internal (%s)", job.id, job.kind, type(exc).__name__)
        else:
            log.warning("job %s: %s failed: %s", job.id, job.kind, failure.error_class)
        try:
            outcome = jobs.fail(conn, job, failure.error_class, timings=self.config.timings,
                                reset_at=failure.reset_at, license_message=failure.license_message)
            if outcome is None:
                log.warning("job %s: lease lost before the failure was recorded", job.id)
                return
            runner.audit_job(conn, job, outcome.status, {"error_class": failure.error_class})
        except Exception as db_exc:
            log.error("job %s: recording the failure failed (%s)", job.id, type(db_exc).__name__)

    def _tick_periodic(self) -> None:
        now = time.monotonic()
        for entry in self._periodic:
            fn, seconds, due = entry
            if now >= due:
                entry[2] = now + seconds
                try:
                    fn()
                except Exception as exc:
                    log.error("periodic callback failed (%s)", type(exc).__name__)

    def run_forever(self, stop: threading.Event) -> None:
        """Poll, claim and run jobs until ``stop`` is set; then let running jobs finish."""
        running: set[Future] = set()
        with ThreadPoolExecutor(max_workers=self.config.concurrency, thread_name_prefix="erebus-sync") as pool:
            while not stop.is_set():
                self._tick_periodic()
                running = {f for f in running if not f.done()}
                try:
                    while len(running) < self.config.concurrency and (job := self._claim()) is not None:
                        running.add(pool.submit(self._run, job))
                except Exception as exc:  # the DB is down: wait and poll again
                    log.error("claiming jobs failed (%s)", type(exc).__name__)
                stop.wait(self.config.poll_s)
