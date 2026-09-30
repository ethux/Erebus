"""Per-replica known-value matchers and the thread that builds them (spec 015 "Gateway replicas").

:class:`MatcherRegistry` is server instance state (FR-043: no module-level container): one
immutable :class:`~erebus.gateway.known_values.KnownValueMatcher` per tenant, swapped whole
by one assignment under a lock, so a request reads one reference and keeps that snapshot.

:class:`MatcherBuilder` runs on its own thread with its own small pool (never the request
pool or anyio's workers). Every ``poll_s`` seconds, or at once when woken, it reads
``scopes`` and ``catalog_versions`` (neither has RLS) and builds each active scope whose
version moved or whose retry is due. Outcomes:

* success: the new matcher is swapped in (an empty catalog gives an empty, ready matcher);
* ``CryptoErased``, an unprovisioned scope (``KeyError``), or a scope that is not
  ``active`` or no longer exists: the matcher is evicted, so the tenant gets 503;
* any other failure: the previous matcher stays and readiness reports ``degraded``.

Failed builds retry with backoff from 5 s doubling to 5 min. Readiness is ``loading``
until the first pass has tried every active scope. Values live only in memory.
"""
from __future__ import annotations

import contextlib
import threading
import time
import uuid
from collections.abc import Callable

from . import catalog
from .crypto.keyprovider import CryptoErased, KeyProvider
from .known_values import KnownValueMatcher
from .observability import Metric, Metrics
from .store import catalog_versions

LOADING = "loading"
READY = "ready"
DEGRADED = "degraded"

_BACKOFF_MIN_S = 5.0
_BACKOFF_MAX_S = 300.0

Scan = Callable[[object], "tuple[dict[uuid.UUID, str], dict[uuid.UUID, int]]"]
Load = Callable[[object, KeyProvider, uuid.UUID], KnownValueMatcher]


def scan_scopes(conn) -> tuple[dict[uuid.UUID, str], dict[uuid.UUID, int]]:
    """Every scope's status and catalog version (no RLS on either table)."""
    with conn.transaction():
        scopes = {sid: status for sid, status in conn.execute("SELECT id, status FROM scopes").fetchall()}
    return scopes, catalog_versions.read_all(conn)


class MatcherRegistry:
    """The tenant matchers of this replica plus the readiness they add up to."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._matchers: dict[uuid.UUID, KnownValueMatcher] = {}
        self._attempted: set[uuid.UUID] = set()  # the builder decided on these
        self._failing: set[uuid.UUID] = set()
        self._first_pass = False
        self._empty = KnownValueMatcher.build([])
        self._wake = threading.Event()

    def get(self, scope_id: uuid.UUID) -> KnownValueMatcher | None:
        return self._matchers.get(scope_id)

    def attempted(self, scope_id: uuid.UUID) -> bool:
        return scope_id in self._attempted

    def put(self, scope_id: uuid.UUID, matcher: KnownValueMatcher) -> None:
        with self._lock:
            self._matchers[scope_id] = matcher
            self._attempted.add(scope_id)
            self._failing.discard(scope_id)

    def failed(self, scope_id: uuid.UUID) -> None:
        """A build failed for a reason that does not evict: keep what is there."""
        with self._lock:
            self._attempted.add(scope_id)
            self._failing.add(scope_id)

    def evict(self, scope_id: uuid.UUID) -> None:
        with self._lock:
            self._matchers.pop(scope_id, None)
            self._attempted.add(scope_id)
            self._failing.discard(scope_id)

    def adopt_empty(self, scope_id: uuid.UUID) -> KnownValueMatcher | None:
        """An empty matcher for a tenant the builder has not decided on yet (onboarded since
        the last pass, catalog checked empty by the caller); ``None`` once it has."""
        with self._lock:
            if scope_id in self._attempted:
                return self._matchers.get(scope_id)
            return self._matchers.setdefault(scope_id, self._empty)

    def scope_ids(self) -> set[uuid.UUID]:
        with self._lock:
            return set(self._matchers) | self._failing

    def first_pass_done(self) -> None:
        self._first_pass = True

    def state(self) -> str:
        """Aggregate readiness; never names a scope (``/readyz`` is unauthenticated)."""
        if not self._first_pass:
            return LOADING
        return DEGRADED if self._failing else READY

    def wake(self) -> None:
        self._wake.set()

    def wait(self, timeout: float) -> None:
        self._wake.wait(timeout)
        self._wake.clear()


class MatcherBuilder:
    """Builds and swaps tenant matchers on a dedicated thread with its own pool."""

    def __init__(self, registry: MatcherRegistry, pool, key_provider: KeyProvider, *, poll_s: float = 5.0,
                 metrics: Metrics | None = None, scan: Scan = scan_scopes, load: Load = catalog.load_matcher,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._registry = registry
        self._pool = pool
        self._kp = key_provider
        self._poll_s = poll_s
        self._metrics = metrics
        self._scan = scan
        self._load = load
        self._clock = clock
        self._built: dict[uuid.UUID, int] = {}  # scope -> catalog version of its matcher
        self._retry: dict[uuid.UUID, tuple[float, float]] = {}  # scope -> (due, backoff)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_pass(self) -> None:
        """One poll: evict what is gone or inactive, build what moved or is due.

        A failed scan changes nothing (readiness stays ``loading`` before the first pass).
        """
        try:
            with self._pool.connection() as conn:
                scopes, versions = self._scan(conn)
        except Exception:
            return
        active = {sid for sid, status in scopes.items() if status == "active"}
        for sid in (self._registry.scope_ids() | set(self._built) | set(self._retry)) - active:
            self._registry.evict(sid)
            self._built.pop(sid, None)
            self._retry.pop(sid, None)
        for sid in sorted(active):
            if self._stop.is_set():
                return
            version = versions.get(sid, 0)
            if self._due(sid, version):
                self._build(sid, version)
        self._registry.first_pass_done()

    def retry_in(self, scope_id: uuid.UUID) -> float:
        """The current backoff of a failing scope (0 when it is not failing)."""
        return self._retry.get(scope_id, (0.0, 0.0))[1]

    def _due(self, sid: uuid.UUID, version: int) -> bool:
        retry = self._retry.get(sid)
        if retry is not None:
            return self._clock() >= retry[0]
        return self._built.get(sid) != version

    def _build(self, sid: uuid.UUID, version: int) -> None:
        try:
            with self._pool.connection() as conn:
                matcher = self._load(conn, self._kp, sid)
        except (CryptoErased, KeyError):
            self._registry.evict(sid)
            self._failure(sid)
        except Exception:  # keep the previous matcher; readiness reports degraded
            self._registry.failed(sid)
            self._failure(sid)
        else:
            self._registry.put(sid, matcher)
            self._built[sid] = version
            self._retry.pop(sid, None)
            self._record(sid, Metric.KNOWN_VALUE_REBUILDS)

    def _failure(self, sid: uuid.UUID) -> None:
        self._built.pop(sid, None)
        backoff = self._retry.get(sid, (0.0, 0.0))[1]
        backoff = min(max(backoff * 2, _BACKOFF_MIN_S), _BACKOFF_MAX_S)
        self._retry[sid] = (self._clock() + backoff, backoff)
        self._record(sid, Metric.KNOWN_VALUE_REBUILD_FAILURES)

    def _record(self, sid: uuid.UUID, metric: Metric) -> None:
        if self._metrics is not None:
            with contextlib.suppress(Exception):
                self._metrics.record(str(sid), metric)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="erebus-known-values", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            with contextlib.suppress(Exception):  # never let the thread die; retried at the next poll
                self.run_pass()
            self._registry.wait(self._poll_s)

    def close(self, timeout: float = 10.0) -> None:
        """Stop the thread (a build in progress finishes first) and close the pool."""
        self._stop.set()
        self._registry.wake()
        if self._thread is not None:
            self._thread.join(timeout)
        self._pool.close()
