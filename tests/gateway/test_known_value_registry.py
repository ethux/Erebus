"""Per-replica matcher registry and its builder (spec 015 "Gateway replicas", "Fail closed").

Pure: the scope scan, the loader, the pool and the clock are fakes. The builder builds
every active scope on the first pass (an empty catalog is a ready, empty matcher),
rebuilds when a scope's catalog version moves, keeps the previous matcher when a rebuild
fails (degraded, retried with backoff 5 s doubling to 5 min), and evicts on
``CryptoErased``, an unprovisioned scope, or a scope that is not ``active``. Readiness is
``loading`` until the first pass tried every active scope.
"""
import os
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.crypto.keyprovider import CryptoErased
from erebus.gateway.known_value_registry import MatcherBuilder, MatcherRegistry
from erebus.gateway.known_values import KnownValueMatcher
from erebus.gateway.observability import Metric, Metrics

_passed = 0
A, B, C = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class FakePool:
    def __init__(self):
        self.closed = False

    class _Conn:
        def __enter__(self):
            return "conn"

        def __exit__(self, *exc):
            return False

    def connection(self):
        return self._Conn()

    def close(self):
        self.closed = True


class World:
    """Scopes, versions and per-scope loader behaviour the builder sees."""

    def __init__(self):
        self.scopes = {}
        self.versions = {}
        self.values = {}
        self.errors = {}
        self.loads = []
        self.scan_error = None
        self.now = 1000.0

    def scan(self, _conn):
        if self.scan_error is not None:
            raise self.scan_error
        return dict(self.scopes), dict(self.versions)

    def load(self, _conn, _kp, sid):
        self.loads.append(sid)
        error = self.errors.get(sid)
        if error is not None:
            raise error
        return KnownValueMatcher.build(self.values.get(sid, []))

    def clock(self):
        return self.now


def _builder(world, metrics=None, poll_s=5.0):
    registry = MatcherRegistry()
    builder = MatcherBuilder(registry, FakePool(), key_provider=None, poll_s=poll_s, metrics=metrics,
                             scan=world.scan, load=world.load, clock=world.clock)
    return registry, builder


def _hits(registry, sid, text):
    matcher = registry.get(sid)
    return None if matcher is None else [text[s:e] for s, e, _l in matcher.match(text)]


def test_first_pass_and_rebuild():
    world = World()
    world.scopes = {A: "active", B: "active"}
    world.versions = {A: 1}
    world.values = {A: [("Zyx Qorbel", "PERSON")]}
    metrics = Metrics()
    registry, builder = _builder(world, metrics)
    check("readiness is loading before the first pass", registry.state() == "loading")
    world.scan_error = RuntimeError("db down")
    builder.run_pass()
    check("a failed scan leaves readiness loading", registry.state() == "loading" and world.loads == [])
    world.scan_error = None
    builder.run_pass()
    check("the first pass makes readiness ready", registry.state() == "ready")
    check("a tenant's values match after the first pass", _hits(registry, A, "hi Zyx Qorbel") == ["Zyx Qorbel"])
    check("a tenant with no catalog gets an empty matcher", _hits(registry, B, "hi Zyx Qorbel") == [])
    builder.run_pass()
    check("an unchanged version does not rebuild", world.loads.count(A) == 1)
    world.values[A] = [("Zyx Qorbel", "PERSON"), ("Mira Vantol", "PERSON")]
    world.versions[A] = 2
    old = registry.get(A)
    builder.run_pass()
    check("a moved version rebuilds and swaps the matcher",
          registry.get(A) is not old and _hits(registry, A, "Mira Vantol") == ["Mira Vantol"])
    check("rebuilds are counted per scope", metrics.snapshot(str(A))[Metric.KNOWN_VALUE_REBUILDS] == 2)


def test_failures():
    world = World()
    world.scopes = {A: "active", B: "active"}
    world.values = {A: [("Zyx Qorbel", "PERSON")]}
    metrics = Metrics()
    registry, builder = _builder(world, metrics)
    world.errors[B] = RuntimeError("decrypt failed")
    builder.run_pass()
    check("a first build that fails still ends the loading state", registry.state() == "degraded")
    check("a tenant whose first build failed has no matcher", registry.get(B) is None)
    world.errors[A] = RuntimeError("boom")
    world.versions[A] = 1
    old = registry.get(A)
    builder.run_pass()
    check("a failed rebuild keeps the previous matcher", registry.get(A) is old)
    check("readiness reports degraded", registry.state() == "degraded")
    check("failures are counted per scope", metrics.snapshot(str(A))[Metric.KNOWN_VALUE_REBUILD_FAILURES] == 1)
    loads = len(world.loads)
    builder.run_pass()
    check("a failed scope waits for its backoff", len(world.loads) == loads)
    world.now += 5
    builder.run_pass()
    check("it retries after 5 s", len(world.loads) == loads + 2)
    world.now += 5
    builder.run_pass()
    check("the backoff doubles after a second failure", len(world.loads) == loads + 2)
    world.now += 5
    del world.errors[A], world.errors[B]
    builder.run_pass()
    check("a successful retry clears degraded", registry.state() == "ready" and registry.get(B) is not None)
    check("the new matcher is in place", registry.get(A) is not old)
    world.errors[A] = RuntimeError("again")
    world.versions[A] = 2
    for _ in range(12):
        builder.run_pass()
        world.now += 301
    check("the backoff is capped at 5 min", builder.retry_in(A) == 300)


def test_eviction():
    world = World()
    world.scopes = {A: "active", B: "active", C: "active"}
    world.values = {A: [("Zyx Qorbel", "PERSON")], B: [("Mira Vantol", "PERSON")], C: [("Acme Corp", "ORG")]}
    registry, builder = _builder(world)
    builder.run_pass()
    world.errors[A] = CryptoErased(str(A))
    world.versions[A] = 1
    world.errors[B] = KeyError("not provisioned")
    world.versions[B] = 1
    builder.run_pass()
    check("a crypto-erased tenant's matcher is evicted", registry.get(A) is None)
    check("an unprovisioned tenant's matcher is evicted", registry.get(B) is None)
    check("eviction is not degraded", registry.state() == "ready")
    world.scopes[C] = "suspended"
    loads = len(world.loads)
    builder.run_pass()
    check("a scope that is not active is evicted without a build",
          registry.get(C) is None and len(world.loads) == loads)
    world.scopes = {}
    registry.put(C, KnownValueMatcher.build([]))
    builder.run_pass()
    check("a deleted scope is evicted", registry.get(C) is None)
    check("an evicted tenant is not adopted as empty", registry.adopt_empty(A) is None)
    fresh = uuid.uuid4()
    check("a tenant the builder never saw can be adopted empty", len(registry.adopt_empty(fresh)) == 0)
    registry.evict(fresh)
    check("evict drops an adopted matcher", registry.get(fresh) is None)


def test_thread():
    world = World()
    world.scopes = {A: "active"}
    world.values = {A: [("Zyx Qorbel", "PERSON")]}
    registry, builder = _builder(world, poll_s=60.0)
    pool = builder._pool
    builder.start()
    deadline = time.monotonic() + 5
    while registry.state() == "loading" and time.monotonic() < deadline:
        time.sleep(0.01)
    check("the background thread runs the first pass", registry.state() == "ready")
    world.values[A] = [("Mira Vantol", "PERSON")]
    world.versions[A] = 1
    registry.wake()
    deadline = time.monotonic() + 5
    while _hits(registry, A, "Mira Vantol") != ["Mira Vantol"] and time.monotonic() < deadline:
        time.sleep(0.01)
    check("a wake runs a pass before the poll interval", _hits(registry, A, "Mira Vantol") == ["Mira Vantol"])
    builder.close()
    check("close stops the thread and closes its pool",
          not any(t.name == "erebus-known-values" for t in threading.enumerate()) and pool.closed)


def main():
    print("\n=== Gateway known values: registry and builder ===\n")
    test_first_pass_and_rebuild()
    test_failures()
    test_eviction()
    test_thread()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
