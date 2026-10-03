"""Sync worker extensions via the erebus.worker.extensions entry point group (spec 015).

Pure logic: fake entry points stand in for installed distributions, mirroring the
gateway's extensions. Each gets hooks with ``state``, ``add_periodic`` and
``enqueue_job``; none installed is a no-op; broken extension code stops the worker
(fail closed). The worker runs periodic callbacks when due, and one failing callback
does not stop the others.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sync_fakes import config

from erebus.gateway.store.scope_context import scoped
from erebus.sync.extensions import GROUP, WorkerHooks, load_extensions
from erebus.sync.worker import Worker

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _EP:
    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    def load(self):
        return self._fn


def _boom(_hooks):
    raise RuntimeError("broken extension")


def _check_loading(worker):
    hooks = WorkerHooks(state={"k": 1}, add_periodic=worker.add_periodic, enqueue_job=worker.enqueue_job)
    seen = []
    loaded = load_extensions(hooks, eps=[_EP("a", seen.append)])
    check("group name mirrors the gateway's", GROUP == "erebus.worker.extensions")
    check("an extension receives the hooks", seen == [hooks] and seen[0].state == {"k": 1})
    check("the hooks expose add_periodic and enqueue_job",
          seen[0].add_periodic == worker.add_periodic and seen[0].enqueue_job == worker.enqueue_job)
    check("loaded extension names are returned", loaded == ["a"])
    check("no installed extensions is a no-op", load_extensions(hooks, eps=[]) == [])
    try:
        load_extensions(hooks, eps=[_EP("bad", _boom)])
        raised = False
    except RuntimeError:
        raised = True
    check("broken extension code stops the worker", raised)


def _check_periodic(worker):
    calls = []

    def fail():
        calls.append("fail")
        raise RuntimeError("callback bug")

    worker.add_periodic(lambda: calls.append("a"), 3600)
    worker.add_periodic(fail, 3600)
    worker.add_periodic(lambda: calls.append("b"), 3600)
    worker._tick_periodic()
    check("due callbacks run in order, a failing one does not stop the rest", calls == ["a", "fail", "b"])
    worker._tick_periodic()
    check("a callback is not run again before its interval", calls == ["a", "fail", "b"])
    try:
        worker.add_periodic(lambda: None, 0)
        refused = False
    except ValueError:
        refused = True
    check("a non-positive interval is refused", refused)


def _check_worker_hooks(worker):
    hooks = worker.hooks()
    check("the worker builds its hooks", isinstance(hooks, WorkerHooks))
    check("state carries the config, pool and key provider",
          hooks.state.config is worker.config and hooks.state.pool is worker.pool
          and hooks.state.provider is worker.provider)
    check("the hooks queue jobs and add periodic callbacks through the worker",
          hooks.enqueue_job == worker.enqueue_job and hooks.add_periodic == worker.add_periodic)
    check("scoped binds a transaction to a tenant (RLS)", hooks.scoped is scoped)
    check("connector_family names a type's family",
          hooks.connector_family("mysql") == "database" and hooks.connector_family("sqlite") == "file")
    check("an unknown type has no family", hooks.connector_family("no-such-type") is None)


def main():
    print("\n=== Sync worker extensions (spec 015) ===\n")
    worker = Worker(config("postgresql:///unused"), pool=None, provider=None, connectors=lambda _t: None)
    _check_loading(worker)
    _check_periodic(worker)
    _check_worker_hooks(worker)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
