"""Optional sync worker extensions, discovered through the ``erebus.worker.extensions``
entry point group (mirrors ``erebus.gateway.extensions``).

Each entry point is ``register(hooks) -> None``. ``hooks.state`` holds the worker's
config, pool and key provider; ``hooks.add_periodic(fn, seconds)`` runs ``fn`` from the
job loop; ``hooks.enqueue_job(conn, scope_id, source_id, kind, not_before=None)`` queues
a job. Exceptions propagate: an extension that cannot load is a code bug and the worker
must not start half-wired.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from importlib import metadata
from typing import Any

GROUP = "erebus.worker.extensions"


@dataclass(frozen=True)
class WorkerHooks:
    """What a worker extension may use."""

    state: Any
    add_periodic: Callable[..., None]
    enqueue_job: Callable[..., Any]


def load_extensions(hooks: WorkerHooks, eps: Iterable[Any] | None = None) -> list[str]:
    """Call every installed extension's ``register(hooks)``; return their names."""
    entries = metadata.entry_points(group=GROUP) if eps is None else eps
    loaded: list[str] = []
    for ep in entries:
        ep.load()(hooks)
        loaded.append(ep.name)
    return loaded
