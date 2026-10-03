"""Optional sync worker extensions, discovered through the ``erebus.worker.extensions``
entry point group (mirrors ``erebus.gateway.extensions``).

Each entry point is ``register(hooks) -> None``. ``hooks.state`` holds the worker's
config, pool and key provider; ``hooks.add_periodic(fn, seconds)`` runs ``fn`` from the
job loop; ``hooks.enqueue_job(conn, scope_id, source_id, kind, not_before=None)`` queues
a job; ``hooks.scoped(conn, scope_id)`` opens a transaction bound to a tenant (RLS);
``hooks.connector_family(type_id)`` names a connector type's family, or ``None``.
Exceptions propagate: an extension that cannot load is a code bug and the worker must
not start half-wired. Core checks no license here; an extension gates itself.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from importlib import metadata
from typing import Any

from ..cataloging import connector_types
from ..gateway.store.scope_context import scoped as _scoped

GROUP = "erebus.worker.extensions"


def family_of(type_id: str) -> str | None:
    """The family of an installed connector type, or ``None`` for an unknown one."""
    ctype = connector_types.get(type_id)
    return ctype.family if ctype else None


@dataclass(frozen=True)
class WorkerHooks:
    """What a worker extension may use."""

    state: Any
    add_periodic: Callable[..., None]
    enqueue_job: Callable[..., Any]
    scoped: Callable[..., Any] = _scoped
    connector_family: Callable[[str], str | None] = family_of


def load_extensions(hooks: WorkerHooks, eps: Iterable[Any] | None = None) -> list[str]:
    """Call every installed extension's ``register(hooks)``; return their names."""
    entries = metadata.entry_points(group=GROUP) if eps is None else eps
    loaded: list[str] = []
    for ep in entries:
        ep.load()(hooks)
        loaded.append(ep.name)
    return loaded
