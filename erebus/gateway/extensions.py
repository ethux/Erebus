"""Optional gateway extensions, discovered through the ``erebus.gateway.extensions``
entry point group (same pattern as ``erebus.sources`` for catalog connectors).

Each entry point is ``register(app, config) -> None``. Exceptions propagate: an
extension that cannot load is a code bug and the gateway must not start half-wired.
"""
from __future__ import annotations

from collections.abc import Iterable
from importlib import metadata
from typing import Any

GROUP = "erebus.gateway.extensions"


def load_extensions(app: Any, config: Any, eps: Iterable[Any] | None = None) -> list[str]:
    """Call every installed extension's ``register(app, config)``; return their names."""
    entries = metadata.entry_points(group=GROUP) if eps is None else eps
    loaded: list[str] = []
    for ep in entries:
        ep.load()(app, config)
        loaded.append(ep.name)
    return loaded
