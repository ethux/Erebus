"""Connector types as data (spec 015 "Architecture").

Family, tier and allowed setting keys per type, so the gateway validates a source and
the sync worker checks its settings without loading any connector or driver. Pro adds
its types through the ``erebus.source_types`` entry-point group: each entry point is a
data-only module (or object) with a ``TYPES`` iterable of ``ConnectorType``.

No type allows a raw DSN, a libpq file key (``passfile``, ``service``, ``sslkey``,
``sslrootcert``), ``hostaddr`` or a driver option: the worker resolves and checks the
host itself and hands the connector the address to use (see ``erebus.sync.netpolicy``).
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cache
from importlib import metadata
from typing import Any

GROUP = "erebus.source_types"
FAMILIES = ("file", "database", "warehouse", "app")
TIERS = ("free", "pro")


@dataclass(frozen=True)
class ConnectorType:
    """One connector type. ``default_port`` is set for types that dial a host."""

    id: str
    family: str
    tier: str
    setting_keys: frozenset[str]
    default_port: int | None = None


_DB_KEYS = frozenset({"host", "port", "dbname", "user", "sslmode", "schemas", "collections"})
_BUILTIN = (
    ConnectorType("sqlite", "file", "free", frozenset({"path", "collections"})),
    ConnectorType("postgres", "database", "free", _DB_KEYS, 5432),
    ConnectorType("mysql", "database", "free", _DB_KEYS, 3306),
)


def builtin_types() -> tuple[ConnectorType, ...]:
    """The free types core ships."""
    return _BUILTIN


def load_types(eps: Iterable[Any] | None = None) -> dict[str, ConnectorType]:
    """Built-in types plus every ``erebus.source_types`` module's; errors propagate.

    A module may not redefine a type another one declared.
    """
    types = {t.id: t for t in _BUILTIN}
    entries = metadata.entry_points(group=GROUP) if eps is None else eps
    for ep in entries:
        for t in ep.load().TYPES:
            if not isinstance(t, ConnectorType) or t.family not in FAMILIES or t.tier not in TIERS:
                raise ValueError("malformed connector type")
            if t.id in types:
                raise ValueError("connector type declared twice")
            types[t.id] = t
    return types


@cache
def _installed() -> Mapping[str, ConnectorType]:
    return load_types()


def get(type_id: str) -> ConnectorType | None:
    """The installed type ``type_id``, or ``None`` (an unknown connector type)."""
    return _installed().get(type_id)


def unknown_keys(ctype: ConnectorType, settings: Mapping[str, Any]) -> list[str]:
    """Setting keys ``ctype`` does not allow, sorted."""
    return sorted(k for k in settings if k not in ctype.setting_keys)
