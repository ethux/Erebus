"""Trusted local source connector contract and registry.

Connectors normalize databases and external APIs into collections, fields, and
records. Erebus owns scanning and catalog decisions after that normalization.

A database or warehouse source may also offer ``iter_distinct_values(collection,
fields, limit)``: distinct tuples of ``fields`` in that order, rows that are all NULL
skipped, at most ``limit`` (spec 015 D9). Callers use ``distinct_values``, which falls
back to de-duplicating ``iter_records`` for a source without it. Connectors raise
``ConnectorError`` (fixed text) for driver failures. Free connectors live in
``erebus.cataloging.connectors`` and register through the ``erebus.sources`` group;
the built-in SQLite one is loaded only when first asked for.
"""
from __future__ import annotations

import importlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Protocol

# Part of the contract: connectors raise these (re-exported for them).
from .connector_errors import ConnectorError, DriverMissing, LicenseRequired  # noqa: F401


@dataclass
class ConnectorMetadata:
    id: str
    name: str
    version: str = "0.0.0"
    capabilities: list[str] = field(default_factory=list)
    settings_schema: dict[str, Any] = field(default_factory=dict)
    secrets_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectionInfo:
    name: str
    label: str = ""
    record_count_hint: int | None = None


@dataclass
class FieldInfo:
    """A field. ``db_type`` is the type the source reports (``""``: unknown), ``nullable``
    ``None`` when unknown, ``primary_key`` true for a primary-key column."""

    name: str
    label: str = ""
    kind_hint: str = ""
    pii_hint: str = ""
    db_type: str = ""
    nullable: bool | None = None
    primary_key: bool = False


@dataclass
class SourceRecord:
    record_ref: str
    values: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


class RowSource(Protocol):
    """Normalized read-only source returned by a connector."""

    def list_collections(self) -> list[CollectionInfo]:
        ...

    def list_fields(self, collection: str) -> list[FieldInfo]:
        ...

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        ...

    def close(self) -> None:
        ...


class SourceConnector(Protocol):
    """Trusted local plugin that can open one source type."""

    def connector_id(self) -> str:
        ...

    def connector_metadata(self) -> ConnectorMetadata:
        ...

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        ...


_CONNECTORS: dict[str, SourceConnector] = {}
_ENTRYPOINTS_LOADED = False
GROUP = "erebus.sources"


def distinct_values(row_source: Any, collection: str, fields: list[str], limit: int) -> Iterator[tuple]:
    """Distinct tuples of ``fields`` in ``collection``, at most ``limit``.

    Uses the source's ``iter_distinct_values`` when it has one; otherwise reads only
    ``fields`` through ``iter_records`` and de-duplicates.
    """
    method = getattr(row_source, "iter_distinct_values", None)
    if method is not None:
        yield from method(collection, fields, limit)
        return
    seen: set[tuple] = set()
    for record in row_source.iter_records(collection, fields=fields):
        key = tuple(record.values.get(f) for f in fields)
        if key not in seen:
            seen.add(key)
            yield key
            if len(seen) >= limit:
                return


def distinct_groups(row_source: Any, collection: str, groups: list[list[str]], limit: int
                    ) -> Iterator[tuple[int, tuple]]:
    """``(index into groups, distinct tuple)`` for each field group of ``collection``, at
    most ``limit`` in total.

    Uses the source's ``iter_distinct_groups`` (one query per table) when it has one;
    otherwise reads each group through ``distinct_values`` with what is left of ``limit``.
    """
    method = getattr(row_source, "iter_distinct_groups", None)
    if method is not None:
        yield from method(collection, groups, limit)
        return
    left = limit
    for index, group in enumerate(groups):
        if left <= 0:
            return
        for row in distinct_values(row_source, collection, group, left):
            left -= 1
            yield index, row


def register_connector(connector: SourceConnector, replace: bool = True) -> None:
    cid = connector.connector_id()
    if not replace and cid in _CONNECTORS:
        raise ValueError(f"Connector already registered: {cid}")
    _CONNECTORS[cid] = connector


def load_connectors(*, strict: bool = False, eps: Iterable[Any] | None = None) -> None:
    """Register every ``erebus.sources`` entry point (once, unless ``eps`` is given).

    ``strict`` (the sync worker): a plugin that fails to load, or claims an id already
    registered, raises. Otherwise (the laptop) it is skipped.
    """
    global _ENTRYPOINTS_LOADED
    if eps is None:
        if _ENTRYPOINTS_LOADED:
            return
        _ENTRYPOINTS_LOADED = True
        try:
            eps = metadata.entry_points(group=GROUP)
        except Exception:
            if strict:
                raise
            return
    for ep in eps:
        try:
            obj = ep.load()
            register_connector(obj() if isinstance(obj, type) else obj, replace=False)
        except Exception:
            if strict:
                raise


def load_connector_from_import_path(path: str) -> SourceConnector:
    module_name, _, attr = path.partition(":")
    if not module_name or not attr:
        raise ValueError("Connector import path must look like module:object")
    module = importlib.import_module(module_name)
    obj = getattr(module, attr)
    return obj() if isinstance(obj, type) else obj


def ensure_builtin_connectors() -> None:
    if "sqlite" not in _CONNECTORS:
        from .connectors.sqlite import SQLiteConnector as _SQLite

        register_connector(_SQLite())


def __getattr__(name: str) -> Any:
    # SQLiteConnector and SQLiteRowSource moved to erebus.cataloging.connectors.sqlite.
    if name in ("SQLiteConnector", "SQLiteRowSource"):
        from .connectors import sqlite

        return getattr(sqlite, name)
    raise AttributeError(name)


def list_connectors() -> list[ConnectorMetadata]:
    ensure_builtin_connectors()
    load_connectors()
    return sorted(
        [connector.connector_metadata() for connector in _CONNECTORS.values()],
        key=lambda item: item.id,
    )


def get_connector(connector_id: str) -> SourceConnector | None:
    ensure_builtin_connectors()
    load_connectors()
    return _CONNECTORS.get(connector_id)


def connect_source(connector_id: str, settings: dict[str, Any],
                   secret_refs: dict[str, str]) -> RowSource:
    connector = get_connector(connector_id)
    if connector is None:
        available = ", ".join(item.id for item in list_connectors())
        raise ValueError(f"Unknown connector '{connector_id}'. Available: {available}")
    import os
    secrets = {key: os.environ.get(env_name, "") for key, env_name in secret_refs.items()}
    return connector.connect(settings, secrets)
