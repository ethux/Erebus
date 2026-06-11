"""Trusted local source connector contract and registry.

Connectors normalize databases and external APIs into collections, fields, and
records. Erebus owns scanning and catalog decisions after that normalization.
"""
from __future__ import annotations

import importlib
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any, Protocol


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
    name: str
    label: str = ""
    kind_hint: str = ""
    pii_hint: str = ""


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


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _kind_hint(name: str) -> tuple[str, str]:
    lower = name.lower()
    if "email" in lower:
        return "email", "email"
    if "phone" in lower or "mobile" in lower:
        return "phone", "phone"
    if lower in ("first_name", "last_name", "name", "full_name") or lower.endswith("_name"):
        return "text", "person"
    if "address" in lower or "street" in lower or "city" in lower or "zip" in lower:
        return "text", "address"
    if "account" in lower or lower.endswith("_id") or lower == "id":
        return "identifier", "identifier"
    return "text", ""


class SQLiteRowSource:
    """Read-only SQLite source normalized into RowSource records."""

    def __init__(self, path: str):
        self.path = Path(path)
        uri = f"file:{self.path}?mode=ro"
        self.conn = sqlite3.connect(uri, uri=True)
        self.conn.row_factory = sqlite3.Row

    def list_collections(self) -> list[CollectionInfo]:
        rows = self.conn.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
        return [CollectionInfo(row["name"]) for row in rows]

    def list_fields(self, collection: str) -> list[FieldInfo]:
        rows = self.conn.execute(f"PRAGMA table_info({_quote_identifier(collection)})").fetchall()
        fields = []
        for row in rows:
            kind, pii = _kind_hint(row["name"])
            fields.append(FieldInfo(row["name"], kind_hint=kind, pii_hint=pii))
        return fields

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        available = {field.name for field in self.list_fields(collection)}
        selected = fields or sorted(available)
        missing = [field for field in selected if field not in available]
        if missing:
            raise ValueError(f"Unknown field(s) for {collection}: {', '.join(missing)}")
        select_sql = ", ".join(_quote_identifier(field) for field in selected)
        pk = "id" if "id" in available else None
        if pk and pk not in selected:
            select_sql = f"{_quote_identifier(pk)}, {select_sql}"
        sql = f"SELECT {select_sql} FROM {_quote_identifier(collection)}"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        cur = self.conn.execute(sql)
        count = 0
        for row in cur:
            count += 1  # noqa: SIM113
            record_ref = str(row[pk]) if pk and pk in row.keys() else str(count)  # noqa: SIM118
            values = {field: row[field] for field in selected}
            yield SourceRecord(f"{collection}:{record_ref}", values, {})

    def close(self) -> None:
        self.conn.close()


class SQLiteConnector:
    def connector_id(self) -> str:
        return "sqlite"

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="sqlite",
            name="SQLite",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records"],
            settings_schema={"path": {"required": True}},
            secrets_schema={},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        path = settings.get("path") or settings.get("location_ref")
        if not path:
            raise ValueError("SQLite connector requires a path")
        return SQLiteRowSource(str(path))


def register_connector(connector: SourceConnector, replace: bool = True) -> None:
    cid = connector.connector_id()
    if not replace and cid in _CONNECTORS:
        raise ValueError(f"Connector already registered: {cid}")
    _CONNECTORS[cid] = connector


def _load_entrypoints() -> None:
    global _ENTRYPOINTS_LOADED
    if _ENTRYPOINTS_LOADED:
        return
    _ENTRYPOINTS_LOADED = True
    try:
        eps = metadata.entry_points()
        group = eps.select(group="erebus.sources") if hasattr(eps, "select") else eps.get("erebus.sources", [])
    except Exception:
        return
    for ep in group:
        try:
            obj = ep.load()
            connector = obj() if isinstance(obj, type) else obj
            register_connector(connector, replace=False)
        except Exception:
            continue


def load_connector_from_import_path(path: str) -> SourceConnector:
    module_name, _, attr = path.partition(":")
    if not module_name or not attr:
        raise ValueError("Connector import path must look like module:object")
    module = importlib.import_module(module_name)
    obj = getattr(module, attr)
    return obj() if isinstance(obj, type) else obj


def ensure_builtin_connectors() -> None:
    if "sqlite" not in _CONNECTORS:
        register_connector(SQLiteConnector())


def list_connectors() -> list[ConnectorMetadata]:
    ensure_builtin_connectors()
    _load_entrypoints()
    return sorted(
        [connector.connector_metadata() for connector in _CONNECTORS.values()],
        key=lambda item: item.id,
    )


def get_connector(connector_id: str) -> SourceConnector | None:
    ensure_builtin_connectors()
    _load_entrypoints()
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
