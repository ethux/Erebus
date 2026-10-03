"""SQLite source connector: the laptop's built-in, and a free sync-worker type.

Opens the file read-only (``mode=ro`` plus ``query_only``) with ``trusted_schema`` off,
so a crafted file's views and triggers cannot call SQL functions. The worker hands it a
path already confined to ``EREBUS_SYNC_SQLITE_DIR`` (``erebus.sync.netpolicy``); the
laptop hands it its own configured file. Every sqlite3 failure is a fixed-text
``ConnectorError``.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ..connector_errors import ConnectorError
from ..sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _kind_hint(name: str) -> tuple[str, str]:
    """(kind, pii) hints from a column name: the laptop scan's input; the gateway ignores them."""
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
        try:
            self.conn = sqlite3.connect(f"file:{quote(str(self.path))}?mode=ro", uri=True)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA query_only = ON")
            self.conn.execute("PRAGMA trusted_schema = OFF")
            self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()  # not a database: fail here
        except sqlite3.Error:
            raise ConnectorError("unreachable") from None

    def _query(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        try:
            return self.conn.execute(sql, params)
        except sqlite3.Error:
            raise ConnectorError("query") from None

    def list_collections(self) -> list[CollectionInfo]:
        rows = self._query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return [CollectionInfo(row["name"]) for row in rows]

    def _table(self, collection: str) -> list[sqlite3.Row]:
        if collection not in {c.name for c in self.list_collections()}:
            raise ConnectorError("query")
        return self._query(f"PRAGMA table_info({_quote_identifier(collection)})").fetchall()

    def list_fields(self, collection: str) -> list[FieldInfo]:
        fields = []
        for row in self._table(collection):
            kind, pii = _kind_hint(row["name"])
            fields.append(FieldInfo(row["name"], kind_hint=kind, pii_hint=pii, db_type=str(row["type"] or ""),
                                    nullable=not row["notnull"] and not row["pk"], primary_key=row["pk"] > 0))
        return fields

    def _columns(self, collection: str, fields: list[str]) -> set[str]:
        available = {row["name"] for row in self._table(collection)}
        if not fields or any(f not in available for f in fields):
            raise ConnectorError("query")
        return available

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        available = {row["name"] for row in self._table(collection)}
        selected = fields or sorted(available)
        self._columns(collection, selected)
        select_sql = ", ".join(_quote_identifier(field) for field in selected)
        pk = "id" if "id" in available else None
        if pk and pk not in selected:
            select_sql = f"{_quote_identifier(pk)}, {select_sql}"
        sql = f"SELECT {select_sql} FROM {_quote_identifier(collection)}"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        cur = self._query(sql)
        count = 0
        while True:
            try:
                row = cur.fetchone()
            except sqlite3.Error:
                raise ConnectorError("query") from None
            if row is None:
                return
            count += 1
            record_ref = str(row[pk]) if pk else str(count)
            yield SourceRecord(f"{collection}:{record_ref}", {field: row[field] for field in selected}, {})

    def iter_distinct_values(self, collection: str, fields: list[str], limit: int) -> Iterator[tuple]:
        """Distinct tuples of ``fields`` (in that order), rows all NULL skipped, at most ``limit``."""
        self._columns(collection, fields)
        cols = ", ".join(_quote_identifier(f) for f in fields)
        not_all_null = " OR ".join(f"{_quote_identifier(f)} IS NOT NULL" for f in fields)
        cur = self._query(f"SELECT DISTINCT {cols} FROM {_quote_identifier(collection)} WHERE {not_all_null} "
                          f"LIMIT {int(limit)}")
        while True:
            try:
                row = cur.fetchone()
            except sqlite3.Error:
                raise ConnectorError("query") from None
            if row is None:
                return
            yield tuple(row)

    def close(self) -> None:
        self.conn.close()


class SQLiteConnector:
    def connector_id(self) -> str:
        return "sqlite"

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="sqlite",
            name="SQLite",
            version="1.1",
            capabilities=["list_collections", "list_fields", "page_records", "distinct_values"],
            settings_schema={"path": {"required": True}},
            secrets_schema={},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        path = settings.get("path") or settings.get("location_ref")
        if not path:
            raise ValueError("SQLite connector requires a path")
        return SQLiteRowSource(str(path))
