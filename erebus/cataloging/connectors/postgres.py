"""Postgres source connector (free; spec 015 "Security": read-only, network).

Dials the ``hostaddr`` the worker checked, with ``host`` kept for TLS: ``sslmode``
defaults to ``verify-full`` against the system CAs. No passfile, client certificate or
GSS credential of the worker is ever offered. Every session is read-only twice over
(``default_transaction_read_only`` and ``conn.read_only``) with a statement timeout;
rows stream through server-side cursors. The documented read-only role is the real
guard. Every driver failure is a fixed-text ``ConnectorError`` raised ``from None``.
"""
from __future__ import annotations

import itertools
import os
import re
from collections.abc import Iterator
from typing import Any

from ..connector_errors import ConnectorError
from ..sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord
from . import _sql

_VERIFYING = ("verify-ca", "verify-full")
_AUTH = re.compile(r"FATAL:\s+(role \".*\" does not exist|password authentication failed|no pg_hba\.conf entry"
                   r"|.*authentication failed)|authentication method requirement|no password supplied", re.S)
_PERMISSION = re.compile(r"FATAL:\s+permission denied", re.S)
_LIST = """
SELECT n.nspname, c.relname FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm') AND NOT c.relispartition
  AND n.nspname <> ALL(%(system)s) AND n.nspname NOT LIKE 'pg\\_%%'
  AND (%(schemas)s::text[] IS NULL OR n.nspname = ANY(%(schemas)s::text[]))
  AND has_table_privilege(c.oid, 'SELECT')
ORDER BY 1, 2
"""
_FIELDS = """
SELECT a.attname, format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
       COALESCE(a.attnum = ANY(i.indkey), false)
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_index i ON i.indrelid = c.oid AND i.indisprimary
WHERE n.nspname = %s AND c.relname = %s AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum
"""


def _kind(exc: BaseException, *, connecting: bool) -> str:
    state = getattr(exc, "sqlstate", None) or ""
    if state.startswith("28"):
        return "auth"
    if state in ("42501", "25006"):
        return "permission"
    if state.startswith(("08", "57P")) or state == "3D000":
        return "unreachable"
    if connecting and not state:
        text = str(exc)
        if _AUTH.search(text):
            return "auth"
        if _PERMISSION.search(text):
            return "permission"
        return "unreachable"
    return "query"


class PostgresRowSource:
    """A read-only Postgres database; collections are ``schema.table``."""

    def __init__(self, conn: Any, schemas: list[str] | None) -> None:
        self.conn = conn
        self._schemas = schemas
        self._catalog = _sql.Catalog()
        self._cursors = itertools.count(1)

    def _fresh(self) -> None:
        # A new read-only transaction per operation: no long snapshot, and an aborted one is cleared.
        from psycopg import pq

        if self.conn.info.transaction_status != pq.TransactionStatus.IDLE:
            self.conn.rollback()

    def _fetch(self, query: str, params: Any) -> list[tuple]:
        import psycopg

        try:
            self._fresh()
            rows = self.conn.execute(query, params).fetchall()
            self.conn.rollback()
            return rows
        except psycopg.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None

    def list_collections(self) -> list[CollectionInfo]:
        rows = self._fetch(_LIST, {"system": list(_sql.SYSTEM_SCHEMAS["postgres"]), "schemas": self._schemas})
        return [CollectionInfo(name) for name in self._catalog.fill(rows)]

    def list_fields(self, collection: str) -> list[FieldInfo]:
        if not self._catalog.known():
            self.list_collections()
        schema, table = self._catalog.get(collection)
        return [FieldInfo(name, db_type=db_type, nullable=bool(nullable), primary_key=bool(pk))
                for name, db_type, nullable, pk in self._fetch(_FIELDS, (schema, table))]

    def _stream(self, query: Any, params: Any, page_size: int) -> Iterator[tuple]:
        import psycopg

        try:
            self._fresh()
            cur = self.conn.cursor(name=f"erebus_sync_{next(self._cursors)}")
        except psycopg.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None
        try:
            cur.itersize = max(1, page_size)
            cur.execute(query, params)
            yield from cur
        except psycopg.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None
        finally:
            try:
                cur.close()
                self.conn.rollback()
            except psycopg.Error:
                pass

    def _table(self, collection: str, wanted: list[str] | None) -> tuple[Any, list[str], str | None]:
        from psycopg import sql

        fields = self.list_fields(collection)
        selected, pk = _sql.check_fields(fields, wanted)
        return sql.Identifier(*self._catalog.get(collection)), selected, pk

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        from psycopg import sql

        table, selected, pk = self._table(collection, fields)
        columns = selected + ([pk] if pk and pk not in selected else [])
        query = sql.SQL("SELECT {} FROM {}").format(sql.SQL(", ").join(map(sql.Identifier, columns)), table)
        if limit is not None:
            query = sql.SQL("{} LIMIT {}").format(query, sql.Literal(int(limit)))
        for count, row in enumerate(self._stream(query, None, page_size), 1):
            values = dict(zip(columns, row, strict=True))
            ref = values[pk] if pk else count
            yield SourceRecord(f"{collection}:{ref}", {f: values[f] for f in selected}, {})

    def iter_distinct_values(self, collection: str, fields: list[str], limit: int) -> Iterator[tuple]:
        """``SELECT DISTINCT`` of ``fields`` as text compared byte for byte (a nondeterministic
        collation would fold case and accents), all-NULL rows skipped, at most ``limit``."""
        from psycopg import sql

        table, selected, _pk = self._table(collection, fields)
        cols = [sql.SQL('({}::text) COLLATE "C"').format(sql.Identifier(f)) for f in selected]
        some = sql.SQL(" OR ").join(sql.SQL("{} IS NOT NULL").format(sql.Identifier(f)) for f in selected)
        query = sql.SQL("SELECT DISTINCT {} FROM {} WHERE {} LIMIT {}").format(
            sql.SQL(", ").join(cols), table, some, sql.Literal(max(0, int(limit))))
        for row in self._stream(query, None, 2000):
            yield tuple(row)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


class PostgresConnector:
    def connector_id(self) -> str:
        return "postgres"

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="postgres",
            name="PostgreSQL",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records", "distinct_values"],
            settings_schema={"host": {"required": True}, "port": {}, "dbname": {}, "user": {}, "sslmode": {},
                             "schemas": {}, "collections": {}},
            secrets_schema={"password": {}},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        import psycopg

        sslmode = settings.get("sslmode") or "verify-full"
        timeout_ms = _sql.STATEMENT_TIMEOUT_S * 1000
        params: dict[str, Any] = {
            "host": str(settings["host"]), "hostaddr": _sql.hostaddr(settings),
            "port": int(settings.get("port") or 5432),
            "sslmode": sslmode, "connect_timeout": _sql.CONNECT_TIMEOUT_S, "application_name": "erebus-sync",
            # Never offer the worker's own credentials: its passfile, client cert or Kerberos ticket.
            "passfile": os.devnull, "sslcertmode": "disable", "gssencmode": "disable", "require_auth": "!gss,!sspi",
            "options": f"-c default_transaction_read_only=on -c statement_timeout={timeout_ms} "
                       f"-c idle_in_transaction_session_timeout={timeout_ms}",
        }
        if sslmode in _VERIFYING:
            params["sslrootcert"] = "system"
        for key in ("dbname", "user"):
            if settings.get(key):
                params[key] = str(settings[key])
        if secrets.get("password"):
            params["password"] = secrets["password"]
        try:
            conn = psycopg.connect(**params)
        except psycopg.Error as exc:
            raise ConnectorError(_kind(exc, connecting=True)) from None
        try:
            conn.read_only = True
        except psycopg.Error:
            conn.close()
            raise ConnectorError("unreachable") from None
        return PostgresRowSource(conn, _sql.schema_filter(settings))
