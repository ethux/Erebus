"""MySQL source connector (free; spec 015 "Security": read-only, network).

PyMySQL on its own socket: the connector opens the TCP connection to the ``hostaddr``
the worker checked and hands it to PyMySQL, which keeps ``host`` for TLS. ``sslmode``
defaults to ``verify-full`` against the system CAs; ``require`` and stronger refuse a
server without TLS before any credential is sent. ``local_infile`` and multi-statements
stay off. The session is read-only and every read runs in ``START TRANSACTION READ
ONLY`` with ``max_execution_time``; rows stream through unbuffered cursors. The
documented read-only user is the real guard. Every driver failure is a fixed-text
``ConnectorError`` raised ``from None``.
"""
from __future__ import annotations

import socket
import ssl
from collections.abc import Iterator
from typing import Any

from ..connector_errors import ConnectorError
from ..sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord
from . import _sql

_AUTH = frozenset({1045, 1251, 1698, 2059, 2061})
_PERMISSION = frozenset({1044, 1130, 1142, 1143, 1227, 1370, 1792})
_UNREACHABLE = frozenset({1040, 1049, 1129, 1203, 2002, 2003, 2005, 2006, 2013, 2026, 2055})
_LIST = ("SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES "
         "WHERE TABLE_TYPE IN ('BASE TABLE', 'VIEW') AND TABLE_SCHEMA NOT IN %s{only} ORDER BY 1, 2")
_FIELDS = ("SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY FROM information_schema.COLUMNS "
           "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION")


def _kind(exc: BaseException, *, connecting: bool) -> str:
    code = exc.args[0] if exc.args and isinstance(exc.args[0], int) else None
    if code in _AUTH:
        return "auth"
    if code in _PERMISSION:
        return "permission"
    if code in _UNREACHABLE or connecting:
        return "unreachable"
    return "query"


def _ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def _tls(sslmode: str) -> dict[str, Any]:
    """PyMySQL TLS arguments for a libpq-style ``sslmode``."""
    if sslmode == "disable":
        return {"ssl_disabled": True}
    if sslmode == "prefer":
        return {}  # PyMySQL's preferred mode: TLS when the server offers it
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if sslmode != "verify-full":
        ctx.check_hostname = False
    if sslmode == "require":
        ctx.verify_mode = ssl.CERT_NONE
    return {"ssl": ctx}  # an ssl context makes TLS required


class MySQLRowSource:
    """A read-only MySQL server; collections are ``schema.table``."""

    def __init__(self, conn: Any, schemas: list[str] | None) -> None:
        self.conn = conn
        self._schemas = schemas
        self._catalog = _sql.Catalog()
        self._open: Any = None

    def _cursor(self) -> Any:
        import pymysql

        if self._open is not None:  # an abandoned stream: drain it before the next read
            self._open.close()
            self._open = None
        self.conn.rollback()
        cur = self.conn.cursor(pymysql.cursors.SSCursor)
        cur.execute("START TRANSACTION READ ONLY")
        return cur

    def _fetch(self, query: str, params: Any) -> list[tuple]:
        import pymysql

        try:
            cur = self._cursor()
            try:
                cur.execute(query, params)
                rows = list(cur.fetchall())
            finally:
                cur.close()
            self.conn.rollback()
            return rows
        except pymysql.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None

    def list_collections(self) -> list[CollectionInfo]:
        system = tuple(sorted(_sql.SYSTEM_SCHEMAS["mysql"]))
        if self._schemas:
            rows = self._fetch(_LIST.format(only=" AND TABLE_SCHEMA IN %s"), (system, tuple(self._schemas)))
        else:
            rows = self._fetch(_LIST.format(only=""), (system,))
        return [CollectionInfo(name) for name in self._catalog.fill([(str(s), str(t)) for s, t in rows])]

    def list_fields(self, collection: str) -> list[FieldInfo]:
        if not self._catalog.known():
            self.list_collections()
        schema, table = self._catalog.get(collection)
        return [FieldInfo(str(name), db_type=str(db_type), nullable=nullable == "YES", primary_key=key == "PRI")
                for name, db_type, nullable, key in self._fetch(_FIELDS, (schema, table))]

    def _stream(self, query: str, page_size: int) -> Iterator[tuple]:
        import pymysql

        try:
            cur = self._cursor()
            self._open = cur
            cur.execute(query)
        except pymysql.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None
        try:
            while rows := cur.fetchmany(max(1, page_size)):
                yield from rows
        except pymysql.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None
        finally:
            self._open = None
            try:
                cur.close()
                self.conn.rollback()
            except pymysql.Error:
                pass

    def _table(self, collection: str, wanted: list[str] | None) -> tuple[str, list[str], str | None]:
        selected, pk = _sql.check_fields(self.list_fields(collection), wanted)
        schema, table = self._catalog.get(collection)
        return f"{_ident(schema)}.{_ident(table)}", selected, pk

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        table, selected, pk = self._table(collection, fields)
        columns = selected + ([pk] if pk and pk not in selected else [])
        query = f"SELECT {', '.join(map(_ident, columns))} FROM {table}"
        if limit is not None:
            query += f" LIMIT {max(0, int(limit))}"
        for count, row in enumerate(self._stream(query, page_size), 1):
            values = dict(zip(columns, row, strict=True))
            ref = values[pk] if pk else count
            yield SourceRecord(f"{collection}:{ref}", {f: values[f] for f in selected}, {})

    def iter_distinct_values(self, collection: str, fields: list[str], limit: int) -> Iterator[tuple]:
        """``SELECT DISTINCT`` of ``fields`` as utf8mb4 text compared byte for byte (the
        default collations would fold case and accents), all-NULL rows skipped."""
        table, selected, _pk = self._table(collection, fields)
        cols = ", ".join(f"CAST({_ident(f)} AS CHAR CHARACTER SET utf8mb4) COLLATE utf8mb4_bin" for f in selected)
        some = " OR ".join(f"{_ident(f)} IS NOT NULL" for f in selected)
        query = f"SELECT DISTINCT {cols} FROM {table} WHERE {some} LIMIT {max(0, int(limit))}"
        for row in self._stream(query, 2000):
            yield tuple(row)

    def close(self) -> None:
        self._open = None
        try:
            self.conn.close()
        except Exception:
            pass


class MySQLConnector:
    def connector_id(self) -> str:
        return "mysql"

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="mysql",
            name="MySQL",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records", "distinct_values"],
            settings_schema={"host": {"required": True}, "port": {}, "dbname": {}, "user": {"required": True},
                             "sslmode": {}, "schemas": {}, "collections": {}},
            secrets_schema={"password": {}},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        import pymysql

        addr = _sql.hostaddr(settings)
        port = int(settings.get("port") or 3306)
        if not settings.get("user"):
            raise ConnectorError("auth")
        conn = pymysql.connect(
            host=str(settings["host"]), port=port, user=str(settings["user"]), password=secrets.get("password") or "",
            database=str(settings["dbname"]) if settings.get("dbname") else None, charset="utf8mb4",
            connect_timeout=_sql.CONNECT_TIMEOUT_S, read_timeout=_sql.STATEMENT_TIMEOUT_S + 60,
            write_timeout=_sql.STATEMENT_TIMEOUT_S + 60, autocommit=False, local_infile=False, client_flag=0,
            defer_connect=True, **_tls(settings.get("sslmode") or "verify-full"),
        )
        try:
            sock = socket.create_connection((addr, port), timeout=_sql.CONNECT_TIMEOUT_S)
        except OSError:
            raise ConnectorError("unreachable") from None
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            conn.connect(sock)
            with conn.cursor() as cur:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
                cur.execute("SET SESSION max_execution_time = %s", (_sql.STATEMENT_TIMEOUT_S * 1000,))
                cur.execute("SET SESSION net_write_timeout = %s", (_sql.STATEMENT_TIMEOUT_S,))
        except (pymysql.Error, OSError) as exc:
            sock.close()
            raise ConnectorError(_kind(exc, connecting=True)) from None
        return MySQLRowSource(conn, _sql.schema_filter(settings))
