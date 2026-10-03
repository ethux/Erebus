# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""MSSQL / Azure SQL source connector (Erebus Pro, feature ``connectors.mssql``).

The driver follows ``auth``: ``sql`` (the default) signs in a SQL login (``user`` and a
password) through pymssql, which ships in the image; ``entra`` signs in an Entra service
principal (``client_id`` and its ``client_secret``) through Microsoft's mssql-python, an
optional extra (``erebus-pro[mssql-entra]``) the image does not ship. See
``_mssql_drivers`` for how each is set up.

Like the free database connectors it dials the ``hostaddr`` the sync worker checked
against its host lists, never a name it resolves itself, and keeps ``host`` for TLS.
``sslmode`` defaults to ``verify-full``: TLS required, the certificate verified against
the system CAs (``SSL_CERT_FILE`` adds a private CA) and its name matched against
``host`` before the password is sent. ``verify-ca`` skips the name, ``require`` the
certificate; ``disable`` asks for no TLS (SQL Server still encrypts the login packet
when it can). There is no ``prefer``. An Entra source takes only ``verify-full`` or
``require``: the ODBC driver checks both chain and name, or neither. Azure SQL's
``Redirect`` connection policy hands the client another node's address after sign-in,
which the ODBC driver follows; the ``Proxy`` policy keeps the session on the address the
worker checked.

Fields come from ``INFORMATION_SCHEMA.COLUMNS`` of ``database``, without the system and
fixed-role schemas; collections are ``schema.table``. SQL Server has no read-only
session: the login asks for read-only intent (``ApplicationIntent=ReadOnly``, which only
routes to a readable secondary where there is one), the connector sends single SELECTs
only, and the documented read-only login is the real guard. The distinct values of all
asked field groups of a table come from one query, compared in a binary collation so
case and accent variants stay apart; ``text``, ``ntext`` and ``(n)varchar(max)`` values
are read as ``nvarchar(4000)`` and longer ones skipped. Every driver failure is a
fixed-text ``ConnectorError`` raised ``from None``.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterator
from typing import Any

from erebus.cataloging.connector_errors import ConnectorError
from erebus.cataloging.sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord

from . import _mssql_drivers as drivers
from . import _warehouse
from ._licensed import LicensedConnector

_DATABASE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.$#@ -]{0,127}")
_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.$#@-]{0,127}")
_CLIENT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_AUTH = re.compile(r"sql|entra")
_SSL_MODES = frozenset({"verify-full", "verify-ca", "require", "disable"})
_ENTRA_SSL_MODES = frozenset({"verify-full", "require"})
_TEXT_CHARS = 4000
_SYSTEM_SCHEMAS = ("sys", "INFORMATION_SCHEMA", "guest", "db_owner", "db_accessadmin", "db_securityadmin",
                   "db_ddladmin", "db_backupoperator", "db_datareader", "db_datawriter", "db_denydatareader",
                   "db_denydatawriter")
_COLUMNS = ("SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH "
            "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA NOT IN ({}) "
            "ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION").format(", ".join(f"'{s}'" for s in _SYSTEM_SCHEMAS))
_KEYS = ("SELECT k.TABLE_SCHEMA, k.TABLE_NAME, k.COLUMN_NAME FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS t "
         "JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE k ON k.CONSTRAINT_SCHEMA = t.CONSTRAINT_SCHEMA "
         "AND k.CONSTRAINT_NAME = t.CONSTRAINT_NAME WHERE t.CONSTRAINT_TYPE = 'PRIMARY KEY'")
_DATETIME = frozenset({"date", "time", "datetime", "datetime2", "smalldatetime", "datetimeoffset"})
_NATIONAL = frozenset({"nchar", "nvarchar", "ntext"})
_SIZED = frozenset({"char", "varchar", "nchar", "nvarchar", "binary", "varbinary"})
_COLLATION = "Latin1_General_100_BIN2"


def _quote(identifier: str) -> str:
    return "[" + identifier.replace("]", "]]") + "]"


def _db_type(data_type: str, length: Any) -> str:
    """``nvarchar(200)``, ``varchar(max)``, ``ntext``: the length is kept for sized types."""
    if data_type in _SIZED and isinstance(length, int):
        return f"{data_type}({'max' if length == -1 else length})"
    return data_type


def _long(db_type: str) -> bool:
    """A text type that may hold more than 4,000 characters."""
    base, _, size = db_type.partition("(")
    size = size.rstrip(")")
    return base in ("text", "ntext") or (base in ("char", "varchar", "nchar", "nvarchar")
                                         and (size == "max" or (size.isdigit() and int(size) > _TEXT_CHARS)))


def _as_text(name: str, info: FieldInfo) -> str:
    q, base = _quote(name), info.db_type.partition("(")[0]
    if base in _DATETIME:
        return f"CONVERT(NVARCHAR({_TEXT_CHARS}), {q}, 126)"  # ISO 8601
    return f"CAST({q} AS NVARCHAR({_TEXT_CHARS}))"


def _short_enough(name: str, info: FieldInfo) -> str | None:
    """A guard skipping values longer than 4,000 characters, for a long text type."""
    if not _long(info.db_type):
        return None
    base = info.db_type.partition("(")[0]
    return f"DATALENGTH({_quote(name)}) <= {_TEXT_CHARS * (2 if base in _NATIONAL else 1)}"


def _hostaddr(settings: dict[str, Any]) -> str:
    """The address the worker checked; the connector dials exactly this."""
    try:
        return str(ipaddress.ip_address(settings.get("hostaddr")))
    except ValueError:
        raise ValueError("the sync worker must supply a checked hostaddr") from None


def _params(settings: dict[str, Any]) -> dict[str, Any]:
    """The connection parameters; ``settings`` errors first."""
    host = _warehouse.setting(settings, "host", required=True).lower()
    port = settings.get("port", 1433)
    sslmode = settings.get("sslmode") or "verify-full"
    if type(port) is not int or not 0 < port < 65536 or sslmode not in _SSL_MODES:
        raise ConnectorError("settings") from None
    database = _warehouse.setting(settings, "database", _DATABASE, required=True)
    auth = _warehouse.setting(settings, "auth", _AUTH) or "sql"
    params = {"host": host, "port": port, "sslmode": sslmode, "database": database, "auth": auth}
    if auth == "sql":
        params["user"] = _warehouse.setting(settings, "user", _USER, required=True)
    else:
        params["client_id"] = _warehouse.setting(settings, "client_id", _CLIENT_ID, required=True)
        if sslmode not in _ENTRA_SSL_MODES:
            raise ConnectorError("settings") from None
    params["hostaddr"] = _hostaddr(settings)
    return params


class MssqlRowSource:
    """One SQL Server database; collections are ``schema.table``."""

    def __init__(self, conn: Any, schemas: list[str] | None, errors: type[BaseException],
                 kind: Callable[..., str]) -> None:
        self.conn = conn
        self._schemas = {s.lower() for s in schemas} if schemas else None
        self._errors = errors
        self._kind = kind
        self._columns = _warehouse.Columns()

    def _rows(self, query: str, page_size: int) -> Iterator[tuple]:
        try:
            cur = self.conn.cursor()
            cur.execute(query)
        except self._errors as exc:
            raise ConnectorError(self._kind(exc, connecting=False)) from None
        try:
            while rows := cur.fetchmany(max(1, page_size)):
                yield from rows
        except self._errors as exc:
            raise ConnectorError(self._kind(exc, connecting=False)) from None
        finally:
            try:
                cur.close()
            except Exception:
                pass

    def list_collections(self) -> list[CollectionInfo]:
        keys = {tuple(row) for row in self._rows(_KEYS, 2000)}
        names = self._columns.fill(
            (schema, table, FieldInfo(column, db_type=_db_type(dtype, length), nullable=nullable == "YES",
                                      primary_key=(schema, table, column) in keys))
            for schema, table, column, dtype, nullable, length in self._rows(_COLUMNS, 2000)
            if self._schemas is None or schema.lower() in self._schemas)
        return [CollectionInfo(name) for name in names]

    def list_fields(self, collection: str) -> list[FieldInfo]:
        if not self._columns.known():
            self.list_collections()
        return list(self._columns.get(collection)[2])

    def _table(self, collection: str) -> tuple[str, dict[str, FieldInfo]]:
        fields = self.list_fields(collection)
        schema, table, _ = self._columns.get(collection)
        return f"{_quote(schema)}.{_quote(table)}", {f.name: f for f in fields}

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        table, infos = self._table(collection)
        selected = _warehouse.check_fields(list(infos.values()), fields)
        pks = [n for n, f in infos.items() if f.primary_key]
        pk = pks[0] if len(pks) == 1 else None
        columns = selected + ([pk] if pk and pk not in selected else [])
        exprs = [f"CAST(SUBSTRING({_quote(n)}, 1, {_TEXT_CHARS}) AS NVARCHAR({_TEXT_CHARS}))"
                 if _long(infos[n].db_type) else _quote(n) for n in columns]
        top = f"TOP ({max(0, int(limit))}) " if limit is not None else ""
        for count, row in enumerate(self._rows(f"SELECT {top}{', '.join(exprs)} FROM {table}", page_size), 1):
            values = dict(zip(columns, tuple(row), strict=True))
            ref = values[pk] if pk else count
            yield SourceRecord(f"{collection}:{ref}", {f: values[f] for f in selected}, {})

    def iter_distinct_groups(self, collection: str, groups: list[list[str]], limit: int
                             ) -> Iterator[tuple[int, tuple]]:
        """``(group index, distinct tuple as text)`` for every group, from one query."""
        table, infos = self._table(collection)
        groups = _warehouse.check_groups(list(infos.values()), groups)
        width = max(len(g) for g in groups)
        branches = []
        for index, group in enumerate(groups):
            inner = ", ".join(f"{_as_text(f, infos[f])} COLLATE {_COLLATION} AS _c{k}" for k, f in enumerate(group))
            some = " OR ".join(f"{_quote(f)} IS NOT NULL" for f in group)
            guards = [g for f in group if (g := _short_enough(f, infos[f]))]
            where = " AND ".join([f"({some})", *guards])
            values = ", ".join(f"_c{k} AS v{k}" if k < len(group) else f"CAST(NULL AS NVARCHAR({_TEXT_CHARS})) AS v{k}"
                               for k in range(width))
            branches.append(f"SELECT {index} AS g, {values} FROM (SELECT DISTINCT {inner} FROM {table} "
                            f"WHERE {where}) AS t{index}")
        query = f"SELECT TOP ({max(0, int(limit))}) * FROM ({' UNION ALL '.join(branches)}) AS u"
        for row in self._rows(query, 2000):
            index = row[0]
            yield index, tuple(row[1:1 + len(groups[index])])

    def iter_distinct_values(self, collection: str, fields: list[str], limit: int) -> Iterator[tuple]:
        for _index, row in self.iter_distinct_groups(collection, [fields], limit):
            yield row

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


class MssqlConnector(LicensedConnector):
    type_id = "mssql"

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="mssql",
            name="MSSQL / Azure SQL",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records", "distinct_values", "distinct_groups"],
            settings_schema={"host": {"required": True}, "port": {}, "database": {"required": True}, "user": {},
                             "client_id": {}, "sslmode": {}, "auth": {}, "schemas": {}, "collections": {}},
            secrets_schema={"password": {}, "client_secret": {}},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        self.require_license()
        params = _params(settings)
        schemas = _warehouse.schema_filter(settings)
        secret = secrets.get("password" if params["auth"] == "sql" else "client_secret")
        if not isinstance(secret, str) or not secret:
            raise ConnectorError("auth") from None
        if params["auth"] == "entra":
            driver = drivers.entra_driver()
            errors, kind = driver.Error, drivers.entra_kind
        else:
            import pymssql
            driver, errors, kind = None, pymssql.Error, drivers.pymssql_kind
        try:
            conn = (drivers.connect_entra(driver, params, secret) if driver is not None
                    else drivers.connect_pymssql(params, secret))
        except errors as exc:
            raise ConnectorError(kind(exc, connecting=True)) from None
        except OSError:
            raise ConnectorError("unreachable") from None
        return MssqlRowSource(conn, schemas, errors, kind)
