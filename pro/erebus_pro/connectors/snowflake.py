# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Snowflake source connector (Erebus Pro, feature ``connectors.snowflake``).

A ``TYPE=SERVICE`` user signs in with its key pair: the PEM key (optionally encrypted,
``private_key_passphrase``) is opened here and handed to the driver as DER bytes. The
driver derives the host from the account id (``orgname-account`` or a legacy locator),
so no setting names a host; the worker checks every address the driver connects to
against its deny list, and its allow list when one is set. The driver's probing of cloud
metadata addresses (to name its platform) is off. Fields come from the database's
``INFORMATION_SCHEMA.COLUMNS``, read once; collections are ``SCHEMA.TABLE``. Distinct
values are compared in the binary collation (``'utf8'``), so a column collated to ignore
case or accents keeps every spelling. Every
session is tagged ``erebus-sync`` with a statement timeout. Snowflake has no read-only
session: the documented read-only role is the guard, and the connector only ever sends
SELECTs. Resuming a suspended warehouse bills at least 60 seconds. Every driver failure
is a fixed-text ``ConnectorError`` raised ``from None``.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from typing import Any

from erebus.cataloging.connector_errors import ConnectorError
from erebus.cataloging.sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord

from . import _warehouse
from ._licensed import LicensedConnector

# orgname-account_name, or a legacy locator with its region and cloud (xy12345.eu-west-1.aws).
_ACCOUNT = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,253}[A-Za-z0-9])?(?:\.[A-Za-z0-9-]{1,64}){0,3}")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_$]{0,254}")
_COLUMNS = (
    "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, NUMERIC_PRECISION, NUMERIC_SCALE "
    "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA <> 'INFORMATION_SCHEMA' "
    "ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION"
)
# Snowflake answers "does not exist or not authorized" alike; for a listed object that is a privilege.
_PERMISSION_ERRNOS = frozenset({2003, 2043, 3001, 90105})


def _kind(exc: BaseException, *, connecting: bool) -> str:
    errno = getattr(exc, "errno", None) or 0
    state = getattr(exc, "sqlstate", None) or ""
    if 390000 <= errno < 391000 or 251000 <= errno < 252000 or state.startswith("28"):
        return "auth"
    if errno in _PERMISSION_ERRNOS or state == "42501":
        return "permission"
    if connecting or 250000 <= errno < 251000 or state.startswith("08"):
        return "unreachable"
    return "query"


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _db_type(data_type: str, precision: Any, scale: Any) -> str:
    if data_type == "NUMBER" and precision is not None and scale is not None:
        return f"NUMBER({precision},{scale})"
    return data_type


def _private_key(secrets: dict[str, str]) -> bytes:
    """The PEM key as unencrypted PKCS#8 DER; any problem is ``auth``."""
    from cryptography.hazmat.primitives import serialization

    pem = secrets.get("private_key")
    passphrase = secrets.get("private_key_passphrase")
    if not isinstance(pem, str) or not pem.strip():
        raise ConnectorError("auth") from None
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=passphrase.encode() if passphrase else None)
        return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    except Exception:  # a malformed key, a wrong passphrase, an unsupported algorithm
        raise ConnectorError("auth") from None


class SnowflakeRowSource:
    """A Snowflake database through a read-only role; collections are ``SCHEMA.TABLE``."""

    def __init__(self, conn: Any, schemas: list[str] | None) -> None:
        self.conn = conn
        self._schemas = schemas
        self._columns = _warehouse.Columns()

    def _execute(self, query: str, params: Any = None) -> Any:
        from snowflake.connector import errors

        try:
            cur = self.conn.cursor()
            cur.execute(query, params)
            return cur
        except errors.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None

    def _rows(self, query: str, page_size: int) -> Iterator[tuple]:
        from snowflake.connector import errors

        cur = self._execute(query)
        try:
            while rows := cur.fetchmany(max(1, page_size)):
                yield from rows
        except errors.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None
        finally:
            try:
                cur.close()
            except errors.Error:
                pass

    def _wanted(self, schema: str) -> bool:
        return self._schemas is None or any(schema in (s, s.upper()) for s in self._schemas)

    def list_collections(self) -> list[CollectionInfo]:
        rows = self._rows(_COLUMNS, 2000)
        names = self._columns.fill(
            (schema, table, FieldInfo(column, db_type=_db_type(dtype, prec, scale), nullable=nullable == "YES"))
            for schema, table, column, dtype, nullable, prec, scale in rows if self._wanted(schema))
        return [CollectionInfo(name) for name in names]

    def list_fields(self, collection: str) -> list[FieldInfo]:
        if not self._columns.known():
            self.list_collections()
        return list(self._columns.get(collection)[2])

    def _table(self, collection: str) -> tuple[str, list[FieldInfo]]:
        fields = self.list_fields(collection)
        schema, table, _ = self._columns.get(collection)
        return f"{_quote(schema)}.{_quote(table)}", fields

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        table, infos = self._table(collection)
        selected = _warehouse.check_fields(infos, fields)
        query = f"SELECT {', '.join(map(_quote, selected))} FROM {table}"
        if limit is not None:
            query += f" LIMIT {max(0, int(limit))}"
        for count, row in enumerate(self._rows(query, page_size), 1):
            yield SourceRecord(f"{collection}:{count}", dict(zip(selected, row, strict=True)), {})

    def iter_distinct_values(self, collection: str, fields: list[str], limit: int) -> Iterator[tuple]:
        """``SELECT DISTINCT`` of ``fields`` as text compared byte for byte (a column's
        collation may fold case and accents), all-NULL rows skipped, at most ``limit``."""
        table, infos = self._table(collection)
        selected = _warehouse.check_fields(infos, fields)
        cols = ", ".join(f"COLLATE({_quote(f)}::VARCHAR, 'utf8')" for f in selected)
        some = " OR ".join(f"{_quote(f)} IS NOT NULL" for f in selected)
        query = f"SELECT DISTINCT {cols} FROM {table} WHERE {some} LIMIT {max(0, int(limit))}"
        for row in self._rows(query, 2000):
            yield tuple(row)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


class SnowflakeConnector(LicensedConnector):
    type_id = "snowflake"

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="snowflake",
            name="Snowflake",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records", "distinct_values"],
            settings_schema={"account": {"required": True}, "user": {"required": True},
                             "database": {"required": True}, "warehouse": {"required": True}, "role": {},
                             "schemas": {}, "collections": {}},
            secrets_schema={"private_key": {"required": True}, "private_key_passphrase": {}},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        self.require_license()
        params: dict[str, Any] = {
            "account": _warehouse.setting(settings, "account", _ACCOUNT, required=True),
            "user": _warehouse.setting(settings, "user", required=True),
            "database": _warehouse.setting(settings, "database", _IDENTIFIER, required=True),
            # Without a warehouse every query fails (errno 606); a user's default may not be set.
            "warehouse": _warehouse.setting(settings, "warehouse", _IDENTIFIER, required=True),
        }
        role = _warehouse.setting(settings, "role", _IDENTIFIER)
        if role is not None:
            params["role"] = role
        schemas = _warehouse.schema_filter(settings)
        params.update(
            authenticator="SNOWFLAKE_JWT", private_key=_private_key(secrets),
            login_timeout=_warehouse.LOGIN_TIMEOUT_S, client_session_keep_alive=False,
            # No probing of cloud metadata addresses to name the platform: the worker refuses them.
            platform_detection_timeout_seconds=0.0,
            session_parameters={"QUERY_TAG": _warehouse.QUERY_TAG,
                                "STATEMENT_TIMEOUT_IN_SECONDS": _warehouse.STATEMENT_TIMEOUT_S},
        )
        # The driver logs connection details at info level; the worker log keeps none of it.
        logging.getLogger("snowflake.connector").setLevel(logging.WARNING)
        import snowflake.connector
        from snowflake.connector import errors

        try:
            conn = snowflake.connector.connect(**params)
        except errors.Error as exc:
            raise ConnectorError(_kind(exc, connecting=True)) from None
        except OSError:
            raise ConnectorError("unreachable") from None
        return SnowflakeRowSource(conn, schemas)
