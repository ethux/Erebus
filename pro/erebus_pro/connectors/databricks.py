# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Databricks source connector (Erebus Pro, feature ``connectors.databricks``).

A service principal signs in by OAuth machine-to-machine through databricks-sdk: its
client-credentials token source asks the workspace's own token endpoint
(``https://<workspace>/oidc/v1/token``, scope ``all-apis``; basic auth, no redirects, a
timeout) and the SQL driver gets only a credentials provider that adds the access token
to its requests, never the secret. ``server_hostname`` must be a workspace on one of
Databricks' own domains and ``http_path`` a SQL warehouse's, so no setting can point the
worker at another host. As for the other vendor-hosted warehouses, the worker checks
every address the driver connects to against its deny list, and its allow list when one
is set. Results are not fetched from cloud storage and the driver sends no telemetry,
so the worker talks to the workspace host only.

Collections are ``schema.table`` in the ``catalog`` setting; fields come from the
catalog's Unity Catalog ``information_schema.columns``. A sync wakes the SQL warehouse
(Pro and classic warehouses bill at least ten minutes), so the distinct values of all
asked field groups of a table come from one query: a ``UNION ALL`` of per-group
``SELECT DISTINCT``, tagged by group, name parts as extra columns, every value read as
text in the binary collation (``UTF8_BINARY``). Sessions are tagged
``erebus-sync`` and every statement times out. Databricks has no read-only session: the
documented grants are the guard, and the connector only sends single SELECTs. Every
failure is a fixed-text ``ConnectorError`` raised ``from None``.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta
from functools import cache
from typing import Any

from erebus.cataloging.connector_errors import ConnectorError
from erebus.cataloging.sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord

from . import _warehouse
from ._licensed import LicensedConnector

_DOMAINS = ("cloud.databricks.com", "cloud.databricks.us", "gcp.databricks.com", "azuredatabricks.net",
            "databricks.azure.us", "databricks.azure.cn")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# One or two labels before a Databricks domain: dbc-…cloud.databricks.com, adb-….7.azuredatabricks.net.
_HOST = re.compile(rf"(?:{_LABEL}\.){{1,2}}(?:{'|'.join(map(re.escape, _DOMAINS))})")
_HTTP_PATH = re.compile(r"/sql/1\.0/(?:warehouses|endpoints)/[0-9a-f]{16}")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,254}")
_CLIENT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_TOKEN_TIMEOUT_S = 30
_BINARY = "COLLATE UTF8_BINARY"  # Databricks SQL and Runtime 16.1+, which every SQL warehouse runs
_COLUMNS = ("SELECT table_schema, table_name, column_name, data_type, is_nullable FROM {}.information_schema.columns "
            "WHERE table_schema <> 'information_schema' ORDER BY table_schema, table_name, ordinal_position")
# Unity Catalog reports an object the principal may not use as not found.
_PERMISSION_MARKS = ("INSUFFICIENT_PERMISSIONS", "PERMISSION_DENIED", "_NOT_FOUND]", "SQLSTATE: 42501")


class _TokenRefused(Exception):
    """A token request failed; ``kind`` classes it. Fixed text: never the response."""

    def __init__(self, kind: str) -> None:
        super().__init__("token request failed")
        self.kind = kind


@cache
def _token_class() -> type:
    """databricks-sdk's client-credentials source, asking with a timeout and no redirects."""
    from databricks.sdk import oauth

    class Tokens(oauth.ClientCredentials):
        post: Callable[..., Any] | None = None
        failure: str | None = None  # why the last refresh failed, for errors the driver wraps

        def refresh(self) -> oauth.Token:
            try:
                resp = self.post(self.token_url, data={"grant_type": "client_credentials", "scope": self.scopes},
                                 auth=(self.client_id, self.client_secret), timeout=_TOKEN_TIMEOUT_S,
                                 allow_redirects=False)
            except Exception:  # unreachable, a TLS failure, a timeout
                raise self._refused("unreachable") from None
            if resp.status_code == 429:
                raise self._refused("limit")
            if 400 <= resp.status_code < 500:
                raise self._refused("auth")
            if not resp.ok:
                raise self._refused("unreachable")
            try:
                body = resp.json()
                token = oauth.Token(access_token=str(body["access_token"]),
                                    token_type=str(body.get("token_type") or "Bearer"),
                                    expiry=datetime.now() + timedelta(seconds=int(body["expires_in"])))
            except Exception:  # not the token response the protocol promises
                raise self._refused("auth") from None
            self.failure = None
            return token

        def _refused(self, kind: str) -> _TokenRefused:
            self.failure = kind
            return _TokenRefused(kind)

    return Tokens


def _tokens(host: str, client_id: str, secret: str, post: Callable[..., Any]) -> Any:
    tokens = _token_class()(client_id=client_id, client_secret=secret, token_url=f"https://{host}/oidc/v1/token",
                            scopes="all-apis")
    tokens.post = post
    return tokens


def _provider(tokens: Any) -> Callable[[], Callable[[], dict[str, str]]]:
    """The driver's credentials provider: a factory of request headers."""
    def provider() -> Callable[[], dict[str, str]]:
        def headers() -> dict[str, str]:
            token = tokens.token()
            return {"Authorization": f"{token.token_type} {token.access_token}"}
        return headers
    return provider


def _refusal(exc: BaseException) -> _TokenRefused | None:
    """A refused token request anywhere in the chain of ``exc`` (the driver wraps it)."""
    seen = 0
    while exc is not None and seen < 10:
        if isinstance(exc, _TokenRefused):
            return exc
        context = getattr(exc, "context", None)
        inner = context.get("original-exception") if isinstance(context, dict) else None
        exc = inner if isinstance(inner, BaseException) else (exc.__cause__ or exc.__context__)
        seen += 1
    return None


def _kind(exc: BaseException, tokens: Any, *, connecting: bool) -> str:
    refused = _refusal(exc)
    if refused is not None:
        return refused.kind
    if tokens.failure:
        return tokens.failure
    context = getattr(exc, "context", None)
    code = context.get("http-code") if isinstance(context, dict) else None
    if code == 429:
        return "limit"
    if code == 401:
        return "auth"
    if code == 403:
        return "permission"
    message = str(getattr(exc, "message", None) or "")  # read to class the error, never shown
    if any(mark in message for mark in _PERMISSION_MARKS):
        return "permission"
    from databricks.sql import exc as dbx
    if connecting or isinstance(exc, (dbx.RequestError, OSError)):
        return "unreachable"
    return "query"


def _quote(identifier: str) -> str:
    return "`" + identifier.replace("`", "``") + "`"


def _host(settings: dict[str, Any]) -> str:
    host = _warehouse.setting(settings, "server_hostname", required=True).lower()
    if not _HOST.fullmatch(host):
        raise ConnectorError("settings") from None
    return host


class DatabricksRowSource:
    """A Unity Catalog catalog through a SQL warehouse; collections are ``schema.table``."""

    def __init__(self, conn: Any, catalog: str, schemas: list[str] | None, tokens: Any) -> None:
        self.conn = conn
        self._catalog = catalog
        self._schemas = {s.lower() for s in schemas} if schemas else None
        self._tokens = tokens
        self._columns = _warehouse.Columns()

    def _rows(self, query: str, page_size: int) -> Iterator[tuple]:
        try:
            cur = self.conn.cursor()
            cur.execute(query)
        except Exception as exc:
            raise ConnectorError(_kind(exc, self._tokens, connecting=False)) from None
        try:
            while rows := cur.fetchmany(max(1, page_size)):
                yield from rows
        except Exception as exc:
            raise ConnectorError(_kind(exc, self._tokens, connecting=False)) from None
        finally:
            try:
                cur.close()
            except Exception:
                pass

    def list_collections(self) -> list[CollectionInfo]:
        rows = self._rows(_COLUMNS.format(_quote(self._catalog)), 2000)
        names = self._columns.fill(
            (schema, table, FieldInfo(column, db_type=dtype, nullable=nullable == "YES"))
            for schema, table, column, dtype, nullable in rows
            if self._schemas is None or schema.lower() in self._schemas)
        return [CollectionInfo(name) for name in names]

    def list_fields(self, collection: str) -> list[FieldInfo]:
        if not self._columns.known():
            self.list_collections()
        return list(self._columns.get(collection)[2])

    def _table(self, collection: str) -> tuple[str, list[FieldInfo]]:
        fields = self.list_fields(collection)
        schema, table, _ = self._columns.get(collection)
        return f"{_quote(self._catalog)}.{_quote(schema)}.{_quote(table)}", fields

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
            yield SourceRecord(f"{collection}:{count}", dict(zip(selected, tuple(row), strict=True)), {})

    def iter_distinct_groups(self, collection: str, groups: list[list[str]], limit: int
                             ) -> Iterator[tuple[int, tuple]]:
        """``(group index, distinct tuple as text)`` for every group, from one query. Values
        are compared as text in the binary collation, so a column whose collation ignores
        case or accents keeps every spelling."""
        table, infos = self._table(collection)
        groups = _warehouse.check_groups(infos, groups)
        width = max(len(g) for g in groups)
        branches = []
        for index, group in enumerate(groups):
            inner = ", ".join(f"CAST({_quote(f)} AS STRING) {_BINARY} AS _c{k}" for k, f in enumerate(group))
            some = " OR ".join(f"{_quote(f)} IS NOT NULL" for f in group)
            values = ", ".join(f"_c{k} AS v{k}" if k < len(group) else f"CAST(NULL AS STRING) {_BINARY} AS v{k}"
                               for k in range(width))
            branches.append(f"SELECT {index} AS g, {values} FROM (SELECT DISTINCT {inner} FROM {table} "
                            f"WHERE {some}) AS t{index}")
        query = f"SELECT * FROM ({' UNION ALL '.join(branches)}) AS u LIMIT {max(0, int(limit))}"
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


class DatabricksConnector(LicensedConnector):
    type_id = "databricks"

    def __init__(self, entitlements: Any = None, *, sql_connect: Callable[..., Any] | None = None,
                 token_post: Callable[..., Any] | None = None) -> None:
        super().__init__(entitlements)
        self._sql_connect = sql_connect
        self._token_post = token_post

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="databricks",
            name="Databricks",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records", "distinct_values", "distinct_groups"],
            settings_schema={"server_hostname": {"required": True}, "http_path": {"required": True},
                             "catalog": {"required": True}, "client_id": {"required": True}, "schemas": {},
                             "collections": {}},
            secrets_schema={"client_secret": {"required": True}},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        self.require_license()
        host = _host(settings)
        http_path = _warehouse.setting(settings, "http_path", _HTTP_PATH, required=True)
        catalog = _warehouse.setting(settings, "catalog", _IDENTIFIER, required=True)
        client_id = _warehouse.setting(settings, "client_id", _CLIENT_ID, required=True)
        schemas = _warehouse.schema_filter(settings)
        secret = secrets.get("client_secret")
        if not isinstance(secret, str) or not secret:
            raise ConnectorError("auth") from None
        post = self._token_post
        if post is None:
            import requests
            post = requests.post
        tokens = _tokens(host, client_id, secret, post)
        try:
            tokens.token()  # sign in before the driver opens a session
        except _TokenRefused as exc:
            raise ConnectorError(exc.kind) from None
        # The driver logs hosts and request details below warning level; the worker log keeps none.
        logging.getLogger("databricks").setLevel(logging.WARNING)
        connect = self._sql_connect
        if connect is None:
            from databricks import sql
            connect = sql.connect
        try:
            conn = connect(server_hostname=host, http_path=http_path, credentials_provider=_provider(tokens),
                           catalog=catalog, user_agent_entry=_warehouse.QUERY_TAG, query_tags={"erebus": "sync"},
                           session_configuration={"STATEMENT_TIMEOUT": str(_warehouse.STATEMENT_TIMEOUT_S)},
                           enable_telemetry=False, use_cloud_fetch=False)
        except Exception as exc:
            raise ConnectorError(_kind(exc, tokens, connecting=True)) from None
        return DatabricksRowSource(conn, catalog, schemas, tokens)
