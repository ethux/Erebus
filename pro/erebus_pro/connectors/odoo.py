# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Odoo source connector (Erebus Pro, feature ``connectors.odoo``).

Reads contacts and companies (``res.partner``) and leads (``crm.lead``) as an
integration user with an API key. Odoo 19 and later answer the JSON-2 API
(``POST /json/2/<model>/<method>``, the key as a bearer token, ``X-Odoo-Database`` when
a database is set); older versions XML-RPC ``execute_kw`` with database, login and key
(deprecated, removed in Odoo 22). ``api`` picks one, else ``GET /web/version`` decides.
Only ``fields_get`` and ``search_read`` are ever called (plus ``authenticate`` on
XML-RPC): nothing is written. Contacts are always listed and leads unless ``ir.model``
says CRM is not installed; any other error while listing or reading fields is raised,
so a failing call never passes as a missing collection (whose values a sync would then
retire).

Fields come from ``fields_get``: the known contact fields of each model (with a hint for
the field rules) and custom ``x_`` text fields, whichever exist for the user. On
``res.partner`` a company's name is read as the ``company`` field (ORGANIZATION) and a
person's as ``name``. Archived records are read too (``active_test`` off): an archived
contact still holds a real name. A full read pages by id; the cursor is the newest
``write_date`` when it started. A change read starts ``OVERLAP`` before the cursor and
pages by ``write_date, id``, so a transaction that committed late is read again. Odoo
reports no deletions: a full sync retires a deleted record's values.

Odoo Online (``*.odoo.com``) allows about one call per second and no parallel calls,
so calls there are paced; a 429 slows down, then reschedules the job. The integration
user's API key expiry (non-admin keys last at most three months) is reported when the
user has exactly one key. Every failure is a fixed-text ``ConnectorError``.
"""
from __future__ import annotations

import re
import xmlrpc.client
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from xml.parsers.expat import ExpatError

from erebus.cataloging.connector_errors import ConnectorError, CursorExpired
from erebus.cataloging.sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord

from . import _warehouse
from .http import AppHttp, HttpAppConnector, LimitRules, app_url, is_host, keyset_pages, overlap_since

PAGE = 500
OVERLAP = timedelta(minutes=10)
ONLINE_INTERVAL_S = 1.0
_STAMP = "%Y-%m-%d %H:%M:%S"
_CURSOR = re.compile(r"wd:(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")
_EPOCH = "1970-01-01 00:00:00"
_TEXT = frozenset({"char", "text"})
_READS = frozenset({"fields_get", "search_read"})
_ACTIVE_OFF = {"active_test": False}
# Odoo's XML-RPC fault codes: 3 access denied (bad login or key), 4 access error.
_FAULT_KIND = {3: "auth", 4: "permission"}
# The models read, each field the connector knows with its hint for the field rules.
OBJECTS: dict[str, tuple[str, dict[str, str]]] = {
    "res.partner": ("Contacts and companies", {
        "name": "person", "company": "organization", "company_name": "organization", "email": "email",
        "phone": "phone", "mobile": "mobile", "street": "address", "street2": "address", "vat": "identifier",
        "ref": "identifier"}),
    "crm.lead": ("Leads", {
        "contact_name": "person", "partner_name": "organization", "email_from": "email", "phone": "phone",
        "mobile": "mobile", "street": "address", "street2": "address"}),
}
# res.partner's derived fields: ``name`` holds a person's name, ``company`` a company's.
_SPLIT_NAME = {"name": False, "company": True}


class OdooLimits(LimitRules):
    """Odoo Online answers 429 when calls come too fast and may name no wait: back off from 5 s."""

    backoff_s = 5.0


class _Json2:
    """The JSON-2 API: named arguments, the key as a bearer token."""

    def __init__(self, http: AppHttp, key: str, database: str | None) -> None:
        self._http = http
        self._headers = {"Authorization": f"bearer {key}"}
        if database:
            self._headers["X-Odoo-Database"] = database

    def open(self) -> None:
        pass  # the key is checked on the first call

    def call(self, model: str, method: str, **kwargs: Any) -> Any:
        if method not in _READS:
            raise ConnectorError("query") from None
        response = self._http.request("POST", f"/json/2/{model}/{method}", json=kwargs, headers=self._headers)
        try:
            return response.json()
        except ValueError:
            raise ConnectorError("query") from None


class _XmlRpc:
    """XML-RPC ``execute_kw`` with database, user id and key; named arguments only."""

    def __init__(self, http: AppHttp, key: str, database: str, login: str) -> None:
        self._http = http
        self._key = key
        self._database = database
        self._login = login
        self._uid: int | None = None

    def _rpc(self, path: str, method: str, params: tuple) -> Any:
        body = xmlrpc.client.dumps(params, methodname=method)
        response = self._http.request("POST", path, content=body.encode("utf-8"),
                                      headers={"Content-Type": "text/xml"})
        try:
            return xmlrpc.client.loads(response.content)[0][0]
        except xmlrpc.client.Fault as fault:
            raise ConnectorError(_FAULT_KIND.get(fault.faultCode, "query")) from None
        except (ExpatError, IndexError, ValueError):
            raise ConnectorError("query") from None

    def open(self) -> None:
        uid = self._rpc("/xmlrpc/2/common", "authenticate", (self._database, self._login, self._key, {}))
        if type(uid) is not int:
            raise ConnectorError("auth") from None
        self._uid = uid

    def call(self, model: str, method: str, **kwargs: Any) -> Any:
        if method not in _READS:
            raise ConnectorError("query") from None
        return self._rpc("/xmlrpc/2/object", "execute_kw",
                         (self._database, self._uid, self._key, model, method, [], kwargs))


def _value(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _parse_stamp(value: str) -> datetime:
    return datetime.strptime(value, _STAMP).replace(tzinfo=UTC)


class OdooSource:
    """An Odoo database as collections of records; see the module docstring."""

    def __init__(self, rpc: Any, http: AppHttp) -> None:
        self._rpc = rpc
        self._http = http
        self._fields: dict[str, list[FieldInfo]] = {}
        self._positions: dict[str, str] = {}

    def list_collections(self) -> list[CollectionInfo]:
        """Contacts always; leads unless ir.model says CRM is not installed."""
        return [CollectionInfo(model, label) for model, (label, _hints) in OBJECTS.items()
                if model == "res.partner" or self._installed(model)]

    def _installed(self, model: str) -> bool:
        """Whether ir.model lists ``model``; a user who may not read ir.model gets ``True``
        (the model's own read then decides). Any other error is raised."""
        try:
            rows = self._rpc.call("ir.model", "search_read", domain=[("model", "=", model)], fields=["model"])
        except ConnectorError as exc:
            if exc.kind == "permission":
                return True
            raise
        if not isinstance(rows, list):
            raise ConnectorError("query") from None
        return any(isinstance(r, dict) and r.get("model") == model for r in rows)

    def list_fields(self, collection: str) -> list[FieldInfo]:
        if collection not in OBJECTS:
            raise ConnectorError("query") from None
        if collection not in self._fields:
            self._fields[collection] = self._discover(collection)
        return list(self._fields[collection])

    def _discover(self, model: str) -> list[FieldInfo]:
        described = self._rpc.call(model, "fields_get", attributes=["type", "string", "store"])
        if not isinstance(described, dict):
            raise ConnectorError("query") from None
        hints = OBJECTS[model][1]

        def text(name: str) -> bool:
            info = described.get(name)
            return isinstance(info, dict) and info.get("type") in _TEXT and info.get("store", True) is not False

        out = []
        for name, hint in hints.items():
            if name in _SPLIT_NAME and model == "res.partner":
                if text("name") and "is_company" in described:
                    label = "Company name" if _SPLIT_NAME[name] else str(described["name"].get("string", "Name"))
                    out.append(FieldInfo(name, label=label, db_type="char", pii_hint=hint))
            elif text(name):
                out.append(FieldInfo(name, label=str(described[name].get("string", name)),
                                     db_type=described[name]["type"], pii_hint=hint))
        for name in sorted(described):
            if name.startswith("x_") and text(name):
                out.append(FieldInfo(name, label=str(described[name].get("string", name)),
                                     db_type=described[name]["type"]))
        return out

    def _odoo_fields(self, collection: str, fields: list[str] | None) -> tuple[list[str], list[str]]:
        """(the fields to report, the Odoo fields to ask for)."""
        known = [f.name for f in self.list_fields(collection)]
        wanted = list(fields) if fields else known
        if any(f not in known for f in wanted):
            raise ConnectorError("query") from None
        asked = set(wanted)
        if collection == "res.partner" and asked & set(_SPLIT_NAME):
            asked = (asked - set(_SPLIT_NAME)) | {"name", "is_company"}
        return wanted, sorted(asked)

    def _record(self, collection: str, row: dict, wanted: list[str]) -> SourceRecord:
        values: dict[str, Any] = {}
        for name in wanted:
            if collection == "res.partner" and name in _SPLIT_NAME:
                values[name] = _value(row.get("name")) if bool(row.get("is_company")) == _SPLIT_NAME[name] else None
            else:
                values[name] = _value(row.get(name))
        return SourceRecord(str(row["id"]), values)

    def _search(self, collection: str, domain: list, fields: list[str], limit: int, order: str) -> list[dict]:
        rows = self._rpc.call(collection, "search_read", domain=domain, fields=fields, limit=limit, order=order,
                              context=_ACTIVE_OFF)
        if not isinstance(rows, list) or not all(isinstance(r, dict) and type(r.get("id")) is int for r in rows):
            raise ConnectorError("query") from None
        return rows

    def _head(self, collection: str) -> str:
        """The cursor for "now": the newest write_date of the collection."""
        rows = self._search(collection, [], ["write_date"], 1, "write_date desc, id desc")
        stamp = rows[0].get("write_date") if rows else None
        return "wd:" + (stamp if isinstance(stamp, str) and _CURSOR.fullmatch("wd:" + stamp) else _EPOCH)

    def iter_records(self, collection: str, fields: list[str] | None = None, limit: int | None = None,
                     page_size: int = PAGE) -> Iterator[SourceRecord]:
        """Every record (archived ones too), paged by id; at most ``limit``."""
        wanted, asked = self._odoo_fields(collection, fields)
        if limit is None:
            self._positions[collection] = self._head(collection)
        read = 0

        def fetch(after: int | None, count: int) -> list[dict]:
            nonlocal read
            count = count if limit is None else min(count, limit - read)
            if count <= 0:
                return []  # Odoo reads "limit 0" as no limit
            rows = self._search(collection, [] if after is None else [("id", ">", after)], asked, count, "id asc")
            read += len(rows)
            return rows

        for row in keyset_pages(fetch, lambda r: r["id"], max(1, min(page_size, PAGE))):
            yield self._record(collection, row, wanted)

    def iter_changes(self, collection: str, fields: list[str], cursor: str) -> Iterator[SourceRecord]:
        """Records written since ``cursor`` minus ``OVERLAP``, by ``write_date, id``."""
        match = _CURSOR.fullmatch(cursor) if isinstance(cursor, str) else None
        if match is None:
            raise CursorExpired()
        since = match.group(1)
        start = overlap_since(_parse_stamp(since), OVERLAP).strftime(_STAMP)
        wanted, asked = self._odoo_fields(collection, fields)
        asked = sorted(set(asked) | {"write_date"})
        newest = since

        def fetch(after: tuple[str, int] | None, count: int) -> list[dict]:
            domain: list = [("write_date", ">=", start)]
            if after is not None:
                domain = ["|", ("write_date", ">", after[0]), "&", ("write_date", "=", after[0]),
                          ("id", ">", after[1])]
            return self._search(collection, domain, asked, count, "write_date asc, id asc")

        for row in keyset_pages(fetch, lambda r: (r.get("write_date"), r["id"]), PAGE):
            stamp = row.get("write_date")
            if not isinstance(stamp, str) or not _CURSOR.fullmatch("wd:" + stamp):
                raise ConnectorError("query") from None
            newest = max(newest, stamp)
            yield self._record(collection, row, wanted)
        self._positions[collection] = "wd:" + newest

    def cursor(self, collection: str) -> str | None:
        return self._positions.get(collection)

    def credentials_expire_at(self) -> datetime | None:
        """When the integration user's API key expires, if it has exactly one with an expiry."""
        try:
            keys = self._rpc.call("res.users.apikeys", "search_read", domain=[], fields=["expiration_date"])
        except ConnectorError as exc:
            if exc.kind in ("auth", "limit", "unreachable"):
                raise
            return None  # an Odoo without key expiry, or keys the user may not read
        if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
            return None
        stamp = keys[0].get("expiration_date")
        try:
            return _parse_stamp(stamp) if isinstance(stamp, str) else None
        except ValueError:
            return None

    def close(self) -> None:
        self._http.close()


class OdooConnector(HttpAppConnector):
    type_id = "odoo"

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="odoo",
            name="Odoo",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records", "changes_since"],
            settings_schema={"url": {"required": True}, "database": {}, "login": {}, "api": {}, "collections": {}},
            secrets_schema={"api_key": {"required": True}},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        self.require_license()
        url = app_url(settings.get("url"))
        api = _warehouse.setting(settings, "api")
        database = _warehouse.setting(settings, "database")
        login = _warehouse.setting(settings, "login")
        if api not in (None, "json2", "xmlrpc") or (api == "xmlrpc" and not (database and login)):
            raise ConnectorError("settings") from None
        key = secrets.get("api_key")
        if not isinstance(key, str) or not key.strip():
            raise ConnectorError("auth") from None
        http = self.open_http(url, limits=OdooLimits(),
                              min_interval=ONLINE_INTERVAL_S if is_host(url, "odoo.com") else 0.0)
        try:
            api = api or _detect(http)
            if api == "xmlrpc" and not (database and login):
                raise ConnectorError("settings") from None
            rpc = _Json2(http, key.strip(), database) if api == "json2" else _XmlRpc(http, key.strip(), database,
                                                                                     login)
            rpc.open()
        except BaseException:
            http.close()
            raise
        return OdooSource(rpc, http)


def _detect(http: AppHttp) -> str:
    """``json2`` when ``/web/version`` names Odoo 19 or later, else ``xmlrpc``."""
    response = http.request("GET", "/web/version", accept=frozenset({404}))
    if response.status_code == 404:
        return "xmlrpc"
    try:
        major = response.json()["version_info"][0]
    except (ValueError, KeyError, IndexError, TypeError):
        return "xmlrpc"
    return "json2" if type(major) is int and major >= 19 else "xmlrpc"
