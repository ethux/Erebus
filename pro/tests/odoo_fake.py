# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""A hand-written Odoo behind ``respx`` for the Odoo connector tests (not a test module).

``FakeOdoo(version)`` answers what the connector may send: ``GET /web/version`` (19 and
up; 404 before), ``POST /xmlrpc/2/common`` (``authenticate``), ``POST /xmlrpc/2/object``
(``execute_kw``) and ``POST /json/2/<model>/<method>`` (19 and up). It evaluates the
domains the connector builds (``|``, ``&``, ``!`` and leaves with ``=``, ``!=``, ``<``,
``<=``, ``>``, ``>=``), hides archived records unless ``active_test`` is false, and
keeps every request so a test can check the connector only reads. ``queue`` holds
responses (a 429, say) to send before the next real answer. Made-up data only.
"""
from __future__ import annotations

import json
import re
import xmlrpc.client
from datetime import datetime, timedelta

import httpx

BASE = "https://acme-zq.odoo.com"
DB = "acme-zq"
LOGIN = "erebus-sync"
KEY = "zq" * 20  # a made-up key
UID = 7
_OPS = {"=": lambda a, b: a == b, "!=": lambda a, b: a != b, "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}


def partner_fields(version: int) -> dict:
    fields = {"id": "integer", "name": "char", "is_company": "boolean", "email": "char", "phone": "char",
              "street": "char", "street2": "char", "city": "char", "company_name": "char", "vat": "char",
              "ref": "char", "comment": "html", "active": "boolean", "write_date": "datetime",
              "x_customer_code": "char"}
    if version < 19:
        fields["mobile"] = "char"
    return {k: {"type": v, "string": k.replace("_", " ").title(), "store": True} for k, v in fields.items()}


def lead_fields(version: int) -> dict:
    fields = {"id": "integer", "name": "char", "contact_name": "char", "partner_name": "char", "email_from": "char",
              "phone": "char", "street": "char", "active": "boolean", "write_date": "datetime"}
    if version < 19:
        fields["mobile"] = "char"
    return {k: {"type": v, "string": k.replace("_", " ").title(), "store": True} for k, v in fields.items()}


def _match(domain: list, record: dict) -> bool:
    def walk(i: int) -> tuple[bool, int]:
        term = domain[i]
        if term in ("|", "&"):
            left, j = walk(i + 1)
            right, k = walk(j)
            return (left or right) if term == "|" else (left and right), k
        if term == "!":
            value, j = walk(i + 1)
            return not value, j
        field, op, value = term
        return _OPS[op](record.get(field), value), i + 1

    ok, i = True, 0
    while i < len(domain):
        value, i = walk(i)
        ok = ok and value
    return ok


class FakeOdoo:
    def __init__(self, version: int = 19, *, base: str = BASE) -> None:
        self.version = version
        self.base = base
        self.models = {"res.partner": partner_fields(version), "crm.lead": lead_fields(version)}
        self.records: dict[str, dict[int, dict]] = {"res.partner": {}, "crm.lead": {}}
        self.next_id = 100
        self.clock = 0
        self.requests: list[tuple[str, str, str]] = []  # (method, path, rpc method or "")
        self.queue: list[httpx.Response] = []
        self.key_expiry: list[str | bool] = ["2026-12-31 00:00:00"]
        self.denied_models: set[str] = set()

    # -- data ------------------------------------------------------------------------
    def stamp(self) -> str:
        """The next write_date: one second after the last, unless ``advance`` moved the clock."""
        self.clock += 1
        return (datetime(2026, 10, 4, 8) + timedelta(seconds=self.clock)).strftime("%Y-%m-%d %H:%M:%S")

    def advance(self, seconds: int) -> None:
        self.clock += seconds

    def add(self, model: str, **values) -> int:
        self.next_id += 1
        record = {k: False for k in self.models[model] if k not in ("id", "active", "write_date")}
        record.update({"id": self.next_id, "active": True, "write_date": self.stamp(), **values})
        self.records[model][self.next_id] = record
        return self.next_id

    def write(self, model: str, record_id: int, **values) -> None:
        self.records[model][record_id].update(values, write_date=self.stamp())

    def unlink(self, model: str, record_id: int) -> None:
        del self.records[model][record_id]

    # -- ORM ---------------------------------------------------------------------------
    def _search_read(self, model, domain=(), fields=None, limit=None, order=None, context=None, offset=0):
        rows = [r for r in self.records[model].values() if _match(list(domain), r)]
        if (context or {}).get("active_test", True):
            rows = [r for r in rows if r.get("active", True)]
        keys = [(p.split()[0], p.split()[-1].lower() == "desc") for p in (order or "id").split(",")]
        for field, desc in reversed(keys):
            rows.sort(key=lambda r, f=field: r[f], reverse=desc)
        rows = rows[offset:offset + limit if limit else None]
        wanted = fields or list(self.models[model])
        return [{"id": r["id"], **{f: r.get(f, False) for f in wanted if f != "id"}} for r in rows]

    def _call(self, model: str, method: str, kwargs: dict):
        if model == "res.users.apikeys" and method == "search_read":
            return [{"id": i + 1, "expiration_date": e} for i, e in enumerate(self.key_expiry)]
        if model not in self.models:
            raise LookupError(model)
        if model in self.denied_models:
            raise PermissionError(model)
        if method == "fields_get":
            attrs = kwargs.get("attributes") or ["type", "string", "store"]
            return {f: {a: d[a] for a in attrs if a in d} for f, d in self.models[model].items()}
        if method == "search_read":
            return self._search_read(model, **kwargs)
        raise AssertionError(f"unexpected method {method}")

    # -- HTTP ----------------------------------------------------------------------------
    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if self.queue:
            self.requests.append((request.method, path, "queued"))
            return self.queue.pop(0)
        if request.method == "GET" and path == "/web/version":
            self.requests.append(("GET", path, ""))
            if self.version < 19:
                return httpx.Response(404, text="<html>not found</html>")
            return httpx.Response(200, json={"version_info": [self.version, 0, 0, "final", 0, ""],
                                             "version": f"{self.version}.0"})
        if path.startswith("/json/2/"):
            return self._json2(request, path)
        if path in ("/xmlrpc/2/common", "/xmlrpc/2/object"):
            return self._xmlrpc(request, path)
        self.requests.append((request.method, path, ""))
        return httpx.Response(404)

    def _json2(self, request, path):
        _, _, _, model, method = path.split("/", 4)
        self.requests.append(("POST", path, method))
        if self.version < 19:
            return httpx.Response(404)
        if request.headers.get("authorization") != f"bearer {KEY}":
            return httpx.Response(401, json={"name": "werkzeug.exceptions.Unauthorized", "message": "Invalid apikey"})
        try:
            return httpx.Response(200, json=self._call(model, method, json.loads(request.content or b"{}")))
        except LookupError:
            return httpx.Response(404, json={"name": "werkzeug.exceptions.NotFound", "message": "no model"})
        except PermissionError:
            return httpx.Response(403, json={"name": "odoo.exceptions.AccessError", "message": "Zyx Qorbel"})

    def _xmlrpc(self, request, path):
        params, method = xmlrpc.client.loads(request.content)
        tag = method if path.endswith("common") else f"execute_kw:{params[4]}:{params[3]}"
        self.requests.append(("POST", path, tag))

        def fault(code, text):
            return httpx.Response(200, content=xmlrpc.client.dumps(xmlrpc.client.Fault(code, text),
                                                                   methodresponse=True))
        if path.endswith("common"):
            if method != "authenticate":
                return fault(1, "unexpected")
            db, login, key, _env = params
            uid = UID if (db, login, key) == (DB, LOGIN, KEY) else False
            return httpx.Response(200, content=xmlrpc.client.dumps((uid,), methodresponse=True))
        db, uid, key, model, rpc_method, args, kwargs = params
        if (db, uid, key) != (DB, UID, KEY):
            return fault(3, "Access Denied")
        if args:
            return fault(1, "positional arguments are not expected")
        try:
            result = self._call(model, rpc_method, kwargs)
        except LookupError:
            return fault(1, "Object no.such doesn't exist")
        except PermissionError:
            return fault(4, "odoo.exceptions.AccessError: Zyx Qorbel")
        return httpx.Response(200, content=xmlrpc.client.dumps((result,), methodresponse=True, allow_none=True))


def read_only(requests: list[tuple[str, str, str]]) -> bool:
    """Whether every request is one the connector may send (method and path, RPC method)."""
    models = r"(res\.partner|crm\.lead|res\.users\.apikeys)"
    allowed_json2 = re.compile(rf"/json/2/{models}/(fields_get|search_read)")
    allowed_xmlrpc = re.compile(rf"execute_kw:(fields_get|search_read):{models}")
    for method, path, rpc in requests:
        if rpc == "queued":
            continue
        if (method, path) == ("GET", "/web/version") and not rpc:
            continue
        if method == "POST" and path == "/xmlrpc/2/common" and rpc == "authenticate":
            continue
        if method == "POST" and path == "/xmlrpc/2/object" and allowed_xmlrpc.fullmatch(rpc):
            continue
        if method == "POST" and allowed_json2.fullmatch(path):
            continue
        return False
    return True
