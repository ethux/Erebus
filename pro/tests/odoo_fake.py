# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""A hand-written Odoo behind ``respx`` for the Odoo connector tests (not a test module).

``FakeOdoo(version)`` answers what the connector may send: ``GET /web/version`` (19 and
up; 404 before), ``POST /xmlrpc/2/common`` (``authenticate``), ``POST /xmlrpc/2/object``
(``execute_kw``) and ``POST /json/2/<model>/<method>`` (19 and up). It evaluates the
domains the connector builds (``|``, ``&``, ``!`` and leaves with ``=``, ``!=``, ``<``,
``<=``, ``>``, ``>=``, ``in``), hides archived records unless ``active_test`` is false,
and keeps every request so a test can check the connector only reads.

``write_date`` behaves as in Odoo: stored with microseconds, the timestamp of the
transaction that wrote the record (every write in ``with fake.transaction():`` shares
one), returned cut to whole seconds, compared as a datetime, NULL for some base records
(first in a descending order). ``queue`` holds responses (a 429, say) to send before the
next real answer; ``fail[(model, method)] = n`` makes the next ``n`` such calls fail as
an internal server error. Made-up data only.
"""
from __future__ import annotations

import contextlib
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
STAMP = "%Y-%m-%d %H:%M:%S"
_ORDERED = {"<": lambda a, b: a < b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}


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


def _leaf(record: dict, field: str, op: str, value) -> bool:
    actual = record.get(field)
    if field == "write_date" and isinstance(value, str):
        value = datetime.strptime(value, STAMP)  # Odoo compares the stored datetime
    if value is False and field == "write_date":
        value = None
    if op == "in":
        return actual in value
    if op in ("=", "!="):
        return (actual == value) == (op == "=")
    if actual is None or value is None:
        return False  # SQL: a comparison with NULL is not true
    return _ORDERED[op](actual, value)


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
        return _leaf(record, *term), i + 1

    ok, i = True, 0
    while i < len(domain):
        value, i = walk(i)
        ok = ok and value
    return ok


def _out(field: str, value):
    if field == "write_date":
        return value.strftime(STAMP) if value is not None else False
    return value


class FakeOdoo:
    def __init__(self, version: int = 19, *, base: str = BASE) -> None:
        self.version = version
        self.version_info: list | None = None  # what /web/version reports, when set
        self.base = base
        self.models = {"res.partner": partner_fields(version), "crm.lead": lead_fields(version)}
        self.installed = {"res.partner", "crm.lead", "res.users.apikeys", "ir.model"}
        self.records: dict[str, dict[int, dict]] = {"res.partner": {}, "crm.lead": {}}
        self.next_id = 100
        self.now = datetime(2026, 10, 4, 8, 0, 0, 123456)
        self._tx: datetime | None = None
        self.requests: list[tuple[str, str, str]] = []  # (method, path, rpc method or "")
        self.queue: list[httpx.Response] = []
        self.fail: dict[tuple[str, str], int] = {}
        self.key_expiry: list[str | bool] = ["2026-12-31 00:00:00"]
        self.denied_models: set[str] = set()

    # -- data ------------------------------------------------------------------------
    def stamp(self) -> datetime:
        """The write_date of the next write: the open transaction's timestamp, or a new
        transaction 0.35 s after the last (so several share one second)."""
        if self._tx is not None:
            return self._tx
        self.now += timedelta(microseconds=350_000)
        return self.now

    @contextlib.contextmanager
    def transaction(self):
        """Writes inside share one write_date, as one Odoo transaction (an import) does."""
        self._tx = self.stamp()
        try:
            yield
        finally:
            self._tx = None

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)

    def newest(self, model: str) -> str:
        """The newest write_date of ``model`` as the API returns it."""
        return max(r["write_date"] for r in self.records[model].values() if r["write_date"]).strftime(STAMP)

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
            # Postgres: NULLs last ascending, first descending.
            rows.sort(key=lambda r, f=field: (r[f] is None, r[f] if r[f] is not None else 0), reverse=desc)
        rows = rows[offset:offset + limit if limit else None]
        wanted = fields or list(self.models[model])
        return [{"id": r["id"], **{f: _out(f, r.get(f, False)) for f in wanted if f != "id"}} for r in rows]

    def _call(self, model: str, method: str, kwargs: dict):
        if self.fail.get((model, method)):
            self.fail[(model, method)] -= 1
            raise RuntimeError("internal server error")
        if model in self.denied_models:
            raise PermissionError(model)
        if model == "res.users.apikeys" and method == "search_read":
            return [{"id": i + 1, "expiration_date": e} for i, e in enumerate(self.key_expiry)]
        if model == "ir.model" and method == "search_read":
            rows = [{"id": i + 1, "model": m} for i, m in enumerate(sorted(self.installed))]
            return [r for r in rows if _match(list(kwargs.get("domain") or []), r)]
        if model not in self.models or model not in self.installed:
            raise LookupError(model)
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
            if self.version_info is not None:
                return httpx.Response(200, json={"version_info": self.version_info, "version": "x"})
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
        except RuntimeError:
            return httpx.Response(500, json={"name": "psycopg2.OperationalError", "message": "Zyx Qorbel"})

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
        except RuntimeError:
            return fault(1, "psycopg2.OperationalError: Zyx Qorbel")
        return httpx.Response(200, content=xmlrpc.client.dumps((result,), methodresponse=True, allow_none=True))


def read_only(requests: list[tuple[str, str, str]]) -> bool:
    """Whether every request is one the connector may send (method and path, RPC method)."""
    models = r"(res\.partner|crm\.lead|res\.users\.apikeys|ir\.model)"
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
