# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The Databricks backend for the shared connector contract suite (not a test module itself).

Databricks has no emulator, so the connector is tested at the driver boundary:
``FakeDatabricks.connect`` stands in for ``databricks.sql.connect`` and
``FakeDatabricks.post`` for the workspace's OAuth token endpoint. The fake connection
records every statement and answers it from an in-memory DuckDB holding the contract
fixture in catalog ``erebus_ct`` (schemas ``crm`` and ``other``). Only dialect is
translated: Spark's backtick identifiers become DuckDB's double quotes, the binary
collation ``UTF8_BINARY`` becomes DuckDB's ``"binary"``, and
``<catalog>.information_schema.columns`` becomes a view with Unity Catalog's type names
(``STRING``, ``INT``). DuckDB errors come back as the driver's own
``ServerOperationError`` with Databricks' error class in the message.

Credentials are made up at run time; nothing here is a real secret or workspace.
"""
from __future__ import annotations

import json
import re
import secrets

from connector_backends import FIELDS, FOLDED, ROWS
from warehouse_backends import declared_type, licensed, unlicensed_cases

HOST = "dbc-a1b2c3d4-e5f6.cloud.databricks.com"
HTTP_PATH = "/sql/1.0/warehouses/0123456789abcdef"
CATALOG = "erebus_ct"
CLIENT_ID = "6f1e0a52-9a8b-4c1d-8e2f-3a4b5c6d7e8f"
_COLUMNS_REF = re.compile(r"`((?:[^`]|``)+)`\.information_schema\.columns")
_CUSTOMERS = ("CREATE TABLE {t} (id INTEGER NOT NULL, email VARCHAR(200), full_name VARCHAR(200) NOT NULL, "
              "first_name VARCHAR(100), last_name VARCHAR(100), active BOOLEAN, signup DATE, notes TEXT)")
_ORDERS = "CREATE TABLE {t} (id INTEGER, product_name VARCHAR(100))"


def _duck_sql(sql: str) -> str:
    """Spark SQL as DuckDB reads it: backtick identifiers become double-quoted ones."""
    sql = sql.replace("COLLATE UTF8_BINARY", 'COLLATE "binary"')
    sql = _COLUMNS_REF.sub(lambda m: f"memory.main.\"{m.group(1).replace('``', '`')}_columns\"", sql)
    out, i = [], 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            end = sql.index("'", i + 1)
            out.append(sql[i:end + 1])
            i = end + 1
        elif ch == "`":
            name, i = [], i + 1
            while True:
                if sql[i] == "`" and sql[i + 1:i + 2] == "`":
                    name.append("`")
                    i += 2
                elif sql[i] == "`":
                    i += 1
                    break
                else:
                    name.append(sql[i])
                    i += 1
            out.append('"' + "".join(name).replace('"', '""') + '"')
        else:
            out.append(ch)
            i += 1
    return "".join(out)


class _Response:
    def __init__(self, status, body):
        self.status_code = status
        self.ok = 200 <= status < 300
        self._body = body

    def json(self):
        if isinstance(self._body, str):
            raise json.JSONDecodeError("not JSON", self._body, 0)
        return self._body


class FakeDatabricks:
    """``databricks.sql.connect`` and the token endpoint, recorded."""

    def __init__(self, db):
        self.db = db
        self.connects = []  # kwargs of every connect
        self.headers = []  # the headers the credentials provider produced at each connect
        self.posts = []  # (url, data, auth, kwargs) of every token request
        self.sent = []  # every statement, as the connector sent it
        self.token_reply = None  # (status, body) to answer the next token request with, or an exception
        self.connect_error = None
        self.tokens = 0
        self.expires_in = 3600  # under 40 s the SDK treats a token as expired: every request refreshes

    def post(self, url, data=None, auth=None, **kwargs):
        self.posts.append((url, dict(data or {}), auth, kwargs))
        reply, self.token_reply = self.token_reply, None
        if isinstance(reply, BaseException):
            raise reply
        if reply is not None:
            return _Response(*reply)
        self.tokens += 1
        return _Response(200, {"access_token": f"dbx-access-{self.tokens}-{secrets.token_hex(8)}",
                               "token_type": "Bearer", "expires_in": self.expires_in, "scope": "all-apis"})

    def connect(self, **kwargs):
        self.connects.append(kwargs)
        header_factory = kwargs["credentials_provider"]()
        self.headers.append(header_factory())  # as the driver does on its first request
        if self.connect_error is not None:
            raise self.connect_error
        return _Connection(self, header_factory)


class _Connection:
    def __init__(self, fake, header_factory):
        self.fake = fake
        self.header_factory = header_factory
        self.closed = False

    def cursor(self, *_a, **_kw):
        return _Cursor(self.fake, self.header_factory)

    def close(self):
        self.closed = True


class _Cursor:
    def __init__(self, fake, header_factory):
        self.fake = fake
        self.header_factory = header_factory
        self.arraysize = 10000
        self._result = None

    def execute(self, operation, parameters=None):
        import duckdb
        from databricks.sql.exc import RequestError, ServerOperationError

        try:
            self.fake.headers.append(self.header_factory())  # every request carries a fresh-enough token
        except Exception as exc:  # the driver wraps whatever the provider raised
            raise RequestError("Error during request to server", context={"original-exception": exc}) from exc
        self.fake.sent.append(operation)
        if parameters:
            raise AssertionError("the connector sends no parameters")
        try:
            self._result = self.fake.db.cursor().execute(_duck_sql(operation))
        except duckdb.CatalogException:
            raise ServerOperationError("[TABLE_OR_VIEW_NOT_FOUND] The table or view cannot be found. "
                                       "SQLSTATE: 42P01") from None
        except duckdb.Error:
            raise ServerOperationError("[PARSE_SYNTAX_ERROR] Syntax error. SQLSTATE: 42601") from None
        return self

    def fetchmany(self, size=None):
        return self._result.fetchmany(size or self.arraysize)

    def fetchall(self):
        return self._result.fetchall()

    def close(self):
        self._result = None


class DatabricksBackend:
    name = "databricks"
    tier = "pro"
    schemas = True
    primary_key = False  # Unity Catalog keys are informational; the connector reads none
    folds = True  # a column collated like UNICODE_CI_AI (DuckDB's NOACCENT.NOCASE)

    def connector_type(self):
        return declared_type(self.name)

    def unavailable(self):
        try:
            import duckdb  # noqa: F401
            from databricks import sdk, sql  # noqa: F401
        except ImportError as exc:
            return f"{exc.name} is not installed (pip install './pro[test]')"
        return None

    def setup(self):
        import duckdb

        db = duckdb.connect()
        db.execute(f"ATTACH ':memory:' AS {CATALOG}")
        for stmt in (f"CREATE SCHEMA {CATALOG}.crm", f"CREATE SCHEMA {CATALOG}.other",
                     _CUSTOMERS.format(t=f"{CATALOG}.crm.customers"), _ORDERS.format(t=f"{CATALOG}.crm.orders"),
                     _ORDERS.format(t=f"{CATALOG}.other.orders"),
                     f"INSERT INTO {CATALOG}.crm.orders VALUES (1, 'Widget')",
                     f"CREATE TABLE {CATALOG}.crm.folded (id INTEGER, name VARCHAR COLLATE NOACCENT.NOCASE)",
                     # Unity Catalog's information_schema.columns, with its type names.
                     f"CREATE VIEW memory.main.\"{CATALOG}_columns\" AS SELECT table_catalog, table_schema, "
                     "table_name, column_name, ordinal_position, is_nullable, "
                     "CASE data_type WHEN 'VARCHAR' THEN 'STRING' WHEN 'INTEGER' THEN 'INT' ELSE data_type END "
                     "AS data_type FROM information_schema.columns "
                     f"WHERE table_catalog = '{CATALOG}'"):
            db.execute(stmt)
        db.executemany(f"INSERT INTO {CATALOG}.crm.customers ({', '.join(FIELDS)}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       [list(r) for r in ROWS])
        db.executemany(f"INSERT INTO {CATALOG}.crm.folded VALUES (?, ?)", [list(r) for r in enumerate(FOLDED)])
        self.db = db
        self.fake = FakeDatabricks(db)
        self.secret = "dbx-secret-" + secrets.token_hex(16)

    def teardown(self):
        self.db.close()

    def connector(self, entitlements=None):
        from erebus_pro.connectors.databricks import DatabricksConnector
        return DatabricksConnector(entitlements or licensed(["connectors.databricks"]), sql_connect=self.fake.connect,
                                   token_post=self.fake.post)

    def unlicensed(self):
        return unlicensed_cases("connectors.databricks")

    def settings(self, **over):
        return {"server_hostname": HOST, "http_path": HTTP_PATH, "catalog": CATALOG, "client_id": CLIENT_ID, **over}

    def secrets(self):
        return {"client_secret": self.secret}

    def collection(self, table):
        return f"crm.{table}"

    def statements(self, _source):
        return list(self.fake.sent)

    def bad_cases(self):
        from databricks.sql.exc import RequestError

        class _Reply:
            """Make the next token request answer ``reply`` while the case runs."""

            def __init__(self, fake, reply):
                self.fake, self.reply = fake, reply

            def __enter__(self):
                self.fake.token_reply = self.reply

            def __exit__(self, *_exc):
                self.fake.token_reply = None

        class _ConnectError:
            def __init__(self, fake, exc):
                self.fake, self.exc = fake, exc

            def __enter__(self):
                self.fake.connect_error = self.exc

            def __exit__(self, *_exc):
                self.fake.connect_error = None

        secret = self.secret
        echo = {"error": "invalid_client",
                "error_description": f"Client authentication failed for {CLIENT_ID} {secret}"}
        down = RequestError(f"Error during request to server: {HOST}", context={"http-code": 503})
        limited = RequestError(f"Too many requests to {HOST}", context={"http-code": 429})
        return [
            ("a server hostname outside Databricks", self.settings(server_hostname="evil.example"), self.secrets(),
             "settings", ["evil.example", secret]),
            ("a server hostname given as a URL", self.settings(server_hostname=f"https://{HOST}/x"), self.secrets(),
             "settings", [secret]),
            ("an http path that is not a SQL warehouse", self.settings(http_path="/sql/protocolv1/o/1/0123-456789-ab"),
             self.secrets(), "settings", ["0123-456789-ab", secret]),
            ("a catalog name with SQL in it", self.settings(catalog="x`; DROP TABLE y; --"), self.secrets(),
             "settings", ["DROP TABLE", secret]),
            ("a client id that is not a service principal id", self.settings(client_id="admin@acme.example"),
             self.secrets(), "settings", ["admin@acme.example", secret]),
            ("no client secret", self.settings(), {}, "auth", [CLIENT_ID, HOST]),
            ("a client secret Databricks rejects", self.settings(), self.secrets(), "auth", [CLIENT_ID, HOST, secret],
             _Reply(self.fake, (401, echo))),
            ("a token endpoint that cannot be reached", self.settings(), self.secrets(), "unreachable",
             [HOST, secret], _Reply(self.fake, ConnectionError(f"cannot reach {HOST}"))),
            ("a catalog the service principal cannot see", self.settings(catalog="no_such_cat_zq"), self.secrets(),
             "permission", ["no_such_cat_zq", secret]),
            ("a warehouse that cannot be reached", self.settings(), self.secrets(), "unreachable", [HOST, secret],
             _ConnectError(self.fake, down)),
            ("a workspace rate limit", self.settings(), self.secrets(), "limit", [HOST, secret],
             _ConnectError(self.fake, limited)),
        ]
