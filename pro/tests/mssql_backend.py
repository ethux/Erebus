# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The MSSQL backend for the shared connector contract suite (not a test module itself).

A throwaway SQL Server (``mcr.microsoft.com/mssql/server``) named by
``EREBUS_TEST_MSSQL_DSN`` (``mssql://sa:<password>@127.0.0.1:14330``); skipped without
it. The fixture is the database ``erebus_crm_zq`` with schemas ``crm`` and ``other``. The
connector signs in over pymssql as ``erebus_sync_zq``, a login whose database user is in
``db_datareader`` only (the documented read-only login), so a write through its
connection is refused (229). SQL Server's own certificate is self-signed, so the
connector uses ``sslmode: require`` here and the default ``verify-full`` must refuse it.
``least_privileged()`` adds a login with only SELECT on ``crm.customers``.
"""
from __future__ import annotations

import os
import secrets
import socket
from urllib.parse import unquote, urlparse

from connector_backends import FIELDS, ROWS
from warehouse_backends import declared_type, licensed, unlicensed_cases

DATABASE = "erebus_crm_zq"
READER = "erebus_sync_zq"
LEAST = "erebus_least_zq"
_CUSTOMERS = ("CREATE TABLE {s}.customers (id INT PRIMARY KEY, email NVARCHAR(200), full_name NVARCHAR(200) NOT NULL, "
              "first_name NVARCHAR(100), last_name NVARCHAR(100), active BIT, signup DATE, notes NTEXT)")
_ORDERS = "CREATE TABLE {s}.orders (id INT PRIMARY KEY, product_name NVARCHAR(100))"


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def error_code(exc):
    """The SQL Server message number pymssql reports for ``exc``."""
    first = exc.args[0] if getattr(exc, "args", None) else None
    return first[0] if isinstance(first, tuple) else first


class MssqlBackend:
    name = "mssql"
    tier = "pro"
    schemas = True

    def connector_type(self):
        return declared_type(self.name)

    def unavailable(self):
        raw = os.environ.get("EREBUS_TEST_MSSQL_DSN", "")
        if not raw:
            return "EREBUS_TEST_MSSQL_DSN is not set"
        try:
            import pymssql
        except ImportError:
            return "pymssql is not installed (pip install ./pro)"
        self.url = urlparse(raw)
        try:
            self._admin().close()
        except pymssql.Error as exc:
            return f"no SQL Server at EREBUS_TEST_MSSQL_DSN ({type(exc).__name__})"
        return None

    def _admin(self, database="master"):
        import pymssql
        return pymssql.connect(server=self.url.hostname, port=str(self.url.port or 1433),
                               user=unquote(self.url.username or "sa"), password=unquote(self.url.password or ""),
                               database=database, login_timeout=10, autocommit=True)

    def _drop(self, cur):
        cur.execute(f"IF DB_ID('{DATABASE}') IS NOT NULL "
                    f"ALTER DATABASE {DATABASE} SET SINGLE_USER WITH ROLLBACK IMMEDIATE")
        cur.execute(f"IF DB_ID('{DATABASE}') IS NOT NULL DROP DATABASE {DATABASE}")
        for login in (READER, LEAST):
            cur.execute(f"IF SUSER_ID('{login}') IS NOT NULL DROP LOGIN {login}")

    def setup(self):
        self.admin = self._admin()
        cur = self.admin.cursor()
        self._drop(cur)
        cur.execute(f"CREATE DATABASE {DATABASE}")
        self.reader_password = "Rd-" + secrets.token_hex(12)
        self.least_password = "Ls-" + secrets.token_hex(12)
        cur.execute(f"CREATE LOGIN {READER} WITH PASSWORD = '{self.reader_password}', CHECK_POLICY = OFF")
        self.db = self._admin(DATABASE)
        cur = self.db.cursor()
        for schema in ("crm", "other"):
            cur.execute(f"CREATE SCHEMA {schema}")
        for stmt in (_CUSTOMERS.format(s="crm"), _ORDERS.format(s="crm"), _ORDERS.format(s="other"),
                     "INSERT INTO crm.orders VALUES (1, 'Widget')",
                     f"CREATE USER {READER} FOR LOGIN {READER}", f"ALTER ROLE db_datareader ADD MEMBER {READER}"):
            cur.execute(stmt)
        cols = ", ".join(FIELDS)
        cur.executemany(f"INSERT INTO crm.customers ({cols}) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        [(r[0], r[1], r[2], r[3], r[4], int(r[5]), r[6], r[7]) for r in ROWS])

    def least_privileged(self):
        """A login with only SELECT on ``crm.customers`` (the README's grants)."""
        self.admin.cursor().execute(f"CREATE LOGIN {LEAST} WITH PASSWORD = '{self.least_password}', "
                                    "CHECK_POLICY = OFF")
        cur = self.db.cursor()
        cur.execute(f"CREATE USER {LEAST} FOR LOGIN {LEAST}")
        cur.execute(f"GRANT SELECT ON crm.customers TO {LEAST}")
        return self.settings(user=LEAST), {"password": self.least_password}

    def admin_cursor(self):
        return self.db.cursor()

    def teardown(self):
        self.db.close()
        self._drop(self.admin.cursor())
        self.admin.close()

    def connector(self, entitlements=None):
        from erebus_pro.connectors.mssql import MssqlConnector
        return MssqlConnector(entitlements or licensed(["connectors.mssql"]))

    def unlicensed(self):
        return unlicensed_cases("connectors.mssql")

    def settings(self, **over):
        base = {"host": "localhost", "hostaddr": self.url.hostname, "port": self.url.port or 1433,
                "database": DATABASE, "user": READER, "sslmode": "require"}
        return {**base, **over}

    def secrets(self):
        return {"password": self.reader_password}

    def collection(self, table):
        return f"crm.{table}"

    def write_probe(self, source):
        source.conn.cursor().execute("INSERT INTO crm.orders VALUES (2, 'Gadget')")

    def is_write_refusal(self, exc):
        return error_code(exc) == 229

    def session(self, source):
        """(encrypted, program name) of ``source``'s session, as the server sees it."""
        cur = source.conn.cursor()
        cur.execute("SELECT @@SPID")
        spid = cur.fetchone()[0]
        admin = self.admin.cursor()
        admin.execute("SELECT c.encrypt_option, s.program_name FROM sys.dm_exec_connections c "
                      "JOIN sys.dm_exec_sessions s ON s.session_id = c.session_id WHERE c.session_id = %s", (spid,))
        encrypted, program = admin.fetchone()
        return encrypted == "TRUE", program

    def tls_in_use(self, source):
        return self.session(source)[0]

    def bad_cases(self):
        port = closed_port()
        wrong = "Wrong-Zq-" + secrets.token_hex(6)
        password = self.reader_password
        return [
            ("a wrong password", self.settings(), {"password": wrong}, "auth", [wrong, password, "localhost", READER]),
            ("an unknown database", self.settings(database="no_such_db_zq"), self.secrets(), "auth",
             ["no_such_db_zq", password]),
            ("a closed port", self.settings(port=port), self.secrets(), "unreachable", [str(port), "127.0.0.1"]),
            ("TLS verified by default, and this server's certificate is self-signed",
             {k: v for k, v in self.settings().items() if k != "sslmode"}, self.secrets(), "unreachable",
             ["localhost", password]),
            ("a malformed database name", self.settings(database="crm]; DROP DATABASE x; --"), self.secrets(),
             "settings", ["DROP DATABASE", password]),
            ("sslmode prefer (encryption is required or off)", self.settings(sslmode="prefer"), self.secrets(),
             "settings", [password]),
            ("no password", self.settings(), {}, "auth", [READER]),
        ]
