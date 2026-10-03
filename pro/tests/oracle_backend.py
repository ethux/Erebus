# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The Oracle backend for the shared connector contract suite (not a test module itself).

A throwaway Oracle Database (``gvenzl/oracle-free``) named by ``EREBUS_TEST_ORACLE_DSN``
(``oracle://system:<password>@127.0.0.1:1521/FREEPDB1``); skipped without it. The
fixture lives in two schemas, ``EREBUS_CRM`` and ``EREBUS_OTHER``, with lower-case
quoted names so the shared field names apply. The connector signs in as the DSN's
account (SYSTEM: every privilege, every schema visible), so a refused write proves the
connector's own read-only transaction, and the listing proves Oracle-maintained schemas
are left out. ``least_privileged()`` adds a user with only the documented grants.
"""
from __future__ import annotations

import datetime
import os
import secrets
import socket
import time
from urllib.parse import unquote, urlparse

from connector_backends import FIELDS, ROWS
from warehouse_backends import declared_type, licensed, unlicensed_cases

CRM = "EREBUS_CRM"
OTHER = "EREBUS_OTHER"
READER = "EREBUS_SYNC_ZQ"
_CUSTOMERS = ('CREATE TABLE {s}."customers" ("id" NUMBER(10) PRIMARY KEY, "email" VARCHAR2(200), '
              '"full_name" VARCHAR2(200) NOT NULL, "first_name" VARCHAR2(100), "last_name" VARCHAR2(100), '
              '"active" BOOLEAN, "signup" DATE, "notes" CLOB)')
_ORDERS = 'CREATE TABLE {s}."orders" ("id" NUMBER(10) PRIMARY KEY, "product_name" VARCHAR2(100))'


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class OracleBackend:
    name = "oracle"
    tier = "pro"
    schemas = True
    integer_classes = ("numeric",)  # NUMBER(10,0)

    def connector_type(self):
        return declared_type(self.name)

    def unavailable(self):
        raw = os.environ.get("EREBUS_TEST_ORACLE_DSN", "")
        if not raw:
            return "EREBUS_TEST_ORACLE_DSN is not set"
        try:
            import oracledb
        except ImportError:
            return "oracledb is not installed (pip install ./pro)"
        self.url = urlparse(raw)
        try:
            self._admin().close()
        except oracledb.Error as exc:
            return f"no Oracle at EREBUS_TEST_ORACLE_DSN ({type(exc).__name__})"
        return None

    def _admin(self):
        import oracledb
        return oracledb.connect(user=unquote(self.url.username or "system"), password=unquote(self.url.password or ""),
                                host=self.url.hostname, port=self.url.port or 1521,
                                service_name=self.url.path.lstrip("/") or "FREEPDB1", tcp_connect_timeout=5)

    def _drop(self, cur):
        import oracledb
        for user in (READER, CRM, OTHER):
            try:
                cur.execute(f"DROP USER {user} CASCADE")
            except oracledb.DatabaseError:
                pass  # not there yet

    def setup(self):
        self.admin = self._admin()
        cur = self.admin.cursor()
        self._drop(cur)
        for schema in (CRM, OTHER):
            cur.execute(f"CREATE USER {schema} NO AUTHENTICATION QUOTA UNLIMITED ON USERS")
        for stmt in (_CUSTOMERS.format(s=CRM), _ORDERS.format(s=CRM), _ORDERS.format(s=OTHER),
                     f"INSERT INTO {CRM}.\"orders\" VALUES (1, 'Widget')"):
            cur.execute(stmt)
        cols = ", ".join(f'"{f}"' for f in FIELDS)
        rows = [(r[0], r[1], r[2], r[3], r[4], r[5], datetime.date.fromisoformat(r[6]), r[7])
                for r in ROWS]
        cur.executemany(f'INSERT INTO {CRM}."customers" ({cols}) VALUES (:1, :2, :3, :4, :5, :6, :7, :8)', rows)
        self.admin.commit()
        self._settle(cur)
        self.reader_password = "Rd-" + secrets.token_hex(12)

    def _settle(self, cur):
        """Wait until a read-only transaction may read the new tables: Oracle refuses a
        table whose DDL is only seconds older than the snapshot (ORA-01466)."""
        import oracledb
        for _ in range(60):
            try:
                cur.execute("SET TRANSACTION READ ONLY")
                for table in (f'{CRM}."customers"', f'{CRM}."orders"', f'{OTHER}."orders"'):
                    cur.execute(f"SELECT COUNT(*) FROM {table}").fetchall()
                self.admin.rollback()
                return
            except oracledb.DatabaseError:
                self.admin.rollback()
                time.sleep(0.5)
        raise RuntimeError("the Oracle fixture never became readable in a read-only transaction")

    def least_privileged(self):
        """A user with only CREATE SESSION and SELECT on ``customers`` (the README's grants)."""
        cur = self.admin.cursor()
        cur.execute(f'CREATE USER {READER} IDENTIFIED BY "{self.reader_password}"')
        cur.execute(f"GRANT CREATE SESSION TO {READER}")
        cur.execute(f'GRANT SELECT ON {CRM}."customers" TO {READER}')
        return self.settings(user=READER), {"password": self.reader_password}

    def admin_cursor(self):
        return self.admin.cursor()

    def teardown(self):
        cur = self.admin.cursor()
        self._drop(cur)
        self.admin.close()

    def connector(self, entitlements=None):
        from erebus_pro.connectors.oracle import OracleConnector
        return OracleConnector(entitlements or licensed(["connectors.oracle"]))

    def unlicensed(self):
        return unlicensed_cases("connectors.oracle")

    def settings(self, **over):
        base = {"host": "localhost", "hostaddr": self.url.hostname, "port": self.url.port or 1521,
                "service_name": self.url.path.lstrip("/") or "FREEPDB1",
                "user": unquote(self.url.username or "system"), "sslmode": "disable"}
        return {**base, **over}

    def secrets(self):
        return {"password": unquote(self.url.password or "")}

    def collection(self, table):
        return f"{CRM}.{table}"

    def write_probe(self, source):
        source.conn.cursor().execute(f"INSERT INTO {CRM}.\"orders\" VALUES (2, 'Gadget')")

    def is_write_refusal(self, exc):
        error = exc.args[0] if getattr(exc, "args", None) else None
        return getattr(error, "full_code", None) == "ORA-01456"

    def bad_cases(self):
        port = closed_port()
        password = self.secrets()["password"]
        wrong = "Wrong-Zq-" + secrets.token_hex(6)
        user = self.settings()["user"]
        return [
            ("a wrong password", self.settings(), {"password": wrong}, "auth", [wrong, password, "localhost"]),
            ("an unknown service name", self.settings(service_name="NO_SUCH_SVC_ZQ"), self.secrets(), "unreachable",
             ["NO_SUCH_SVC_ZQ", password]),
            ("a closed port", self.settings(port=port), self.secrets(), "unreachable", [str(port), "127.0.0.1"]),
            ("TLS verified by default, and this listener has none",
             {k: v for k, v in self.settings().items() if k != "sslmode"}, self.secrets(), "unreachable",
             ["localhost", password]),
            ("a malformed service name", self.settings(service_name="FREEPDB1)(HOST=evil.example"), self.secrets(),
             "settings", ["evil.example", password]),
            ("sslmode prefer (Oracle serves TLS on its own port)", self.settings(sslmode="prefer"), self.secrets(),
             "settings", [password]),
            ("no password", self.settings(), {}, "auth", [user]),
        ]
