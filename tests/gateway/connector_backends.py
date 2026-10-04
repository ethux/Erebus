"""Source backends for the shared connector contract suite (not a test module itself).

Each backend builds the same fixture (``customers`` and ``orders``, plus a second schema
where the backend has schemas), and knows how to open it, how to attempt a raw write
through an open source's connection, and which bad settings must fail with which error
class. ``unavailable()`` says why a backend cannot run here (then the suite skips it).
"""
from __future__ import annotations

import os
import socket
import sqlite3
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse

PASSWORD = "Pw-contract-Zq9x"
ROWS = [
    (1, "zyx.qorbel@acme.example", "Zyx Qorbel", "Zyx", "Qorbel", True, "2026-01-02", None),
    (2, "mila.brandt@acme.example", "Mila Brandt", "Mila", "Brandt", False, "2026-02-03", "vip"),
    (3, "zyx.qorbel@acme.example", "Zyx Qorbel", "Zyx", "Qorbel", True, "2026-03-04", None),
    (4, None, "Anna Visser", "Anna", "Visser", False, "2026-04-05", None),
    # Case and accent variants: DISTINCT must keep them apart (MySQL's default collations fold both).
    (5, "Zyx.Qorbel@ACME.example", "Zyx Qorbël", "Zyx", "Qorbël", True, "2026-05-06", None),
]
FIELDS = ["id", "email", "full_name", "first_name", "last_name", "active", "signup", "notes"]
# The ``name`` values of a backend's ``folded`` table, in a column whose collation folds case or accents.
FOLDED = ["Müller", "Muller", "MULLER", "Ångström", "Angstrom"]
_CUSTOMERS = ("CREATE TABLE {t} (id INTEGER PRIMARY KEY, email VARCHAR(200), full_name VARCHAR(200) NOT NULL, "
              "first_name VARCHAR(100), last_name VARCHAR(100), active BOOLEAN, signup DATE, notes TEXT)")
_ORDERS = "CREATE TABLE {t} (id INTEGER PRIMARY KEY, product_name VARCHAR(100))"


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SQLiteBackend:
    name = "sqlite"
    schemas = False
    folds = True  # NOCASE folds ASCII case

    def unavailable(self):
        return None

    def setup(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        db = sqlite3.connect(self.root / "crm.db")
        db.execute(_CUSTOMERS.format(t="customers"))
        db.execute(_ORDERS.format(t="orders"))
        db.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?)", ROWS)
        db.execute("INSERT INTO orders VALUES (1, 'Widget')")
        db.execute("CREATE TABLE folded (id INTEGER PRIMARY KEY, name TEXT COLLATE NOCASE)")
        db.executemany("INSERT INTO folded VALUES (?, ?)", list(enumerate(FOLDED)))
        db.commit()
        db.close()
        (self.root / "not-a-db.db").write_text("plain text, not a database")

    def teardown(self):
        self._dir.cleanup()

    def connector(self):
        from erebus.cataloging.connectors.sqlite import SQLiteConnector
        return SQLiteConnector()

    def settings(self, **over):
        return {"path": str(self.root / "crm.db"), **over}

    def secrets(self):
        return {}

    def collection(self, table):
        return table

    def write_probe(self, source):
        source.conn.execute("INSERT INTO orders VALUES (2, 'Gadget')")

    def is_write_refusal(self, exc):
        return isinstance(exc, sqlite3.OperationalError) and "readonly" in str(exc).lower()

    def bad_cases(self):
        """(case, settings, secrets, error class, texts the error must not show)."""
        missing = str(self.root / "missing-zq.db")
        return [
            ("a missing file", {"path": missing}, {}, "unreachable", [missing, "missing-zq"]),
            ("a file that is not a database", {"path": str(self.root / "not-a-db.db")}, {}, "unreachable",
             ["not-a-db"]),
        ]


class PostgresBackend:
    """The test's own database (``EREBUS_PG_DSN``) is the source: schemas ``crm`` and ``other``."""

    name = "postgres"
    schemas = True
    folds = True  # a nondeterministic ICU collation that ignores case and accents

    def unavailable(self):
        if not os.environ.get("EREBUS_PG_DSN"):
            return "EREBUS_PG_DSN is not set"
        try:
            import psycopg
            with psycopg.connect(os.environ["EREBUS_PG_DSN"], connect_timeout=5) as conn:
                dbname = conn.info.dbname
        except Exception as exc:
            return f"no Postgres at EREBUS_PG_DSN ({type(exc).__name__})"
        if dbname == "postgres":  # never build fixtures in the shared maintenance database
            return "EREBUS_PG_DSN names the shared 'postgres' database"
        return None

    def setup(self):
        import psycopg
        self.admin = psycopg.connect(os.environ["EREBUS_PG_DSN"], autocommit=True)
        self.info = self.admin.info
        for stmt in ("DROP SCHEMA IF EXISTS crm CASCADE", "DROP SCHEMA IF EXISTS other CASCADE",
                     "CREATE SCHEMA crm", "CREATE SCHEMA other", _CUSTOMERS.format(t="crm.customers"),
                     _ORDERS.format(t="crm.orders"), _ORDERS.format(t="other.orders"),
                     "INSERT INTO crm.orders VALUES (1, 'Widget')",
                     "CREATE COLLATION crm.folding (provider = icu, locale = 'und-u-ks-level1', deterministic = false)",
                     "CREATE TABLE crm.folded (id INTEGER PRIMARY KEY, name TEXT COLLATE crm.folding)"):
            self.admin.execute(stmt)
        with self.admin.cursor() as cur:
            cur.executemany("INSERT INTO crm.customers VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", ROWS)
            cur.executemany("INSERT INTO crm.folded VALUES (%s, %s)", list(enumerate(FOLDED)))

    def teardown(self):
        self.admin.execute("DROP SCHEMA crm CASCADE")
        self.admin.execute("DROP SCHEMA other CASCADE")
        self.admin.close()

    def connector(self):
        from erebus.cataloging.connectors.postgres import PostgresConnector
        return PostgresConnector()

    def settings(self, **over):
        base = {"host": "localhost", "hostaddr": "127.0.0.1", "port": self.info.port or 5432,
                "dbname": self.info.dbname, "user": self.info.user, "sslmode": "disable"}
        return {**base, **over}

    def secrets(self):
        # The DSN's own password where the server checks one (CI); any text under trust auth.
        return {"password": self.info.password or PASSWORD}

    def collection(self, table):
        return f"crm.{table}"

    def write_probe(self, source):
        source.conn.execute("INSERT INTO crm.orders VALUES (2, 'Gadget')")

    def is_write_refusal(self, exc):
        return getattr(exc, "sqlstate", None) == "25006"

    def bad_cases(self):
        port = _closed_port()
        return [
            ("an unknown role", self.settings(user="no_such_role_zq"), self.secrets(), "auth",
             ["no_such_role_zq", self.secrets()["password"]]),
            ("an unknown database", self.settings(dbname="no_such_db_zq"), self.secrets(), "unreachable",
             ["no_such_db_zq", self.secrets()["password"]]),
            ("a closed port", self.settings(port=port), self.secrets(), "unreachable", [str(port), "127.0.0.1"]),
            ("TLS verified by default, and this server has none", {k: v for k, v in self.settings().items()
                                                                   if k != "sslmode"},
             self.secrets(), "unreachable", ["localhost", self.secrets()["password"]]),
        ]


class MySQLBackend:
    """A throwaway MySQL named by ``EREBUS_TEST_MYSQL_DSN`` (``mysql://root:pw@127.0.0.1:13306``).

    The connector logs in with that account (full privileges), so the refused write
    proves the connector's own read-only transaction, not a grant.
    """

    name = "mysql"
    schemas = True
    folds = True  # a latin1 column with a case-insensitive collation (the fixture's utf8mb4 one folds accents)
    _DB = "erebus_contract"
    _OTHER = "erebus_contract_other"

    def unavailable(self):
        if not os.environ.get("EREBUS_TEST_MYSQL_DSN"):
            return "EREBUS_TEST_MYSQL_DSN is not set"
        return None

    def _admin(self, **kw):
        import pymysql
        url = urlparse(os.environ["EREBUS_TEST_MYSQL_DSN"])
        self.url = url
        return pymysql.connect(host=url.hostname, port=url.port or 3306, user=unquote(url.username or "root"),
                               password=unquote(url.password or ""), autocommit=True, **kw)

    def setup(self):
        self.admin = self._admin()
        with self.admin.cursor() as cur:
            for stmt in (f"DROP DATABASE IF EXISTS {self._DB}", f"DROP DATABASE IF EXISTS {self._OTHER}",
                         f"CREATE DATABASE {self._DB}", f"CREATE DATABASE {self._OTHER}",
                         _CUSTOMERS.format(t=f"{self._DB}.customers"), _ORDERS.format(t=f"{self._DB}.orders"),
                         _ORDERS.format(t=f"{self._OTHER}.orders"),
                         f"INSERT INTO {self._DB}.orders VALUES (1, 'Widget')",
                         f"CREATE TABLE {self._DB}.folded (id INTEGER PRIMARY KEY, "
                         "name VARCHAR(100) CHARACTER SET latin1 COLLATE latin1_german1_ci)"):
                cur.execute(stmt)
            cur.executemany(f"INSERT INTO {self._DB}.customers VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", ROWS)
            cur.executemany(f"INSERT INTO {self._DB}.folded VALUES (%s, %s)", list(enumerate(FOLDED)))

    def teardown(self):
        with self.admin.cursor() as cur:
            cur.execute(f"DROP DATABASE {self._DB}")
            cur.execute(f"DROP DATABASE {self._OTHER}")
        self.admin.close()

    def connector(self):
        from erebus.cataloging.connectors.mysql import MySQLConnector
        return MySQLConnector()

    def settings(self, **over):
        base = {"host": "localhost", "hostaddr": self.url.hostname, "port": self.url.port or 3306,
                "dbname": self._DB, "user": unquote(self.url.username or "root"), "sslmode": "require",
                "schemas": [self._DB, self._OTHER]}
        return {**base, **over}

    def secrets(self):
        return {"password": unquote(self.url.password or "")}

    def collection(self, table):
        return f"{self._DB}.{table}"

    def write_probe(self, source):
        with source.conn.cursor() as cur:
            cur.execute(f"INSERT INTO {self._DB}.orders VALUES (2, 'Gadget')")

    def is_write_refusal(self, exc):
        return bool(getattr(exc, "args", None)) and exc.args[0] == 1792

    def tls_in_use(self, source):
        with source.conn.cursor() as cur:
            cur.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
            row = cur.fetchone()
        source.conn.rollback()
        return bool(row and row[1])

    def bad_cases(self):
        port = _closed_port()
        wrong = "Wrong-Zq-" + PASSWORD
        return [
            ("a wrong password", self.settings(), {"password": wrong}, "auth", [wrong, "root", "localhost"]),
            ("an unknown database", self.settings(dbname="no_such_db_zq"), self.secrets(), "unreachable",
             ["no_such_db_zq", self.secrets()["password"]]),
            ("a closed port", self.settings(port=port), self.secrets(), "unreachable", [str(port), "127.0.0.1"]),
            ("TLS verified by default, and this certificate is self-signed",
             {k: v for k, v in self.settings().items() if k != "sslmode"}, self.secrets(), "unreachable",
             ["localhost", self.secrets()["password"]]),
        ]


BACKENDS = (SQLiteBackend, PostgresBackend, MySQLBackend)
