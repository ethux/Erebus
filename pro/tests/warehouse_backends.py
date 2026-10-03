# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Warehouse backends for the shared connector contract suite (not a test module itself).

Each builds the contract fixture (``tests/gateway/connector_backends.py``: ``customers``
and ``orders`` plus a second schema) in a fake warehouse, opens it through the Pro
connector with a license carrying its feature, and records every statement the
connector sends (fakes refuse no write: the documented read-only role is the guard).

* Snowflake: ``fakesnow`` (an in-process DuckDB behind the real driver API). Auth is
  not checked by the fake, so auth and network failures are raised at the driver
  boundary, with the error codes Snowflake sends.
* BigQuery: the ``goccy/bigquery-emulator`` container named by
  ``EREBUS_TEST_BIGQUERY_EMULATOR`` (``http://127.0.0.1:9050``); skipped without it.

Key material is generated at run time; nothing here is a real credential.
"""
from __future__ import annotations

import contextlib
import time
import tomllib
from importlib import metadata
from pathlib import Path

from connector_backends import FIELDS, ROWS

LICENSE_ID = "lic-contract"
_SF_DB = "CONTRACT_DB"
_SF_ACCOUNT = "acme-zq"
_SF_USER = "SVC_EREBUS_ZQ"


def declared_entry_points(group):
    """The entry points ``pro/pyproject.toml`` declares for ``group`` (installed or not)."""
    with open(Path(__file__).resolve().parents[1] / "pyproject.toml", "rb") as fh:
        declared = tomllib.load(fh)["project"]["entry-points"].get(group, {})
    return [metadata.EntryPoint(name, value, group) for name, value in declared.items()]


def licensed(features, *, expires_in=86400):
    from erebus_pro.license import Entitlements, License
    now = int(time.time())
    return Entitlements(License(LICENSE_ID, "Acme", frozenset(features), now - 86400, now + expires_in))


def rsa_pem(passphrase: str | None = None) -> str:
    """A fresh RSA private key as PKCS#8 PEM text (encrypted when ``passphrase`` is given)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    crypt = (serialization.BestAvailableEncryption(passphrase.encode()) if passphrase
             else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, crypt).decode()


def unlicensed_cases(feature):
    from erebus_pro.license import GRACE_SECONDS, from_env
    return [("no license key", from_env({})),
            ("a license without the feature", licensed(["sync.schedule"])),
            ("a lapsed license", licensed([feature], expires_in=-GRACE_SECONDS - 60))]


def declared_type(type_id):
    """``type_id`` as erebus-pro declares it (whether or not this checkout is installed)."""
    from erebus.cataloging import connector_types
    return connector_types.load_types(eps=declared_entry_points(connector_types.GROUP)).get(type_id)


class _Raising:
    """Swap ``module.attr`` for a callable raising ``exc`` while the case runs."""

    def __init__(self, module, attr, exc):
        self.module, self.attr, self.exc = module, attr, exc

    def __enter__(self):
        self.saved = getattr(self.module, self.attr)

        def boom(*_a, **_kw):
            raise self.exc
        setattr(self.module, self.attr, boom)

    def __exit__(self, *_exc):
        setattr(self.module, self.attr, self.saved)


class SnowflakeBackend:
    name = "snowflake"
    tier = "pro"
    schemas = True
    primary_key = False  # INFORMATION_SCHEMA names no key columns; a key is not enforced anyway
    integer_classes = ("numeric",)  # INTEGER is NUMBER(38,0)

    def connector_type(self):
        return declared_type(self.name)

    def unavailable(self):
        try:
            import fakesnow  # noqa: F401
            import snowflake.connector  # noqa: F401
        except ImportError as exc:
            return f"{exc.name} is not installed (pip install './pro[test]')"
        return None

    def setup(self):
        import fakesnow
        import snowflake.connector
        from fakesnow.cursor import FakeSnowflakeCursor

        self._stack = contextlib.ExitStack()
        self._stack.enter_context(fakesnow.patch(create_database_on_connect=False))
        admin = snowflake.connector.connect(account=_SF_ACCOUNT, user="ADMIN")
        cur = admin.cursor()
        cols = ('"id" INTEGER NOT NULL, "email" VARCHAR(200), "full_name" VARCHAR(200) NOT NULL, '
                '"first_name" VARCHAR(100), "last_name" VARCHAR(100), "active" BOOLEAN, "signup" DATE, "notes" TEXT')
        for stmt in (f"CREATE DATABASE {_SF_DB}", f"USE DATABASE {_SF_DB}", "CREATE SCHEMA CRM", "CREATE SCHEMA OTHER",
                     f'CREATE TABLE CRM."customers" ({cols})', 'CREATE TABLE CRM."orders" ("id" INTEGER, '
                     '"product_name" VARCHAR(100))', 'CREATE TABLE OTHER."orders" ("id" INTEGER, '
                     '"product_name" VARCHAR(100))', "INSERT INTO CRM.\"orders\" VALUES (1, 'Widget')"):
            cur.execute(stmt)
        cur.executemany(f'INSERT INTO CRM."customers" ({", ".join(chr(34) + f + chr(34) for f in FIELDS)}) '
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", ROWS)
        admin.close()
        self.sent = []
        real = FakeSnowflakeCursor.execute
        sent = self.sent

        def recording(cursor, command, *args, **kwargs):
            sent.append(command)
            return real(cursor, command, *args, **kwargs)
        FakeSnowflakeCursor.execute = recording
        self._stack.callback(setattr, FakeSnowflakeCursor, "execute", real)
        self.key = rsa_pem()

    def teardown(self):
        self._stack.close()

    def connector(self, entitlements=None):
        from erebus_pro.connectors.snowflake import SnowflakeConnector
        return SnowflakeConnector(entitlements or licensed(["connectors.snowflake"]))

    def unlicensed(self):
        return unlicensed_cases("connectors.snowflake")

    def settings(self, **over):
        return {"account": _SF_ACCOUNT, "user": _SF_USER, "database": _SF_DB, "warehouse": "SYNC_WH",
                "role": "EREBUS_READER", **over}

    def secrets(self):
        return {"private_key": self.key}

    def collection(self, table):
        return f"CRM.{table}"

    def statements(self, _source):
        return list(self.sent)

    def bad_cases(self):
        """(case, settings, secrets, error class, texts the error must not show[, around])."""
        import snowflake.connector
        from snowflake.connector import errors

        wrapped = rsa_pem("Zq-right-phrase")
        host = f"{_SF_ACCOUNT}.snowflakecomputing.com"
        return [
            ("a database the role cannot see", self.settings(database="NO_SUCH_DB_ZQ"), self.secrets(),
             "permission", ["NO_SUCH_DB_ZQ", self.key]),
            ("a malformed account id", self.settings(account="acme/evil.example#"), self.secrets(), "settings",
             ["evil.example", self.key]),
            ("no private key", self.settings(), {}, "auth", [_SF_USER]),
            ("a private key that is not PEM", self.settings(), {"private_key": "not-a-key-Zq-77"}, "auth",
             ["not-a-key-Zq-77"]),
            ("a wrong key passphrase", self.settings(),
             {"private_key": wrapped, "private_key_passphrase": "Zq-wrong-phrase"}, "auth",
             ["Zq-wrong-phrase", wrapped]),
            ("a key Snowflake rejects", self.settings(), self.secrets(), "auth", [_SF_USER, host, self.key],
             _Raising(snowflake.connector, "connect", errors.DatabaseError(
                 msg=f"JWT token is invalid. [{_SF_USER}@{host}]", errno=390144, sqlstate="08004"))),
            ("an account that cannot be reached", self.settings(), self.secrets(), "unreachable", [host],
             _Raising(snowflake.connector, "connect", errors.OperationalError(
                 msg=f"Could not connect to Snowflake backend after 2 attempt(s): {host}:443", errno=250001))),
        ]
