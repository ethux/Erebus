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
import os
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


_BQ_PROJECT = "erebus-test"
_BQ_CRM = "erebus_contract_crm"
_BQ_OTHER = "erebus_contract_other"
_BQ_CAP = 10**9


def service_account_key(**over) -> str:
    """A made-up service-account key file (JSON text) with a fresh RSA key."""
    import json
    info = {"type": "service_account", "project_id": _BQ_PROJECT, "private_key_id": "zq-key-id",
            "private_key": rsa_pem(), "client_email": f"erebus-sync@{_BQ_PROJECT}.iam.gserviceaccount.com",
            "client_id": "1000000000000000000001", "token_uri": "https://oauth2.googleapis.com/token"}
    return json.dumps({**info, **over})


class BigQueryBackend:
    """The goccy BigQuery emulator at ``EREBUS_TEST_BIGQUERY_EMULATOR`` (project ``erebus-test``).

    The connector parses the credentials as in production; the client factory then talks
    to the emulator anonymously and records the credentials it was handed.
    """

    name = "bigquery"
    tier = "pro"
    schemas = True
    primary_key = False  # keys are unenforced metadata; INFORMATION_SCHEMA.COLUMNS names none
    nullability = False  # the emulator reports every column nullable

    def connector_type(self):
        return declared_type(self.name)

    def unavailable(self):
        self.endpoint = os.environ.get("EREBUS_TEST_BIGQUERY_EMULATOR", "").rstrip("/")
        if not self.endpoint:
            return "EREBUS_TEST_BIGQUERY_EMULATOR is not set"
        try:
            self._client().list_datasets(timeout=5, retry=None, max_results=1)
        except Exception as exc:
            return f"no BigQuery emulator at EREBUS_TEST_BIGQUERY_EMULATOR ({type(exc).__name__})"
        return None

    def _client(self, endpoint=None):
        from google.api_core.client_options import ClientOptions
        from google.auth.credentials import AnonymousCredentials
        from google.cloud import bigquery
        return bigquery.Client(project=_BQ_PROJECT, credentials=AnonymousCredentials(),
                               client_options=ClientOptions(api_endpoint=endpoint or self.endpoint))

    def make_client(self, project, credentials, location, endpoint=None):
        from google.api_core.client_options import ClientOptions
        from google.auth.credentials import AnonymousCredentials
        from google.cloud import bigquery
        self.handed.append((project, credentials, location))
        return bigquery.Client(project=project, location=location, credentials=AnonymousCredentials(),
                               client_options=ClientOptions(api_endpoint=endpoint or self.endpoint))

    def setup(self):
        from google.cloud import bigquery

        admin = self._client()
        string = lambda n, mode="NULLABLE": bigquery.SchemaField(n, "STRING", mode=mode)
        customers = [bigquery.SchemaField("id", "INT64", mode="REQUIRED"), string("email"),
                     string("full_name", "REQUIRED"), string("first_name"), string("last_name"),
                     bigquery.SchemaField("active", "BOOL"), bigquery.SchemaField("signup", "DATE"), string("notes")]
        orders = [bigquery.SchemaField("id", "INT64"), string("product_name")]
        for ds in (_BQ_CRM, _BQ_OTHER):
            admin.delete_dataset(ds, delete_contents=True, not_found_ok=True)
            admin.create_dataset(ds)
            admin.create_table(bigquery.Table(f"{_BQ_PROJECT}.{ds}.orders", schema=orders))
        admin.create_table(bigquery.Table(f"{_BQ_PROJECT}.{_BQ_CRM}.customers", schema=customers))
        errors = admin.insert_rows_json(f"{_BQ_PROJECT}.{_BQ_CRM}.customers", [dict(zip(FIELDS, r, strict=True))
                                                                               for r in ROWS])
        errors += admin.insert_rows_json(f"{_BQ_PROJECT}.{_BQ_CRM}.orders", [{"id": 1, "product_name": "Widget"}])
        if errors:
            raise RuntimeError("could not load the BigQuery fixture")
        self.admin = admin
        self.handed = []
        self.sent = []  # (sql, job config) per query the connector ran
        self._stack = contextlib.ExitStack()
        real = bigquery.Client.query
        sent = self.sent

        def recording(client, query, job_config=None, *args, **kwargs):
            sent.append((query, job_config))
            return real(client, query, job_config, *args, **kwargs)
        bigquery.Client.query = recording
        self._stack.callback(setattr, bigquery.Client, "query", real)
        self.key = service_account_key()

    def teardown(self):
        self._stack.close()
        for ds in (_BQ_CRM, _BQ_OTHER):
            self.admin.delete_dataset(ds, delete_contents=True, not_found_ok=True)

    def connector(self, entitlements=None, endpoint=None):
        from erebus_pro.connectors.bigquery import BigQueryConnector
        connector = BigQueryConnector(entitlements or licensed(["connectors.bigquery"]),
                                      client_factory=lambda p, c, loc: self.make_client(p, c, loc, endpoint))
        connector.retry_s = 2  # the emulator answers at once; a closed port should fail fast
        return connector

    def unlicensed(self):
        return unlicensed_cases("connectors.bigquery")

    def settings(self, **over):
        # Named datasets: the emulator is shared, and it cannot read an empty dataset's INFORMATION_SCHEMA.
        return {"project": _BQ_PROJECT, "max_bytes_billed": _BQ_CAP, "schemas": [_BQ_CRM, _BQ_OTHER], **over}

    def secrets(self):
        return {"service_account_key": self.key}

    def collection(self, table):
        return f"{_BQ_CRM}.{table}"

    def statements(self, _source):
        return [sql for sql, _config in self.sent]

    def bad_cases(self):
        import google.auth.exceptions
        from google.api_core import exceptions
        from google.cloud import bigquery

        email = f"erebus-sync@{_BQ_PROJECT}.iam.gserviceaccount.com"
        capped = exceptions.BadRequest(f"Query exceeded limit for bytes billed: {_BQ_CAP}. Zyx Qorbel",
                                       errors=[{"reason": "bytesBilledLimitExceeded", "message": email}])
        limited = exceptions.Forbidden(f"Exceeded rate limits for {email}",
                                       errors=[{"reason": "rateLimitExceeded", "message": email}])
        denied = exceptions.Forbidden(f"Access Denied: Project {_BQ_PROJECT}: User does not have permission {email}",
                                      errors=[{"reason": "accessDenied", "message": email}])
        rejected = google.auth.exceptions.RefreshError(f"invalid_grant: Invalid JWT Signature. {email}")
        external = service_account_key(type="external_account")
        return [
            ("a malformed project id", self.settings(project="acme/evil.example"), self.secrets(), "settings",
             ["evil.example", self.key]),
            ("a byte cap that is not a positive number", self.settings(max_bytes_billed=0), self.secrets(),
             "settings", [self.key]),
            ("no credentials", self.settings(), {}, "auth", [email]),
            ("a key that is not JSON", self.settings(), {"service_account_key": "not-json-Zq-77"}, "auth",
             ["not-json-Zq-77"]),
            ("an external account file instead of a service-account key", self.settings(),
             {"service_account_key": external}, "auth", [email, external]),
            ("a key Google rejects", self.settings(), self.secrets(), "auth", [email, self.key],
             _Raising(bigquery.Client, "query", rejected)),
            ("a project the account may not read", self.settings(), self.secrets(), "permission", [email, _BQ_PROJECT],
             _Raising(bigquery.Client, "list_datasets", denied)),
            ("a query over the byte cap", self.settings(), self.secrets(), "incomplete", [email, "Zyx", str(_BQ_CAP)],
             _Raising(bigquery.Client, "query", capped)),
            ("a rate limit", self.settings(), self.secrets(), "limit", [email], _Raising(bigquery.Client, "query",
                                                                                         limited)),
        ]
