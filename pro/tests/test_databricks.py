# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The Databricks connector at the driver boundary (spec 015 "Warehouse connectors", D10).

No emulator exists, so a fake ``databricks.sql.connect`` and token endpoint record what
the connector sends (see ``databricks_backend``). A service principal signs in by OAuth
machine-to-machine through databricks-sdk: the connector asks the workspace's own token
endpoint (basic auth, no redirects, a timeout) and hands the driver only a credentials
provider, never the secret. The workspace host and HTTP path are checked against strict
patterns (a Databricks workspace domain, a SQL warehouse path), so a setting cannot
point the worker at another host. Sessions are tagged and time-limited, send no
telemetry and fetch no results from cloud storage. Every statement is a single SELECT,
and all accepted field groups of a table are read in one query. Without the license
feature nothing is requested.
"""
import inspect
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from databricks_backend import CLIENT_ID, HOST, HTTP_PATH, DatabricksBackend
from warehouse_backends import licensed

from erebus.cataloging import sources
from erebus.cataloging.connector_errors import ConnectorError, LicenseRequired

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _kind(fn):
    try:
        fn()
    except ConnectorError as exc:
        return exc.kind
    return None


def _check_sign_in(b):
    fake = b.fake
    src = b.connector().connect(b.settings(), b.secrets())
    try:
        url, data, auth, kw = fake.posts[-1]
        check("asks the workspace's own token endpoint for a client-credentials token",
              url == f"https://{HOST}/oidc/v1/token" and data == {"grant_type": "client_credentials",
                                                                 "scope": "all-apis"})
        check("... with the service principal as basic auth, no redirects and a timeout",
              auth == (CLIENT_ID, b.secret) and kw.get("allow_redirects") is False and 0 < kw.get("timeout", 0) <= 60)
        kw = fake.connects[-1]
        check("hands the driver the workspace host, warehouse path and catalog",
              (kw["server_hostname"], kw["http_path"], kw["catalog"]) == (HOST, HTTP_PATH, "erebus_ct"))
        check("... and a credentials provider, never the secret or a token",
              callable(kw["credentials_provider"]) and b.secret not in repr(kw)
              and not {"access_token", "oauth_client_secret", "password", "username", "auth_type"} & set(kw))
        check("the driver's requests carry the OAuth access token",
              fake.headers[-1]["Authorization"].startswith("Bearer dbx-access-"))
        posts = len(fake.posts)
        header = kw["credentials_provider"]()
        check("the token is reused until it expires", header() == header() and len(fake.posts) == posts)
        check("the session is tagged and every statement time-limited",
              kw["user_agent_entry"] == "erebus-sync" and kw["query_tags"] == {"erebus": "sync"}
              and kw["session_configuration"] == {"STATEMENT_TIMEOUT": "600"})
        check("no telemetry is sent and no result is fetched from cloud storage",
              kw["enable_telemetry"] is False and kw["use_cloud_fetch"] is False)
        check("TLS verification is never turned off", not {k for k in kw if k.startswith("_tls")})
    finally:
        src.close()
    from databricks.sql.client import Connection
    known = set(inspect.signature(Connection.__init__).parameters)
    import databricks.sql
    driver = "".join(_read(p) for p in _driver_files(databricks.sql.__path__[0]))
    check("every argument handed to the driver is one the installed driver reads",
          all(k in known or f'"{k}"' in driver for k in kw))


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _driver_files(root):
    for base, _dirs, files in os.walk(root):
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(base, name)


def _check_settings(b):
    good = ["dbc-a1b2c3d4-e5f6.cloud.databricks.com", "adb-1234567890123456.7.azuredatabricks.net",
            "1234567890123456.7.gcp.databricks.com", "acme-prod.cloud.databricks.com",
            "DBC-A1B2C3D4-E5F6.cloud.databricks.com"]
    for host in good:
        src = b.connector().connect(b.settings(server_hostname=host), b.secrets())
        src.close()
        check(f"accepts the workspace host {host}", b.fake.connects[-1]["server_hostname"] == host.lower())
    bad = ["evil.example", "cloud.databricks.com", "dbc-1.cloud.databricks.com.evil.example", f"https://{HOST}",
           f"{HOST}:8443", f"{HOST}/", f"user@{HOST}", "10.0.0.5", "dbc-1.cloud.databricks.com\x00", "localhost",
           "a.b.c.d.cloud.databricks.com"]
    for host in bad:
        before = len(b.fake.posts)
        kind = _kind(lambda host=host: b.connector().connect(b.settings(server_hostname=host), b.secrets()))
        check(f"refuses the host {host!r} before any request", kind == "settings" and len(b.fake.posts) == before)
    for path in ("/sql/1.0/warehouses/0123456789abcdef", "/sql/1.0/endpoints/0123456789abcdef"):
        src = b.connector().connect(b.settings(http_path=path), b.secrets())
        src.close()
        check(f"accepts the SQL warehouse path {path}", b.fake.connects[-1]["http_path"] == path)
    for path in ("/sql/protocolv1/o/123/0123-456789-abcdefgh", "/sql/1.0/warehouses/0123456789abcdef/../x",
                 "/sql/1.0/warehouses/0123456789abcdef?x=1", "https://evil.example/sql/1.0/warehouses/0123456789abcdef",
                 "sql/1.0/warehouses/0123456789abcdef", "/sql/1.0/warehouses/"):
        kind = _kind(lambda path=path: b.connector().connect(b.settings(http_path=path), b.secrets()))
        check(f"refuses the http path {path!r}", kind == "settings")
    check("a catalog is required", _kind(lambda: b.connector().connect(
        {k: v for k, v in b.settings().items() if k != "catalog"}, b.secrets())) == "settings")
    src = b.connector().connect(b.settings(schemas=["CRM"]), b.secrets())
    try:
        names = [c.name for c in src.list_collections()]
    finally:
        src.close()
    check("a schemas entry matches Unity Catalog's lower-case name", names and all(n.startswith("crm.") for n in names))


def _check_queries(b):
    fake = b.fake
    src = b.connector().connect(b.settings(), b.secrets())
    try:
        coll = b.collection("customers")
        fields = {f.name: f.db_type for f in src.list_fields(coll)}
        check("fields come from the catalog's information_schema.columns, with Unity Catalog's types",
              "information_schema.columns" in fake.sent[-1] and "`erebus_ct`" in fake.sent[-1]
              and fields["id"] == "INT" and fields["email"] == "STRING")
        before = len(fake.sent)
        got = list(sources.distinct_groups(src, coll, [["email"], ["first_name", "last_name"], ["notes"]], 100))
        check("all field groups of a table come from one query",
              len(fake.sent) - before == 1 and "UNION ALL" in fake.sent[-1])
        check("... tagged by group, name parts as extra columns",
              {row for i, row in got if i == 1} >= {("Zyx", "Qorbel"), ("Anna", "Visser")}
              and [row for i, row in got if i == 2] == [("vip",)])
        check("tables are named in full (catalog, schema, table)", "`erebus_ct`.`crm`.`customers`" in fake.sent[-1])
        list(src.iter_records(coll, limit=3, page_size=2))
    finally:
        src.close()
    check("every statement sent is a single SELECT",
          fake.sent and all(s.lstrip().upper().startswith("SELECT") and ";" not in s for s in fake.sent))


def _check_refresh_failure(b):
    """A token that can no longer be refreshed mid-sync fails the read as 'auth', naming nothing."""
    b.fake.expires_in = 30  # expired at once for the SDK: every request refreshes
    try:
        src = b.connector().connect(b.settings(), b.secrets())
        try:
            coll = b.collection("customers")
            src.list_fields(coll)
            b.fake.token_reply = (400, {"error": "invalid_client", "error_description": f"{CLIENT_ID} {b.secret}"})
            try:
                list(src.iter_records(coll, limit=1))
                exc = None
            except ConnectorError as raised:
                exc = raised
            check("a token refused mid-sync fails the read as 'auth' with fixed text",
                  exc is not None and exc.kind == "auth" and exc.__cause__ is None and b.secret not in repr(exc))
        finally:
            src.close()
    finally:
        b.fake.expires_in = 3600


def _check_license(b):
    posts, connects = len(b.fake.posts), len(b.fake.connects)
    from erebus_pro.license import from_env
    try:
        b.connector(entitlements=from_env({})).connect(b.settings(), b.secrets())
        refused = False
    except LicenseRequired:
        refused = True
    check("without the license feature nothing is requested: no token, no session",
          refused and len(b.fake.posts) == posts and len(b.fake.connects) == connects)
    src = b.connector(entitlements=licensed(["connectors.databricks"], expires_in=-60)).connect(b.settings(),
                                                                                                 b.secrets())
    src.close()
    check("a license in its grace period still syncs", len(b.fake.connects) == connects + 1)


def main():
    print("\n=== Databricks connector (spec 015) ===\n")
    b = DatabricksBackend()
    reason = b.unavailable()
    if reason:
        if os.environ.get("EREBUS_REQUIRE_DATABRICKS") == "1":
            raise AssertionError(reason)
        print(f"  - skipped ({reason})")
        return
    b.setup()
    try:
        _check_sign_in(b)
        _check_settings(b)
        _check_queries(b)
        _check_refresh_failure(b)
        _check_license(b)
    finally:
        b.teardown()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
