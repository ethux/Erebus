# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The BigQuery connector at the client boundary (spec 015 "Warehouse connectors", D9, D10).

On the goccy BigQuery emulator (``EREBUS_TEST_BIGQUERY_EMULATOR``; skipped without it
unless ``EREBUS_REQUIRE_BIGQUERY=1``). Every query bills at least 10 MB, so the distinct
values of all asked field groups of a table come from one query (a ``UNION ALL`` of
per-group ``SELECT DISTINCT``, tagged by group), each capped by ``max_bytes_billed``,
labelled and time-limited; sample rows come from the free table-read API, not a query.
A service-account key is used as given except its token endpoint, which is always
Google's; a workload identity (external account) file is refused. The worker's own
identity (ADC) is used only when the source asks for it (``auth: attached``). An
unreachable API fails fast with fixed text.
"""
import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from warehouse_backends import BigQueryBackend, licensed, service_account_key

from erebus.cataloging import sources
from erebus.cataloging.connector_errors import ConnectorError

_passed = 0
_GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _error(fn):
    try:
        fn()
    except ConnectorError as exc:
        return exc
    return None


def _check_one_query_per_table(b):
    src = b.connector().connect(b.settings(location="EU"), b.secrets())
    try:
        coll = b.collection("customers")
        src.list_fields(coll)
        before = len(b.sent)
        got = list(sources.distinct_groups(src, coll, [["email"], ["first_name", "last_name"], ["notes"]], 100))
        sent = b.sent[before:]
        check("all field groups of a table come from one query", len(sent) == 1 and "UNION ALL" in sent[0][0])
        check("... tagged by group, name parts as extra columns",
              {row for i, row in got if i == 1} >= {("Zyx", "Qorbel"), ("Anna", "Visser")}
              and [row for i, row in got if i == 2] == [("vip",)])
        config = sent[0][1]
        check("every query is capped by max_bytes_billed", config.maximum_bytes_billed == 10**9)
        check("every query is labelled and time-limited",
              config.labels == {"erebus": "sync"} and int(config.job_timeout_ms) == 600_000)
        check("the client runs in the source's location", b.handed[-1][2] == "EU")
        before = len(b.sent)
        list(sources.distinct_values(src, coll, ["email"], 100))
        check("one field's distinct values are one query too", len(b.sent) - before == 1)
        before = len(b.sent)
        records = list(src.iter_records(coll, limit=3, page_size=2))
        check("sample rows come from the table-read API, not a billed query",
              len(records) == 3 and len(b.sent) == before)
    finally:
        src.close()
    src = b.connector().connect({k: v for k, v in b.settings().items() if k != "max_bytes_billed"}, b.secrets())
    try:
        list(sources.distinct_values(src, b.collection("customers"), ["email"], 10))
        check("without max_bytes_billed no cap is sent", b.sent[-1][1].maximum_bytes_billed is None)
    finally:
        src.close()


def _check_locations(b):
    """With ``location`` set, a dataset in another location is skipped: BigQuery answers a
    query there 404 (not found in that location), which failed every sync as 'permission'.
    Without it every query runs where its dataset lives."""
    from google.api_core import exceptions
    from google.cloud import bigquery

    project, tokyo = b.settings()["project"], "erebus_contract_tokyo"
    b.admin.delete_dataset(tokyo, delete_contents=True, not_found_ok=True)
    dataset = bigquery.Dataset(f"{project}.{tokyo}")
    dataset.location = "asia-northeast1"
    b.admin.create_dataset(dataset)
    b.admin.create_table(bigquery.Table(f"{project}.{tokyo}.leads", schema=[bigquery.SchemaField("email", "STRING")]))
    real = bigquery.Client.query

    def located(client, query, *args, location=None, **kwargs):  # as BigQuery answers a pinned job location
        where = location or client.location
        if tokyo in query and where and where.lower() != "asia-northeast1":
            raise exceptions.NotFound(f"Not found: Dataset {project}:{tokyo} was not found in location {where}")
        return real(client, query, *args, location=location, **kwargs)
    bigquery.Client.query = located
    try:
        datasets = [*b.settings()["schemas"], tokyo]
        src = b.connector().connect(b.settings(location="EU", schemas=datasets), b.secrets())
        try:
            names = [c.name for c in src.list_collections()]
        finally:
            src.close()
        check("with a location set, a dataset in another location is skipped, not a failed sync",
              b.collection("customers") in names and not any(n.startswith(tokyo + ".") for n in names))
        src = b.connector().connect(b.settings(schemas=datasets), b.secrets())
        try:
            names = [c.name for c in src.list_collections()]
        finally:
            src.close()
        check("without a location, datasets in every location are read", {b.collection("customers"),
                                                                           f"{tokyo}.leads"} <= set(names))
    finally:
        bigquery.Client.query = real
        b.admin.delete_dataset(tokyo, delete_contents=True, not_found_ok=True)


def _check_credentials(b):
    import google.auth
    from google.oauth2 import service_account

    key = service_account_key(token_uri="https://evil.example/token", universe_domain="evil.example")
    b.connector().connect(b.settings(), {"service_account_key": key}).close()
    creds = b.handed[-1][1]
    check("a service-account key becomes service-account credentials",
          isinstance(creds, service_account.Credentials) and creds.service_account_email.startswith("erebus-sync@"))
    check("its token endpoint and universe are always Google's, whatever the file says",
          creds._token_uri == _GOOGLE_TOKEN and creds.universe_domain == "googleapis.com")

    asked = []
    real = google.auth.default
    sentinel = object()
    google.auth.default = lambda **kw: asked.append(kw) or (sentinel, "worker-project")
    try:
        exc = _error(lambda: b.connector().connect(b.settings(), {}))
        check("without a key and without auth: attached, the worker's identity is not used",
              exc is not None and exc.kind == "auth" and not asked)
        b.connector().connect(b.settings(auth="attached"), {}).close()
        check("auth: attached uses the worker's attached identity (ADC)", asked and b.handed[-1][1] is sentinel)
        exc = _error(lambda: b.connector().connect(b.settings(auth="sso"), {}))
        check("an unknown auth mode is a settings error", exc is not None and exc.kind == "settings")
    finally:
        google.auth.default = real


def _check_unreachable(b):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"

    def attempt():
        src = b.connector(endpoint=endpoint).connect(b.settings(), b.secrets())
        try:
            src.list_collections()
        finally:
            src.close()
    exc = _error(attempt)
    check("an unreachable API fails as 'unreachable' with fixed text",
          exc is not None and exc.kind == "unreachable" and str(exc) == "source unreachable")
    check("... naming no endpoint, and not chained", str(port) not in repr(exc) and exc.__cause__ is None
          and exc.__suppress_context__)


def _check_egress_exceptions():
    from erebus_pro.connectors.bigquery import BigQueryConnector

    connector = BigQueryConnector(licensed(["connectors.bigquery"]))
    check("auth: attached may reach the GCP metadata server past the worker's host lists, nothing else",
          set(connector.egress_exceptions({"project": "erebus-test", "auth": "attached"}))
          == {("169.254.169.254", 80), ("fd20:ce::254", 80)})
    check("... a service-account key needs no exception", not connector.egress_exceptions({"project": "erebus-test"}))


class _NoClient:
    def close(self):
        pass


def _check_byte_cap():
    from erebus_pro.connectors.bigquery import BigQueryConnector

    connector = BigQueryConnector(licensed(["connectors.bigquery"]), client_factory=lambda *_a: _NoClient())
    key = {"service_account_key": service_account_key()}
    mib10 = 10 * 1024 * 1024
    exc = _error(lambda: connector.connect({"project": "erebus-test", "max_bytes_billed": mib10 - 1}, key))
    check("a byte cap under BigQuery's 10 MiB minimum bill is a settings error (every query would be capped)",
          exc is not None and exc.kind == "settings")
    check("... 10 MiB itself is accepted", _error(lambda: connector.connect(
        {"project": "erebus-test", "max_bytes_billed": mib10}, key).close()) is None)


def main():
    print("\n=== BigQuery connector (spec 015) ===\n")
    _check_egress_exceptions()
    _check_byte_cap()
    b = BigQueryBackend()
    reason = b.unavailable()
    if reason:
        if os.environ.get("EREBUS_REQUIRE_BIGQUERY") == "1":
            raise AssertionError(reason)
        print(f"  - skipped ({reason})")
        return
    b.setup()
    try:
        _check_one_query_per_table(b)
        _check_locations(b)
        _check_credentials(b)
        _check_unreachable(b)
    finally:
        b.teardown()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
