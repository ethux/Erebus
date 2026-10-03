# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The Pro warehouse and database connectors through the shared contract suite (spec 015
SC-6, SC-9, D6, D9).

The same checks as the free connectors (``tests/gateway/connector_contract.py``): each
lists collections and fields from the catalog, streams records and distinct values
(BigQuery: every field group of a table in one query), stays read-only (warehouses send
only reads; Oracle refuses a write through its connection, ORA-01456), fails with fixed
text that names no account, host, user, key or value, and takes its settings as the
worker checked them (Oracle dials only the address the worker's host lists allowed).
Each refuses to connect without ``connectors.<type>``. They register through
``erebus.sources`` and import their driver only in ``connect()``. Snowflake runs on
fakesnow; BigQuery on the emulator named by ``EREBUS_TEST_BIGQUERY_EMULATOR``; Oracle on
the database named by ``EREBUS_TEST_ORACLE_DSN`` (each skipped without it unless
``EREBUS_REQUIRE_<TYPE>=1``).
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import connector_contract
from connector_contract import check
from oracle_backend import OracleBackend
from warehouse_backends import BigQueryBackend, SnowflakeBackend, declared_entry_points

from erebus.cataloging import sources

_CONNECTORS = {"snowflake": ("erebus_pro.connectors.snowflake:SnowflakeConnector", "snowflake.connector"),
               "bigquery": ("erebus_pro.connectors.bigquery:BigQueryConnector", "google.cloud.bigquery"),
               "oracle": ("erebus_pro.connectors.oracle:OracleConnector", "oracledb")}


def _registration():
    eps = {ep.name: ep for ep in declared_entry_points(sources.GROUP)}
    for name, (target, driver) in _CONNECTORS.items():
        check(f"{name} registers through erebus.sources", name in eps and eps[name].value == target)
        check(f"{name}: the entry point loads a connector with that id", eps[name].load()().connector_id() == name)
        module = target.split(":")[0]
        code = f"import sys, {module}; print({driver!r} in sys.modules)"
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                             env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path[:4])})
        check(f"{name}: importing the connector module loads no driver", out.stdout.strip() == "False")


def main():
    print("\n=== Pro connector contract (spec 015 SC-6) ===\n")
    _registration()
    for backend in (SnowflakeBackend, BigQueryBackend, OracleBackend):
        connector_contract.run(backend)
    print(f"\n{connector_contract.passed}/{connector_contract.passed} passed\n")


if __name__ == "__main__":
    main()
