"""One contract suite for every free source connector (spec 015 SC-6, SC-9).

Runs the same checks against SQLite (a temp file), Postgres (this test's own database
as the source) and MySQL (a throwaway server named by ``EREBUS_TEST_MYSQL_DSN``;
skipped without it unless ``EREBUS_REQUIRE_MYSQL=1``). A connector lists collections
(user schemas only) and fields (db type, nullable, primary key), streams records and
distinct values, stays read-only (a raw write through its own connection is refused:
SQLite read-only, Postgres 25006, MySQL 1792), raises only fixed-text errors (no host,
DSN, user, password or value in the message or traceback) and dials only the address
the worker's network policy checked. Connector modules import their driver only in
``connect()``, and the database ones register through ``erebus.sources``. The checks
live in ``connector_contract``, shared with the Pro connectors.
"""
import os
import subprocess
import sys
from importlib import metadata
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import connector_contract
from connector_backends import BACKENDS
from connector_contract import check

from erebus.cataloging import sources

_REPO = Path(__file__).resolve().parents[2]


def _registration():
    eps = {ep.name: ep.value for ep in metadata.entry_points(group=sources.GROUP)}
    check("postgres and mysql register through erebus.sources",
          eps.get("postgres") == "erebus.cataloging.connectors.postgres:PostgresConnector"
          and eps.get("mysql") == "erebus.cataloging.connectors.mysql:MySQLConnector")
    code = ("import sys; import erebus.cataloging.connectors.postgres, erebus.cataloging.connectors.mysql;"
            "print('psycopg' in sys.modules, 'pymysql' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=_REPO, check=True)
    check("importing a connector module loads no driver", out.stdout.split() == ["False", "False"])


def main():
    print("\n=== source connector contract (spec 015 SC-6) ===\n")
    _registration()
    for backend in BACKENDS:
        connector_contract.run(backend)
    print(f"\n{connector_contract.passed}/{connector_contract.passed} passed\n")


if __name__ == "__main__":
    main()
