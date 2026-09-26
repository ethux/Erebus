"""Create/drop a throwaway database for the gateway release gate (run.sh --db).

Gives every gateway test its own pristine database so the --db gate never
self-skips (a release gate must actually run) and so the few tests that apply a
migration subset out-of-band cannot pollute a shared database. Derives the
per-test DSN from the maintenance DSN, so it works for a local socket or a
fully-qualified remote DSN alike.

Usage:
  python tests/gateway/_dbgate.py create <maintenance_dsn> <dbname>  # prints the per-test DSN
  python tests/gateway/_dbgate.py drop   <maintenance_dsn> <dbname>
"""
import sys

import psycopg
from psycopg import conninfo


def main() -> int:
    action, maint_dsn, dbname = sys.argv[1], sys.argv[2], sys.argv[3]
    info = conninfo.conninfo_to_dict(maint_dsn)
    info["dbname"] = info.get("dbname") or "postgres"  # connect to a maintenance DB
    with psycopg.connect(conninfo.make_conninfo(**info), autocommit=True) as conn:
        # dbname is derived from a test filename by the caller (alnum + underscore),
        # so identifier quoting here is sufficient; CREATE/DROP cannot run in a txn.
        conn.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
        if action == "create":
            conn.execute(f'CREATE DATABASE "{dbname}"')
    if action == "create":
        info["dbname"] = dbname
        print(conninfo.make_conninfo(**info))  # the DSN the test should use
    return 0


if __name__ == "__main__":
    sys.exit(main())
