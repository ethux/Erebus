# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""A throwaway Postgres database per Pro test (not a test module itself).

Derived from ``EREBUS_PG_DSN`` (the maintenance DSN, as in the gateway gate) and dropped
afterwards, so no Pro test migrates the shared database. Unset: the test skips.
"""
from __future__ import annotations

import contextlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


@contextlib.contextmanager
def temp_database(name: str):
    """Yield the DSN of a new, empty database ``erebus_pro_<name>``, or ``None`` to skip."""
    maint = os.environ.get("EREBUS_PG_DSN")
    if not maint:
        yield None
        return
    import psycopg
    from psycopg import conninfo

    info = conninfo.conninfo_to_dict(maint)
    info["dbname"] = "postgres"
    admin_dsn = conninfo.make_conninfo(**info)
    db = f"erebus_pro_{name}"
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(f'DROP DATABASE IF EXISTS "{db}"')
        admin.execute(f'CREATE DATABASE "{db}"')
    info["dbname"] = db
    try:
        yield conninfo.make_conninfo(**info)
    finally:
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
