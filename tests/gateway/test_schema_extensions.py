"""Extension schema files applied by core (spec 015 "Architecture": ``erebus.schema``).

Live Postgres on its own database. An entry point in ``erebus.schema`` names a directory
whose files all start with ``<entry point name>_``; core applies them after its own
migrations, under the same advisory lock, and records them in ``_migrations``. A file
without the prefix, a missing directory, a malformed name or a name used twice stops the
migration before anything is applied; an explicit ``schema_dir`` applies only that
directory.
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.store import db

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_schema_extensions")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _EP:
    def __init__(self, name, value):
        self.name = name
        self._value = value

    def load(self):
        return self._value


def _dir(files):
    root = Path(tempfile.mkdtemp())
    for name, sql in files.items():
        (root / name).write_text(sql)
    return root


def _refused(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


def _reset(conn):
    conn.execute("DROP SCHEMA public CASCADE")
    conn.execute("CREATE SCHEMA public")


def _check_validation(conn):
    good = _dir({"pro_0001_t.sql": "CREATE TABLE pro_t (id INT)"})
    check("the entry point group is erebus.schema", db.SCHEMA_GROUP == "erebus.schema")
    check("an extension's directory is listed under its name",
          db.extension_schema_dirs([_EP("pro", str(good))]) == [("pro", good)])
    unprefixed = _dir({"0001_t.sql": "CREATE TABLE t (id INT)"})
    for label, eps in (
        ("a file without the extension's prefix", [_EP("pro", unprefixed)]),
        ("a missing directory", [_EP("pro", good / "missing")]),
        ("a name that is not a lowercase word", [_EP("0001", good)]),
        ("the same name twice", [_EP("pro", good), _EP("pro", good)]),
    ):
        check(f"{label} is refused", _refused(lambda eps=eps: db.extension_schema_dirs(eps)))
    _reset(conn)
    check("a refused extension stops the migration", _refused(
        lambda: db.run_migrations(conn, extensions=[_EP("pro", unprefixed)])))
    check("and nothing was applied",
          conn.execute("SELECT to_regclass('public._migrations') IS NULL").fetchone()[0])


def _check_apply(conn):
    _reset(conn)
    ext = _dir({
        "pro_0001_sched.sql": "CREATE TABLE pro_sched (source_id UUID NOT NULL REFERENCES sources(id) "
                              "ON DELETE CASCADE, every_min INT)",
        "pro_0002_more.sql": "ALTER TABLE pro_sched ADD COLUMN note TEXT",
    })
    core = sorted(p.name for p in db._SCHEMA_DIR.glob("*.sql"))
    applied = db.run_migrations(conn, extensions=[_EP("pro", ext)])
    check("core files apply first, then the extension's in name order",
          applied == [*core, "pro_0001_sched.sql", "pro_0002_more.sql"])
    check("an extension table may reference a core table",
          conn.execute("SELECT to_regclass('public.pro_sched') IS NOT NULL").fetchone()[0])
    recorded = {r[0] for r in conn.execute("SELECT name FROM _migrations").fetchall()}
    check("extension files are recorded in _migrations", {"pro_0001_sched.sql", "pro_0002_more.sql"} <= recorded)
    check("a second run applies nothing", db.run_migrations(conn, extensions=[_EP("pro", ext)]) == [])
    (ext / "pro_0003_late.sql").write_text("CREATE INDEX pro_sched_every ON pro_sched (every_min)")
    check("a new extension file applies on the next run",
          db.run_migrations(conn, extensions=[_EP("pro", ext)]) == ["pro_0003_late.sql"])
    check("an explicit schema_dir applies only that directory",
          db.migration_files(db._SCHEMA_DIR) == sorted(db._SCHEMA_DIR.glob("*.sql")))


def main():
    print("\n=== Extension schema files (spec 015 D6) ===\n")
    with psycopg.connect(_DSN, autocommit=True) as conn:
        _check_validation(conn)
        _check_apply(conn)
        _reset(conn)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
