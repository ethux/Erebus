"""Connector tables of migration 0021 (spec 015 "Data model").

Checks the shape the spec fixes: which tables carry FORCE row-level security and which
have none, scope_id on the link tables, the composite source FKs that stop cross-tenant
links, the one-active-job-per-source index, the catalog_entries defaults for rows that
predate 0021, and RLS isolation between two scopes under a role that does not bypass it.
Live Postgres; self-skips without it.
"""
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
from helpers import restricted_role
from psycopg import errors as pg_errors

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_connectors_schema")
_SCHEMA = Path(__file__).resolve().parents[2] / "erebus" / "gateway" / "schema"
_RLS_TABLES = ("sources", "source_fields", "catalog_entries", "catalog_entry_sources", "catalog_suppressions")
_OPEN_TABLES = ("sync_jobs", "catalog_versions")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _raises(exc_type, fn):
    try:
        fn()
    except exc_type:
        return True
    return False


def _migrate_to_0020(conn):
    """Apply every migration before 0021, so a pre-0021 catalog row can be written."""
    tmp = Path(tempfile.mkdtemp())
    try:
        for path in sorted(_SCHEMA.glob("*.sql")):
            if path.name < "0021":
                shutil.copy(path, tmp / path.name)
        db.run_migrations(conn, tmp)
    finally:
        shutil.rmtree(tmp)


def _columns(conn, table):
    rows = conn.execute(
        "SELECT column_name, is_nullable, column_default FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = %s",
        (table,),
    ).fetchall()
    return {name: (nullable == "YES", default) for name, nullable, default in rows}


def _fks(conn, table):
    """Return {(local cols), (referenced table, referenced cols), on-delete} per FK of ``table``."""
    rows = conn.execute(
        "SELECT c.conname, c.confrelid::regclass::text, c.confdeltype, "
        "  ARRAY(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n, i) "
        "        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n ORDER BY k.i), "
        "  ARRAY(SELECT a.attname FROM unnest(c.confkey) WITH ORDINALITY k(n, i) "
        "        JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n ORDER BY k.i) "
        "FROM pg_constraint c WHERE c.contype = 'f' AND c.conrelid = %s::regclass",
        (table,),
    ).fetchall()
    return {(tuple(local), ref, tuple(ref_cols), deltype) for _name, ref, deltype, local, ref_cols in rows}


def _check_shape(conn):
    for table in _RLS_TABLES:
        rls, force = conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass", (table,)
        ).fetchone()
        check(f"{table} has row-level security enabled and forced", rls and force)
        policies = conn.execute("SELECT policyname FROM pg_policies WHERE tablename = %s", (table,)).fetchall()
        check(f"{table} has its scope policy", (f"{table}_scope",) in policies)
    for table in _OPEN_TABLES:
        rls = conn.execute("SELECT relrowsecurity FROM pg_class WHERE oid = %s::regclass", (table,)).fetchone()[0]
        check(f"{table} has no row-level security (read across tenants)", rls is False)

    for table in ("source_fields", "catalog_entry_sources", "catalog_suppressions", "sync_jobs", "catalog_versions"):
        cols = _columns(conn, table)
        check(f"{table} carries a NOT NULL scope_id", "scope_id" in cols and cols["scope_id"][0] is False)

    source_fk = (("scope_id", "source_id"), "sources", ("scope_id", "id"), "c")
    for table in ("source_fields", "catalog_entry_sources", "sync_jobs"):
        check(f"{table} has the composite source FK with ON DELETE CASCADE", source_fk in _fks(conn, table))
    entry_fk = (("scope_id", "entry_id"), "catalog_entries", ("scope_id", "id"), "c")
    check("catalog_entry_sources has a composite entry FK", entry_fk in _fks(conn, "catalog_entry_sources"))

    src = _columns(conn, "sources")
    for col in ("id", "scope_id", "name", "connector_type", "settings", "secrets_ciphertext", "secrets_nonce",
                "secrets_key_version", "credentials_expire_at", "cursor", "status", "max_values",
                "created_at", "updated_at"):
        check(f"sources.{col} exists", col in src)
    check("sources.max_values defaults to 1,000,000", "1000000" in (src["max_values"][1] or ""))
    check("sources.status defaults to active", "active" in (src["status"][1] or ""))

    jobs = _columns(conn, "sync_jobs")
    for col in ("id", "scope_id", "source_id", "kind", "status", "attempts", "created_at", "not_before",
                "heartbeat_at", "leased_until", "started_at", "finished_at", "rows_seen", "values_added",
                "values_retired", "error", "lease_token", "limited_since"):
        check(f"sync_jobs.{col} exists", col in jobs)
    fields = _columns(conn, "source_fields")
    for col in ("id", "scope_id", "source_id", "collection", "field", "db_type", "label", "decision", "reason"):
        check(f"source_fields.{col} exists", col in fields)
    links = _columns(conn, "catalog_entry_sources")
    check("catalog_entry_sources has entry_id, source_id, last_seen_sync_id",
          {"entry_id", "source_id", "last_seen_sync_id"} <= set(links))
    check("catalog_suppressions keys on a label-free value_index",
          {"scope_id", "value_index", "created_at"} <= set(_columns(conn, "catalog_suppressions")))
    check("catalog_versions has scope_id, version, updated_at",
          {"scope_id", "version", "updated_at"} <= set(_columns(conn, "catalog_versions")))


def _insert_source(conn, scope_id, name="crm"):
    with scoped(conn, scope_id):
        return conn.execute(
            "INSERT INTO sources (scope_id, name, connector_type, secrets_ciphertext, secrets_nonce) "
            "VALUES (%s, %s, 'postgres', '\\x00', '\\x00') RETURNING id",
            (scope_id, name),
        ).fetchone()[0]


def _insert_job(conn, scope_id, source_id, status="queued"):
    with conn.transaction():
        conn.execute(
            "INSERT INTO sync_jobs (scope_id, source_id, kind, status) VALUES (%s, %s, 'full', %s)",
            (scope_id, source_id, status),
        )


def _check_constraints(conn, a_id, b_id):
    src_a = _insert_source(conn, a_id)
    src_a2 = _insert_source(conn, a_id, "erp")
    _insert_job(conn, a_id, src_a)
    check("a second queued job for one source is refused",
          _raises(pg_errors.UniqueViolation, lambda: _insert_job(conn, a_id, src_a)))
    check("a running job also blocks a queued one",
          _raises(pg_errors.UniqueViolation, lambda: _insert_job(conn, a_id, src_a, "running")))
    _insert_job(conn, a_id, src_a, "done")
    _insert_job(conn, a_id, src_a, "failed")
    check("finished jobs do not count against the one-job rule", True)
    _insert_job(conn, a_id, src_a2)
    check("another source of the same scope gets its own queued job", True)

    check("a job naming another scope's source is refused by the composite FK",
          _raises(pg_errors.ForeignKeyViolation, lambda: _insert_job(conn, b_id, src_a2, "done")))

    def cross_field():
        with scoped(conn, b_id):
            conn.execute(
                "INSERT INTO source_fields (scope_id, source_id, collection, field, decision) "
                "VALUES (%s, %s, 'customers', 'email', 'auto')",
                (b_id, src_a),
            )

    check("a field row naming another scope's source is refused", _raises(pg_errors.ForeignKeyViolation, cross_field))

    def bad_status():
        with scoped(conn, a_id):
            conn.execute("UPDATE sources SET status = 'deleted' WHERE id = %s", (src_a,))

    check("sources.status accepts only active/paused/needs_attention", _raises(pg_errors.CheckViolation, bad_status))

    def bad_kind():
        with conn.transaction():
            conn.execute(
                "INSERT INTO sync_jobs (scope_id, source_id, kind, status) VALUES (%s, %s, 'export', 'done')",
                (a_id, src_a),
            )

    check("sync_jobs.kind accepts only the four job kinds", _raises(pg_errors.CheckViolation, bad_kind))

    with scoped(conn, a_id):
        conn.execute("DELETE FROM sources WHERE id = %s", (src_a,))
    left = conn.execute("SELECT count(*) FROM sync_jobs WHERE source_id = %s", (src_a,)).fetchone()[0]
    conn.commit()
    check("deleting a source cascades to its jobs", left == 0)


def _seed_scope(conn, scope_id, tag):
    """Write one row per RLS table (and the open tables) for ``scope_id`` through ``conn``."""
    src = _insert_source(conn, scope_id, f"src-{tag}")
    with scoped(conn, scope_id):
        entry = conn.execute(
            "INSERT INTO catalog_entries (scope_id, label, value_ciphertext, value_nonce, value_blind_index) "
            "VALUES (%s, 'PERSON', '\\x01', '\\x01', %s) RETURNING id",
            (scope_id, uuid.uuid4().bytes),
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO source_fields (scope_id, source_id, collection, field, decision) "
            "VALUES (%s, %s, 'customers', 'email', 'auto')",
            (scope_id, src),
        )
        conn.execute(
            "INSERT INTO catalog_entry_sources (scope_id, entry_id, source_id, last_seen_sync_id) "
            "VALUES (%s, %s, %s, %s)",
            (scope_id, entry, src, uuid.uuid4()),
        )
        conn.execute(
            "INSERT INTO catalog_suppressions (scope_id, value_index) VALUES (%s, %s)", (scope_id, uuid.uuid4().bytes)
        )
    _insert_job(conn, scope_id, src)
    with conn.transaction():
        conn.execute("INSERT INTO catalog_versions (scope_id, version) VALUES (%s, 1)", (scope_id,))
    return src


def _check_rls(dsn, a_id, b_id):
    with restricted_role(dsn) as role:
        unbound = {t: role.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in _RLS_TABLES}
        role.commit()
        check("an unbound session of a non-bypass role sees no tenant rows", set(unbound.values()) == {0})

        src_a = _seed_scope(role, a_id, "a")
        _seed_scope(role, b_id, "b")
        for table in _RLS_TABLES:
            with scoped(role, a_id):
                own = role.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                other = role.execute(f"SELECT count(*) FROM {table} WHERE scope_id = %s", (b_id,)).fetchone()[0]
            check(f"{table}: scope A sees only its own row under RLS", own == 1 and other == 0)

        def write_into_b_while_bound_to_a():
            with scoped(role, a_id):
                role.execute(
                    "INSERT INTO catalog_suppressions (scope_id, value_index) VALUES (%s, %s)",
                    (b_id, uuid.uuid4().bytes),
                )

        check("a write for scope B while bound to scope A violates the policy",
              _raises(pg_errors.InsufficientPrivilege, write_into_b_while_bound_to_a))

        def update_b_source_from_a():
            with scoped(role, a_id):
                return role.execute(
                    "UPDATE sources SET name = 'stolen' WHERE scope_id = %s RETURNING id", (b_id,)
                ).fetchall()

        check("scope A cannot update scope B's sources", update_b_source_from_a() == [])

        with role.transaction():
            jobs = role.execute("SELECT count(DISTINCT scope_id) FROM sync_jobs").fetchone()[0]
            versions = role.execute("SELECT count(*) FROM catalog_versions").fetchone()[0]
        check("sync_jobs is readable across tenants without a scope binding", jobs == 2)
        check("catalog_versions is readable across tenants without a scope binding", versions == 2)
        check("seeded scope A has a source id", isinstance(src_a, uuid.UUID))


def main():
    print("\n=== Connector schema: migration 0021 (spec 015 Data model) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        existing = conn.execute("SELECT to_regclass('_migrations')").fetchone()[0]
        conn.commit()
        if existing is not None:
            print("  (skipped: needs an empty database, as the release gate gives each test)")
            return
        _migrate_to_0020(conn)
        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/connectors/a")
        b_id = provision_scope(conn, kms, "org/connectors/b")
        with scoped(conn, a_id):
            old = conn.execute(
                "INSERT INTO catalog_entries (scope_id, label, value_ciphertext, value_nonce, value_blind_index) "
                "VALUES (%s, 'PERSON', '\\x02', '\\x02', '\\x02') RETURNING id",
                (a_id,),
            ).fetchone()[0]

        applied = db.run_migrations(conn)
        check("0021_connectors.sql applies on top of 0020", "0021_connectors.sql" in applied)
        with scoped(conn, a_id):
            origin, status, retired_at = conn.execute(
                "SELECT origin, status, retired_at FROM catalog_entries WHERE id = %s", (old,)
            ).fetchone()
        check("a pre-0021 catalog row becomes origin=manual, status=active", (origin, status) == ("manual", "active"))
        check("a pre-0021 catalog row has no retired_at", retired_at is None)

        def bad_origin():
            with scoped(conn, a_id):
                conn.execute("UPDATE catalog_entries SET origin = 'import' WHERE id = %s", (old,))

        check("catalog_entries.origin accepts only manual/source", _raises(pg_errors.CheckViolation, bad_origin))

        _check_shape(conn)
        conn.commit()
        with scoped(conn, a_id):
            conn.execute("DELETE FROM catalog_entries WHERE scope_id = %s", (a_id,))
        _check_constraints(conn, a_id, b_id)
        with conn.transaction():
            conn.execute("DELETE FROM sources")
            conn.execute("DELETE FROM catalog_suppressions")
        _check_rls(_DSN, a_id, b_id)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
