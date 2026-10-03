"""Source store on Postgres (spec 015 "Data model": sources; "Security": credentials).

Live Postgres on its own database. Credentials round-trip only for the source they were
sealed to (a ciphertext moved onto another row, or a changed key version, does not
open), are replaced whole by an update, and never appear in what list/get return. A
delete is refused while a job runs and cascades queued jobs otherwise. RLS keeps one
scope's sources out of another's reads and writes under a non-bypass role.
"""
import dataclasses
import os
import sys
import uuid
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers import fresh_db, restricted_role

from erebus.gateway.connectors import sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_connector_sources")
_SECRET = {"password": "Zq-hunter2-secret", "user": "reader"}
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


def _new(conn, crypto, scope_id, name="crm", **kw):
    return sources.create_source(conn, crypto, scope_id, name=name, connector_type="postgres",
                                 settings={"host": "db.example", "dbname": "crm"}, secrets=_SECRET, **kw)


def _check_roundtrip(conn, crypto, a_id):
    expires = datetime(2027, 8, 31, tzinfo=UTC)
    sid = _new(conn, crypto, a_id, credentials_expire_at=expires)
    info = sources.get_source(conn, a_id, sid)
    check("get_source returns the row", info is not None and info.name == "crm" and info.connector_type == "postgres")
    check("a new source is active with the default cap", (info.status, info.max_values) == ("active", 1000000))
    check("settings and credential expiry come back", info.settings["host"] == "db.example"
          and info.credentials_expire_at == expires)
    fields = {f.name for f in dataclasses.fields(sources.SourceInfo)}
    check("SourceInfo has no secret field", not {n for n in fields if "secret" in n})
    check("nothing list_sources returns carries the credential",
          all("hunter2" not in repr(s) for s in sources.list_sources(conn, a_id)))
    check("read_secrets opens the credentials for the worker", sources.read_secrets(conn, crypto, a_id, sid) == _SECRET)
    with scoped(conn, a_id):
        ct = conn.execute("SELECT secrets_ciphertext FROM sources WHERE id = %s", (sid,)).fetchone()[0]
    check("the stored blob is ciphertext", b"hunter2" not in bytes(ct))
    return sid


def _check_tamper(conn, crypto, a_id, sid):
    other = _new(conn, crypto, a_id, name="erp")
    with scoped(conn, a_id):
        conn.execute(
            "UPDATE sources SET (secrets_ciphertext, secrets_nonce) = "
            "(SELECT secrets_ciphertext, secrets_nonce FROM sources WHERE id = %s) WHERE id = %s",
            (sid, other),
        )
    check("a ciphertext moved onto another source does not open",
          _raises(sources.SecretsUnreadable, lambda: sources.read_secrets(conn, crypto, a_id, other)))
    with scoped(conn, a_id):
        conn.execute("UPDATE sources SET secrets_key_version = 99 WHERE id = %s", (other,))
    check("a key version other than the tenant key's does not open",
          _raises(sources.SecretsUnreadable, lambda: sources.read_secrets(conn, crypto, a_id, other)))
    check("an unknown source raises KeyError",
          _raises(KeyError, lambda: sources.read_secrets(conn, crypto, a_id, uuid.uuid4())))
    try:
        sources.read_secrets(conn, crypto, a_id, other)
    except sources.SecretsUnreadable as exc:
        check("the error names no credential and no cause", str(exc) == "source credentials cannot be read"
              and exc.__cause__ is None
              and (exc.__context__ is None or exc.__suppress_context__))


def _check_update(conn, crypto, a_id, sid):
    check("update_source replaces the credentials whole",
          sources.update_source(conn, crypto, a_id, sid, secrets={"token": "new-Tok"})
          and sources.read_secrets(conn, crypto, a_id, sid) == {"token": "new-Tok"})
    sources.update_source(conn, crypto, a_id, sid, status="paused", settings={"host": "db2.example"},
                          credentials_expire_at=None, name="crm2", max_values=5000)
    info = sources.get_source(conn, a_id, sid)
    check("update_source changes status, settings, name, cap and clears expiry",
          (info.status, info.settings, info.name, info.max_values, info.credentials_expire_at)
          == ("paused", {"host": "db2.example"}, "crm2", 5000, None))
    check("updated_at moves on update", info.updated_at >= info.created_at)
    check("an unknown status is refused",
          _raises(ValueError, lambda: sources.update_source(conn, crypto, a_id, sid, status="deleted")))
    check("update_source of a missing source returns False",
          sources.update_source(conn, crypto, a_id, uuid.uuid4(), name="x") is False)
    check("set_cursor stores the opaque cursor", sources.set_cursor(conn, a_id, sid, {"customers": "c-42"})
          and sources.get_source(conn, a_id, sid).cursor == {"customers": "c-42"})


def _check_delete(conn, crypto, a_id):
    busy = _new(conn, crypto, a_id, name="busy")
    with conn.transaction():
        conn.execute("INSERT INTO sync_jobs (scope_id, source_id, kind, status) VALUES (%s, %s, 'full', 'running')",
                     (a_id, busy))
    check("delete_source raises SourceBusy while a job runs",
          _raises(sources.SourceBusy, lambda: sources.delete_source(conn, a_id, busy)))
    check("a refused delete leaves the source", sources.get_source(conn, a_id, busy) is not None)
    queued = _new(conn, crypto, a_id, name="queued")
    with conn.transaction():
        conn.execute("INSERT INTO sync_jobs (scope_id, source_id, kind) VALUES (%s, %s, 'sample')", (a_id, queued))
    check("delete_source with only a queued job succeeds", sources.delete_source(conn, a_id, queued) == 0)
    with conn.transaction():
        left = conn.execute("SELECT count(*) FROM sync_jobs WHERE source_id = %s", (queued,)).fetchone()[0]
    check("its queued job is gone with it", left == 0)


def _check_rls(kms, a_id, b_id):
    with restricted_role(_DSN) as role:
        crypto_a = open_store(role, kms, a_id)._crypto
        crypto_b = open_store(role, kms, b_id)._crypto
        b_src = _new(role, crypto_b, b_id, name="b-only")
        check("scope A does not list scope B's source",
              all(s.id != b_src for s in sources.list_sources(role, a_id)))
        check("scope A cannot get scope B's source", sources.get_source(role, a_id, b_src) is None)
        check("scope A cannot update scope B's source",
              sources.update_source(role, crypto_a, a_id, b_src, name="stolen") is False)
        check("scope A cannot read scope B's credentials",
              _raises(KeyError, lambda: sources.read_secrets(role, crypto_a, a_id, b_src)))
        check("scope A cannot delete scope B's source", sources.delete_source(role, a_id, b_src) is None)
        check("scope B still has its source", sources.get_source(role, b_id, b_src).name == "b-only")


def main():
    print("\n=== Source store (spec 015 sources, credentials) ===\n")
    try:
        conn = fresh_db("erebus_gw_connector_sources")
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    try:
        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/sources/a")
        b_id = provision_scope(conn, kms, "org/sources/b")
        crypto = open_store(conn, kms, a_id)._crypto
        sid = _check_roundtrip(conn, crypto, a_id)
        _check_tamper(conn, crypto, a_id, sid)
        _check_update(conn, crypto, a_id, sid)
        _check_delete(conn, crypto, a_id)
        conn.commit()
        _check_rls(kms, a_id, b_id)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
