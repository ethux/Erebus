"""Known values from sources: upsert, links, retire, erase (spec 015 "Data model", "Sync behaviour").

Live Postgres on its own database. Checks the upsert rules (label normalized before the
blind index, short/numeric/single-word/suppressed values rejected, retired entries come
back, manual origin never downgraded, one entry per (value, label)), that only unseen
links retire and only source entries left with no link retire, that a retire waits for
a concurrent upsert holding the entry, the tenant cap, erasure under every label with a
suppression, catalog version bumps, and RLS isolation under a non-bypass role.
"""
import os
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
from helpers import fresh_db, restricted_role

from erebus.gateway import catalog
from erebus.gateway.connectors import sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store import catalog_versions
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_catalog_upsert")
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


def _entries(conn, crypto, scope_id):
    """{(value, label): (origin, status, retired_at is set)} of the scope."""
    with scoped(conn, scope_id):
        rows = conn.execute(
            "SELECT value_nonce, value_ciphertext, label, origin, status, retired_at "
            "FROM catalog_entries WHERE scope_id = %s",
            (scope_id,),
        ).fetchall()
    return {
        (crypto.decrypt(bytes(n), bytes(c)).decode(), label): (origin, status, retired is not None)
        for n, c, label, origin, status, retired in rows
    }


def _links(conn, scope_id, source_id):
    with scoped(conn, scope_id):
        return conn.execute(
            "SELECT count(*) FROM catalog_entry_sources WHERE scope_id = %s AND source_id = %s", (scope_id, source_id)
        ).fetchone()[0]


def _source(conn, crypto, scope_id, name):
    return sources.create_source(conn, crypto, scope_id, name=name, connector_type="postgres",
                                 settings={}, secrets={"password": "x"})


def _check_upsert(conn, crypto, a_id, src):
    sync1 = uuid.uuid4()
    res = catalog.upsert_values(conn, crypto, a_id, src, sync1, [
        ("Zyx Qorbel", "PERSON"), ("zyx   QORBEL", "person"), ("Al", "PERSON"), ("Mark", "PERSON"),
        ("12345", "IDENTIFIER"), ("jan@acme.com", "EMAIL_ADDRESS"), ("Zyx Qorbel", "ORGANIZATION"),
        ("Support", "ORGANIZATION"),
    ], stop_words={"support"})
    check("new values count as added", res.added == 3)
    check("rejected values are counted", res.rejected == 4)
    check("every kept value is linked", res.seen == 3 and _links(conn, a_id, src) == 3)
    got = _entries(conn, crypto, a_id)
    check("the label is normalized before the blind index (person = PERSON)",
          ("Zyx Qorbel", "PERSON") in got and len([k for k in got if k[1] == "PERSON"]) == 1)
    check("one value under two labels is two entries", ("Zyx Qorbel", "ORGANIZATION") in got)
    check("synced entries are origin=source and active",
          got[("jan@acme.com", "EMAIL_ADDRESS")] == ("source", "active", False))
    check("short, numeric, single-word PERSON and stop-list values never enter",
          not {"Al", "Mark", "12345", "Support"} & {v for v, _ in got})
    with scoped(conn, a_id):
        raw = conn.execute("SELECT value_ciphertext FROM catalog_entries WHERE scope_id = %s", (a_id,)).fetchall()
    check("values are stored as ciphertext", all(b"Qorbel" not in bytes(r[0]) for r in raw))

    again = catalog.upsert_values(conn, crypto, a_id, src, sync1, [("ZYX QORBEL", "PERSON")])
    check("re-seeing an active value adds nothing", again.added == 0 and again.seen == 1)
    check("an empty batch is a no-op", catalog.upsert_values(conn, crypto, a_id, src, sync1, []).seen == 0)
    return sync1


def _check_manual_and_retire(conn, crypto, a_id, src, src2, sync1):
    manual = catalog.add_known_value(conn, crypto, a_id, "Acme Holding", "ORGANIZATION")
    catalog.upsert_values(conn, crypto, a_id, src, sync1, [("acme holding", "organization")])
    got = _entries(conn, crypto, a_id)
    check("a source re-seeing a manual value keeps origin=manual", got[("Acme Holding", "ORGANIZATION")][0] == "manual")
    check("add_known_value dedupes into the same entry",
          catalog.add_known_value(conn, crypto, a_id, "ACME holding", "Organization") == manual)
    catalog.upsert_values(conn, crypto, a_id, src2, uuid.uuid4(), [("jan@acme.com", "EMAIL_ADDRESS")])

    sync2 = uuid.uuid4()
    catalog.upsert_values(conn, crypto, a_id, src, sync2, [("Zyx Qorbel", "PERSON")])
    retired = catalog.retire_unseen(conn, a_id, src, sync2)
    got = _entries(conn, crypto, a_id)
    check("retire_unseen retires the source entry no link holds", got[("Zyx Qorbel", "ORGANIZATION")][1:] ==
          ("retired", True))
    check("an entry another source still links stays active", got[("jan@acme.com", "EMAIL_ADDRESS")][1] == "active")
    check("a manual entry never retires", got[("Acme Holding", "ORGANIZATION")][1] == "active")
    check("the seen entry stays active", got[("Zyx Qorbel", "PERSON")][1] == "active")
    check("retire_unseen reports one retired entry", retired == 1)
    check("only the seen link of the source remains", _links(conn, a_id, src) == 1)

    back = catalog.upsert_values(conn, crypto, a_id, src, sync2, [("Zyx Qorbel", "ORGANIZATION")])
    got = _entries(conn, crypto, a_id)
    check("a re-seen retired entry becomes active with no retired_at",
          got[("Zyx Qorbel", "ORGANIZATION")] == ("source", "active", False))
    check("a re-activated entry counts as added", back.added == 1)


def _check_cap_and_race(dsn, conn, crypto, a_id, src):
    before = _entries(conn, crypto, a_id)
    active = sum(1 for v in before.values() if v[1] == "active")
    check("a batch passing the tenant cap raises TenantCapExceeded",
          _raises(catalog.TenantCapExceeded, lambda: catalog.upsert_values(
              conn, crypto, a_id, src, uuid.uuid4(), [("Kees Koevoet", "PERSON")], tenant_max=active)))
    check("the batch over the cap wrote nothing", _entries(conn, crypto, a_id) == before)
    check("the cap text is fixed", str(catalog.TenantCapExceeded()) == "tenant known-value cap reached")

    # A retire of source 1 waits on a concurrent source-2 upsert holding the entry, then
    # sees the new link and leaves the entry active.
    src2b = _source(conn, crypto, a_id, "race")
    sync_r = uuid.uuid4()
    catalog.upsert_values(conn, crypto, a_id, src, sync_r, [("Race Value", "PERSON")])
    other = psycopg.connect(dsn)
    result = {}
    conn.commit()  # the block below must be a real transaction, not a savepoint
    with conn.transaction():
        catalog.upsert_values(conn, crypto, a_id, src2b, uuid.uuid4(), [("Race Value", "PERSON")])
        worker = threading.Thread(
            target=lambda: result.setdefault("n", catalog.retire_unseen(other, a_id, src, uuid.uuid4())))
        worker.start()
        time.sleep(0.5)
        check("the retire blocks while the upsert holds the entry", worker.is_alive())
    worker.join(10)
    other.close()
    check("after the upsert commits the entry is still active",
          _entries(conn, crypto, a_id)[("Race Value", "PERSON")][1] == "active")


def _check_erase(conn, kms, crypto, a_id, src):
    store = open_store(conn, kms, a_id)
    store.mint("Zyx Qorbel", "PERSON")
    store.mint("Zyx Qorbel", "ORGANIZATION")
    v0 = catalog_versions.read(conn, a_id)
    counts = catalog.erase_value(conn, crypto, a_id, "zyx qorbel")
    check("erase removes the value's entries under every label", counts.entries == 2)
    check("erase removes the value's token_maps rows under every label", counts.tokens == 2)
    check("erase bumps the catalog version", catalog_versions.read(conn, a_id) == v0 + 1)
    got = _entries(conn, crypto, a_id)
    check("no entry of the erased value is left", not [k for k in got if k[0] == "Zyx Qorbel"])
    res = catalog.upsert_values(conn, crypto, a_id, src, uuid.uuid4(),
                                [("Zyx Qorbel", "PERSON"), ("Zyx Qorbel", "IDENTIFIER")])
    check("a suppressed value is refused under any label", res.rejected == 2 and res.added == 0)
    check("add_known_value refuses an erased value",
          _raises(ValueError, lambda: catalog.add_known_value(conn, crypto, a_id, "Zyx Qorbel", "PERSON")))
    check("add_known_value refuses a value under 3 characters",
          _raises(ValueError, lambda: catalog.add_known_value(conn, crypto, a_id, "Al", "PERSON")))
    v1 = catalog_versions.read(conn, a_id)
    catalog.add_known_value(conn, crypto, a_id, "Project Olympus", "PROJECT")
    check("add_known_value bumps the catalog version", catalog_versions.read(conn, a_id) == v1 + 1)


def _check_delete(conn, crypto, a_id):
    src = _source(conn, crypto, a_id, "doomed")
    catalog.upsert_values(conn, crypto, a_id, src, uuid.uuid4(), [("Doomed Person", "PERSON")])
    v0 = catalog_versions.read(conn, a_id)
    retired = sources.delete_source(conn, a_id, src)
    check("deleting a source retires the entries only it held", retired == 1)
    check("the retired entry keeps its row (token until retention)",
          _entries(conn, crypto, a_id)[("Doomed Person", "PERSON")][1] == "retired")
    check("deleting a source bumps the catalog version", catalog_versions.read(conn, a_id) == v0 + 1)
    check("deleting a missing source returns None", sources.delete_source(conn, a_id, src) is None)


def _check_rls(dsn, kms, a_id, b_id):
    with restricted_role(dsn) as role:
        crypto_a = open_store(role, kms, a_id)._crypto
        crypto_b = open_store(role, kms, b_id)._crypto
        src_b = _source(role, crypto_b, b_id, "b-crm")
        catalog.upsert_values(role, crypto_b, b_id, src_b, uuid.uuid4(), [("Bee Person", "PERSON")])
        check("scope B sees only its own entries under RLS", set(_entries(role, crypto_b, b_id)) ==
              {("Bee Person", "PERSON")})
        check("scope A sees none of scope B's entries",
              ("Bee Person", "PERSON") not in _entries(role, crypto_a, a_id))
        check("retire_unseen for a B source bound to A touches nothing",
              catalog.retire_unseen(role, a_id, src_b, uuid.uuid4()) == 0)
        check("scope B's entry is still active",
              _entries(role, crypto_b, b_id)[("Bee Person", "PERSON")][1] == "active")
        check("erasing in scope A leaves scope B's value",
              catalog.erase_value(role, crypto_a, a_id, "Bee Person").entries == 0)


def main():
    print("\n=== Known values from sources: upsert, retire, erase (spec 015) ===\n")
    try:
        conn = fresh_db("erebus_gw_catalog_upsert")
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    try:
        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/upsert/a")
        b_id = provision_scope(conn, kms, "org/upsert/b")
        crypto = open_store(conn, kms, a_id)._crypto
        src = _source(conn, crypto, a_id, "crm")
        src2 = _source(conn, crypto, a_id, "erp")
        sync1 = _check_upsert(conn, crypto, a_id, src)
        _check_manual_and_retire(conn, crypto, a_id, src, src2, sync1)
        _check_cap_and_race(_DSN, conn, crypto, a_id, src)
        _check_erase(conn, kms, crypto, a_id, src)
        _check_delete(conn, crypto, a_id)
        conn.commit()
        _check_rls(_DSN, kms, a_id, b_id)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
