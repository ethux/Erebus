"""Loading a tenant's known-value matcher from the catalog (spec 015 "Gateway replicas").

Live Postgres on its own database. ``catalog.load_matcher`` streams the tenant's active
entries through a server-side cursor, decrypts them with one cipher and builds the
matcher: retired entries and values under 3 characters stay out, a value with several
labels matches as the manual one first and then the oldest, another tenant's values
never load (also under a non-bypass role), and a crypto-erased or unknown tenant raises.
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
from helpers import fresh_db, restricted_role

from erebus.gateway import catalog
from erebus.gateway.connectors import sources
from erebus.gateway.crypto.keyprovider import CryptoErased, LocalKms
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
from erebus.gateway.store.scope_context import scoped

_DB = "erebus_gw_known_values_load"
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


def _labels(matcher, text):
    return [(text[s:e], label) for s, e, label in matcher.match(text)]


def _insert_raw(conn, crypto, scope_id, value, label):
    """An entry written before the 3-character rule (the build must still skip it)."""
    nonce, ct = crypto.encrypt(value.encode("utf-8"))
    with scoped(conn, scope_id):
        conn.execute(
            "INSERT INTO catalog_entries (scope_id, label, value_ciphertext, value_nonce, value_blind_index) "
            "VALUES (%s, %s, %s, %s, %s)",
            (scope_id, label, ct, nonce, crypto.blind_index(value, label)),
        )


def _check_load(conn, kms, a_id, b_id):
    a = open_scope_crypto(conn, kms, a_id)
    b = open_scope_crypto(conn, kms, b_id)
    src = sources.create_source(conn, a, a_id, name="crm", connector_type="postgres", settings={},
                                secrets={"password": "x"})
    catalog.upsert_values(conn, a, a_id, src, uuid.uuid4(), [("Globex Inc", "ORGANIZATION")])
    catalog.upsert_values(conn, a, a_id, src, uuid.uuid4(), [("GLOBEX INC", "PERSON"), ("Acme Corp", "PERSON")])
    catalog.add_known_value(conn, a, a_id, "acme  corp", "IDENTIFIER")
    sync = uuid.uuid4()
    catalog.upsert_values(conn, a, a_id, src, sync, [("Old Customer", "PERSON")])
    with scoped(conn, a_id):
        conn.execute("UPDATE catalog_entries SET status = 'retired' WHERE scope_id = %s AND label = 'PERSON' "
                     "AND value_blind_index = %s", (a_id, a.blind_index("Old Customer", "PERSON")))
    _insert_raw(conn, a, a_id, "Li", "PERSON")
    for i in range(20):
        catalog.add_known_value(conn, a, a_id, f"Project Zyx{i:02d}", "PROJECT")
    catalog.add_known_value(conn, b, b_id, "Tenant Bee", "ORGANIZATION")
    conn.commit()

    matcher = catalog.load_matcher(conn, kms, a_id, batch=7)
    check("every active entry of a usable length loads (streamed in batches)", len(matcher) == 22)
    check("the manual label wins over an older source label",
          _labels(matcher, "Mail Acme Corp.") == [("Acme Corp", "IDENTIFIER")])
    check("among source labels the oldest wins",
          _labels(matcher, "Mail Globex Inc.") == [("Globex Inc", "ORGANIZATION")])
    check("a retired entry does not load", matcher.match("Old Customer") == [])
    check("an entry under 3 characters does not load", matcher.match("ask Li now") == [])
    check("another tenant's value does not load", matcher.match("Tenant Bee") == [])
    check("batched rows all match", len(matcher.match(" ".join(f"Project Zyx{i:02d}" for i in range(20)))) == 20)
    check("the other tenant loads only its own", len(catalog.load_matcher(conn, kms, b_id)) == 1)
    check("an empty tenant loads an empty matcher", len(catalog.load_matcher(conn, kms, provision_scope(
        conn, kms, "tenant-c"))) == 0)
    check("an unknown tenant raises", _raises(KeyError, lambda: catalog.load_matcher(conn, kms, uuid.uuid4())))


def main():
    print("\n=== Gateway known values: loading a tenant matcher ===\n")
    try:
        conn = fresh_db(_DB)
    except psycopg.OperationalError as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    dsn = conn.info.dsn
    kms = LocalKms()
    try:
        a_id = provision_scope(conn, kms, "tenant-a")
        b_id = provision_scope(conn, kms, "tenant-b")
        _check_load(conn, kms, a_id, b_id)
        with restricted_role(dsn) as restricted:
            loaded = catalog.load_matcher(restricted, kms, a_id)
            check("under a non-bypass role RLS still yields only the tenant's rows",
                  len(loaded) == 22 and loaded.match("Tenant Bee") == [])
        kms.destroy_kek(str(b_id))
        check("a crypto-erased tenant raises CryptoErased",
              _raises(CryptoErased, lambda: catalog.load_matcher(conn, kms, b_id)))
    finally:
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
