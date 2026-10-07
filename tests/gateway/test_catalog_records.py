"""Record links of app sources (``catalog_entry_records``).

Live Postgres on its own database. An app source links each value to the record it came
from. Relinking a changed record drops the links that sync did not renew and retires
entries left with no link of either kind; a deleted record (no new links) does the same.
A complete full sync drops every link of the source it did not renew. A value another
record, another source (value link) or an admin (manual) still holds stays active, and a
value-level retire leaves an entry a record still links. Deleting the source drops its
record links too. Rows are confined to their tenant under RLS.
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers import fresh_db, restricted_role

from erebus.gateway import catalog
from erebus.gateway.connectors import sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store.known_value_store import open_scope_crypto, open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_catalog_records")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _status(conn, crypto, scope_id):
    """{value: status} of the scope's entries."""
    with scoped(conn, scope_id):
        rows = conn.execute("SELECT value_nonce, value_ciphertext, status FROM catalog_entries WHERE scope_id = %s",
                            (scope_id,)).fetchall()
    return {crypto.decrypt(bytes(n), bytes(c)).decode(): s for n, c, s in rows}


def _links(conn, scope_id, source_id):
    """{(collection, record_id)} of the source's record links, with how many links each."""
    with scoped(conn, scope_id):
        rows = conn.execute("SELECT collection, record_id, count(*) FROM catalog_entry_records "
                            "WHERE scope_id = %s AND source_id = %s GROUP BY 1, 2", (scope_id, source_id)).fetchall()
    return {(c, r): n for c, r, n in rows}


def _source(conn, crypto, scope_id, name, connector_type="odoo"):
    return sources.create_source(conn, crypto, scope_id, name=name, connector_type=connector_type,
                                 settings={}, secrets={"api_key": "x"})


def _check_shape(conn):
    with conn.transaction():
        row = conn.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                           "WHERE relname = 'catalog_entry_records'").fetchone()
        fks = {r[0] for r in conn.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'catalog_entry_records'::regclass "
            "AND contype = 'f'").fetchall()}
    check("catalog_entry_records exists with forced row-level security", row == (True, True))
    check("... with a composite source FK and entry FK, both cascading",
          any("(scope_id, source_id) REFERENCES sources(scope_id, id) ON DELETE CASCADE" in f for f in fks)
          and any("(scope_id, entry_id) REFERENCES catalog_entries(scope_id, id) ON DELETE CASCADE" in f
                  for f in fks))


def _check_links(conn, crypto, scope_id, app):
    sync1 = uuid.uuid4()
    res = catalog.upsert_record_values(conn, crypto, scope_id, app, sync1, [
        ("res.partner", "7", "Zyx Qorbel", "PERSON"), ("res.partner", "7", "zyx@acme.example", "EMAIL_ADDRESS"),
        ("res.partner", "8", "Ilsabet Vranckx", "PERSON"), ("crm.lead", "3", "Ilsabet Vranckx", "PERSON"),
        ("res.partner", "9", "Mark", "PERSON"),
    ])
    check("record values are upserted once per value and label", res.added == 3 and res.rejected == 1)
    check("each kept value is linked to its record",
          _links(conn, scope_id, app) == {("res.partner", "7"): 2, ("res.partner", "8"): 1, ("crm.lead", "3"): 1})
    check("record values are active", set(_status(conn, crypto, scope_id).values()) == {"active"})
    return sync1


def _check_relink(conn, crypto, scope_id, app, other):
    sync2 = uuid.uuid4()
    catalog.upsert_values(conn, crypto, scope_id, other, uuid.uuid4(), [("zyx@acme.example", "EMAIL_ADDRESS")])
    catalog.upsert_record_values(conn, crypto, scope_id, app, sync2, [
        ("res.partner", "7", "Zyx Qorbel-Vranckx", "PERSON"), ("res.partner", "8", "Ilsabet Vranckx", "PERSON")])
    retired = catalog.relink_records(conn, scope_id, app, sync2, [("res.partner", "7"), ("res.partner", "8")])
    got = _status(conn, crypto, scope_id)
    check("relinking a changed record retires its old value", got["Zyx Qorbel"] == "retired")
    check("... and keeps its new value", got["Zyx Qorbel-Vranckx"] == "active")
    check("a value another source still links stays active", got["zyx@acme.example"] == "active")
    check("an unchanged record keeps its value", got["Ilsabet Vranckx"] == "active")
    check("relink reports one retired entry", retired == 1)
    check("only the renewed links of the relinked records remain",
          _links(conn, scope_id, app) == {("res.partner", "7"): 1, ("res.partner", "8"): 1, ("crm.lead", "3"): 1})

    gone = catalog.relink_records(conn, scope_id, app, uuid.uuid4(), [("res.partner", "8")])
    got = _status(conn, crypto, scope_id)
    check("a deleted record loses its links, but a value another record links stays",
          gone == 0 and got["Ilsabet Vranckx"] == "active" and ("res.partner", "8") not in _links(conn, scope_id, app))
    check("relinking nothing retires nothing", catalog.relink_records(conn, scope_id, app, uuid.uuid4(), []) == 0)


def _check_full_retire(conn, crypto, scope_id, app):
    catalog.add_known_value(conn, crypto, scope_id, "Acme Holding BV", "ORGANIZATION")
    catalog.upsert_record_values(conn, crypto, scope_id, app, uuid.uuid4(),
                                 [("res.partner", "12", "Acme Holding BV", "ORGANIZATION")])
    sync3 = uuid.uuid4()
    catalog.upsert_record_values(conn, crypto, scope_id, app, sync3,
                                 [("res.partner", "7", "Zyx Qorbel-Vranckx", "PERSON")])
    retired = catalog.retire_unseen_records(conn, scope_id, app, sync3)
    got = _status(conn, crypto, scope_id)
    check("a complete full sync drops the links it did not renew and retires what they held",
          got["Ilsabet Vranckx"] == "retired" and retired == 1)
    check("a manual value a record linked never retires", got["Acme Holding BV"] == "active")
    check("every remaining link carries the full sync's id", _links(conn, scope_id, app) == {("res.partner", "7"): 1})

    db_src = _source(conn, crypto, scope_id, "warehouse", "postgres")
    catalog.upsert_values(conn, crypto, scope_id, db_src, uuid.uuid4(), [("Zyx Qorbel-Vranckx", "PERSON")])
    check("a value-level retire keeps an entry a record still links",
          catalog.retire_unseen(conn, scope_id, db_src, uuid.uuid4()) == 0
          and _status(conn, crypto, scope_id)["Zyx Qorbel-Vranckx"] == "active")
    check("deleting the app source drops its record links and retires what only it held",
          sources.delete_source(conn, scope_id, app) == 1 and not _links(conn, scope_id, app)
          and _status(conn, crypto, scope_id)["Zyx Qorbel-Vranckx"] == "retired")


def _check_rls(dsn, kms, a_id, b_id):
    with restricted_role(dsn) as role:
        crypto_b = open_store(role, kms, b_id)._crypto
        src_b = _source(role, crypto_b, b_id, "b-odoo")
        catalog.upsert_record_values(role, crypto_b, b_id, src_b, uuid.uuid4(),
                                     [("res.partner", "1", "Bee Person", "PERSON")])
        role.commit()
        with scoped(role, a_id):
            seen = role.execute("SELECT count(*) FROM catalog_entry_records").fetchone()[0]
        check("a tenant bound to scope A sees none of scope B's record links", seen == 0)
        check("relinking B's record while bound to A touches nothing",
              catalog.relink_records(role, a_id, src_b, uuid.uuid4(), [("res.partner", "1")]) == 0
              and _links(role, b_id, src_b) == {("res.partner", "1"): 1})


def main():
    print("\n=== Record links of app sources ===\n")
    conn = fresh_db("erebus_gw_catalog_records")
    conn.autocommit = True
    kms = LocalKms()
    try:
        _check_shape(conn)
        a_id = provision_scope(conn, kms, "tenant-records-a")
        b_id = provision_scope(conn, kms, "tenant-records-b")
        crypto = open_scope_crypto(conn, kms, a_id)
        app = _source(conn, crypto, a_id, "odoo")
        other = _source(conn, crypto, a_id, "crm", "postgres")
        _check_links(conn, crypto, a_id, app)
        _check_relink(conn, crypto, a_id, app, other)
        _check_full_retire(conn, crypto, a_id, app)
        _check_rls(_DSN, kms, a_id, b_id)
    finally:
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
