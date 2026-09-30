"""Field mapping store (spec 015 "Data model": source_fields; "Sync behaviour": sample job).

Live Postgres on its own database. A sample writes one row per field or name tuple; an
admin decision survives re-samples unless the field turned unconfirmable; rule rows the
new sample no longer has go, admin rows stay; unconfirmable fields cannot be confirmed;
a decision bumps the catalog version; another scope's fields stay invisible.
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers import fresh_db, restricted_role

from erebus.gateway.connectors import fields, sources
from erebus.gateway.connectors.fields import FieldSample
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store import catalog_versions
from erebus.gateway.store.known_value_store import open_store, provision_scope

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_source_fields")
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


_FIRST = [
    FieldSample("customers", "email", "text", "EMAIL_ADDRESS", "auto", "name and pattern"),
    FieldSample("customers", "product_name", "text", "PERSON", "pending", "other *_name"),
    FieldSample("customers", "first_name", "text", None, "ignored", "pair required", confirmable=False),
    FieldSample("customers", "first_name+last_name", "text", "PERSON", "auto", "name tuple"),
    FieldSample("customers", "notes", "text", "PERSON", "pending", "model flagged"),
]


def _by_field(conn, scope_id, source_id):
    return {f.field: f for f in fields.list_fields(conn, scope_id, source_id)}


def _check_sample_and_decide(conn, a_id, src):
    accepted = fields.record_sample(conn, a_id, src, _FIRST)
    check("record_sample reports the accepted fields", accepted == 2)
    got = _by_field(conn, a_id, src)
    check("one row per field or name tuple", set(got) == {f.field for f in _FIRST})
    check("rule rows are decided_by=rule", {f.decided_by for f in got.values()} == {"rule"})
    check("accepted_fields lists auto fields", {f.field for f in fields.accepted_fields(conn, a_id, src)}
          == {"email", "first_name+last_name"})

    v0 = catalog_versions.read(conn, a_id)
    done = fields.decide_field(conn, a_id, src, got["product_name"].id, "confirmed")
    check("an admin can confirm a pending field", done.decision == "confirmed" and done.decided_by == "admin")
    check("a field decision bumps the catalog version", catalog_versions.read(conn, a_id) == v0 + 1)
    fields.decide_field(conn, a_id, src, got["email"].id, "ignored")
    check("an admin can ignore an auto field", _by_field(conn, a_id, src)["email"].decision == "ignored")
    check("an unconfirmable field cannot be confirmed", _raises(
        fields.FieldNotConfirmable, lambda: fields.decide_field(conn, a_id, src, got["first_name"].id, "confirmed")))
    check("the refusal is fixed text", str(fields.FieldNotConfirmable()) == "this field cannot be confirmed")
    check("only confirmed or ignored are admin decisions",
          _raises(ValueError, lambda: fields.decide_field(conn, a_id, src, got["notes"].id, "auto")))
    check("an unknown field id returns None", fields.decide_field(conn, a_id, src, uuid.uuid4(), "ignored") is None)
    check("a rule sample cannot claim confirmed",
          _raises(ValueError, lambda: fields.record_sample(
              conn, a_id, src, [FieldSample("customers", "x", "text", "PERSON", "confirmed")])))
    return got


def _check_resample(conn, a_id, src):
    second = [
        FieldSample("customers", "email", "varchar", "EMAIL_ADDRESS", "auto", "name and pattern"),
        FieldSample("customers", "product_name", "bytea", None, "ignored", "binary", confirmable=False),
        FieldSample("customers", "first_name+last_name", "text", "PERSON", "auto", "name tuple"),
    ]
    accepted = fields.record_sample(conn, a_id, src, second)
    got = _by_field(conn, a_id, src)
    check("an admin ignore survives a re-sample", (got["email"].decision, got["email"].decided_by)
          == ("ignored", "admin"))
    check("a re-sample refreshes db_type", got["email"].db_type == "varchar")
    check("an admin confirm of a field turned unconfirmable falls back to the rule",
          (got["product_name"].decision, got["product_name"].decided_by, got["product_name"].confirmable)
          == ("ignored", "rule", False))
    check("rule rows missing from the new sample are removed", "notes" not in got and "first_name" not in got)
    check("the accepted count honours admin decisions", accepted == 1)

    fields.decide_field(conn, a_id, src, got["first_name+last_name"].id, "confirmed")
    fields.record_sample(conn, a_id, src, [FieldSample("customers", "email", "text", "EMAIL_ADDRESS", "auto")])
    got = _by_field(conn, a_id, src)
    check("an admin row missing from the new sample is kept", "first_name+last_name" in got)


def _check_rls(kms, a_id, b_id):
    with restricted_role(_DSN) as role:
        crypto_b = open_store(role, kms, b_id)._crypto
        b_src = sources.create_source(role, crypto_b, b_id, name="b", connector_type="postgres", settings={},
                                      secrets={})
        fields.record_sample(role, b_id, b_src, _FIRST[:1])
        b_field = fields.list_fields(role, b_id, b_src)[0]
        check("scope A sees none of scope B's fields", fields.list_fields(role, a_id, b_src) == [])
        check("scope A cannot decide scope B's field",
              fields.decide_field(role, a_id, b_src, b_field.id, "ignored") is None)
        check("scope B's field is unchanged", fields.list_fields(role, b_id, b_src)[0].decision == "auto")


def main():
    print("\n=== Source field mapping (spec 015 source_fields) ===\n")
    try:
        conn = fresh_db("erebus_gw_source_fields")
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    try:
        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/fields/a")
        b_id = provision_scope(conn, kms, "org/fields/b")
        crypto = open_store(conn, kms, a_id)._crypto
        src = sources.create_source(conn, crypto, a_id, name="crm", connector_type="postgres", settings={},
                                    secrets={})
        _check_sample_and_decide(conn, a_id, src)
        _check_resample(conn, a_id, src)
        conn.commit()
        _check_rls(kms, a_id, b_id)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
