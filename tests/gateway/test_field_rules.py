"""The gateway field rules and guards (spec 015 D2, D9, SC-10, "Sync behaviour").

Pure. Every guard is checked on its own, then the SC-10 table is sampled end to end
through fake connections: a Postgres-shaped and a MySQL-shaped fake row source report
their column types and rows the way their information_schema and drivers do, plus a
real SQLite file read through PRAGMA table_info. None of those fields may be
auto-accepted, and name parts must yield full names only.
"""
import ast
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.cataloging import field_rules as fr
from erebus.gateway.connectors import policy

_passed = 0
_EMAILS = [f"user{i}@acme.nl" for i in range(10)]
_PHONES = ["+31 6 1234 5678", "020 555 0100", "(030) 123-4567", "+44 20 7946 0958"]


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


def _one(collection, name, db_type, values, *, pk=False, hint="", model=None):
    """Rule for a single field given its sample values."""
    spec = fr.FieldSpec(name, db_type, primary_key=pk, hint=hint)
    rows = [{name: v} for v in values]
    got = fr.gateway_rules(collection, [spec], rows, model=model)
    return next(r for r in got if r.field == name)


def _by_field(rules):
    return {r.field: r for r in rules}


def _check_words():
    w = fr.split_words
    check("words split on _, -, spaces and camelCase", w("first_name") == w("First-Name") == w("FirstName")
          == w("first Name") == ["first", "name"])
    check("an acronym ends before the next capitalised word", w("IPAddress") == ["ip", "address"])
    check("digits split off", w("address2") == ["address", "2"])
    check("a run of lowercase letters is one word", w("ipaddress") == ["ipaddress"])
    check("non-ASCII letters stay in the word", w("straßeNaam") == ["straße", "naam"])


def _check_types():
    t = fr.type_class
    for db_type in ("integer", "INT", "bigint", "int unsigned", "tinyint(1)", "smallserial", "INT64"):
        check(f"{db_type} is integer", t(db_type) == "integer")
    for db_type in ("boolean", "bool", "bit(1)", "BIT"):
        check(f"{db_type} is boolean", t(db_type) == "boolean")
    for db_type in ("date", "timestamp with time zone", "TIMESTAMP(6) WITH TIME ZONE", "datetime2", "year",
                    "time without time zone", "TIMESTAMP_NTZ", "interval"):
        check(f"{db_type} is date/time", t(db_type) == "datetime")
    for db_type in ("numeric(10,2)", "decimal", "double precision", "money", "NUMBER(10)", "float8", "real"):
        check(f"{db_type} is numeric", t(db_type) == "numeric")
    for db_type in ("inet", "cidr", "macaddr", "macaddr8"):
        check(f"{db_type} is a network type", t(db_type) == "network")
    for db_type in ("bytea", "BLOB", "longblob", "image", "varbinary(max)", "RAW(16)", "BYTES", "binary"):
        check(f"{db_type} is binary", t(db_type) == "binary")
    check("uuid and uniqueidentifier are uuid", t("uuid") == t("uniqueidentifier") == "uuid")
    check("json, jsonb and VARIANT are json", t("json") == t("jsonb") == t("VARIANT") == "json")
    for db_type in ("text", "character varying(255)", "varchar", "NVARCHAR(MAX)", "ntext", "CLOB", "NCLOB",
                    "VARCHAR2(100)", "STRING", "citext", "bpchar", ""):
        check(f"{db_type!r} is text", t(db_type) == "text")
    for db_type in ("xml", "ARRAY", "USER-DEFINED", "text[]", "enum('a','b')", "ARRAY<STRING>", "geometry"):
        check(f"{db_type!r} is not a type the rules know", t(db_type) == "unknown")


def _check_type_guards():
    for db_type, values in (("integer", [1, 2]), ("boolean", [True, False]), ("date", ["2024-01-15"]),
                            ("numeric", ["12.50"]), ("uuid", ["0f8fad5b-d9cb-469f-a165-70867728950e"]),
                            ("jsonb", ['{"a": 1}']), ("inet", ["10.0.0.1"]), ("cidr", ["10.0.0.0/8"]),
                            ("macaddr", ["08:00:2b:01:02:03"])):
        r = _one("customers", "email", db_type, values)
        check(f"a {db_type} field is ignored even when named email",
              (r.decision, r.reason, r.confirmable) == ("ignored", "non-text type", True))
    r = _one("customers", "photo", "bytea", [b"\x00"])
    check("a binary field is ignored and never confirmable",
          (r.decision, r.reason, r.confirmable) == ("ignored", "binary type", False))
    r = _one("customers", "full_name", "xml", ["<a/>"])
    check("an unknown type is pending, never auto", (r.decision, r.reason) == ("pending", "unsupported type"))
    r = _one("customers", "id", "integer", [1, 2, 3], pk=True)
    check("an integer primary key is ignored", r.decision == "ignored")
    r = _one("customers", "code", "text", ["A-100", "A-101"], pk=True)
    check("a text primary key goes to review", (r.decision, r.reason) == ("pending", "primary key"))
    r = _one("customers", "id", "varchar", ["c_100", "c_101"])
    check("a text id goes to review", (r.decision, r.reason) == ("pending", "primary key"))


def _check_person():
    r = _one("customers", "name", "text", ["Jan de Vries", "Anna Smit"])
    check("bare name in a people collection is PERSON auto",
          (r.decision, r.label, r.reason) == ("auto", "PERSON", "name"))
    for coll in ("public.klanten", "crm_contacts", "Users", "leads", "persons", "people", "members", "employees"):
        check(f"{coll} is named for people", _one(coll, "name", "text", ["Jan de Vries"]).decision == "auto")
    for coll in ("products", "customers_archive", "customer"):
        r = _one(coll, "name", "text", ["Jan de Vries"])
        check(f"bare name in {coll} is pending",
              (r.decision, r.label, r.reason) == ("pending", "PERSON", "name outside a people collection"))
    for name in ("full_name", "FullName", "contact_name", "customerName"):
        r = _one("orders", name, "text", ["Jan de Vries"])
        check(f"{name} is PERSON auto anywhere", (r.decision, r.label) == ("auto", "PERSON"))
    for name in ("product_name", "user_name", "display_name"):
        r = _one("customers", name, "text", ["Widget Pro"])
        check(f"{name} is pending", (r.decision, r.label, r.reason) == ("pending", "PERSON", "other *_name"))


def _check_organization():
    for name in ("company", "company_name", "CompanyName", "organisation", "organization", "account_name"):
        r = _one("customers", name, "text", ["Acme BV"])
        check(f"{name} is ORGANIZATION auto", (r.decision, r.label, r.reason) == ("auto", "ORGANIZATION", "name"))
    r = _one("accounts", "title", "text", ["Acme BV"], hint="organization")
    check("an app's organization hint is ORGANIZATION auto",
          (r.decision, r.label, r.reason) == ("auto", "ORGANIZATION", "connector hint"))
    r = _one("accounts", "title", "text", ["Jan de Vries"], hint="person")
    check("an app's person hint is PERSON auto", (r.decision, r.label) == ("auto", "PERSON"))


def _check_patterns():
    r = _one("customers", "email", "text", _EMAILS)
    check("a named email field of emails is auto", (r.decision, r.label, r.reason)
          == ("auto", "EMAIL_ADDRESS", "name and pattern"))
    r = _one("customers", "email", "text", [*_EMAILS[:8], "n/a", "unknown"])
    check("80% matching is enough", r.decision == "auto")
    r = _one("customers", "email", "text", [*_EMAILS[:7], "n/a", "unknown", "-"])
    check("70% matching is pending", (r.decision, r.label, r.reason)
          == ("pending", "EMAIL_ADDRESS", "pattern below threshold"))
    r = _one("customers", "email", "text", [*_EMAILS[:8], None, "", "  ", "x", "y"])
    check("empty values do not count toward the threshold", r.decision == "auto")
    r = _one("customers", "email_verified", "text", ["yes", "no", "yes"])
    check("email_verified as text is pending, not auto", (r.decision, r.reason)
          == ("pending", "pattern below threshold"))
    r = _one("customers", "email_verified", "boolean", [True, False])
    check("email_verified as boolean is ignored", r.decision == "ignored")
    r = _one("customers", "contact", "text", _EMAILS)
    check("an email by value pattern alone is auto", (r.decision, r.label, r.reason)
          == ("auto", "EMAIL_ADDRESS", "pattern"))
    r = _one("customers", "phone", "text", _PHONES)
    check("a named phone field of phones is auto", (r.decision, r.label) == ("auto", "PHONE_NUMBER"))
    r = _one("customers", "MobilePhone", "text", _PHONES[:1])
    check("camelCase phone names match", r.decision == "auto")
    r = _one("orders", "reference", "text", _PHONES)
    check("a phone by value pattern alone is pending", (r.decision, r.label, r.reason)
          == ("pending", "PHONE_NUMBER", "phone pattern only"))
    r = _one("orders", "created", "text", ["2024-01-15", "2023-12-31", "2024-02-29"])
    check("text dates are pending, not auto", (r.decision, r.reason) == ("pending", "phone pattern only"))
    r = _one("orders", "order_number", "text", ["1234567", "7654321", "1000001"])
    check("7-digit order numbers are pending, not auto", r.decision == "pending")
    r = _one("customers", "email", "text", [None, "", " "])
    check("a field with no non-empty sample is pending", (r.decision, r.reason) == ("pending", "empty sample"))


def _check_address():
    for name in ("address", "street", "home_address", "StreetAddress", "address_line1"):
        r = _one("customers", name, "text", ["Damrak 1, Amsterdam"])
        check(f"{name} is ADDRESS auto", (r.decision, r.label) == ("auto", "ADDRESS"))
    for name in ("ip_address", "IPAddress", "ipaddress", "mac_address", "MacAddress", "ip_street"):
        r = _one("servers", name, "text", ["Damrak 1, Amsterdam"])
        check(f"{name} is not ADDRESS", r.label != "ADDRESS" and r.decision != "auto")
    r = _one("customers", "address_id", "text", ["A1", "A2"])
    check("address before id is an identifier, pending", (r.decision, r.label) == ("pending", "IDENTIFIER"))
    r = _one("hosts", "address", "text", ["192.168.1.10", "10.0.0.1"])
    check("an address field of IP-shaped samples is pending",
          (r.decision, r.reason) == ("pending", "ip-shaped samples"))
    r = _one("hosts", "address", "text", ["Damrak 1", "fe80::1"])
    check("one IPv6 sample is enough to keep it pending", r.decision == "pending")
    r = _one("hosts", "ip_address", "text", ["192.168.1.10", "10.0.0.12"])
    check("ip_address is never auto", r.decision != "auto" and r.label != "ADDRESS")
    r = _one("customers", "email_address", "text", _EMAILS)
    check("email_address is an email, not an address", (r.decision, r.label) == ("auto", "EMAIL_ADDRESS"))


def _check_identifier():
    for name in ("customer_id", "CustomerId", "account", "account_number"):
        r = _one("customers", name, "text", ["C-1001", "C-1002"])
        check(f"{name} is IDENTIFIER pending",
              (r.decision, r.label, r.reason) == ("pending", "IDENTIFIER", "identifier"))


def _check_name_parts():
    p = fr.name_part
    for name in ("first_name", "FirstName", "givenname", "given-name", "voornaam", "First Name"):
        check(f"{name} is a first-name part", p(name) == "first")
    for name in ("middle_name", "MiddleName", "tussenvoegsel", "voorvoegsel"):
        check(f"{name} is a middle part", p(name) == "middle")
    for name in ("last_name", "LastName", "surname", "family_name", "achternaam"):
        check(f"{name} is a last-name part", p(name) == "last")
    for name in ("name", "first_name2", "contact_first_name", "nickname"):
        check(f"{name} is no name part", p(name) is None)
    j = fr.join_name
    check("parts join first, middle, last", j("Jan", ["de"], "Vries") == "Jan de Vries")
    check("an empty middle is left out", j("Jan", ["", None], "Vries") == "Jan Vries")
    check("whitespace is collapsed", j("  Jan ", ["van  der"], " Berg ") == "Jan van der Berg")
    check("several middle parts keep their order", j("Anna", ["van", "der"], "Berg") == "Anna van der Berg")
    check("no first or no last part gives no full name", j("", [], "Vries") is None and j("Jan", [], None) is None)


def _check_tuples():
    specs = [fr.FieldSpec("id", "integer", primary_key=True), fr.FieldSpec("achternaam", "varchar"),
             fr.FieldSpec("tussenvoegsel", "varchar"), fr.FieldSpec("voornaam", "varchar")]
    rows = [{"id": 1, "voornaam": "Jan", "tussenvoegsel": "de", "achternaam": "Vries"},
            {"id": 2, "voornaam": "Anna", "tussenvoegsel": "", "achternaam": "Smit"}]
    got = _by_field(fr.gateway_rules("klanten", specs, rows))
    t = got.get("voornaam+tussenvoegsel+achternaam")
    check("first, middle and last form one tuple in that order", t is not None
          and t.parts == ("voornaam", "tussenvoegsel", "achternaam"))
    check("the tuple is PERSON auto", (t.decision, t.label, t.reason) == ("auto", "PERSON", "name tuple"))
    check("the tuple's parts are never synced alone", all(
        (got[f].decision, got[f].reason, got[f].confirmable) == ("ignored", "in name tuple", False)
        for f in ("voornaam", "tussenvoegsel", "achternaam")))
    check("tuple rows give full names", [fr.tuple_value(t, r) for r in rows] == ["Jan de Vries", "Anna Smit"])

    got = _by_field(fr.gateway_rules("customers", [fr.FieldSpec("first_name", "text")], [{"first_name": "Will"}]))
    lone = got["first_name"]
    check("a lone first_name is ignored, pair required, unconfirmable",
          (lone.decision, lone.reason, lone.confirmable) == ("ignored", "pair required", False))
    check("a lone part forms no tuple", len(got) == 1)
    got = _by_field(fr.gateway_rules("customers", [fr.FieldSpec("tussenvoegsel", "text"),
                                                   fr.FieldSpec("last_name", "text")], [{"last_name": "May"}]))
    check("middle and last without first form no tuple", all(r.reason == "pair required" for r in got.values()))
    specs = [fr.FieldSpec("first_name", "text"), fr.FieldSpec("FirstName", "text"), fr.FieldSpec("surname", "text")]
    got = _by_field(fr.gateway_rules("customers", specs, [{"first_name": "Jan", "FirstName": "Jan",
                                                            "surname": "Vries"}]))
    check("two first-name columns are ambiguous: no tuple, parts unconfirmable",
          len(got) == 3 and all((r.reason, r.confirmable) == ("ambiguous name parts", False) for r in got.values()))
    specs = [fr.FieldSpec("first_name", "text"), fr.FieldSpec("last_name", "text")]
    got = _by_field(fr.gateway_rules("customers", specs, [{"first_name": "", "last_name": None}]))
    check("a tuple with no full name in the sample is pending",
          (got["first_name+last_name"].decision, got["first_name+last_name"].reason) == ("pending", "empty sample"))
    specs = [fr.FieldSpec("first_name", "integer"), fr.FieldSpec("last_name", "text")]
    got = _by_field(fr.gateway_rules("customers", specs, [{"first_name": 1, "last_name": "Vries"}]))
    check("a non-text part is ignored by type and the other part is lone",
          got["first_name"].reason == "non-text type" and got["last_name"].reason == "pair required")
    got = _by_field(fr.gateway_rules("contacts", [fr.FieldSpec("FirstName", "text", hint="person"),
                                                  fr.FieldSpec("LastName", "text", hint="person")],
                                     [{"FirstName": "Jan", "LastName": "Vries"}]))
    check("an app's person hint on a name part still pairs", got["FirstName+LastName"].decision == "auto"
          and got["FirstName"].decision == "ignored")


class _Model:
    def __init__(self, fn):
        self.fn = fn
        self.calls = 0

    def __call__(self, text):
        self.calls += 1
        return self.fn(text)


def _whole_person(text):
    return [(0, len(text), "PERSON")] if text.startswith("P ") else []


def _check_model():
    vals = ["P Jan de Vries", "P Anna Smit", "note", "call back", "ok", "later", "x1", "x2", "x3", "x4"]
    m = _Model(_whole_person)
    r = _one("tickets", "notes", "text", vals, model=m)
    check("a field the model flags in 20% of samples is pending, confirmable",
          (r.decision, r.label, r.reason, r.confirmable) == ("pending", "PERSON", "model flagged", True))
    check("the model sees each non-empty sample once", m.calls == len(vals))
    r = _one("tickets", "notes", "text", vals[:1] + vals[2:] + ["x5"], model=_Model(_whole_person))
    check("under 20% is no signal", (r.decision, r.reason, r.label) == ("ignored", "no pii signal", None))

    def partial(text):
        return [(0, 3, "PERSON")] if text.startswith("Jan") else []

    r = _one("tickets", "body", "text", ["Jan called about the invoice", "Jan again", "other"], model=_Model(partial))
    check("spans not covering the whole value keep it pending as free text, unconfirmable",
          (r.decision, r.reason, r.confirmable) == ("pending", "free text", False))
    m = _Model(_whole_person)
    _one("customers", "email", "text", _EMAILS, model=m)
    _one("customers", "photo", "bytea", [b"x"], model=m)
    check("the model is not asked about fields a rule decided", m.calls == 0)
    r = _one("tickets", "notes", "text", vals, model=None)
    check("with model review off an unmatched field is ignored", (r.decision, r.reason) == ("ignored", "no pii signal"))

    def boom(_text):
        raise RuntimeError("model down")

    check("a model error propagates (the sample job records failed)",
          _raises(RuntimeError, lambda: _one("tickets", "notes", "text", vals, model=boom)))


def _check_value_guards():
    r = fr.reject_value
    check("numeric under 6 digits is dropped", r("12345", "IDENTIFIER") == "numeric")
    check("6 digits are kept", r("123456", "IDENTIFIER") is None)
    check("'Will' as PERSON is a single word, dropped", r("Will", "PERSON") == "single_word")
    check("'May' as PERSON is a single word, dropped", r("May", "PERSON") == "single_word")
    check("'May' as ORGANIZATION is on the bundled stop-list", r("May", "ORGANIZATION") == "stop_word")
    check("'Will' as ORGANIZATION is on the bundled stop-list", r("will", "ORGANIZATION") == "stop_word")
    check("a stop word inside a longer value is kept", r("May Fashion BV", "ORGANIZATION") is None)
    check("a full name is kept", r("Jan de Vries", "PERSON") is None)
    check("a single-word organization not on the list is kept", r("Qorbelix", "ORGANIZATION") is None)
    check("short values are dropped", r("ab", "EMAIL_ADDRESS") == "short")
    check("the stop-list is casefolded single words", all(w == w.casefold() and " " not in w for w in fr.STOP_WORDS))
    check("the upsert policy uses the bundled list by default", policy.reject_reason("May", "ORGANIZATION")
          == "stop_word")


def _check_pure():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "erebus", "cataloging")
    for mod in ("field_rules.py", "field_types.py", "stop_words.py"):
        with open(os.path.join(path, mod), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        names += [("." * n.level) + (n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        bad = [n for n in names if "store" in n or "config" in n or "connector" in n or n.startswith("..")
               or n.startswith("erebus") or n in ("psycopg", "pymysql", "sqlite3")]
        check(f"{mod} imports no store, config, connector or driver", not bad)


# SC-10: the table the spec names, as a Postgres-, MySQL- and SQLite-shaped source reports it.
_SC10_ROWS = [
    {"id": i, "active": i % 2 == 0, "signup_date": "2024-01-15", "last_ip": f"10.0.0.{i}",
     "product_name": f"Widget {i}", "ip_address": f"192.168.1.{i}", "created_text": f"2024-02-{i + 1:02d}",
     "order_number": str(1000000 + i), "email_verified": "yes" if i % 2 else "no", "first_name": "Will"}
    for i in range(20)
]
_SC10_TYPES = {
    "postgres": {"id": "integer", "active": "boolean", "signup_date": "date", "last_ip": "inet",
                 "product_name": "character varying", "ip_address": "character varying", "created_text": "text",
                 "order_number": "text", "email_verified": "boolean", "first_name": "character varying"},
    "mysql": {"id": "int unsigned", "active": "tinyint(1)", "signup_date": "date", "last_ip": "varchar(45)",
              "product_name": "varchar(255)", "ip_address": "varchar(45)", "created_text": "varchar(32)",
              "order_number": "int", "email_verified": "tinyint(1)", "first_name": "varchar(64)"},
}


class _FakeRowSource:
    """What a connector reports: (name, db_type, pk) per column, then sample rows."""

    def __init__(self, types, rows):
        self.types, self.rows = types, rows

    def list_fields(self, _collection):
        return [(name, db_type, name == "id") for name, db_type in self.types.items()]

    def iter_records(self, _collection, limit):
        return iter(self.rows[:limit])


def _sample(source, collection):
    specs = [fr.FieldSpec(n, t, primary_key=pk) for n, t, pk in source.list_fields(collection)]
    return fr.gateway_rules(collection, specs, list(source.iter_records(collection, 1000)), model=_Model(lambda _t: []))


def _sqlite_source(path):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, active BOOLEAN, signup_date DATE, "
                 "last_ip TEXT, product_name TEXT, ip_address TEXT, created_text TEXT, order_number TEXT, "
                 "email_verified TEXT, first_name TEXT)")
    for r in _SC10_ROWS:
        conn.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?,?)", tuple(r.values()))
    conn.commit()
    types = {row[1]: row[2] for row in conn.execute("PRAGMA table_info(customers)")}
    rows = [dict(zip(types, row, strict=True)) for row in conn.execute("SELECT * FROM customers LIMIT 1000")]
    conn.close()
    return _FakeRowSource(types, rows)


def _check_sc10():
    with tempfile.TemporaryDirectory() as tmp:
        sources = {name: _FakeRowSource(types, _SC10_ROWS) for name, types in _SC10_TYPES.items()}
        sources["sqlite"] = _sqlite_source(os.path.join(tmp, "crm.db"))
        for name, source in sources.items():
            got = _by_field(_sample(source, "customers"))
            auto = sorted(f for f, r in got.items() if r.decision == "auto")
            check(f"SC-10 ({name}): no field of the table is auto-accepted", auto == [])
            check(f"SC-10 ({name}): the lone first_name is ignored, pair required",
                  got["first_name"].reason == "pair required")
            check(f"SC-10 ({name}): no ADDRESS label on an IP column",
                  got["ip_address"].label != "ADDRESS" and got["last_ip"].label != "ADDRESS")
    rows = [{"id": 1, "first_name": "Jan", "last_name": "Vries", "email": "jan@acme.nl"},
            {"id": 2, "first_name": "Will", "last_name": "May", "email": "will@acme.nl"}]
    src = _FakeRowSource({"id": "integer", "first_name": "text", "last_name": "text", "email": "text"}, rows)
    got = _by_field(_sample(src, "customers"))
    synced = [(fr.tuple_value(r, row), r.label) for r in got.values() if r.decision == "auto" and r.parts
              for row in rows]
    check("SC-10: name parts yield full names only", synced == [("Jan Vries", "PERSON"), ("Will May", "PERSON")])
    check("SC-10: the parts alone are never auto", got["first_name"].decision == got["last_name"].decision == "ignored")
    check("SC-10: the email beside them is auto", got["email"].decision == "auto")


def main():
    print("\n=== Gateway field rules and guards (spec 015 D2, D9, SC-10) ===\n")
    _check_words()
    _check_types()
    _check_type_guards()
    _check_person()
    _check_organization()
    _check_patterns()
    _check_address()
    _check_identifier()
    _check_name_parts()
    _check_tuples()
    _check_model()
    _check_value_guards()
    _check_pure()
    _check_sc10()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
