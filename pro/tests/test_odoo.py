# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The Odoo connector on respx fixtures: both APIs, fields, paging, cursors, limits.

Pure. ``odoo_fake.FakeOdoo`` stands in for Odoo 19 (JSON-2: bearer API key,
``X-Odoo-Database``) and Odoo 18 (XML-RPC ``execute_kw`` with database, login and key).
Without ``connectors.odoo`` nothing is sent. The API is detected from ``/web/version``
unless the ``api`` setting names it. Collections are ``res.partner`` and ``crm.lead``
with their fields from ``fields_get``: a company's name is the ``company`` field
(ORGANIZATION), a person's the ``name`` field. Leads are listed unless ``ir.model`` says
CRM is not installed; any other error while listing is raised, never read as a missing
collection. Records include archived ones and are paged by id. The cursor is the newest
``write_date`` (records without one ignored) when a read starts. Changes are read from the
cursor minus an overlap window, paged by id, so a late commit is read again and a
thousand records written in one transaction (one stored ``write_date``) end the read.
A malformed cursor is expired. ``saas~19`` and later is JSON-2. Odoo Online is
paced at one call per second; a 429 slows down, then reschedules. A wrong key is an
``auth`` failure, a model the user may not read a ``permission`` one, both in fixed
text. The integration user's key expiry is reported when it has one key. Every request
is a read.
"""
import itertools
import os
import sys
import time
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx
from odoo_fake import DB, KEY, LOGIN, FakeOdoo, read_only

from erebus.cataloging.connector_errors import ConnectorError, CursorExpired, LicenseRequired
from erebus.sync.netpolicy import NetworkPolicy, check_host, parse_hosts

_passed = 0
_FEATURE = "connectors.odoo"
_POLICY = NetworkPolicy(denied=parse_hosts("169.254.0.0/16"))


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def licensed(features, *, expires_in=86400):
    from erebus_pro.license import Entitlements, License
    now = int(time.time())
    return Entitlements(License("lic-odoo", "Acme", frozenset(features), now - 86400, now + expires_in))


class _Clock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def _error(fn):
    try:
        fn()
    except (ConnectorError, LicenseRequired, CursorExpired) as exc:
        return exc
    return None


def _connector(clock=None, features=(_FEATURE,)):
    from erebus_pro.connectors.odoo import OdooConnector
    clock = clock or _Clock()
    return OdooConnector(licensed(features), check=lambda host, port: check_host(_POLICY, host, port),
                         sleep=clock.sleep, clock=clock)


def _settings(fake, **extra):
    base = {"url": fake.base, "database": DB, "login": LOGIN}
    base.update(extra)
    return base


def _seed(fake):
    """Made-up partners and a lead, an hour apart (outside each other's overlap window)."""
    ids = {
        "zyx": fake.add("res.partner", name="Zyx Qorbel", email="zyx.qorbel@acme.example", phone="+31 20 555 0101",
                        street="Keizersgracht 7"),
        "acme": fake.add("res.partner", name="Qorbel Holding BV", is_company=True, email="info@qorbel.example",
                         vat="NL001234567B01"),
        "ilsabet": fake.add("res.partner", name="Ilsabet Vranckx", email="ilsabet@acme.example",
                            company_name="Vranckx Atelier", x_customer_code="CUST-88412"),
        "old": fake.add("res.partner", name="Oswin Tarrq", email="oswin.tarrq@acme.example", active=False),
        "lead": fake.add("crm.lead", name="Website inquiry", contact_name="Mila Brandt-Okafor",
                         partner_name="Okafor Logistics", email_from="mila@okafor.example"),
    }
    for model, records in fake.records.items():
        for record_id in sorted(records):
            fake.advance(3600)
            fake.write(model, record_id)
    return ids


def _check_license_and_settings(respx_mock):
    fake = FakeOdoo(19)
    respx_mock.route(host="acme-zq.odoo.com").mock(side_effect=fake.handle)
    err = _error(lambda: _connector(features=("connectors.snowflake",)).connect(_settings(fake), {"api_key": KEY}))
    check("without connectors.odoo the connector refuses before sending anything",
          isinstance(err, LicenseRequired) and str(err) == "requires Erebus Pro (feature connectors.odoo)"
          and fake.requests == [])
    for bad in ({"url": "http://acme-zq.odoo.com"}, {"url": "https://acme-zq.odoo.com/odoo"}, {"api": "jsonrpc"},
                {"database": ["x"]}):
        err = _error(lambda b=bad: _connector().connect(_settings(fake, **b), {"api_key": KEY}))
        check(f"a bad setting {sorted(bad)} fails as settings", err is not None and err.kind == "settings")
    err = _error(lambda: _connector().connect({"url": fake.base, "api": "xmlrpc"}, {"api_key": KEY}))
    check("XML-RPC without a database and login fails as settings", err.kind == "settings")
    check("a missing API key fails as auth", _error(lambda: _connector().connect(_settings(fake), {})).kind == "auth")
    check("none of that sent a request", fake.requests == [])


def _check_api(respx_mock, version):
    fake = FakeOdoo(version)
    respx_mock.route(host="acme-zq.odoo.com").mock(side_effect=fake.handle)
    ids = _seed(fake)
    ids["base"] = fake.add("res.partner", name="YourCompany Zq", is_company=True)
    fake.records["res.partner"][ids["base"]]["write_date"] = None  # as Odoo's own first partner
    clock = _Clock()
    source = _connector(clock).connect(_settings(fake), {"api_key": KEY})
    api = "JSON-2" if version >= 19 else "XML-RPC"
    paths = {p for _m, p, _r in fake.requests}
    check(f"Odoo {version}: the connector detects {api}",
          fake.requests[0][:2] == ("GET", "/web/version")
          and (("/xmlrpc/2/common" in paths) == (version < 19)))
    collections = [c.name for c in source.list_collections()]
    check(f"Odoo {version}: collections are res.partner and crm.lead", collections == ["res.partner", "crm.lead"])
    fields = {f.name: f for f in source.list_fields("res.partner")}
    check(f"Odoo {version}: a person's name and a company's name are separate fields",
          fields["name"].pii_hint == "person" and fields["company"].pii_hint == "organization")
    check(f"Odoo {version}: fields_get decides which fields exist (mobile only before 19)",
          ("mobile" in fields) == (version < 19) and fields["email"].pii_hint == "email"
          and fields["company_name"].pii_hint == "organization" and fields["vat"].pii_hint == "identifier"
          and fields["x_customer_code"].pii_hint == "" and fields["street"].pii_hint == "address")
    check(f"Odoo {version}: non-text and technical fields are left out",
          not {"id", "is_company", "active", "write_date", "comment", "city"} & set(fields))
    lead = {f.name: f.pii_hint for f in source.list_fields("crm.lead")}
    check(f"Odoo {version}: lead fields carry hints (the lead title is no person)",
          lead["contact_name"] == "person" and lead["partner_name"] == "organization"
          and lead["email_from"] == "email" and "name" not in lead)

    records = {r.record_ref: r.values for r in source.iter_records("res.partner", page_size=2)}
    check(f"Odoo {version}: every partner is read, archived ones included",
          set(records) == {str(i) for k, i in ids.items() if k != "lead"})
    check(f"Odoo {version}: a company is typed organization, a person keeps the name field",
          records[str(ids["acme"])]["company"] == "Qorbel Holding BV" and records[str(ids["acme"])]["name"] is None
          and records[str(ids["zyx"])]["name"] == "Zyx Qorbel" and records[str(ids["zyx"])]["company"] is None)
    check(f"Odoo {version}: empty Odoo values read as None", records[str(ids["zyx"])]["vat"] is None)
    reads = [r for r in fake.requests if "search_read" in r[2] and "apikeys" not in r[1] + r[2]]
    check(f"Odoo {version}: records are paged by id", len(reads) >= 3)
    cursor = source.cursor("res.partner")
    check(f"Odoo {version}: the cursor is the newest write_date when the read started, a record without one "
          "ignored", cursor == "wd:" + fake.newest("res.partner"))
    sample = list(source.iter_records("crm.lead", limit=1000))
    check(f"Odoo {version}: a lead reads its contact and company", sample[0].values["contact_name"]
          == "Mila Brandt-Okafor" and sample[0].values["partner_name"] == "Okafor Logistics")

    fake.advance(3600)
    fake.write("res.partner", ids["zyx"], name="Zyx Qorbel-Vranckx")
    fake.write("res.partner", ids["old"], active=True)
    changed = {r.record_ref: r.values for r in source.iter_changes("res.partner", ["name", "company"], cursor)}
    check(f"Odoo {version}: changes since the cursor are read, nothing else",
          changed == {str(ids["zyx"]): {"name": "Zyx Qorbel-Vranckx", "company": None},
                      str(ids["old"]): {"name": "Oswin Tarrq", "company": None}})
    newer = source.cursor("res.partner")
    check(f"Odoo {version}: the cursor moves to the newest change", newer > cursor)
    fake.advance(-120)  # a transaction that started two minutes earlier commits now
    fake.write("res.partner", ids["ilsabet"], name="Ilsabet Vranckx-Qorbel")
    fake.advance(600)
    late = {r.record_ref for r in source.iter_changes("res.partner", ["name"], newer)}
    check(f"Odoo {version}: the overlap window reads a late commit again", str(ids["ilsabet"]) in late)
    check(f"Odoo {version}: a malformed cursor is expired",
          isinstance(_error(lambda: list(source.iter_changes("res.partner", ["name"], "page:7"))), CursorExpired))
    check(f"Odoo {version}: the key's expiry is reported",
          source.credentials_expire_at() == datetime(2026, 12, 31, tzinfo=UTC))
    fake.key_expiry = ["2026-12-31 00:00:00", "2027-02-01 00:00:00"]
    check(f"Odoo {version}: with several keys the expiry is unknown", source.credentials_expire_at() is None)
    check(f"Odoo {version}: Odoo Online is paced at one call per second", clock.slept and set(clock.slept) == {1.0})
    check(f"Odoo {version}: every request was a read", read_only(fake.requests))
    source.close()


def _check_failures(respx_mock, version):
    fake = FakeOdoo(version, base="https://odoo.zq.example")
    respx_mock.route(host="odoo.zq.example").mock(side_effect=fake.handle)
    _seed(fake)
    clock = _Clock()
    err = _error(lambda: _connector(clock).connect(_settings(fake), {"api_key": "wrong-key"}).list_collections())
    check(f"Odoo {version}: a wrong API key fails as auth, in fixed text",
          err is not None and err.kind == "auth" and "wrong" not in str(err))
    source = _connector(clock).connect(_settings(fake, api="json2" if version >= 19 else "xmlrpc"), {"api_key": KEY})
    check(f"Odoo {version}: a self-hosted Odoo is not paced", clock.slept == [])
    fake.fail = {("ir.model", "search_read"): 1, ("res.partner", "fields_get"): 1}
    fresh = _connector(clock).connect(_settings(fake, api="json2" if version >= 19 else "xmlrpc"), {"api_key": KEY})
    err = _error(lambda: fresh.list_collections() and fresh.list_fields("res.partner"))
    check(f"Odoo {version}: a server error while listing is raised, never read as a missing collection",
          err is not None and err.kind == "query")
    fake.fail = {("res.partner", "fields_get"): 1}
    err = _error(lambda: fresh.list_fields("res.partner"))
    check(f"Odoo {version}: ... and so is one reading a model's fields", err is not None and err.kind == "query"
          and [c.name for c in fresh.list_collections()] == ["res.partner", "crm.lead"])
    fake.denied_models.add("crm.lead")
    check(f"Odoo {version}: a collection the user may not read is still listed",
          [c.name for c in source.list_collections()] == ["res.partner", "crm.lead"])
    err = _error(lambda: list(source.iter_records("crm.lead")))
    check(f"Odoo {version}: reading it fails as permission, in fixed text",
          err.kind == "permission" and "Qorbel" not in str(err))
    fake.denied_models = set()
    fake.installed.discard("crm.lead")
    check(f"Odoo {version}: leads are not listed when ir.model says CRM is not installed",
          [c.name for c in source.list_collections()] == ["res.partner"])
    fake.installed.add("crm.lead")
    fake.denied_models.add("ir.model")
    check(f"Odoo {version}: without access to ir.model leads are listed (their read decides)",
          [c.name for c in source.list_collections()] == ["res.partner", "crm.lead"])
    fake.denied_models = set()
    fake.queue = [httpx.Response(429)]
    check(f"Odoo {version}: a 429 slows down, then the read goes on",
          len(list(source.iter_records("res.partner"))) == 4 and clock.slept[-1] == 5.0)
    fake.queue = [httpx.Response(429)] * 10
    err = _error(lambda: list(source.iter_records("res.partner")))
    check(f"Odoo {version}: repeated 429s reschedule the job", err.kind == "limit" and err.reset_at is not None)
    fake.queue = []
    check(f"Odoo {version}: every request was a read", read_only(fake.requests))


def _check_same_transaction(respx_mock, version):
    fake = FakeOdoo(version, base="https://bulk.zq.example")
    respx_mock.route(host="bulk.zq.example").mock(side_effect=fake.handle)
    with fake.transaction():  # an import: every record gets the same stored write_date
        ids = {str(fake.add("res.partner", name=f"Zyq Bulkara{i:04d}")) for i in range(1200)}
    source = _connector().connect(_settings(fake), {"api_key": KEY})
    before = len(fake.requests)
    got = list(itertools.islice(source.iter_changes("res.partner", ["name"], "wd:2026-10-04 07:00:00"), 5000))
    reads = [r for r in fake.requests[before:] if "search_read" in r[2]]
    check(f"Odoo {version}: 1,200 records written in one transaction are read once each, and the read ends",
          len(got) == 1200 and {r.record_ref for r in got} == ids)
    check(f"Odoo {version}: ... in three pages plus the head read", len(reads) <= 5)
    check(f"Odoo {version}: ... and the cursor moves to that transaction",
          source.cursor("res.partner") == "wd:" + fake.newest("res.partner"))


def _check_detection(respx_mock):
    cases = [(["saas~19", 1, 0, "final", 0, ""], "_Json2"), (["saas~18", 3, 0, "final", 0, ""], "_XmlRpc"),
             ([19, 0, 0, "final", 0, ""], "_Json2"), ([20, 0, 0, "final", 0, ""], "_Json2"),
             ([18, 0, 0, "final", 0, ""], "_XmlRpc"), (["saas~19.2"], "_Json2"), (["garbage"], "_XmlRpc"),
             ([], "_XmlRpc"), ([True], "_XmlRpc"), ("19", "_XmlRpc")]
    for i, (info, expected) in enumerate(cases):
        fake = FakeOdoo(19, base=f"https://v{i}.zq.example")
        fake.version_info = info
        respx_mock.route(host=f"v{i}.zq.example").mock(side_effect=fake.handle)
        source = _connector().connect(_settings(fake), {"api_key": KEY})
        check(f"version_info {info!r} reads over {'JSON-2' if expected == '_Json2' else 'XML-RPC'}",
              type(source._rpc).__name__ == expected)  # pylint: disable=protected-access


def _check_forced_api(respx_mock):
    fake = FakeOdoo(19, base="https://odoo19.zq.example")
    respx_mock.route(host="odoo19.zq.example").mock(side_effect=fake.handle)
    _seed(fake)
    source = _connector().connect(_settings(fake, api="xmlrpc"), {"api_key": KEY})
    check("the api setting forces XML-RPC on Odoo 19, without detection",
          len(list(source.iter_records("res.partner"))) == 4
          and all(p.startswith("/xmlrpc/") for _m, p, _r in fake.requests))


def main():
    print("\n=== Odoo connector on fixtures ===\n")
    try:
        import respx
    except ImportError:
        if os.environ.get("EREBUS_REQUIRE_RESPX") == "1":
            raise
        print("  - skipped (respx is not installed: pip install './pro[test]')")
        return
    checks = [_check_license_and_settings]
    for version in (19, 18):
        checks += [lambda m, v=version: _check_api(m, v), lambda m, v=version: _check_failures(m, v),
                   lambda m, v=version: _check_same_transaction(m, v)]
    for fn in [*checks, _check_detection, _check_forced_api]:
        with respx.mock(assert_all_called=False) as respx_mock:
            fn(respx_mock)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
