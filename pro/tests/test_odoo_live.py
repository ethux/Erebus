# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The Odoo connector against real Odoo servers, through the real sync worker.

Skipped unless ``EREBUS_TEST_ODOO_URLS`` names one or more Odoo servers as
``http://<admin login>:<admin password>@<host>:<port>/<database>`` (comma-separated)
and ``EREBUS_PG_DSN`` a maintenance DSN; ``EREBUS_REQUIRE_ODOO_LIVE=1`` makes a skip a
failure. ``pro/tests/odoo_live_stack.sh up <dir>`` starts Odoo 18 and 19 in Docker on
loopback and writes that variable to ``<dir>/odoo-live.env``.

Per server, as the admin: create an integration user (internal user, sales rights to
read every lead) with an API key that expires in 80 days, and made-up contacts, a
company and a lead. Then, as that user through the worker (the worker's allow list
names the server's address): sample, map, full sync; the known values exist (the
company as ORGANIZATION). A renamed contact is picked up by an incremental sync, which
retires the old name; an archived contact stays matched; a deleted one is retired by
the next full sync. Odoo 19 is read over JSON-2 and Odoo 18 over XML-RPC. The key's
expiry reaches the source; under the default deny list the loopback server is refused;
a wrong key fails as ``auth``. The test's records and user are removed afterwards.
"""
import os
import sys
import time
import urllib.parse
import xmlrpc.client
from datetime import UTC, date, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _pg import temp_database

from erebus.cataloging import connector_types

_passed = 0
_FEATURE = "connectors.odoo"
_MARK = "erebus-live-test"
_LOGIN = "erebus-sync-live"
_PEOPLE = {"zyx": "Zyx Qorbel", "ilsabet": "Ilsabet Vranckx", "oswin": "Oswin Tarrq"}


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def licensed(features):
    from erebus_pro.license import Entitlements, License
    now = int(time.time())
    return Entitlements(License("lic-odoo-live", "Acme", frozenset(features), now - 86400, now + 86400))


class Admin:
    """The server's admin over XML-RPC (password sign-in): test setup and edits only."""

    def __init__(self, url: str) -> None:
        parts = urllib.parse.urlsplit(url)
        self.base = f"{parts.scheme}://{parts.hostname}:{parts.port}"
        self.host = parts.hostname
        self.db = parts.path.strip("/")
        self._password = urllib.parse.unquote(parts.password or "")
        common = xmlrpc.client.ServerProxy(f"{self.base}/xmlrpc/2/common")
        self.version = common.version()["server_version_info"][0]
        self.uid = common.authenticate(self.db, urllib.parse.unquote(parts.username or ""), self._password, {})
        self._object = xmlrpc.client.ServerProxy(f"{self.base}/xmlrpc/2/object", allow_none=True)

    def __call__(self, model, method, *args, **kwargs):
        return self._object.execute_kw(self.db, self.uid, self._password, model, method, list(args), kwargs)

    def ref(self, xmlid):
        return self("ir.model.data", "check_object_reference", *xmlid.split("."))[1]

    def cleanup(self):
        quiet = {"context": {"active_test": False}}
        self("res.partner", "unlink", self("res.partner", "search", [("ref", "=", _MARK)], **quiet))
        self("crm.lead", "unlink", self("crm.lead", "search", [("name", "=", _MARK)], **quiet))
        users = self("res.users", "search", [("login", "=", _LOGIN)], **quiet)
        if users:  # deleting the user deletes its API keys
            try:
                self("res.users", "unlink", users)
            except xmlrpc.client.Fault:
                self("res.users", "write", users, {"active": False, "login": f"{_LOGIN}-{int(time.time())}"})

    def integration_user(self) -> tuple[str, date]:
        """Create the integration user and its API key; return (key, expiry date)."""
        groups = "group_ids" if "group_ids" in self("res.users", "fields_get", attributes=["type"]) else "groups_id"
        uid = self("res.users", "create", {
            "name": "Erebus Sync Live", "login": _LOGIN,
            groups: [(6, 0, [self.ref("base.group_user"), self.ref("sales_team.group_sale_salesman_all_leads")])]})
        expiry = date.today() + timedelta(days=80)
        model_id = self("ir.model", "search", [("model", "=", "res.users")])[0]
        code = (f"key = env['res.users.apikeys'].with_user(env['res.users'].browse({uid}))._generate("
                f"None, 'erebus sync', datetime.datetime({expiry.year}, {expiry.month}, {expiry.day}))\n"
                "action = {'type': 'ir.actions.client', 'tag': 'erebus_key', 'params': {'key': key}}\n")
        act = self("ir.actions.server", "create", {"name": "erebus live key", "model_id": model_id, "state": "code",
                                                   "code": code})
        try:
            key = self("ir.actions.server", "run", [act])["params"]["key"]
        finally:
            self("ir.actions.server", "unlink", [act])
        return key, expiry

    def seed(self) -> dict[str, int]:
        ids = {k: self("res.partner", "create", {"name": n, "email": f"{k}.live@acme.example", "ref": _MARK})
               for k, n in _PEOPLE.items()}
        ids["company"] = self("res.partner", "create", {"name": "Qorbel Vranckx Holding BV", "is_company": True,
                                                        "ref": _MARK, "email": "info@qorbel-vranckx.example"})
        ids["lead"] = self("crm.lead", "create", {
            "name": _MARK, "contact_name": "Mila Brandt-Okafor", "partner_name": "Okafor Logistics",
            "email_from": "mila@okafor.example"})
        return ids


def _values(conn, kms, scope_id):
    from erebus.gateway import catalog
    from erebus.gateway.store.known_value_store import open_scope_crypto
    return dict(catalog.iter_active_values(conn, open_scope_crypto(conn, kms, scope_id), scope_id))


def _run(conn, worker, scope_id, source_id, kind):
    from erebus.gateway.connectors import jobs
    job, _ = jobs.enqueue(conn, scope_id, source_id, kind)
    conn.commit()
    worker.run_once()
    return jobs.get_job(conn, scope_id, job.id)


def _api_used(admin, settings, key):
    from erebus_pro.connectors.odoo import OdooConnector

    from erebus.sync.netpolicy import NetworkPolicy, check_host, parse_hosts
    policy = NetworkPolicy(denied=parse_hosts("169.254.0.0/16"))
    source = OdooConnector(licensed([_FEATURE]), check=lambda host, port: check_host(policy, host, port)
                           ).connect(settings, {"api_key": key})
    try:
        return type(source._rpc).__name__  # pylint: disable=protected-access
    finally:
        source.close()


def _live(conn, dsn, pool, admin):
    from erebus_pro.connectors.odoo import OdooConnector
    from sync_fakes import config

    from erebus.gateway.connectors import fields, jobs, sources
    from erebus.gateway.crypto.keyprovider import LocalKms
    from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
    from erebus.sync.worker import Worker

    tag = f"Odoo {admin.version}"
    admin.cleanup()
    key, expiry = admin.integration_user()
    ids = admin.seed()
    kms = LocalKms()
    settings = {"url": admin.base, "database": admin.db, "login": _LOGIN}
    check(f"{tag}: the connector reads over {'JSON-2' if admin.version >= 19 else 'XML-RPC'}",
          _api_used(admin, settings, key) == ("_Json2" if admin.version >= 19 else "_XmlRpc"))
    scope_id = provision_scope(conn, kms, f"tenant-odoo-live-{admin.version}")
    crypto = open_scope_crypto(conn, kms, scope_id)
    source_id = sources.create_source(conn, crypto, scope_id, name="odoo", connector_type="odoo", settings=settings,
                                      secrets={"api_key": key})
    bad_id = sources.create_source(conn, crypto, scope_id, name="odoo-bad", connector_type="odoo",
                                   settings=settings, secrets={"api_key": "zq" * 20})
    conn.commit()
    connector = OdooConnector(licensed([_FEATURE]))
    worker = Worker(config(dsn, EREBUS_SYNC_ALLOWED_HOSTS=admin.host), pool=pool, provider=kms,
                    connectors=lambda t: connector if t == "odoo" else None)
    try:
        sample = _run(conn, worker, scope_id, source_id, "sample")
        decided = {(f.collection, f.field): f.decision for f in fields.list_fields(conn, scope_id, source_id)}
        check(f"{tag}: sample maps contacts, companies and leads", sample.status == "done" and all(
            decided.get(k) == "auto" for k in (("res.partner", "name"), ("res.partner", "company"),
                                               ("res.partner", "email"), ("crm.lead", "contact_name"))))
        full = jobs.list_jobs(conn, scope_id, source_id=source_id)[0]
        worker.run_once()
        values = _values(conn, kms, scope_id)
        check(f"{tag}: the full sync stores the seeded contacts, company and lead",
              jobs.get_job(conn, scope_id, full.id).status == "done" and set(_PEOPLE.values()) <= set(values)
              and values.get("Qorbel Vranckx Holding BV") == "ORGANIZATION" and "Mila Brandt-Okafor" in values
              and "zyx.live@acme.example" in values)
        stored = sources.get_source(conn, scope_id, source_id)
        check(f"{tag}: the key's expiry reaches the source",
              stored.credentials_expire_at == datetime(expiry.year, expiry.month, expiry.day, tzinfo=UTC))

        time.sleep(1.1)  # write_date has one-second resolution
        admin("res.partner", "write", [ids["zyx"]], {"name": "Zyx Qorbel-Vranckx"})
        admin("res.partner", "write", [ids["ilsabet"]], {"active": False})
        inc = _run(conn, worker, scope_id, source_id, "incremental")
        values = _values(conn, kms, scope_id)
        check(f"{tag}: an incremental sync picks up the new name and retires the old one",
              inc.status == "done" and "Zyx Qorbel-Vranckx" in values and "Zyx Qorbel" not in values)
        check(f"{tag}: an archived contact stays matched", "Ilsabet Vranckx" in values)

        admin("res.partner", "unlink", [ids["oswin"]])
        inc = _run(conn, worker, scope_id, source_id, "incremental")
        check(f"{tag}: a deleted contact stays until a full sync", inc.status == "done"
              and "Oswin Tarrq" in _values(conn, kms, scope_id))
        again = _run(conn, worker, scope_id, source_id, "full")
        check(f"{tag}: ... which retires it", again.status == "done" and "Oswin Tarrq" not in
              _values(conn, kms, scope_id))

        strict = Worker(config(dsn, EREBUS_SYNC_DENIED_HOSTS=""), pool=pool, provider=kms,
                        connectors=lambda t: connector if t == "odoo" else None)
        denied = _run(conn, strict, scope_id, source_id, "sample")
        check(f"{tag}: under the default deny list (loopback denied) the worker refuses the server",
              denied.status == "failed" and denied.error == "source address is not allowed")
        sources.update_source(conn, crypto, scope_id, source_id, status="active")
        conn.commit()

        bad = _run(conn, worker, scope_id, bad_id, "sample")
        check(f"{tag}: a wrong API key fails as auth and flags the source",
              bad.status == "failed" and bad.error == "authentication failed"
              and sources.get_source(conn, scope_id, bad_id).status == "needs_attention")
    finally:
        admin.cleanup()


def main():
    print("\n=== Odoo connector against live Odoo (spec 015) ===\n")
    urls = [u for u in os.environ.get("EREBUS_TEST_ODOO_URLS", "").split(",") if u.strip()]
    reason = None if urls else "EREBUS_TEST_ODOO_URLS is not set (pro/tests/odoo_live_stack.sh up <dir>)"
    if reason is None and connector_types.get("odoo") is None:
        reason = "erebus-pro is not installed (pip install -e './pro[test]')"
    with temp_database("odoo_live") as dsn:
        if reason is None and dsn is None:
            reason = "EREBUS_PG_DSN is not set"
        if reason:
            if os.environ.get("EREBUS_REQUIRE_ODOO_LIVE") == "1":
                raise AssertionError(reason)
            print(f"  - skipped ({reason})")
            return
        import psycopg
        from psycopg_pool import ConnectionPool

        from erebus.gateway.store import db

        conn = psycopg.connect(dsn)
        db.run_migrations(conn)
        conn.commit()
        pool = ConnectionPool(dsn, min_size=1, max_size=3, open=True)
        try:
            for url in urls:
                _live(conn, dsn, pool, Admin(url.strip()))
        finally:
            pool.close()
            conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
