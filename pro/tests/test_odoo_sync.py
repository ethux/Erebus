# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""An Odoo source through the real sync worker.

Live Postgres on a throwaway database; Odoo 19 (JSON-2) and Odoo 18 (XML-RPC) on
``respx`` fixtures. The sample maps contact, company and lead fields; the full sync
stores them (companies as ORGANIZATION, archived contacts too) and the cursors. A
renamed contact is picked up by the next incremental sync, which retires the old name
through the record's links; an archived contact stays matched; a deleted one keeps its
values until the next full sync retires them. A run of 429s puts the job back in the
queue without counting an attempt. The key's expiry reaches the source. When the
license lapses a sync fails unretried and every value stays. No name or key reaches a
job row or an audit event. A server error while a re-sample (every key rotation runs
one) or a full sync reads the contacts' fields is retried: it never drops the contact
fields or retires their values. Needs erebus-pro installed (its types come from the entry
point) and respx.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _pg import temp_database
from odoo_fake import DB, KEY, LOGIN, FakeOdoo

from erebus.cataloging import connector_types

_passed = 0
_FEATURE = "connectors.odoo"


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


def _values(conn, kms, scope_id):
    from erebus.gateway import catalog
    from erebus.gateway.store.known_value_store import open_scope_crypto
    crypto = open_scope_crypto(conn, kms, scope_id)
    return dict(catalog.iter_active_values(conn, crypto, scope_id))


def _run(conn, worker, scope_id, source_id, kind):
    from erebus.gateway.connectors import jobs
    job, _ = jobs.enqueue(conn, scope_id, source_id, kind)
    conn.commit()
    worker.run_once()
    return jobs.get_job(conn, scope_id, job.id)


def _sync(conn, dsn, kms, pool, version):
    import httpx
    import respx
    from erebus_pro.connectors.odoo import OdooConnector
    from sync_fakes import config

    from erebus.gateway.connectors import fields, jobs, sources
    from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
    from erebus.gateway.store.scope_context import scoped
    from erebus.sync.worker import Worker

    fake = FakeOdoo(version, base=f"https://odoo{version}.zq.example")
    tag = f"Odoo {version}"
    ids = {"zyx": fake.add("res.partner", name="Zyx Qorbel", email="zyx.qorbel@acme.example"),
           "acme": fake.add("res.partner", name="Qorbel Holding BV", is_company=True, email="info@qorbel.example"),
           "ilsabet": fake.add("res.partner", name="Ilsabet Vranckx", email="ilsabet@acme.example"),
           "oswin": fake.add("res.partner", name="Oswin Tarrq", active=False),
           "lead": fake.add("crm.lead", name="Website inquiry", contact_name="Mila Brandt-Okafor",
                            partner_name="Okafor Logistics", email_from="mila@okafor.example")}
    for model, record_id in (("res.partner", i) for i in sorted(fake.records["res.partner"])):
        fake.advance(3600)  # an hour apart: only the newest falls inside the overlap window
        fake.write(model, record_id)
    sleeps = []
    current = {"connector": OdooConnector(licensed([_FEATURE]), sleep=sleeps.append)}
    scope_id = provision_scope(conn, kms, f"tenant-odoo-{version}")
    source_id = sources.create_source(conn, open_scope_crypto(conn, kms, scope_id), scope_id, name="odoo",
                                      connector_type="odoo", settings={"url": fake.base, "database": DB,
                                                                       "login": LOGIN}, secrets={"api_key": KEY})
    conn.commit()
    worker = Worker(config(dsn), pool=pool, provider=kms,
                    connectors=lambda t: current["connector"] if t == "odoo" else None)
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host=fake.base.split("//")[1]).mock(side_effect=fake.handle)
        sample = _run(conn, worker, scope_id, source_id, "sample")
        decided = {(f.collection, f.field): (f.decision, f.label) for f in fields.list_fields(conn, scope_id,
                                                                                               source_id)}
        check(f"{tag}: the sample maps contacts, companies and leads",
              sample.status == "done" and decided[("res.partner", "name")] == ("auto", "PERSON")
              and decided[("res.partner", "company")] == ("auto", "ORGANIZATION")
              and decided[("res.partner", "email")] == ("auto", "EMAIL_ADDRESS")
              and decided[("crm.lead", "contact_name")] == ("auto", "PERSON")
              and decided[("crm.lead", "partner_name")] == ("auto", "ORGANIZATION"))
        full = jobs.list_jobs(conn, scope_id, source_id=source_id)[0]
        worker.run_once()
        values = _values(conn, kms, scope_id)
        check(f"{tag}: the full sync stores contacts, archived ones too, and leads",
              jobs.get_job(conn, scope_id, full.id).status == "done"
              and {"Zyx Qorbel", "Ilsabet Vranckx", "Oswin Tarrq", "Mila Brandt-Okafor",
                   "zyx.qorbel@acme.example"} <= set(values))
        check(f"{tag}: companies are ORGANIZATION, people PERSON",
              values["Qorbel Holding BV"] == "ORGANIZATION" and values["Okafor Logistics"] == "ORGANIZATION"
              and values["Zyx Qorbel"] == "PERSON")
        source = sources.get_source(conn, scope_id, source_id)
        check(f"{tag}: a cursor is stored per collection",
              set(source.cursor) == {"res.partner", "crm.lead"} and source.cursor["res.partner"].startswith("wd:"))
        check(f"{tag}: the key's expiry reaches the source", source.credentials_expire_at is not None
              and source.credentials_expire_at.isoformat().startswith("2026-12-31"))

        fake.advance(3600)
        fake.write("res.partner", ids["zyx"], name="Zyx Qorbel-Vranckx")
        fake.write("res.partner", ids["ilsabet"], active=False)
        before = len(fake.requests)
        inc = _run(conn, worker, scope_id, source_id, "incremental")
        reads = [r for r in fake.requests[before:]
                 if "search_read" in r[2] and any(m in r[1] + r[2] for m in ("res.partner", "crm.lead"))]
        check(f"{tag}: the incremental sync reads the head and one page of changes per collection: the two "
              "changed contacts and, inside the overlap window, the newest record of each",
              len(reads) == 4 and inc.rows_seen == 4)
        values = _values(conn, kms, scope_id)
        check(f"{tag}: an incremental sync picks up the new name", inc.status == "done"
              and "Zyx Qorbel-Vranckx" in values)
        check(f"{tag}: ... and retires the old one through the record's links",
              "Zyx Qorbel" not in values and inc.values_retired == 1)
        check(f"{tag}: an archived contact stays matched", "Ilsabet Vranckx" in values)

        fake.advance(3600)
        fake.unlink("res.partner", ids["oswin"])
        inc = _run(conn, worker, scope_id, source_id, "incremental")
        check(f"{tag}: a deleted contact keeps its values through an incremental sync (Odoo reports no deletions)",
              inc.status == "done" and "Oswin Tarrq" in _values(conn, kms, scope_id))
        again = _run(conn, worker, scope_id, source_id, "full")
        check(f"{tag}: ... and the next full sync retires them",
              again.status == "done" and "Oswin Tarrq" not in _values(conn, kms, scope_id))

        fake.queue = [httpx.Response(429)] * 20
        limited = _run(conn, worker, scope_id, source_id, "incremental")
        check(f"{tag}: a run of 429s puts the job back in the queue for later, no attempt counted",
              limited.status == "queued" and limited.attempts == 0 and limited.limited_since is not None
              and limited.error == "source rate limit reached")
        fake.queue = []
        with conn.transaction():
            conn.execute("UPDATE sync_jobs SET not_before = now() WHERE id = %s", (limited.id,))
        worker.run_once()
        check(f"{tag}: once the limit resets the job completes", jobs.get_job(conn, scope_id, limited.id).status
              == "done")

        before = _values(conn, kms, scope_id)
        current["connector"] = OdooConnector(licensed([_FEATURE], expires_in=-30 * 86400))
        lapsed = _run(conn, worker, scope_id, source_id, "incremental")
        check(f"{tag}: after the license lapses a sync fails unretried with the license text",
              lapsed.status == "failed" and lapsed.error == f"requires Erebus Pro (feature {_FEATURE})")
        check(f"{tag}: ... and every value already synced stays", _values(conn, kms, scope_id) == before)
    with scoped(conn, scope_id):
        audit = " ".join(r[0] for r in conn.execute(
            "SELECT metadata::text FROM audit_events WHERE scope_id = %s", (scope_id,)).fetchall())
        errors = " ".join(r[0] or "" for r in conn.execute(
            "SELECT error FROM sync_jobs WHERE scope_id = %s", (scope_id,)).fetchall())
    check(f"{tag}: no name, email or key reaches a job row or an audit event",
          not any(s in audit + errors for s in ("Qorbel", "Vranckx", "Okafor", "acme.example", KEY)))


def _transient(conn, dsn, kms, pool, version):
    import respx
    from erebus_pro.connectors.odoo import OdooConnector
    from sync_fakes import config

    from erebus.gateway.connectors import fields, jobs, sources
    from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
    from erebus.sync.worker import Worker

    fake = FakeOdoo(version, base=f"https://flaky{version}.zq.example")
    tag = f"Odoo {version}"
    for name in ("Zyx Qorbel", "Ilsabet Vranckx", "Oswin Tarrq"):
        fake.add("res.partner", name=name, email=name.split()[0].lower() + "@acme.example")
    fake.add("crm.lead", name="Website inquiry", contact_name="Mila Brandt-Okafor", email_from="mila@okafor.example")
    connector = OdooConnector(licensed([_FEATURE]), sleep=lambda _s: None)
    scope_id = provision_scope(conn, kms, f"tenant-odoo-flaky-{version}")
    source_id = sources.create_source(conn, open_scope_crypto(conn, kms, scope_id), scope_id, name="odoo",
                                      connector_type="odoo", settings={"url": fake.base, "database": DB,
                                                                       "login": LOGIN}, secrets={"api_key": KEY})
    conn.commit()
    worker = Worker(config(dsn), pool=pool, provider=kms, connectors=lambda t: connector if t == "odoo" else None)

    def contact_fields():
        return {f.field for f in fields.accepted_fields(conn, scope_id, source_id) if f.collection == "res.partner"}

    def again(job):
        with conn.transaction():
            conn.execute("UPDATE sync_jobs SET not_before = now() WHERE id = %s", (job.id,))
        worker.run_once()
        return jobs.get_job(conn, scope_id, job.id)

    with respx.mock(assert_all_called=False) as mock:
        mock.route(host=fake.base.split("//")[1]).mock(side_effect=fake.handle)
        _run(conn, worker, scope_id, source_id, "sample")
        worker.run_once()
        before, accepted = _values(conn, kms, scope_id), contact_fields()
        fake.fail[("res.partner", "fields_get")] = 1
        resample = _run(conn, worker, scope_id, source_id, "sample")
        check(f"{tag}: a server error while a re-sample reads the contact fields retries the sample",
              resample.status == "queued" and resample.attempts == 1 and resample.error == "query failed"
              and sources.get_source(conn, scope_id, source_id).status == "active")
        check(f"{tag}: ... keeping the contact fields and every value", contact_fields() == accepted
              and _values(conn, kms, scope_id) == before)
        check(f"{tag}: the retried sample succeeds and its full sync retires nothing",
              again(resample).status == "done" and worker.run_once() is not None
              and jobs.list_jobs(conn, scope_id, source_id=source_id)[0].values_retired == 0
              and _values(conn, kms, scope_id) == before)
        fake.fail[("res.partner", "fields_get")] = 1
        full = _run(conn, worker, scope_id, source_id, "full")
        check(f"{tag}: a server error while a full sync lists the contacts is retried, not incomplete",
              full.status == "queued" and full.error == "query failed"
              and sources.get_source(conn, scope_id, source_id).status == "active")
        check(f"{tag}: ... and the retry completes with every value kept",
              again(full).status == "done" and _values(conn, kms, scope_id) == before)


def main():
    print("\n=== Odoo source through the sync worker ===\n")
    reason = None
    try:
        import respx  # noqa: F401
    except ImportError:
        reason = "respx is not installed (pip install './pro[test]')"
    if reason is None and connector_types.get("odoo") is None:
        reason = "erebus-pro is not installed (pip install -e './pro[test]')"
    with temp_database("odoo_sync") as dsn:
        if reason is None and dsn is None:
            reason = "EREBUS_PG_DSN is not set"
        if reason:
            if os.environ.get("EREBUS_REQUIRE_RESPX") == "1":
                raise AssertionError(reason)
            print(f"  - skipped ({reason})")
            return
        import psycopg
        from psycopg_pool import ConnectionPool

        from erebus.gateway.crypto.keyprovider import LocalKms
        from erebus.gateway.store import db

        conn = psycopg.connect(dsn)
        db.run_migrations(conn)
        conn.commit()
        pool = ConnectionPool(dsn, min_size=1, max_size=3, open=True)
        try:
            for version in (19, 18):
                _transient(conn, dsn, LocalKms(), pool, version)
                _sync(conn, dsn, LocalKms(), pool, version)
        finally:
            pool.close()
            conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
