"""Admin API for sources, fields, sync jobs and erasure (spec 015 "Admin API", SC-4, SC-5, SC-9).

Live Postgres. A tenant credential gets 403 and no data on every route, with no side
effect, and no credential gets 401. An operator creates a source (a sample job is
queued), lists, updates, pauses, samples, syncs, reviews fields, lists jobs, deletes
(orphaned values retired, 409 while a job runs) and erases a value. Another scope's
source is 404 on every route. Credentials and erased values never appear in a response
or an audit row; every action is audited on the tenant's chain with the operator
credential id as actor. Creating a source of every type loads no connector module.
"""
import base64
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

import psycopg
from fastapi.testclient import TestClient
from helpers import fake_detector, operator_bearer

from erebus.cataloging import connector_types
from erebus.gateway import catalog
from erebus.gateway.app import create_app
from erebus.gateway.connectors import fields, jobs, sources
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.governance import audit
from erebus.gateway.providers import quota
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
from erebus.gateway.store.scope_context import scoped
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_sources_api")
_KEY = base64.b64encode(os.urandom(32)).decode()
_SECRET = "Zq-hunter2-secret"
_NEW_SECRET = "Zq-rotated-secret"
_ERASED = "Zyx Qorbel"
_CONNECTOR_MODULES = ("erebus.cataloging.connectors", "erebus_pro.connectors", "pymysql", "psycopg2", "snowflake",
                      "google.cloud", "google.auth", "fakesnow", "duckdb")
# Settings per type a Pro install adds (the gateway checks keys only).
_PRO_SETTINGS = {"snowflake": {"account": "acme-zq", "database": "CRM"}, "bigquery": {"project": "acme-zq"}}
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _count(conn, sql, params=(), scope=None):
    if scope is None:
        return conn.execute(sql, params).fetchone()[0]
    with scoped(conn, scope):
        return conn.execute(sql, params).fetchone()[0]


def _source_body(name="crm", ctype="postgres", **extra):
    settings = {"sqlite": {"path": "crm.db"}, **_PRO_SETTINGS}.get(
        ctype, {"host": "db.example", "dbname": "crm", "user": "reader"})
    return {"name": name, "type": ctype, "settings": settings, "credentials": {"password": _SECRET}, **extra}


class _World:
    """Two tenants, an operator, the wired app, and every response text it saw."""

    def __init__(self, conn, pool, kms, resolver):
        self.conn, self.kms = conn, kms
        self.a = provision_scope(conn, kms, "org/a")
        self.b = provision_scope(conn, kms, "org/b")
        self.cred_a = credentials_directory.provision(conn, self.a, "org/a", label="a")
        for sid in (self.a, self.b):
            quota.set_quota(conn, sid, 1000, 100000, 60)
        self.op = operator_bearer(conn)
        self.op_id = str(conn.execute("SELECT id FROM scope_credentials WHERE credential_hash = %s",
                                      (credentials_directory.hash_credential(self.op),)).fetchone()[0])
        self.home = conn.execute("SELECT id FROM scopes WHERE scope_key = %s",
                                 (credentials_directory.OPERATOR_SCOPE_KEY,)).fetchone()[0]

        async def echo(_scope_id, payload):
            return {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}

        app = create_app(conn=conn, key_provider=kms, detector=fake_detector([]), scopes=resolver,
                         scope_ids={}, pool=pool, egress=echo)
        self.client = TestClient(app)
        self.texts = []

    def call(self, method, path, cred=None, body=None, params=None, content=None):
        headers = {"Authorization": "Bearer " + cred} if cred else {}
        if content is not None:
            headers["Content-Type"] = "application/json"
            r = self.client.request(method, path, content=content, headers=headers, params=params)
        else:
            r = self.client.request(method, path, json=body, headers=headers, params=params)
        self.texts.append(r.text)
        return r

    def op_call(self, method, path, body=None, params=None):
        return self.call(method, path, self.op, body, params)

    def base(self, scope):
        return f"/v1/admin/scopes/{scope}"

    def finish_jobs(self, source_id):
        self.conn.execute("UPDATE sync_jobs SET status = 'done' WHERE source_id = %s AND status IN "
                          "('queued', 'running')", (source_id,))

    def jobs(self, source_id, kind=None):
        return _count(self.conn, "SELECT count(*) FROM sync_jobs WHERE source_id = %s "
                      "AND (%s::text IS NULL OR kind = %s)", (source_id, kind, kind))

    def state(self):
        return {
            "sources": _count(self.conn, "SELECT count(*) FROM sources"),
            "sources_a": [tuple(r) for r in self.conn.execute(
                "SELECT id, name, settings::text, status, secrets_ciphertext FROM sources ORDER BY id").fetchall()],
            "jobs": [tuple(r) for r in self.conn.execute("SELECT id, status FROM sync_jobs ORDER BY id").fetchall()],
            "fields": [tuple(r) for r in self.conn.execute(
                "SELECT id, decision FROM source_fields ORDER BY id").fetchall()],
            "suppressions": _count(self.conn, "SELECT count(*) FROM catalog_suppressions"),
            "entries": _count(self.conn, "SELECT count(*) FROM catalog_entries WHERE status = 'active'"),
            "versions": [tuple(r) for r in self.conn.execute(
                "SELECT scope_id, version FROM catalog_versions ORDER BY scope_id").fetchall()],
        }


def _routes(w, scope, src, field_id):
    base = w.base(scope)
    return [
        ("POST", f"{base}/sources", _source_body("forged")),
        ("GET", f"{base}/sources", None),
        ("PATCH", f"{base}/sources/{src}", {"status": "paused", "credentials": {"password": "forged"}}),
        ("POST", f"{base}/sources/{src}/sample", None),
        ("POST", f"{base}/sources/{src}/sync", None),
        ("GET", f"{base}/sources/{src}/fields", None),
        ("PATCH", f"{base}/sources/{src}/fields/{field_id}", {"decision": "confirmed"}),
        ("GET", f"{base}/sync-jobs", None),
        ("POST", f"{base}/known-values/erase", {"value": "Anne Existing"}),
        ("DELETE", f"{base}/sources/{src}", None),  # last on purpose
    ]


def _seed_fields(w, scope, src):
    fields.record_sample(w.conn, scope, src, [
        fields.FieldSample("customers", "email", "text", "EMAIL_ADDRESS", "auto"),
        fields.FieldSample("customers", "notes", "text", "PERSON", "pending", "free text", confirmable=False),
        fields.FieldSample("customers", "company", "text", "ORGANIZATION", "pending", "model only"),
    ])
    return {f.field: f.id for f in fields.list_fields(w.conn, scope, src)}


def _check_forbidden(w, src_a, field_a):
    """SC-9: a tenant credential gets 403 and nothing else, on its own scope and another."""
    crypto = open_scope_crypto(w.conn, w.kms, w.a)
    catalog.upsert_values(w.conn, crypto, w.a, src_a, uuid.uuid4(), [("Anne Existing", "PERSON")])
    before = w.state()
    for scope in (w.a, w.b):
        for method, path, body in _routes(w, scope, src_a, field_a):
            r = w.call(method, path, w.cred_a, body)
            check(f"tenant gets 403 on {method} {path.replace(str(scope), '{scope}')}",
                  r.status_code == 403 and r.json() == {"detail": "forbidden"})
            forged = w.call(method, path, w.cred_a, {**(body or {}), "role": "operator"},
                            params={"role": "operator"})
            check("  and 403 with a forged role claim", forged.status_code == 403)
            check("  and 401 with no credential", w.call(method, path, None, body).status_code == 401)
            check("  and 401 with the master key as bearer", w.call(method, path, _KEY, body).status_code == 401)
    check("the tenant's calls changed nothing", w.state() == before)
    denied = [e for e in audit.query(w.conn, w.a) if e["outcome"] == "forbidden"]
    check("each denial is audited forbidden on the caller's scope", len(denied) == 2 * 2 * len(_routes(w, w.a, 0, 0)))


def _check_create(w):
    r = w.op_call("POST", f"{w.base(w.a)}/sources",
                  _source_body(credentials_expire_at="2027-08-31T00:00:00+00:00", max_values=5000))
    body = r.json()
    check("operator creates a source", r.status_code == 200 and body["source"]["name"] == "crm"
          and body["source"]["type"] == "postgres" and body["source"]["status"] == "active")
    check("create returns expiry and cap, no credentials",
          body["source"]["credentials_expire_at"].startswith("2027-08-31") and body["source"]["max_values"] == 5000
          and "credentials" not in body["source"] and "secrets" not in str(body["source"]))
    src = uuid.UUID(body["source"]["id"])
    check("create queues a sample job", body["job"]["kind"] == "sample" and body["job"]["status"] == "queued"
          and w.jobs(src, "sample") == 1)
    check("the job carries no lease token", "lease_token" not in body["job"])
    check("the credentials are stored sealed",
          sources.read_secrets(w.conn, open_scope_crypto(w.conn, w.kms, w.a), w.a, src) == {"password": _SECRET})
    listed = w.op_call("GET", f"{w.base(w.a)}/sources").json()["sources"]
    check("the source lists with status and expiry",
          [s["id"] for s in listed] == [str(src)] and listed[0]["credentials_expire_at"].startswith("2027"))
    names_b = [s["name"] for s in w.op_call("GET", f"{w.base(w.b)}/sources").json()["sources"]]
    check("scope B lists only its own source", names_b == ["b-crm"])
    return src


def _check_refusals(w):
    base = w.base(w.a)
    before = w.state()
    cases = [
        (_source_body(ctype="no_such_type_zq"), "unknown connector type"),
        ({**_source_body(), "settings": {"dsn": f"postgresql://u:{_SECRET}@h/db"}},
         "settings contain a key this connector type does not allow"),
        ({**_source_body(), "credentials": _SECRET}, "credentials must be an object"),
    ]
    for body, text in cases:
        r = w.op_call("POST", f"{base}/sources", body)
        check(f"create refuses 400: {text}", r.status_code == 400 and r.json() == {"detail": text})
    r = w.call("POST", f"{base}/sources", w.op, content=b'{"name": "x", "credentials": {"password": "' +
               _SECRET.encode() + b'"')
    check("malformed JSON is 400 with fixed text", r.status_code == 400
          and r.json() == {"detail": "request body must be a JSON object"})
    check("a refused create wrote nothing", w.state() == before)
    for scope in (uuid.uuid4(), "not-a-uuid", w.home):
        r = w.op_call("GET", f"{w.base(scope)}/sources")
        check(f"scope {'home' if scope == w.home else scope} is 404", r.status_code == 404
              and r.json() == {"detail": "scope not found"})


def _check_jobs(w, src):
    base = f"{w.base(w.a)}/sources/{src}"
    first = w.op_call("POST", f"{base}/sync").json()
    check("sync now returns the queued sample instead of a second job",
          first["job"]["kind"] == "sample" and not first["created"] and w.jobs(src) == 1)
    w.finish_jobs(src)
    r = w.op_call("POST", f"{base}/sync").json()
    again = w.op_call("POST", f"{base}/sync").json()
    check("sync now queues one full job", r["created"] and r["job"]["kind"] == "full"
          and not again["created"] and again["job"]["id"] == r["job"]["id"] and w.jobs(src, "full") == 1)
    w.finish_jobs(src)
    s = w.op_call("POST", f"{base}/sample").json()
    check("sample re-runs the sample job", s["created"] and s["job"]["kind"] == "sample")
    listed = w.op_call("GET", f"{w.base(w.a)}/sync-jobs", params={"source_id": str(src)}).json()["jobs"]
    check("the jobs list shows this source's jobs newest first",
          [j["kind"] for j in listed] == ["sample", "full", "sample"] and all("lease_token" not in j for j in listed))
    check("every job row has its counts", all({"rows_seen", "values_added", "values_retired", "error"} <= set(j)
                                               for j in listed))
    check("the jobs list limit applies",
          len(w.op_call("GET", f"{w.base(w.a)}/sync-jobs", params={"limit": "1"}).json()["jobs"]) == 1)
    check("a bad limit is 400", w.op_call("GET", f"{w.base(w.a)}/sync-jobs", params={"limit": "0"})
          .status_code == 400)
    check("scope B sees none of A's jobs", w.op_call("GET", f"{w.base(w.b)}/sync-jobs").json() == {"jobs": []})
    w.finish_jobs(src)


def _check_update(w, src):
    base = f"{w.base(w.a)}/sources/{src}"
    crypto = open_scope_crypto(w.conn, w.kms, w.a)
    r = w.op_call("PATCH", base, {"name": "crm-main"})
    check("a rename queues nothing", r.status_code == 200 and r.json()["source"]["name"] == "crm-main"
          and r.json()["job"] is None and w.jobs(src, "sample") == 2)
    r = w.op_call("PATCH", base, {"settings": {"host": "db.example", "dbname": "crm", "user": "reader"}})
    check("unchanged settings queue nothing", r.json()["job"] is None)
    r = w.op_call("PATCH", base, {"settings": {"host": "db.example", "dbname": "crm", "collections": ["customers"]}})
    check("a collections change queues a sample", r.json()["job"]["kind"] == "sample" and w.jobs(src, "sample") == 3)
    w.finish_jobs(src)
    r = w.op_call("PATCH", base, {"credentials": {"password": _NEW_SECRET}, "credentials_expire_at": None})
    check("a credentials change queues a sample and clears the expiry",
          r.json()["job"]["kind"] == "sample" and r.json()["source"]["credentials_expire_at"] is None)
    check("the credentials are replaced whole",
          sources.read_secrets(w.conn, crypto, w.a, src) == {"password": _NEW_SECRET})
    w.finish_jobs(src)
    check("settings are checked against the stored type",
          w.op_call("PATCH", base, {"settings": {"path": "x.db"}}).status_code == 400)
    check("an empty PATCH is 400", w.op_call("PATCH", base, {}).status_code == 400)
    r = w.op_call("PATCH", base, {"status": "paused"})
    check("pause", r.json()["source"]["status"] == "paused")
    for action in ("sync", "sample"):
        r = w.op_call("POST", f"{base}/{action}")
        check(f"{action} on a paused source is 409",
              r.status_code == 409 and r.json() == {"detail": "source is paused"})
    r = w.op_call("PATCH", base, {"status": "paused", "settings": {"host": "db.example", "dbname": "crm"}})
    check("a collections change while paused queues nothing", r.json()["job"] is None)
    r = w.op_call("PATCH", base, {"status": "active"}).json()
    check("resume", r["source"]["status"] == "active")
    check("resuming queues the sample the paused change is owed",
          r["job"]["kind"] == "sample" and r["source"]["pending_job"] is None)
    w.finish_jobs(src)


def _check_owed(w, src, ids):
    """A field decision or new credentials while a sync runs are queued when it ends."""
    base = f"{w.base(w.a)}/sources/{src}"
    job_id = w.op_call("POST", f"{base}/sync").json()["job"]["id"]
    w.conn.execute("UPDATE sync_jobs SET status = 'running', lease_token = gen_random_uuid() WHERE id = %s",
                   (job_id,))
    r = w.op_call("PATCH", f"{base}/fields/{ids['company']}", {"decision": "ignored"}).json()
    check("a field decision during a running sync is owed as a full sync",
          r["job"]["id"] == job_id and r["pending_job"] == "full")
    r = w.op_call("PATCH", base, {"credentials": {"password": _NEW_SECRET}}).json()
    check("new credentials during a running sync are owed as a sample",
          r["job"]["id"] == job_id and r["source"]["pending_job"] == "sample")
    jobs.finish(w.conn, jobs.get_job(w.conn, w.a, uuid.UUID(job_id)))
    queued = [j for j in jobs.list_jobs(w.conn, w.a, source_id=src) if j.status == "queued"]
    check("the running sync's end queues the owed sample (it queues the full sync)",
          [j.kind for j in queued] == ["sample"] and sources.get_source(w.conn, w.a, src).pending_job is None)
    w.finish_jobs(src)


def _check_fields(w, src, ids):
    base = f"{w.base(w.a)}/sources/{src}/fields"
    listed = w.op_call("GET", base).json()["fields"]
    check("the field mapping lists decisions and reasons",
          {f["field"]: (f["decision"], f["reason"]) for f in listed}
          == {"email": ("auto", ""), "notes": ("pending", "free text"), "company": ("pending", "model only")})
    r = w.op_call("PATCH", f"{base}/{ids['company']}", {"decision": "confirmed"})
    check("confirm a field; a full sync is queued", r.status_code == 200 and r.json()["field"]["decision"]
          == "confirmed" and r.json()["job"]["kind"] == "full")
    w.finish_jobs(src)
    r = w.op_call("PATCH", f"{base}/{ids['notes']}", {"decision": "confirmed"})
    check("an unconfirmable field is 409", r.status_code == 409
          and r.json() == {"detail": "this field cannot be confirmed"})
    check("ignore a field", w.op_call("PATCH", f"{base}/{ids['email']}", {"decision": "ignored"})
          .json()["field"]["decision"] == "ignored")
    w.finish_jobs(src)
    check("an unknown field id is 404", w.op_call("PATCH", f"{base}/{uuid.uuid4()}", {"decision": "ignored"})
          .status_code == 404)
    check("a bad decision is 400", w.op_call("PATCH", f"{base}/{ids['email']}", {"decision": "auto"})
          .status_code == 400)


def _check_cross_scope(w, src_b, field_b):
    before = w.state()
    for method, path, body in _routes(w, w.a, src_b, field_b)[2:]:
        if "known-values" in path or "sync-jobs" in path:
            continue
        r = w.op_call(method, path, body)
        check(f"B's source through A's path is 404: {method} {path.split('/sources/')[-1][:40]}",
              r.status_code == 404 and r.json() == {"detail": "source not found"})
    r = w.op_call("GET", f"{w.base(w.a)}/sync-jobs", params={"source_id": str(src_b)})
    check("B's source id on A's jobs list is 404", r.status_code == 404)
    check("the cross-scope calls changed nothing", w.state() == before)


def _check_delete_and_erase(w, src):
    crypto = open_scope_crypto(w.conn, w.kms, w.a)
    catalog.upsert_values(w.conn, crypto, w.a, src, uuid.uuid4(), [(_ERASED, "PERSON"), ("Anne Other", "PERSON")])
    w.op_call("POST", f"{w.base(w.a)}/sources/{src}/sync")
    w.conn.execute("UPDATE sync_jobs SET status = 'running' WHERE source_id = %s AND status = 'queued'", (src,))
    r = w.op_call("DELETE", f"{w.base(w.a)}/sources/{src}")
    check("delete while a job runs is 409", r.status_code == 409
          and r.json() == {"detail": "a sync job is running for this source"})
    w.finish_jobs(src)
    w.op_call("POST", f"{w.base(w.a)}/sources/{src}/sample")
    r = w.op_call("DELETE", f"{w.base(w.a)}/sources/{src}")
    check("delete retires the source's orphaned values", r.status_code == 200 and r.json()["values_retired"] >= 2)
    check("delete cascades the queued job and fields", w.jobs(src) == 0
          and _count(w.conn, "SELECT count(*) FROM source_fields WHERE source_id = %s", (src,), scope=w.a) == 0)
    check("a deleted source is 404", w.op_call("DELETE", f"{w.base(w.a)}/sources/{src}").status_code == 404)

    r = w.op_call("POST", f"{w.base(w.a)}/known-values/erase", {"value": _ERASED})
    check("erase returns counts only", r.status_code == 200 and set(r.json()) == {"entries_removed", "tokens_removed"}
          and r.json()["entries_removed"] == 1)
    check("erase adds a suppression", _count(w.conn, "SELECT count(*) FROM catalog_suppressions WHERE scope_id = %s",
                                             (w.a,), scope=w.a) == 1)
    check("an empty erase is 400", w.op_call("POST", f"{w.base(w.a)}/known-values/erase", {"value": ""})
          .status_code == 400)


def _check_audit(w, src):
    rows = audit.query(w.conn, w.a)
    mine = [r for r in rows if r["actor_id"] == w.op_id]
    kinds = {r["event_type"] for r in mine}
    check("source actions are audited on the tenant's chain",
          {"source_create", "source_update", "source_delete", "source_sync", "source_field", "known_value_erase"}
          <= kinds)
    check("with the operator credential id and privilege as actor", all(r["actor_role"] == "operator" for r in mine))
    creates = [r for r in mine if r["event_type"] == "source_create"]
    check("audit metadata names the source", any(str(src) in str(r["metadata"]) for r in creates))
    check("the audit chain verifies", audit.verify_chain(w.conn, w.a))
    leaks = (_SECRET, _NEW_SECRET, _ERASED, "Anne Existing")
    check("no audit row carries a credential or a value (SC-4)", not any(s in str(rows) for s in leaks))
    check("no response carried a credential or an erased value (SC-4)",
          not any(s in t for t in w.texts for s in leaks))


def _check_no_connector_loaded(w):
    installed = connector_types.installed()
    check("every built-in type is installed", {"sqlite", "postgres", "mysql"} <= {t.id for t in installed})
    for ctype in installed:
        r = w.op_call("POST", f"{w.base(w.b)}/sources", _source_body(name=ctype.id, ctype=ctype.id))
        check(f"a {ctype.id} source ({ctype.tier}) is created", r.status_code == 200
              and r.json()["source"]["type"] == ctype.id)
        if ctype.tier == "pro":
            check(f"{ctype.id} is a Pro type only because erebus-pro declares it", ctype.id in _PRO_SETTINGS)
    loaded = [m for m in sys.modules if m.startswith(_CONNECTOR_MODULES)]
    check("creating a source of every type loads no connector module or driver (SC-5)", not loaded)


def main():
    print("\n=== Admin API: sources (015) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True
    kms = pool = resolver = None
    try:
        from psycopg_pool import ConnectionPool

        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")
        kms = MasterKeyKms(_DSN, _KEY)
        pool = ConnectionPool(_DSN, min_size=1, max_size=4, open=True)
        resolver = DbScopeResolver(_DSN, ttl_s=5.0)
        w = _World(conn, pool, kms, resolver)
        crypto_b = open_scope_crypto(conn, kms, w.b)
        src_b = sources.create_source(conn, crypto_b, w.b, name="b-crm", connector_type="postgres",
                                      settings={"host": "b.example"}, secrets={"password": _SECRET})
        ids_b = _seed_fields(w, w.b, src_b)
        src = _check_create(w)
        ids = _seed_fields(w, w.a, src)
        _check_forbidden(w, src, ids["company"])
        _check_refusals(w)
        _check_jobs(w, src)
        _check_update(w, src)
        _check_fields(w, src, ids)
        _check_owed(w, src, ids)
        _check_cross_scope(w, src_b, ids_b["company"])
        _check_delete_and_erase(w, src)
        _check_audit(w, src)
        _check_no_connector_loaded(w)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        for closer in (resolver, pool, kms):
            if closer is not None:
                closer.close()
        conn.close()


if __name__ == "__main__":
    main()
