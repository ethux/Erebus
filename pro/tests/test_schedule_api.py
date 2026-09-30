# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""``PUT /v1/admin/scopes/{scope_id}/sources/{id}/schedule`` (Erebus Pro, spec 015 "Admin API").

Live Postgres on a throwaway database; the core app with Pro registered as its gateway
extension. No credential is 401; a tenant gets 403 with no data and nothing written; an
operator without the ``sync.schedule`` feature gets 403 naming it. Licensed, an operator
sets, defaults or turns off a database source's schedule; incremental syncs and bad bodies
are 400 with fixed text; another scope's source, an unknown or reserved scope is 404. The
change is audited with ids and minutes only; no response echoes a setting or credential.
"""
import base64
import os
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

from _pg import temp_database

_SECRET = "Zq-sched-api-secret-7"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _app(conn, kms, resolver, env):
    from erebus_pro.gateway import register

    from erebus.gateway.app import create_app

    class _NoDetect:
        def detect(self, _text):
            return []

    old = {k: os.environ.pop(k, None) for k in ("EREBUS_LICENSE_KEY", "EREBUS_LICENSE_FILE")}
    os.environ.update(env)
    try:
        app = create_app(conn=conn, key_provider=kms, detector=_NoDetect(), scopes=resolver, scope_ids={})
        register(app, None)
        return app
    finally:
        for k in ("EREBUS_LICENSE_KEY", "EREBUS_LICENSE_FILE"):
            os.environ.pop(k, None)
            if old[k] is not None:
                os.environ[k] = old[k]


class _Calls:
    def __init__(self, client):
        self.client = client
        self.texts = []

    def put(self, path, cred=None, body=None, content=None):
        headers = {"Authorization": f"Bearer {cred}"} if cred else {}
        resp = self.client.put(path, headers=headers, json=body, content=content) if content is not None \
            else self.client.put(path, headers=headers, json=body)
        self.texts.append(resp.text)
        return resp


def _row(conn, source_id):
    return conn.execute("SELECT incremental_minutes, full_minutes, next_incremental_at, next_full_at - now() "
                        "FROM source_schedules WHERE source_id = %s", (source_id,)).fetchone()


def _check_gate(conn, calls, path, tenant, op, unlicensed, source_id):
    check("no credential is 401", calls.put(path, body={}).status_code == 401)
    resp = calls.put(path, tenant, {"full_minutes": 720})
    check("a tenant gets 403 with no data", resp.status_code == 403 and str(source_id) not in resp.text)
    check("and nothing is written", _row(conn, source_id) is None)
    resp = unlicensed.put(path, op, {"full_minutes": 720})
    check("an operator without the feature gets 403 naming it",
          resp.status_code == 403 and resp.json()["detail"] == "requires Erebus Pro (feature sync.schedule)")
    check("and still nothing is written", _row(conn, source_id) is None)


def _check_set(conn, calls, path, op, source_id):
    resp = calls.put(path, op, {"full_minutes": 720})
    body = resp.json().get("schedule", {})
    check("an operator sets a full-sync interval", resp.status_code == 200 and body.get("full_minutes") == 720
          and body.get("incremental_minutes") is None and body.get("source_id") == str(source_id))
    inc, full, next_inc, until = _row(conn, source_id)
    check("the row holds it, first run one interval away",
          inc is None and full == 720 and next_inc is None and 43000 < until.total_seconds() <= 43200)
    resp = calls.put(path, op, {})
    check("an empty body restores the defaults (full daily)",
          resp.status_code == 200 and _row(conn, source_id)[1] == 1440)
    resp = calls.put(path, op, {"full_minutes": None})
    check("null turns scheduled syncs off",
          resp.status_code == 200 and _row(conn, source_id)[1] is None and _row(conn, source_id)[3] is None
          and resp.json()["schedule"]["next_full_at"] is None)


def _check_bad(calls, path, op):
    cases = [
        ("an incremental interval on a database", {"incremental_minutes": 60}, 400,
         "incremental sync is not available for this source type"),
        ("an unknown field", {"cron": _SECRET}, 400, "unknown field in schedule"),
        ("a string interval", {"full_minutes": "720"}, 400, "full_minutes must be an integer number of minutes"),
        ("a boolean interval", {"full_minutes": True}, 400, "full_minutes must be an integer number of minutes"),
        ("a too-short interval", {"full_minutes": 10}, 400, "full_minutes must be between 60 and 43200"),
        ("a too-long interval", {"full_minutes": 50000}, 400, "full_minutes must be between 60 and 43200"),
        ("a list body", [1], 400, "request body must be a JSON object"),
    ]
    for label, body, status, detail in cases:
        resp = calls.put(path, op, body)
        check(f"{label} is {status} with fixed text", resp.status_code == status and resp.json()["detail"] == detail)
    resp = calls.put(path, op, content=b"{not json " + _SECRET.encode())
    check("a body that is not JSON is 400 with fixed text",
          resp.status_code == 400 and resp.json()["detail"] == "request body must be a JSON object")


def _check_scopes(calls, op, a, b_source, home):
    other = calls.put(f"/v1/admin/scopes/{a}/sources/{b_source}/schedule", op, {})
    check("another scope's source is 404", other.status_code == 404 and other.json()["detail"] == "source not found")
    for label, scope in (("an unknown scope", uuid.uuid4()), ("the operator home scope", home),
                         ("a malformed scope id", "nope")):
        resp = calls.put(f"/v1/admin/scopes/{scope}/sources/{b_source}/schedule", op, {})
        check(f"{label} is 404", resp.status_code == 404 and resp.json()["detail"] == "scope not found")
    bad = calls.put(f"/v1/admin/scopes/{a}/sources/nope/schedule", op, {})
    check("a malformed source id is 404", bad.status_code == 404)


def main():
    print("\n=== Schedule route (Erebus Pro, spec 015 \"Admin API\") ===\n")
    with temp_database("schedule_api") as dsn:
        if dsn is None:
            print("  (skipped: EREBUS_PG_DSN is not set)")
            return
        _run(dsn)
    print(f"\n{_passed}/{_passed} passed\n")


def _run(dsn):
    import psycopg
    from erebus_pro import license as lic_mod
    from fastapi.testclient import TestClient
    from license_admin import issue, keygen

    from erebus.gateway.connectors import sources
    from erebus.gateway.crypto.keyprovider import MasterKeyKms
    from erebus.gateway.governance import audit
    from erebus.gateway.store import credentials_directory, db
    from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
    from erebus.gateway.tenancy import DbScopeResolver

    tmp = Path(tempfile.mkdtemp())
    lic_mod.PUBLIC_KEYS["test"] = keygen(tmp / "k")
    token = issue((tmp / "k").read_bytes(), kid="test", customer="Acme", features=["sync.schedule"], days=30)
    conn = psycopg.connect(dsn, autocommit=True)
    db.run_migrations(conn)
    kms = MasterKeyKms(dsn, base64.b64encode(os.urandom(32)).decode())
    resolver = DbScopeResolver(dsn)
    try:
        a, b = provision_scope(conn, kms, "org/a"), provision_scope(conn, kms, "org/b")
        tenant = credentials_directory.provision(conn, a, "org/a", label="a")
        home = conn.execute("INSERT INTO scopes (scope_key) VALUES (%s) RETURNING id",
                            (credentials_directory.OPERATOR_SCOPE_KEY,)).fetchone()[0]
        op = credentials_directory.issue(conn, home, credentials_directory.OPERATOR_SCOPE_KEY,
                                         label="op", privilege="operator")[1]

        def source(scope):
            return sources.create_source(conn, open_scope_crypto(conn, kms, scope), scope, name="crm",
                                         connector_type="postgres", settings={"host": "db.example"},
                                         secrets={"password": _SECRET})

        a_source, b_source = source(a), source(b)
        calls = _Calls(TestClient(_app(conn, kms, resolver, {"EREBUS_LICENSE_KEY": token})))
        unlicensed = _Calls(TestClient(_app(conn, kms, resolver, {})))
        path = f"/v1/admin/scopes/{a}/sources/{a_source}/schedule"
        _check_gate(conn, calls, path, tenant, op, unlicensed, a_source)
        _check_set(conn, calls, path, op, a_source)
        _check_bad(calls, path, op)
        _check_scopes(calls, op, a, b_source, home)
        events = [e for e in audit.query(conn, a) if e["event_type"] == "source_schedule" and e["outcome"] == "ok"]
        check("each change is audited on the tenant's chain with ids and minutes",
              len(events) == 3 and events[0]["metadata"] == {"source_id": str(a_source), "incremental_minutes": None,
                                                              "full_minutes": 720})
        texts = calls.texts + unlicensed.texts + [str(e) for e in audit.query(conn, a)]
        check("no response or audit event holds a credential or setting",
              not any(_SECRET in t or "db.example" in t for t in texts))
    finally:
        del lic_mod.PUBLIC_KEYS["test"]
        resolver.close()
        kms.close()
        conn.close()


if __name__ == "__main__":
    main()
