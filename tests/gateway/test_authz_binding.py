"""Authorization comes only from the credential (010 FR-001..011, SC-001..004).

For every gated route, a tenant credential that claims a privileged role (body ``role`` and
``X-Role`` header) is refused 403 with no side effect and nothing disclosed. Operator
credentials still work, name their target scope explicitly, are audited by credential id,
lose admin rights the moment they are revoked, and cannot be minted through onboarding.

``--forged-only`` runs just the forged-role section with pre-fix-compatible APIs, so the
same file run on the pre-fix commit prints one BYPASS line per route and fails (FR-011).
Live Postgres; self-skips without it.
"""
import base64
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

import psycopg
from fastapi.testclient import TestClient
from helpers import fake_detector

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.governance import audit, reveal
from erebus.gateway.observability import Metrics
from erebus.gateway.providers import quota
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_010_authz")
_KEY = base64.b64encode(os.urandom(32)).decode()
_PERSON = re.compile(r"\[PERSON_\d+_[0-9a-f]+\]")
_FORGED = ("GATEWAY_OPERATOR", "POLICY_ADMIN", "KEY_MANAGER", "AUDITOR", "REVEAL_REVIEWER", "operator")
_ONBOARD = {"provider": "openai", "central_credential": "CENTRAL-SECRET",
            "quota": {"rate_limit": 100, "spend_budget": 1000, "window_seconds": 60}}
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


def _cred_id(conn, credential):
    return conn.execute("SELECT id FROM scope_credentials WHERE credential_hash = %s",
                        (credentials_directory.hash_credential(credential),)).fetchone()[0]


class _World:
    """Two tenants, a minted token for A with a reveal grant, and the wired app."""

    def __init__(self, conn, pool, kms, resolver):
        self.conn = conn
        self.a = provision_scope(conn, kms, "org/a")
        self.b = provision_scope(conn, kms, "org/b")
        self.cred_a = credentials_directory.provision(conn, self.a, "org/a", label="a")
        self.cred_b = credentials_directory.provision(conn, self.b, "org/b", label="b")
        for sid in (self.a, self.b):
            quota.set_quota(conn, sid, 1000, 100000, 60)
        self.captured = []

        async def echo(_scope_id, payload):
            self.captured.append(payload)
            return {"choices": [{"message": {"role": "assistant",
                                             "content": "Re: " + payload["messages"][-1]["content"]}}]}

        app = create_app(conn=conn, key_provider=kms, detector=fake_detector([("John Smith", "PERSON")]),
                         scopes=resolver, scope_ids={}, pool=pool, egress=echo,
                         metrics=Metrics(), metrics_enabled=True)
        self.client = TestClient(app)
        check("tenant A chats 200 (setup)", self.chat(self.cred_a, "John Smith").status_code == 200)
        check("tenant B chats 200 (setup)", self.chat(self.cred_b, "hello").status_code == 200)
        self.token = _PERSON.findall(self.captured[0]["messages"][-1]["content"])[0]
        reveal.grant(conn, self.a, "alice", reveal.REVEAL_ROLE, "case 42", [self.token], ttl_seconds=600)
        self.b_cred_id = _cred_id(conn, self.cred_b)

    def chat(self, cred, content):
        return self.client.post("/v1/chat/completions",
                                json={"messages": [{"role": "user", "content": content}]},
                                headers={"Authorization": "Bearer " + cred})

    def call(self, method, path, cred=None, body=None, headers=None, params=None):
        hdrs = dict(headers or {})
        if cred is not None:
            hdrs["Authorization"] = "Bearer " + cred
        return self.client.request(method, path, json=body, headers=hdrs, params=params)

    def routes(self):
        """Every gated route, with a body that would do damage if the gate let it through."""
        return [
            ("GET", "/metrics", None),
            ("GET", "/v1/audit", None),
            ("POST", "/v1/admin/keys", {"op": "rotate", "scope_key": "org/a"}),
            ("POST", "/v1/admin/scopes", {"scope_key": "org/forged-scope"}),
            ("POST", "/v1/admin/tenants", {**_ONBOARD, "scope_key": "org/forged-tenant"}),
            ("DELETE", f"/v1/admin/tenants/{self.b_cred_id}", {}),
            ("POST", "/v1/reveal", {"grantee": "alice", "scope_key": "org/a", "tokens": [self.token]}),
            ("POST", "/v1/admin/operators", {"privilege": "operator", "label": "forged"}),
            ("POST", "/v1/admin/keys", {"op": "crypto_erase", "scope_key": "org/a"}),  # last on purpose
        ]

    def kek_rows(self, sid):
        return _count(self.conn, "SELECT count(*) FROM scope_keks WHERE scope_id = %s", (sid,), scope=sid)

    def requests_used(self, sid):
        return _count(self.conn, "SELECT coalesce(sum(requests), 0) FROM usage_counters WHERE scope_id = %s",
                      (sid,), scope=sid)


def _forged(w):
    """US1: a tenant credential claiming any role gets 403 on every route, with no effect."""
    leaks = (str(w.a), str(w.b), "requests", "John Smith", "events", "values", "egw_")
    keks_before, used_before = w.kek_rows(w.a), w.requests_used(w.a)
    ops_before = _count(w.conn, "SELECT count(*) FROM scope_credentials WHERE scope_key <> 'org/a' "
                                "AND scope_key <> 'org/b'")
    bypass = []
    for method, path, body in w.routes():
        for role in _FORGED:
            payload = None if body is None else {**body, "role": role}
            r = w.call(method, path, w.cred_a, payload, headers={"X-Role": role})
            if r.status_code == 404 and path == "/v1/admin/operators":
                continue  # route missing on pre-fix code: not a bypass
            if r.status_code != 403 or any(x in r.text for x in leaks):
                bypass.append(f"BYPASS {method} {path} {role} -> {r.status_code}")
    for line in bypass:
        print("  " + line)
    check("no gated route honours a forged role (SC-001/FR-011)", not bypass)
    check("forged key ops changed no key material", w.kek_rows(w.a) == keks_before)
    check("forged crypto-erase left tenant A serving", w.chat(w.cred_a, "still here").status_code == 200)
    check("forged provision/onboard created no scope",
          _count(w.conn, "SELECT count(*) FROM scopes WHERE scope_key LIKE 'org/forged%%'") == 0)
    check("forged onboard/operator issuance minted no credential",
          _count(w.conn, "SELECT count(*) FROM scope_credentials WHERE scope_key <> 'org/a' "
                         "AND scope_key <> 'org/b'") == ops_before)
    check("forged cross-tenant revoke left B active",
          _count(w.conn, "SELECT count(*) FROM scope_credentials WHERE id = %s AND status = 'active'",
                 (w.b_cred_id,)) == 1)
    check("tenant B still serves after the forged revoke", w.chat(w.cred_b, "hi").status_code == 200)
    check("forged reveal consumed no quota on A",
          w.requests_used(w.a) == used_before + 1)  # +1 is the 'still here' chat above

    for method, path, body in w.routes():
        r = w.call(method, path, None, body)
        check(f"no credential on {method} {path} is 401 with nothing disclosed",
              r.status_code == 401 and not any(x in r.text for x in leaks))
        r = w.call(method, path, _KEY, body)
        check(f"the master key as a bearer on {method} {path} is 401", r.status_code == 401)


def _operator(w):
    """US2/US4/FR-007: operator credentials work on explicit targets and are audited."""
    from helpers import operator_bearer

    op = operator_bearer(w.conn)
    op_id = _cred_id(w.conn, op)
    home = w.conn.execute("SELECT id FROM scopes WHERE scope_key = %s",
                          (credentials_directory.OPERATOR_SCOPE_KEY,)).fetchone()[0]

    m = w.call("GET", "/metrics", op)
    check("operator reads /metrics 200", m.status_code == 200 and str(w.a) in m.json()["scopes"])
    au = w.call("GET", "/v1/audit", op, params={"scope_key": "org/a"})
    check("operator reads tenant A's audit chain", au.status_code == 200
          and any(e["event_type"] == "chat" for e in au.json()["events"]))
    check("audit of an unknown scope is 404", w.call("GET", "/v1/audit", op, params={"scope_key": "org/x"})
          .status_code == 404)

    keks = w.kek_rows(w.a)
    check("key op without scope_key is 400", w.call("POST", "/v1/admin/keys", op, {"op": "rotate"})
          .status_code == 400)
    check("key op on an unknown scope is 404", w.call("POST", "/v1/admin/keys", op,
                                                      {"op": "rotate", "scope_key": "org/x"}).status_code == 404)
    check("rejected key ops changed nothing", w.kek_rows(w.a) == keks and w.kek_rows(home) == 0)
    rot = w.call("POST", "/v1/admin/keys", op, {"op": "rotate", "scope_key": "org/a"})
    check("operator rotates tenant A's key", rot.status_code == 200 and w.kek_rows(w.a) == keks + 1)
    check("tenant A still serves after rotation", w.chat(w.cred_a, "after rotate").status_code == 200)

    check("operator provisions a scope", w.call("POST", "/v1/admin/scopes", op, {"scope_key": "org/c"})
          .status_code == 200)
    for bad in ("_operators", "_hidden"):
        check(f"provisioning reserved scope key {bad!r} is 400",
              w.call("POST", "/v1/admin/scopes", op, {"scope_key": bad}).status_code == 400)
        check(f"onboarding reserved scope key {bad!r} is 400",
              w.call("POST", "/v1/admin/tenants", op, {**_ONBOARD, "scope_key": bad}).status_code == 400)
    check("no '_hidden' scope was created",
          _count(w.conn, "SELECT count(*) FROM scopes WHERE scope_key = '_hidden'") == 0)
    check("the operator home scope got no tenant credential",
          _count(w.conn, "SELECT count(*) FROM scope_credentials WHERE scope_key = %s AND privilege = 'tenant'",
                 (credentials_directory.OPERATOR_SCOPE_KEY,)) == 0)

    ob = w.call("POST", "/v1/admin/tenants", op,
                {**_ONBOARD, "scope_key": "org/d", "privilege": "operator", "role": "operator"})
    body = ob.json()
    check("operator onboards a tenant with credential_id + api_credential", ob.status_code == 200
          and bool(body.get("credential_id")) and body.get("api_credential", "").startswith("egw_"))
    new = body["api_credential"]
    check("onboarding never elevates: the new credential gets 403 on /metrics (US4)",
          w.call("GET", "/metrics", new).status_code == 403)
    check("the onboarded row is stored as 'tenant'",
          _count(w.conn, "SELECT privilege FROM scope_credentials WHERE id = %s", (body["credential_id"],))
          == "tenant")
    last = audit.query(w.conn, home)[-1]
    check("the onboard is audited on the operator chain with the credential id as actor (D8)",
          last["event_type"] == "onboard" and last["actor_id"] == str(op_id) and last["actor_role"] == "operator")
    check("operator revokes the onboarded credential",
          w.call("DELETE", f"/v1/admin/tenants/{body['credential_id']}", op).status_code == 200)

    rv = w.call("POST", "/v1/reveal", op, {"grantee": "alice", "scope_key": "org/a", "tokens": [w.token]})
    check("operator reveals with a valid grant", rv.status_code == 200 and rv.json()["values"][w.token] == "John Smith")
    check("reveal still requires the grant (bob has none)",
          w.call("POST", "/v1/reveal", op, {"grantee": "bob", "scope_key": "org/a", "tokens": [w.token]})
          .status_code == 403)

    check("operator issuance refuses a non-string label",
          w.call("POST", "/v1/admin/operators", op, {"label": 5}).status_code == 400)
    iss = w.call("POST", "/v1/admin/operators", op, {"label": "second"})
    second = iss.json().get("api_credential", "")
    check("operator issues another operator credential", iss.status_code == 200 and second.startswith("egw_")
          and bool(iss.json().get("credential_id")))
    check("the issued operator credential works on /metrics", w.call("GET", "/metrics", second).status_code == 200)
    check("operator credentials cannot chat (home scope has no quota)", w.chat(second, "hi").status_code == 429)
    check("revoking the second operator is 200",
          w.call("DELETE", f"/v1/admin/tenants/{iss.json()['credential_id']}", op).status_code == 200)
    check("a revoked operator loses admin rights immediately (FR-007)",
          w.call("GET", "/metrics", second).status_code == 401)

    rows = [r for sid in (home, w.a, w.b) for r in audit.query(w.conn, sid)]
    secrets = (op, second, w.cred_a, credentials_directory.hash_credential(op).hex())
    check("no audit row carries a token or its hash", not any(s in str(rows) for s in secrets))
    forbidden = [r for r in audit.query(w.conn, w.a) if r["outcome"] == "forbidden"]
    check("denied admin attempts are audited 'forbidden' on the caller's scope (D7)",
          len(forbidden) >= len(_FORGED) * len(w.routes())
          and all(r["actor_id"] == str(_cred_id(w.conn, w.cred_a)) and r["actor_role"] == "tenant"
                  for r in forbidden))
    check("audit chains still verify", audit.verify_chain(w.conn, home) and audit.verify_chain(w.conn, w.a))


def main():
    forged_only = "--forged-only" in sys.argv
    print("\n=== Authorization bound to the credential (010) ===\n")
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
        world = _World(conn, pool, kms, resolver)
        _forged(world)
        if not forged_only:
            _operator(world)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        for closer in (resolver, pool, kms):
            if closer is not None:
                closer.close()
        conn.close()


if __name__ == "__main__":
    main()
