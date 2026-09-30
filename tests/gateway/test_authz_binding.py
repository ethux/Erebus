"""Authorization comes only from the credential (010 FR-001..011, SC-001..004).

For every gated route, a tenant credential that claims a privileged role (body ``role``,
``X-Role`` header, ``?role=`` query, and all three at once) is refused 403 with no side
effect and nothing disclosed; /metrics shows zero scope ids and zero counters. No
credential is 401. Operator credentials work, name their target scope explicitly, are
audited by credential id, cannot be minted through onboarding, and lose admin rights the
moment they are revoked, inside the 5 s resolver cache window. Live Postgres; self-skips
without it.

``--forged-only`` runs just the forged-role section, which uses only pre-fix APIs. Run on
the pre-fix commit 448a0fa it prints a BYPASS line per honoured forgery and fails (FR-011).
From the repo root, without switching branches::

    PY=$PWD/.venv/bin/python
    git worktree add --detach /tmp/erebus-448a0fa 448a0fa
    cp tests/gateway/test_authz_binding.py /tmp/erebus-448a0fa/tests/gateway/
    createdb erebus_authz_prefix
    (cd /tmp/erebus-448a0fa && EREBUS_PG_DSN=postgresql:///erebus_authz_prefix \
        "$PY" tests/gateway/test_authz_binding.py --forged-only)
    # BYPASS GET /metrics X-Role AUDITOR -> 200 ... AssertionError
    git worktree remove --force /tmp/erebus-448a0fa; dropdb erebus_authz_prefix
"""
import base64
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

import psycopg
from fastapi.testclient import TestClient
from helpers import fake_detector

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.governance import audit, reveal
from erebus.gateway.observability import Metric, Metrics
from erebus.gateway.providers import quota
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_010_authz")
_KEY = base64.b64encode(os.urandom(32)).decode()
_PERSON = re.compile(r"\[PERSON_\d+_[0-9a-f]+\]")
_FORGED = ("GATEWAY_OPERATOR", "POLICY_ADMIN", "KEY_MANAGER", "AUDITOR", "REVEAL_REVIEWER", "operator")
_HOME = "_operators"  # a literal, so --forged-only still imports on 448a0fa
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


def _forgeries(role):
    """Every way a request can claim a privilege, then all of them at once: (name, body, headers, query)."""
    claim = {"role": role, "privilege": role}
    return (("body", claim, {}, {}), ("X-Role", {}, {"X-Role": role}, {}),
            ("query", {}, {}, claim), ("all", claim, {"X-Role": role}, claim))


def _cred_id(conn, credential):
    return conn.execute("SELECT id FROM scope_credentials WHERE credential_hash = %s",
                        (credentials_directory.hash_credential(credential),)).fetchone()[0]


class _World:
    """Two tenants, a minted token for A with a reveal grant, and the wired app."""

    def __init__(self, conn, pool, kms, resolver):
        self.conn, self.resolver, self.metrics = conn, resolver, Metrics()
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
                         metrics=self.metrics, metrics_enabled=True)
        self.client = TestClient(app)
        check("tenant A chats 200 (setup)", self.chat(self.cred_a, "John Smith").status_code == 200)
        check("tenant B chats 200 (setup)", self.chat(self.cred_b, "hello").status_code == 200)
        self.token = _PERSON.findall(self.captured[0]["messages"][-1]["content"])[0]
        reveal.grant(conn, self.a, "alice", reveal.REVEAL_ROLE, "case 42", [self.token], ttl_seconds=600)
        self.b_cred_id = _cred_id(conn, self.cred_b)
        self.forged_requests = 0

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

    def state(self):
        """Everything a forged admin call could change, as one comparable snapshot."""
        return {
            "keks": (self.kek_rows(self.a), self.kek_rows(self.b)),
            "quota_used": self.requests_used(self.a),
            "scopes": _count(self.conn, "SELECT count(*) FROM scopes"),
            "credentials": _count(self.conn, "SELECT count(*) FROM scope_credentials"),
            "active": _count(self.conn, "SELECT count(*) FROM scope_credentials WHERE status = 'active'"),
            "counters": self.metrics.snapshot_all(),
            "audit_b": len(audit.query(self.conn, self.b)),
            "audit_a_not_forbidden": sum(r["outcome"] != "forbidden" for r in audit.query(self.conn, self.a)),
        }

    def scope_ids(self):
        return [str(r[0]) for r in self.conn.execute("SELECT id FROM scopes").fetchall()]


def _forged(w):
    """US1: a tenant credential claiming any role, by any input, gets 403 everywhere, with no effect."""
    ids, counters = w.scope_ids(), [m.value for m in Metric]
    leaks = (*ids, *counters, "John Smith", "events", "values", "egw_", "scopes")  # never in a refusal
    before = w.state()
    bypass, metrics_replies = [], []
    for method, path, body in w.routes():
        for role in _FORGED:
            for vector, claim, headers, query in _forgeries(role):
                payload = None if body is None and not claim else {**(body or {}), **claim}
                r = w.call(method, path, w.cred_a, payload, headers=headers, params=query)
                w.forged_requests += 1
                if r.status_code == 404 and path == "/v1/admin/operators":
                    continue  # route missing on pre-fix code: not a bypass
                if path == "/metrics":
                    metrics_replies.append(r.text)
                if r.status_code != 403 or any(x in r.text for x in leaks):
                    bypass.append(f"BYPASS {method} {path} {vector} {role} -> {r.status_code}")
    for line in bypass:
        print("  " + line)
    check("no gated route honours a forged role in body, X-Role or query (SC-001/FR-011)", not bypass)
    check("forged /metrics disclosed zero scope ids (SC-002)",
          len(metrics_replies) == len(_FORGED) * 4 and sum(sid in t for t in metrics_replies for sid in ids) == 0)
    check("forged /metrics disclosed zero counters (SC-002)",
          sum(name in t for t in metrics_replies for name in counters) == 0)
    after = w.state()
    for field, value in before.items():
        check(f"forged admin calls changed nothing: {field}", after[field] == value)
    check("tenant A still serves after the forged crypto-erase", w.chat(w.cred_a, "still here").status_code == 200)
    check("tenant B still serves after the forged revoke", w.chat(w.cred_b, "hi").status_code == 200)

    for method, path, body in w.routes():
        claim = {"role": "operator", "privilege": "operator"}
        r = w.call(method, path, None, {**(body or {}), **claim}, headers={"X-Role": "operator"}, params=claim)
        check(f"no credential on {method} {path} is 401 with nothing disclosed, forged role or not",
              r.status_code == 401 and not any(x in r.text for x in leaks))
        r = w.call(method, path, _KEY, body)
        check(f"the master key as a bearer on {method} {path} is 401", r.status_code == 401)


def _operator(w):
    """US2/US4/FR-007: operator credentials work on explicit targets and are audited."""
    from helpers import operator_bearer

    check("the test's home scope key is the gateway's reserved one", _HOME == credentials_directory.OPERATOR_SCOPE_KEY)
    op = operator_bearer(w.conn)
    op_id = _cred_id(w.conn, op)
    home = w.conn.execute("SELECT id FROM scopes WHERE scope_key = %s", (_HOME,)).fetchone()[0]

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
    check("operator crypto-erases that scope", w.call("POST", "/v1/admin/keys", op,
                                                      {"op": "crypto_erase", "scope_key": "org/c"}).status_code == 200)
    for bad in ("_operators", "_hidden"):
        check(f"provisioning reserved scope key {bad!r} is 400",
              w.call("POST", "/v1/admin/scopes", op, {"scope_key": bad}).status_code == 400)
        check(f"onboarding reserved scope key {bad!r} is 400",
              w.call("POST", "/v1/admin/tenants", op, {**_ONBOARD, "scope_key": bad}).status_code == 400)
    check("no '_hidden' scope was created",
          _count(w.conn, "SELECT count(*) FROM scopes WHERE scope_key = '_hidden'") == 0)
    check("the operator home scope got no tenant credential",
          _count(w.conn, "SELECT count(*) FROM scope_credentials WHERE scope_key = %s AND privilege = 'tenant'",
                 (_HOME,)) == 0)

    claim = {"privilege": "operator", "role": "operator"}
    ob = w.call("POST", "/v1/admin/tenants", op, {**_ONBOARD, "scope_key": "org/d", **claim},
                headers={"X-Role": "operator"}, params=claim)
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
    second, second_id = iss.json().get("api_credential", ""), iss.json().get("credential_id")
    check("operator issuance returns credential_id + api_credential",
          iss.status_code == 200 and second.startswith("egw_") and bool(second_id))
    check("the issued row is stored as 'operator'",
          _count(w.conn, "SELECT privilege FROM scope_credentials WHERE id = %s", (second_id,)) == "operator")
    _revoked_operator(w, op, second, second_id)

    rows = [r for sid in (home, w.a, w.b) for r in audit.query(w.conn, sid)]
    secrets = (op, second, w.cred_a, credentials_directory.hash_credential(op).hex())
    check("no audit row carries a token or its hash", not any(s in str(rows) for s in secrets))
    forbidden = [r for r in audit.query(w.conn, w.a) if r["outcome"] == "forbidden"]
    check("every denied admin attempt is audited 'forbidden' once, on the caller's scope (D7)",
          len(forbidden) == w.forged_requests
          and all(r["actor_id"] == str(_cred_id(w.conn, w.cred_a)) and r["actor_role"] == "tenant"
                  for r in forbidden))
    check("audit chains still verify", audit.verify_chain(w.conn, home) and audit.verify_chain(w.conn, w.a))


def _revoked_operator(w, op, second, second_id):
    """FR-007: revoking an operator beats the 5 s resolver cache on every gated route."""
    window = time.monotonic()  # the /metrics lookup below (re)fills the cache entry
    check("the issued operator credential works on /metrics", w.call("GET", "/metrics", second).status_code == 200)
    check("operator credentials cannot chat (home scope has no quota)", w.chat(second, "hi").status_code == 429)
    check("revoking the second operator is 200",
          w.call("DELETE", f"/v1/admin/tenants/{second_id}", op).status_code == 200)
    check("the resolver cache still maps the revoked operator (inside the 5 s window)",
          w.resolver.resolve(second) == _HOME)
    keks, active = w.kek_rows(w.a), w.state()["active"]
    codes = {f"{m} {p}": w.call(m, p, second, b).status_code for m, p, b in w.routes()}
    check("the revoked operator is 401 on every gated route at once (FR-007)", set(codes.values()) == {401})
    check("all of it ran inside the cache window", time.monotonic() - window < 5.0)
    check("the revoked operator changed nothing", w.kek_rows(w.a) == keks and w.state()["active"] == active)
    check("the fresh admin lookup evicted the stale entry: chat is 401 too", w.chat(second, "hi").status_code == 401)


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
