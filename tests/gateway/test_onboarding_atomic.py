"""Tenant onboarding is validated up front and atomic (009 R4/FR-004).

Regression for the 008 review finding that ``POST /v1/admin/tenants`` interpreted its body
step-by-step in separate transactions: a route missing ``base_url`` or a non-numeric quota
raised an uncaught ``KeyError``/``ValueError`` (500) and could leave a partially-provisioned
tenant behind. Onboarding must now:

* reject malformed input (missing route ``base_url``; non-numeric/negative quota) with a 4xx
  and create ZERO rows;
* roll the WHOLE sequence back if any step fails mid-way (no partial tenant);
* still provision a fully servable tenant for a well-formed request.

Drives the live app with a ``MasterKeyKms`` + ``DbScopeResolver`` + a fake echo egress. Live
Postgres; self-skips without it.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway import rbac
from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_009_onboard_atomic")
_KEY = base64.b64encode(os.urandom(32)).decode()
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _scope_exists(pool, scope_key):
    with pool.connection() as c:
        return c.execute(
            "SELECT count(*) FROM scopes WHERE scope_key = %s", (scope_key,)
        ).fetchone()[0]


def main():
    print("\n=== Tenant onboarding validated + atomic (009 R4/FR-004) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True
    kms = None
    pool = None
    resolver = None
    try:
        from psycopg_pool import ConnectionPool

        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")

        kms = MasterKeyKms(_DSN, _KEY)
        op_id = provision_scope(conn, kms, "ops/admin")
        op_cred = credentials_directory.provision(conn, op_id, "ops/admin", label="operator")

        async def echo_egress(scope_id, payload):
            content = payload["messages"][-1]["content"]
            return {"choices": [{"message": {"role": "assistant", "content": "Re: " + content}}]}

        pool = ConnectionPool(_DSN, min_size=1, max_size=4, open=True)
        resolver = DbScopeResolver(_DSN, ttl_s=0.5)
        app = create_app(
            conn=conn, key_provider=kms, detector=lambda _t: [],
            scopes=resolver, scope_ids={}, egress=echo_egress, pool=pool,
        )
        # raise_server_exceptions=False so a forced mid-sequence failure surfaces as a 500
        # RESPONSE (the DB-rollback assertions below run) instead of re-raising into the test.
        client = TestClient(app, raise_server_exceptions=False)

        op_role = str(rbac.Role.GATEWAY_OPERATOR)
        op_headers = {"Authorization": "Bearer " + op_cred}

        def onboard(body):
            return client.post("/v1/admin/tenants", json=body, headers=op_headers)

        base = {
            "provider": "openai",
            "central_credential": "CENTRAL-SECRET",
            "routes": [{"base_url": "https://api.openai.com", "model_allowlist": ["gpt-4o"]}],
            "quota": {"rate_limit": 100, "spend_budget": 1000, "window_seconds": 60},
            "role": op_role,
        }

        def scopes_before():
            with pool.connection() as c:
                return c.execute("SELECT count(*) FROM scopes").fetchone()[0]

        # --- 1) A route missing base_url -> 4xx, and NOTHING provisioned. ---
        before = scopes_before()
        bad_route = {**base, "scope_key": "org/no-base-url",
                     "routes": [{"model_allowlist": ["gpt-4o"]}]}  # base_url missing
        r = onboard(bad_route)
        check("onboard with a route missing base_url is 4xx (FR-004)",
              400 <= r.status_code < 500)
        check("the malformed-route onboard created no scope row",
              _scope_exists(pool, "org/no-base-url") == 0)
        check("the malformed-route onboard created no rows at all", scopes_before() == before)

        # --- 2) A non-numeric quota -> 4xx, NOTHING provisioned. ---
        bad_quota = {**base, "scope_key": "org/bad-quota",
                     "quota": {"rate_limit": "lots", "spend_budget": 1000, "window_seconds": 60}}
        r = onboard(bad_quota)
        check("onboard with a non-numeric quota is 4xx (FR-004)", 400 <= r.status_code < 500)
        check("the non-numeric-quota onboard created no scope row",
              _scope_exists(pool, "org/bad-quota") == 0)

        # --- 3) A negative quota -> 4xx, NOTHING provisioned. ---
        neg_quota = {**base, "scope_key": "org/neg-quota",
                     "quota": {"rate_limit": -5, "spend_budget": 1000, "window_seconds": 60}}
        r = onboard(neg_quota)
        check("onboard with a negative quota is 4xx (FR-004)", 400 <= r.status_code < 500)
        check("the negative-quota onboard created no scope row",
              _scope_exists(pool, "org/neg-quota") == 0)

        # --- 4) A forced mid-sequence failure rolls the WHOLE sequence back. ---
        # Patch the LAST provisioning step (set_quota) to raise: by then the scope, API
        # credential, central credential, and routes are already written, so a single
        # transaction must roll ALL of them back, leaving no partial tenant.
        from erebus.gateway import app as app_mod

        orig_set_quota = app_mod.quota.set_quota

        def boom(*_a, **_k):
            raise RuntimeError("forced mid-sequence failure")

        before = scopes_before()
        app_mod.quota.set_quota = boom
        try:
            r = onboard({**base, "scope_key": "org/forced-fail"})
        finally:
            app_mod.quota.set_quota = orig_set_quota
        check("a forced mid-sequence failure is a 5xx (no success)", r.status_code >= 500)
        check("a forced mid-sequence failure left no scope row (rolled back, FR-004)",
              _scope_exists(pool, "org/forced-fail") == 0)
        check("a forced mid-sequence failure created no rows at all", scopes_before() == before)
        with pool.connection() as c:
            orphan_creds = c.execute(
                "SELECT count(*) FROM scope_credentials WHERE scope_key = 'org/forced-fail'"
            ).fetchone()[0]
        check("a forced mid-sequence failure left no orphaned API credential", orphan_creds == 0)

        # --- 5) A well-formed request still provisions a SERVABLE tenant. ---
        ok = onboard({**base, "scope_key": "org/good"})
        check("a well-formed onboard returns 200", ok.status_code == 200)
        body = ok.json()
        check("a well-formed onboard returns scope_id + api_credential",
              bool(body.get("scope_id")) and body.get("api_credential", "").startswith("egw_"))
        cred = body["api_credential"]
        served = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]},
            headers={"Authorization": "Bearer " + cred},
        )
        check("the onboarded tenant serves chat immediately (atomic provision)",
              served.status_code == 200)
        with pool.connection() as c:
            sid = c.execute("SELECT id FROM scopes WHERE scope_key = 'org/good'").fetchone()[0]
            routes = c.execute(
                "SELECT count(*) FROM provider_routes WHERE scope_id = %s AND approved = true",
                (sid,),
            ).fetchone()[0]
            creds = c.execute(
                "SELECT count(*) FROM provider_credentials WHERE scope_id = %s", (sid,)
            ).fetchone()[0]
            quotas = c.execute(
                "SELECT count(*) FROM quotas WHERE scope_id = %s", (sid,)
            ).fetchone()[0]
        check("the servable tenant has its approved route, credential, and quota",
              routes == 1 and creds == 1 and quotas == 1)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if resolver is not None:
            resolver.close()
        if pool is not None:
            pool.close()
        if kms is not None:
            kms.close()
        conn.close()


if __name__ == "__main__":
    main()
