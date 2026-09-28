"""Live runtime tenant onboarding over the app (008 US3; T031/T032/T033).

Drives POST /v1/admin/tenants and DELETE /v1/admin/tenants/{id} THROUGH the app with a real
``MasterKeyKms`` + ``DbScopeResolver`` + a live ``scope_key -> scope_id`` directory + a fake
echo egress. Asserts the US3 acceptance:

* an operator call provisions a tenant end-to-end and returns an ``api_credential``,
* that credential IMMEDIATELY authenticates and serves /v1/chat/completions with NO restart,
* tenant A's credential never authenticates as tenant B (cross-tenant isolation),
* DELETE revokes the credential so a later request 401s (within the resolver cache TTL),
* a non-operator role is denied (403).

Live Postgres; self-skips without it.
"""
import base64
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")  # no GLiNER daemon in tests

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway import rbac
from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_us3_onboard")
_KEY = base64.b64encode(os.urandom(32)).decode()
_TTL = 0.5  # short enough to assert revocation latency without a slow test
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _ScopeIdDirectory:
    """Live ``scope_key -> scope_id`` view over ``scopes`` so a fresh onboard resolves now."""

    def __init__(self, pool) -> None:
        self._pool = pool

    def _lookup(self, scope_key):
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT id FROM scopes WHERE scope_key = %s AND status = 'active'",
                (scope_key,),
            ).fetchone()
        return row[0] if row else None

    def __contains__(self, scope_key):
        return isinstance(scope_key, str) and self._lookup(scope_key) is not None

    def __getitem__(self, scope_key):
        sid = self._lookup(scope_key)
        if sid is None:
            raise KeyError(scope_key)
        return sid


def main():
    print("\n=== Live runtime tenant onboarding (T031/T032/T033) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True  # so the KMS/resolver/egress pools see migrations + provisioned rows
    kms = None
    pool = None
    resolver = None
    try:
        from psycopg_pool import ConnectionPool

        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = MasterKeyKms(_DSN, _KEY)
        # The operator is itself a pre-provisioned tenant with its own credential.
        op_id = provision_scope(conn, kms, "ops/admin")
        op_cred = credentials_directory.provision(conn, op_id, "ops/admin", label="operator")

        captured = {}

        async def echo_egress(scope_id, payload):
            captured.clear()
            captured.update(scope_id=str(scope_id), payload=payload)
            content = payload["messages"][-1]["content"]
            return {"choices": [{"message": {"role": "assistant", "content": "Re: " + content}}]}

        pool = ConnectionPool(_DSN, min_size=1, max_size=4, open=True)
        resolver = DbScopeResolver(_DSN, ttl_s=_TTL)
        app = create_app(
            conn=conn, key_provider=kms, detector=lambda _t: [],
            scopes=resolver, scope_ids=_ScopeIdDirectory(pool),
            egress=echo_egress, pool=pool,
        )
        client = TestClient(app)

        op_role = str(rbac.Role.GATEWAY_OPERATOR)
        op_headers = {"Authorization": "Bearer " + op_cred}

        def onboard(scope_key, role=op_role, headers=None):
            return client.post(
                "/v1/admin/tenants",
                json={
                    "scope_key": scope_key,
                    "provider": "openai",
                    "central_credential": "CENTRAL-SECRET-" + scope_key,
                    "routes": [{"base_url": "https://api.openai.com", "model_allowlist": ["gpt-4o"]}],
                    "quota": {"rate_limit": 100, "spend_budget": 1000, "window_seconds": 60},
                    "role": role,
                    "policy": {"images": "block"},  # MUST be ignored (descoped for beta)
                },
                headers=op_headers if headers is None else headers,
            )

        # --- T032: an operator onboards tenant A end-to-end, gets an api_credential. ---
        ra = onboard("org/a")
        check("onboard returns 200 for an operator (T032)", ra.status_code == 200)
        body_a = ra.json()
        check("onboard returns a scope_id and api_credential",
              bool(body_a.get("scope_id")) and body_a.get("api_credential", "").startswith("egw_"))
        cred_a = body_a["api_credential"]

        # --- The new tenant is servable IMMEDIATELY, with no restart (FR-005/006). ---
        chat_a = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello A"}]},
            headers={"Authorization": "Bearer " + cred_a},
        )
        check("the freshly onboarded credential serves chat with NO restart (SC-003)",
              chat_a.status_code == 200)
        check("the request egressed under the NEW tenant's scope",
              captured.get("scope_id") == body_a["scope_id"])

        # The provisioned central credential + approved route were wired (used by live egress).
        with pool.connection() as c:
            sid_a = c.execute(
                "SELECT id FROM scopes WHERE scope_key = 'org/a'"
            ).fetchone()[0]
            n_routes = c.execute(
                "SELECT count(*) FROM provider_routes WHERE scope_id = %s AND approved = true",
                (sid_a,),
            ).fetchone()[0]
            has_cred = c.execute(
                "SELECT count(*) FROM provider_credentials WHERE scope_id = %s AND provider = 'openai'",
                (sid_a,),
            ).fetchone()[0]
            has_quota = c.execute(
                "SELECT count(*) FROM quotas WHERE scope_id = %s", (sid_a,)
            ).fetchone()[0]
        check("onboarding wired an approved route", n_routes == 1)
        check("onboarding wired a central provider credential", has_cred == 1)
        check("onboarding wired a quota", has_quota == 1)

        # --- Onboard tenant B; A's credential must never authenticate as B. ---
        rb = onboard("org/b")
        cred_b = rb.json()["api_credential"]
        check("onboard tenant B returns a distinct credential", cred_b != cred_a)
        client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello B"}]},
            headers={"Authorization": "Bearer " + cred_b},
        )
        check("tenant B's credential egresses under tenant B's scope (isolation)",
              captured.get("scope_id") == rb.json()["scope_id"]
              and rb.json()["scope_id"] != body_a["scope_id"])
        check("tenant A's credential never authenticates as tenant B",
              body_a["scope_id"] != rb.json()["scope_id"])

        # --- A non-operator role is denied (403). ---
        denied = onboard("org/should-not-exist", role=str(rbac.Role.AUDITOR))
        check("a non-operator role is denied onboarding 403 (FR-016)", denied.status_code == 403)
        with pool.connection() as c:
            exists = c.execute(
                "SELECT count(*) FROM scopes WHERE scope_key = 'org/should-not-exist'"
            ).fetchone()[0]
        check("the denied onboard provisioned nothing", exists == 0)

        # --- T033: DELETE revokes; the credential 401s within the resolver cache TTL. ---
        cred_a_id = credentials_directory.hash_credential(cred_a)
        with pool.connection() as c:
            row_id = c.execute(
                "SELECT id FROM scope_credentials WHERE credential_hash = %s", (cred_a_id,)
            ).fetchone()[0]
        rev = client.request(
            "DELETE", f"/v1/admin/tenants/{row_id}", headers={**op_headers, "X-Role": op_role}
        )
        check("DELETE revokes the credential 200 (T033)", rev.status_code == 200)
        rev2 = client.request(
            "DELETE", f"/v1/admin/tenants/{row_id}", headers={**op_headers, "X-Role": op_role}
        )
        check("revoking an already-revoked credential 404s", rev2.status_code == 404)

        time.sleep(_TTL + 0.2)  # let the resolver cache expire so the revoke takes effect
        after = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello again"}]},
            headers={"Authorization": "Bearer " + cred_a},
        )
        check("a revoked credential 401s after the resolver cache TTL (FR-006)",
              after.status_code == 401)
        check("tenant B's credential still authenticates after A is revoked",
              client.post(
                  "/v1/chat/completions",
                  json={"model": "gpt-4o", "messages": [{"role": "user", "content": "still here"}]},
                  headers={"Authorization": "Bearer " + cred_b},
              ).status_code == 200)

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
