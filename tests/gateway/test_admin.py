"""Admin/governance routes (T049 audit query, T060 key lifecycle, T042 reveal rate-limit).

Live Postgres; self-skips without it. Verifies the operator-credential gate (010) on the
audit query, key rotate (restore preserved) + crypto-erase (fail-closed), detokenization
rate-limiting, and provisioning; a tenant credential is refused whatever role it claims.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


async def _provider(_payload):
    return {"choices": [{"message": {"content": "ok"}}]}


def main():
    print("\n=== Gateway admin/governance routes (T049/T060/T042) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        a = provision_scope(conn, kms, "tenA")
        q = provision_scope(conn, kms, "tenQ")
        op = provision_scope(conn, kms, "ops")
        quota.set_quota(conn, a, 100, 1000, 60)
        quota.set_quota(conn, q, 2, 1000, 60)
        app = create_app(conn=conn, key_provider=kms, detector=lambda _t: [], provider_call=_provider,
                         scopes=ScopeResolver({"cA": "tenA", "cQ": "tenQ", "cOp": "ops"}, operators={"cOp"}),
                         scope_ids={"tenA": a, "tenQ": q, "ops": op})
        client = TestClient(app)
        chat = lambda: client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "hi"}]},
                                   headers={"Authorization": "Bearer cA"})
        tenant = {"Authorization": "Bearer cA"}
        operator = {"Authorization": "Bearer cOp"}

        chat()  # generate an audit event

        # T049: audit query, operator credential only (010).
        ra = client.get("/v1/audit", params={"scope_key": "tenA"}, headers=operator)
        check("operator can query a tenant's audit chain (T049)",
              ra.status_code == 200 and len(ra.json()["events"]) >= 1)
        rden = client.get("/v1/audit", headers={**tenant, "X-Role": "AUDITOR"})
        check("tenant claiming AUDITOR denied audit read (010)", rden.status_code == 403)
        check("audit events carry no raw value",
              all("hi" not in str(e.get("masked_value")) for e in ra.json()["events"]))

        # T060: key lifecycle routes.
        rot = client.post("/v1/admin/keys", json={"op": "rotate", "scope_key": "tenA"}, headers=operator)
        check("key rotation by an operator (T060)", rot.status_code == 200)
        check("chat still works after rotation (SC-008)", chat().status_code == 200)
        bad = client.post("/v1/admin/keys", json={"op": "rotate", "role": "KEY_MANAGER"}, headers=tenant)
        check("key op denied for a tenant claiming KEY_MANAGER (010)", bad.status_code == 403)
        check("key op without a target scope_key is 400",
              client.post("/v1/admin/keys", json={"op": "rotate"}, headers=operator).status_code == 400)
        er = client.post("/v1/admin/keys", json={"op": "crypto_erase", "scope_key": "tenA"}, headers=operator)
        check("crypto-erase by an operator (T060/FR-040)", er.status_code == 200)
        check("chat fails closed after crypto-erase (US5)", chat().status_code == 503)

        # T042: reveal detokenization is rate-limited on the target scope (q, rate=2).
        rev = lambda: client.post("/v1/reveal", json={"grantee": "x", "scope_key": "tenQ", "tokens": ["[X]"]},
                                  headers=operator)
        check("reveal attempt 1 under the rate", rev().status_code == 403)   # reserved, then grant-denied
        check("reveal attempt 2 under the rate", rev().status_code == 403)
        check("reveal attempt 3 rate-limited 429 (T042/FR-018)", rev().status_code == 429)

        # T058: declarative tenancy provisioning, operator credential only.
        pr = client.post("/v1/admin/scopes", json={"scope_key": "neworg/team"}, headers=operator)
        check("provision a scope by an operator (T058/FR-005)",
              pr.status_code == 200 and pr.json().get("scope_id"))
        check("provision denied for a tenant claiming POLICY_ADMIN (010)",
              client.post("/v1/admin/scopes", json={"role": "POLICY_ADMIN", "scope_key": "x"},
                          headers=tenant).status_code == 403)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
