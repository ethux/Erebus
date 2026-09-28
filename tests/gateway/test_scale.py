"""Horizontal-scale properties (T052/T053/T054).

T052: a token minted via one gateway instance restores via another over the shared
Postgres state (FR-037). T053: a concurrency-capped instance still serves (the
per-tenant limiter does not break the normal path; the limiter itself is covered by
test_overload). Live Postgres; self-skips without it.
"""
import os
import re
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
_PERSON = re.compile(r"\[PERSON_\d+_[0-9a-f]+\]")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def detector(text):
    i = text.find("John Smith")
    return [(i, i + 10, "PERSON")] if i != -1 else []


def main():
    print("\n=== Gateway horizontal scale (T052/T053) ===\n")
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
        quota.set_quota(conn, a, 100, 1000, 60)
        resolver = ScopeResolver({"cA": "tenA"})
        ids = {"tenA": a}

        # Instance 1 mints a token for "John Smith".
        captured = []

        async def prov1(payload):
            captured.append(payload)
            return {"choices": [{"message": {"content": "ok"}}]}

        app1 = create_app(conn=conn, key_provider=kms, detector=detector, provider_call=prov1,
                          scopes=resolver, scope_ids=ids)
        TestClient(app1).post("/v1/chat/completions",
                              json={"messages": [{"role": "user", "content": "Email John Smith"}]},
                              headers={"Authorization": "Bearer cA"})
        tok = _PERSON.findall(captured[-1]["messages"][-1]["content"])[0]

        # Instance 2 (separate app object, same shared Postgres) restores it.
        async def prov2(payload):
            return {"choices": [{"message": {"content": "see " + tok}}]}

        app2 = create_app(conn=conn, key_provider=kms, detector=detector, provider_call=prov2,
                          scopes=resolver, scope_ids=ids)
        r2 = TestClient(app2).post("/v1/chat/completions",
                                   json={"messages": [{"role": "user", "content": "hello"}]},
                                   headers={"Authorization": "Bearer cA"})
        out = r2.json()["choices"][0]["message"]["content"]
        check("token minted on instance 1 restores on instance 2 (T052/FR-037)",
              "John Smith" in out and tok not in out)

        # Concurrency-capped instance still serves the normal path (T053).
        app3 = create_app(conn=conn, key_provider=kms, detector=detector, provider_call=prov1,
                          scopes=resolver, scope_ids=ids, concurrency_cap=1)
        r3 = TestClient(app3).post("/v1/chat/completions",
                                   json={"messages": [{"role": "user", "content": "hi"}]},
                                   headers={"Authorization": "Bearer cA"})
        check("concurrency-capped instance serves normally (T053/FR-038)", r3.status_code == 200)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
