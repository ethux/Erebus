"""Real cross-scope concurrency / isolation (T053/FR-037/FR-009) against live Postgres.

The scale test covers sequential cross-instance restore; this one fires many
OVERLAPPING requests across two scopes through a real connection pool, so a shared
connection or a raced per-scope RLS ``set_config`` would surface as a cross-tenant
restore, an unrestored token, or a 500. Each request checks out its own pooled
connection, so every scope must restore only its own value. Self-skips without
Postgres or psycopg_pool.
"""
import concurrent.futures
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import anyio
import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
# Per credential: (its own subject value, the OTHER scope's value it must never see).
_EXPECT = {"cA": ("Alice Adams", "Bob Brown"), "cB": ("Bob Brown", "Alice Adams")}
_NAMES = ("Alice Adams", "Bob Brown")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def detector(text):
    """Find whichever fixture name a request carries (shared across scopes)."""
    return [(text.find(n), text.find(n) + len(n), "PERSON") for n in _NAMES if n in text]


def main():
    print("\n=== Gateway cross-scope concurrency / isolation (FR-009/FR-037) ===\n")
    try:
        from psycopg_pool import ConnectionPool
    except Exception as exc:
        print(f"  (skipped: psycopg_pool unavailable: {exc})")
        return
    try:
        setup = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return

    pool = None
    try:
        db.run_migrations(setup)
        with setup.transaction():
            setup.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        a, b = provision_scope(setup, kms, "tenA"), provision_scope(setup, kms, "tenB")
        quota.set_quota(setup, a, 100000, 10000000, 60)
        quota.set_quota(setup, b, 100000, 10000000, 60)
        setup.commit()

        async def prov(payload):
            await anyio.sleep(0.01)  # force temporal overlap across worker threads
            return {"choices": [{"message": {"content": payload["messages"][-1]["content"]}}]}

        pool = ConnectionPool(_DSN, min_size=2, max_size=8, open=True)
        app = create_app(pool=pool, key_provider=kms, detector=detector, provider_call=prov,
                         scopes=ScopeResolver({"cA": "tenA", "cB": "tenB"}),
                         scope_ids={"tenA": a, "tenB": b})

        def worker(cred):
            mine = _EXPECT[cred][0]
            r = TestClient(app).post("/v1/chat/completions",
                                     headers={"Authorization": f"Bearer {cred}"},
                                     json={"messages": [{"role": "user", "content": f"Hi {mine}"}]})
            try:
                content = r.json()["choices"][0]["message"]["content"]
            except Exception:
                content = ""
            return cred, r.status_code, content

        jobs = ["cA", "cB"] * 20  # 40 overlapping requests, interleaved across the two scopes
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(worker, jobs))

        check("all 40 overlapping cross-scope requests returned 200",
              len(results) == 40 and all(s == 200 for _, s, _ in results))
        check("each scope restored ONLY its own value (no cross-tenant leak, FR-009)",
              all(_EXPECT[c][0] in body and _EXPECT[c][1] not in body for c, _, body in results))
        check("no unrestored token leaked under concurrent load",
              all("[PERSON_" not in body for _, _, body in results))

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if pool is not None:
            pool.close()
        setup.close()


if __name__ == "__main__":
    main()
