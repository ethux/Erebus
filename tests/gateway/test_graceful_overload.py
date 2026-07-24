"""Graceful overload sheds 503 + Retry-After with per-tenant fairness (T036/T043).

A per-tenant :class:`~erebus.gateway.overload.Limiter` is wired into ``create_app``.
Under saturation the gateway must shed overflow requests with ``503`` + a
``Retry-After`` header rather than failing globally, and one tenant's burst must
NOT starve another (FR-047/FR-010).

The provider call blocks on a gate the test controls, so the test can pin
``max_concurrent`` in-flight requests for tenant A (filling its limiter), fire one
more A request that must be shed, and -- while A is saturated -- prove a B request
still serves. Each tenant gets its own cloned limiter, so A's saturation is bounded
to A. Live Postgres; self-skips without it.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.overload import Limiter
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


def main():
    print("\n=== Gateway graceful overload + per-tenant fairness (T036/T043) ===\n")
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
        quota.set_quota(setup, a, 100000, 100000000, 60)
        quota.set_quota(setup, b, 100000, 100000000, 60)
        setup.commit()

        # The gate lets the test pin in-flight requests so a tenant's limiter saturates.
        entered = threading.Semaphore(0)   # released once per request that reaches the provider
        release = threading.Event()        # held requests block here until the test frees them

        async def provider(payload):
            entered.release()
            # Block in a worker thread so the event loop is not stalled.
            import anyio
            await anyio.to_thread.run_sync(release.wait)
            return {"choices": [{"message": {"content": payload["messages"][-1]["content"]}}]}

        pool = ConnectionPool(_DSN, min_size=4, max_size=12, open=True)
        # max_concurrent=2, max_queue=0 -> the 3rd concurrent request for a tenant is shed.
        app = create_app(
            pool=pool, key_provider=kms, detector=lambda _t: [], provider_call=provider,
            scopes=ScopeResolver({"cA": "tenA", "cB": "tenB"}), scope_ids={"tenA": a, "tenB": b},
            limiter=Limiter(max_concurrent=2, max_queue=0, retry_after_seconds=2),
        )

        def fire(cred, out):
            r = TestClient(app).post(
                "/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
                json={"messages": [{"role": "user", "content": "hi"}]},
            )
            out.append((r.status_code, r.headers.get("Retry-After")))

        held = []
        threads = [threading.Thread(target=fire, args=("cA", held)) for _ in range(2)]
        for t in threads:
            t.start()
        # Wait until both A requests are pinned inside the provider (limiter is full).
        both_in = entered.acquire(timeout=10) and entered.acquire(timeout=10)
        check("two tenant-A requests admitted and in flight", both_in)

        # A third A request, with A saturated, must be shed 503 + Retry-After (not blocked).
        shed = []
        fire("cA", shed)
        check("overflow request for the saturated tenant is shed 503 (FR-047)", shed[0][0] == 503)
        check("shed response carries a Retry-After header (FR-047)",
              shed[0][1] is not None and int(shed[0][1]) >= 1)

        # While A is saturated, a tenant-B request must still serve: A does not starve B.
        bout = []
        bt = threading.Thread(target=fire, args=("cB", bout))
        bt.start()
        check("tenant B's request reaches the provider despite A's saturation", entered.acquire(timeout=10))
        release.set()  # free everyone
        bt.join(timeout=10)
        for t in threads:
            t.join(timeout=10)
        check("tenant B served 200 while A was saturated (per-tenant fairness, FR-010)",
              bout and bout[0][0] == 200)
        check("both held tenant-A requests completed 200 after release",
              held and all(s == 200 for s, _ in held))

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        try:
            release.set()
        except Exception:
            pass
        if pool is not None:
            pool.close()
        setup.close()


if __name__ == "__main__":
    main()
