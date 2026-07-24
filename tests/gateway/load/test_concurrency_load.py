"""Multi-tenant load / perf harness for SC-006 (T055). NOT a per-commit gate.

SC-006: the service sustains >=500 concurrent users across multiple tenants on a
single deployment with under 50 ms of gateway-induced added latency (excluding
upstream provider time) and zero isolation failures.

This file is opt-in. By default (``EREBUS_LOAD`` unset) it runs a tiny smoke that
exercises the same path with a handful of requests so the file always exits 0 in
the normal suite. Set ``EREBUS_LOAD=1`` to drive the full ~500-request load.

What it does either way: it builds an in-process gateway (``create_app`` over a
real psycopg pool, a fast in-memory "egress" standing in for the provider, and 2+
tenants), fires many OVERLAPPING multi-tenant requests through a threadpool, and:

  * HARD-asserts ZERO isolation failures: every request gets back ONLY its own
    tenant's restored value, never the other tenant's, and never an unrestored
    token (FR-009/FR-037);
  * measures the gateway-induced added latency (total request time minus the time
    the fake egress deliberately costs) and records the p50/p95/p99. The <50 ms
    p95 budget is the SC-006 target, but since this is a dev box we PRINT/record
    the measured number and only HARD-assert isolation + that the whole run
    completes. The latency line is informational, not a gate.

Mirrors ``tests/gateway/test_concurrency.py`` for the pooled multi-tenant setup.
Self-skips (exit 0) when Postgres or psycopg_pool is unavailable.
"""
import concurrent.futures
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")  # no GLiNER daemon in this harness

import anyio
import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_load")
# Per credential: (its own subject value, the OTHER scope's value it must never see).
_EXPECT = {"cA": ("Alice Adams", "Bob Brown"), "cB": ("Bob Brown", "Alice Adams")}
_NAMES = ("Alice Adams", "Bob Brown")
# Wall time the fake egress deliberately costs, subtracted out so the recorded
# latency is the GATEWAY-induced added latency only (excluding upstream time).
_EGRESS_COST_S = 0.002
# Heavy load when opted in; a tiny smoke otherwise so the file still exits 0.
_LOAD = os.environ.get("EREBUS_LOAD") not in (None, "", "0")
_TOTAL = 500 if _LOAD else 8
_WORKERS = 64 if _LOAD else 8
# Budget high enough to admit the whole run within one window (SC-006 target).
_BUDGET = max(_TOTAL * 4, 100000)

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


def _percentile(values, pct):
    """Nearest-rank percentile of a list of floats (values need not be sorted)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, round((pct / 100.0) * len(ordered) + 0.5) - 1))
    return ordered[rank]


def main():
    mode = "FULL LOAD" if _LOAD else "smoke (set EREBUS_LOAD=1 for full)"
    print(f"\n=== Gateway multi-tenant load / perf harness (SC-006) [{mode}] ===\n")
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
        quota.set_quota(setup, a, _BUDGET, 10 ** 12, 60)
        quota.set_quota(setup, b, _BUDGET, 10 ** 12, 60)
        setup.commit()

        async def prov(payload):
            # Stand-in for the upstream provider: echo the (tokenized) content back
            # so restore is exercised, after a fixed, known cost we subtract out.
            await anyio.sleep(_EGRESS_COST_S)
            return {"choices": [{"message": {"content": payload["messages"][-1]["content"]}}]}

        pool = ConnectionPool(_DSN, min_size=4, max_size=max(_WORKERS, 8), open=True)
        app = create_app(pool=pool, key_provider=kms, detector=detector, provider_call=prov,
                         scopes=ScopeResolver({"cA": "tenA", "cB": "tenB"}),
                         scope_ids={"tenA": a, "tenB": b})
        # Reuse one client across threads; TestClient is backed by a threadsafe
        # transport and each call checks out its own pooled DB connection.
        client = TestClient(app)

        def worker(cred):
            mine = _EXPECT[cred][0]
            t0 = time.perf_counter()
            r = client.post("/v1/chat/completions",
                            headers={"Authorization": f"Bearer {cred}"},
                            json={"messages": [{"role": "user", "content": f"Hi {mine}"}]})
            elapsed = time.perf_counter() - t0
            try:
                content = r.json()["choices"][0]["message"]["content"]
            except Exception:
                content = ""
            # Gateway-induced added latency excludes the egress cost (SC-006).
            added_ms = max(0.0, (elapsed - _EGRESS_COST_S)) * 1000.0
            return cred, r.status_code, content, added_ms

        # Interleave the two tenants so requests genuinely overlap across scopes.
        jobs = (["cA", "cB"] * ((_TOTAL // 2) + 1))[:_TOTAL]
        t_run0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as ex:
            results = list(ex.map(worker, jobs))
        run_s = time.perf_counter() - t_run0

        check(f"all {_TOTAL} concurrent multi-tenant requests returned 200",
              len(results) == _TOTAL and all(s == 200 for _, s, _, _ in results))
        # ISOLATION (hard gate): each tenant sees ONLY its own restored value.
        check("zero isolation failures: every tenant got back only its own value (FR-009)",
              all(_EXPECT[c][0] in body and _EXPECT[c][1] not in body
                  for c, _, body, _ in results))
        check("no unrestored token leaked under concurrent load (FR-037)",
              all("[PERSON_" not in body for _, _, body, _ in results))

        added = [ms for _, _, _, ms in results]
        p50, p95, p99 = _percentile(added, 50), _percentile(added, 95), _percentile(added, 99)
        within = "WITHIN" if p95 < 50.0 else "OVER"
        throughput = _TOTAL / run_s if run_s > 0 else 0.0
        print(
            f"\n  SC-006 added-latency (gateway-induced, excl. upstream): "
            f"p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms "
            f"({within} the <50ms budget) | {_TOTAL} reqs in {run_s:.2f}s "
            f"({throughput:.0f} req/s) across 2 tenants, {_WORKERS} workers"
        )
        if not _LOAD:
            print("  (smoke run; set EREBUS_LOAD=1 to drive the full ~500-request load)")

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if pool is not None:
            pool.close()
        setup.close()


if __name__ == "__main__":
    main()
