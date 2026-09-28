"""GET /metrics is authenticated + RBAC-gated (009 R2/FR-002).

Regression for the 008 review finding that ``GET /metrics`` returned every scope id and
per-tenant counter to ANY caller. The metrics surface must now require an authenticated
credential AND an operator/auditor role, just like the other administrative routes:

* no credential -> 401, with ZERO scope ids/counters in the body;
* a valid credential with a non-operator/auditor role -> 403, again disclosing nothing;
* an operator role -> 200 masked telemetry; an auditor role -> 200 masked telemetry.

Drives the live app with a ``DbScopeResolver`` so the operator credential authenticates the
same way a deployed tenant does. Live Postgres; self-skips without it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway import rbac
from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.observability import Metric, Metrics
from erebus.gateway.providers import quota
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_009_metrics_auth")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


async def _egress(_scope_id, payload):
    user = payload["messages"][-1]["content"]
    return {"choices": [{"message": {"role": "assistant", "content": "Re: " + user}}]}


def main():
    print("\n=== GET /metrics authenticated + RBAC-gated (009 R2/FR-002) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True  # so the resolver's separate pool sees the provisioned rows
    resolver = None
    try:
        from psycopg_pool import ConnectionPool

        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")

        kms = LocalKms()
        served = provision_scope(conn, kms, "tenServed")
        cred = credentials_directory.provision(conn, served, "tenServed", label="ci")
        quota.set_quota(conn, served, 1000, 100000, 60)

        pool = ConnectionPool(_DSN, min_size=1, max_size=4, open=True)
        resolver = DbScopeResolver(_DSN, ttl_s=0.5)
        metrics = Metrics()
        app = create_app(
            conn=conn, key_provider=kms, detector=lambda _t: [],
            scopes=resolver, scope_ids={}, pool=pool,
            egress=_egress, metrics=metrics, metrics_enabled=True,
        )
        client = TestClient(app)

        # Drive one served request so there is real per-scope telemetry to expose/hide.
        served_resp = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": "Bearer " + cred},
        )
        check("a served request is recorded (telemetry exists)", served_resp.status_code == 200)
        sid = str(served)

        # 1) No credential -> 401, and NOTHING disclosed.
        r401 = client.get("/metrics")
        check("GET /metrics with no credential is 401 (FR-002)", r401.status_code == 401)
        check("the 401 body discloses no scope id", sid not in r401.text)
        check("the 401 body discloses no counter name", Metric.REQUESTS.value not in r401.text)

        # 2) A valid credential but a non-operator/auditor role -> 403, again nothing.
        for role in (rbac.Role.REVEAL_REVIEWER, rbac.Role.KEY_MANAGER):
            r403 = client.get(
                "/metrics",
                headers={"Authorization": "Bearer " + cred, "X-Role": str(role)},
            )
            check(f"GET /metrics with non-operator role {role} is 403 (FR-002)",
                  r403.status_code == 403)
            check(f"the {role} 403 body discloses no scope id", sid not in r403.text)
            check(f"the {role} 403 body discloses no counter", Metric.REQUESTS.value not in r403.text)

        # 3) An operator role -> 200 masked telemetry.
        rop = client.get(
            "/metrics",
            headers={"Authorization": "Bearer " + cred, "X-Role": str(rbac.Role.GATEWAY_OPERATOR)},
        )
        check("GET /metrics with an operator role is 200 (FR-002)", rop.status_code == 200)
        op_scopes = rop.json().get("scopes", {})
        check("operator sees the masked per-scope telemetry",
              op_scopes.get(sid, {}).get(Metric.REQUESTS.value, 0) >= 1)
        op_counts = [v for snap in op_scopes.values() for v in snap.values()]
        check("operator telemetry is integer counts only (masked)",
              op_counts and all(isinstance(v, int) for v in op_counts))

        # 4) An auditor role -> 200 masked telemetry too.
        raud = client.get(
            "/metrics",
            headers={"Authorization": "Bearer " + cred, "X-Role": str(rbac.Role.AUDITOR)},
        )
        check("GET /metrics with an auditor role is 200 (FR-002)", raud.status_code == 200)
        check("auditor sees the masked per-scope telemetry",
              raud.json().get("scopes", {}).get(sid, {}).get(Metric.REQUESTS.value, 0) >= 1)

        # An invalid credential is rejected like the missing one (401, nothing disclosed).
        rbad = client.get(
            "/metrics",
            headers={"Authorization": "Bearer egw_not-real",
                     "X-Role": str(rbac.Role.GATEWAY_OPERATOR)},
        )
        check("GET /metrics with an unknown credential is 401", rbad.status_code == 401)
        check("the unknown-credential 401 discloses no scope id", sid not in rbad.text)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if resolver is not None:
            resolver.close()
        conn.close()


if __name__ == "__main__":
    main()
