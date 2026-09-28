"""Readiness + fail-closed under dependency loss (T034/T040; US4, FR-008/FR-010).

Exercises the extended ``/readyz`` over the three critical dependencies (shared
state, key custody, detection) via FastAPI TestClient against live Postgres;
self-skips without it. Verifies:

* ``/readyz`` is 200 when state + custody + detection are all healthy, and the
  body reflects the detection posture.
* ``/readyz`` flips to 503 when the key-custody probe reports down, when the
  detection posture is ``degraded``, and when the state layer is unreachable, so a
  load balancer drains the replica (FR-008).
* A chat request during a key-custody / restore outage fails closed (non-200) and
  leaks no raw PII to the client (the fail-closed posture, FR-010).
* Readiness recovers automatically (back to 200) once the probe reports healthy
  again, with no restart (SC-005).

The probes are simple callables whose return value the test toggles, standing in
for a custody/detection outage without tearing down real infrastructure.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import CryptoErased, LocalKms
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_passed = 0
_SECRET = "John Smith"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _detector(text):
    i = text.find(_SECRET)
    return [(i, i + len(_SECRET), "PERSON")] if i != -1 else []


async def _provider(payload):
    user = payload["messages"][-1]["content"]
    return {"choices": [{"message": {"role": "assistant", "content": "Re: " + user}}]}


class _FailingKms(LocalKms):
    """LocalKms whose unwrap is forced to fail closed, simulating a custody outage."""

    def __init__(self):
        super().__init__()
        self.down = False

    def unwrap_dek(self, scope_id, wrapped_dek):
        if self.down:
            raise CryptoErased(scope_id)
        return super().unwrap_dek(scope_id, wrapped_dek)


def main():
    print("\n=== Gateway readiness + fail-closed under dependency loss (T034/T040) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = _FailingKms()
        a = provision_scope(conn, kms, "tenA")
        quota.set_quota(conn, a, 1000, 100000, 60)

        # Toggleable probes standing in for custody + detection health.
        custody = {"ok": True}
        detection = {"posture": "available"}
        app = create_app(
            conn=conn, key_provider=kms, detector=_detector, provider_call=_provider,
            scopes=ScopeResolver({"cA": "tenA"}), scope_ids={"tenA": a},
            kms_health=lambda: custody["ok"],
            detector_posture=lambda: detection["posture"],
        )
        client = TestClient(app)

        # All three deps healthy -> ready, posture reflected.
        r = client.get("/readyz")
        check("readyz 200 when state + custody + detection healthy (FR-008)", r.status_code == 200)
        check("readyz body reflects detection posture", r.json().get("detection") == "available")
        check("healthz is always 200 (liveness)", client.get("/healthz").status_code == 200)

        # Custody down -> not ready (503).
        custody["ok"] = False
        check("readyz 503 when key custody is down (FR-008)", client.get("/readyz").status_code == 503)

        # A chat request during the custody outage fails closed with no raw PII.
        kms.down = True
        rc = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": f"Email {_SECRET} today"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("chat fails closed during custody outage (non-200)", rc.status_code != 200)
        check("no raw PII in the client response during the outage (FR-010)",
              _SECRET not in rc.text)

        # Detection degraded -> not ready; disabled is a deliberate, healthy posture.
        custody["ok"], kms.down = True, False
        detection["posture"] = "degraded"
        check("readyz 503 when detection is degraded (FR-007/FR-008)",
              client.get("/readyz").status_code == 503)
        detection["posture"] = "disabled"
        rd = client.get("/readyz")
        check("readyz 200 when detection is deliberately disabled (FR-007)",
              rd.status_code == 200 and rd.json().get("detection") == "disabled")

        # Recovery: deps healthy again -> ready, and chat serves once more (SC-005).
        detection["posture"] = "available"
        check("readyz recovers to 200 once deps are healthy again (SC-005)",
              client.get("/readyz").status_code == 200)
        rok = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": f"Email {_SECRET} today"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("chat serves again after recovery, restoring the value (SC-005)",
              rok.status_code == 200 and _SECRET in rok.text)

        # State layer unreachable -> readyz 503 (the probe runs SELECT 1 on a dead conn).
        bad = psycopg.connect(_DSN)
        bad.close()
        app_dead = create_app(
            conn=bad, key_provider=kms, detector=_detector, provider_call=_provider,
            scopes=ScopeResolver({"cA": "tenA"}), scope_ids={"tenA": a},
            kms_health=lambda: True, detector_posture=lambda: "available",
        )
        check("readyz 503 when the state layer is unreachable (FR-008)",
              TestClient(app_dead).get("/readyz").status_code == 503)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
