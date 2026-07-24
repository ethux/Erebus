"""Masked operational telemetry, no raw PII or secrets (T037/T042/T044; FR-011).

Wires a :class:`~erebus.gateway.observability.Metrics` registry into
``create_app`` and drives the four instrumented events, then reads the
config-gated ``GET /metrics`` surface and asserts:

* served requests increment ``requests``;
* quota rejections (429) increment ``quota_rejections``;
* blocked egress (502) and blocked modalities (415) increment ``blocked_egress``;
* the telemetry body is integer counts only and contains NO raw PII, prompt,
  credential, or other secret (FR-011/FR-012);
* ``GET /metrics`` is absent unless explicitly enabled (config-gated, T044).

Live Postgres; self-skips without it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway import rbac
from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.observability import Metric, Metrics
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver
from erebus.gateway.transport import EgressDenied

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_passed = 0
_SECRET_NAME = "John Smith"
_SECRET_EMAIL = "john@corp.com"
_CENTRAL_CRED = "sk-central-deadbeefSECRET"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _detector(text):
    spans = []
    for needle, label in ((_SECRET_NAME, "PERSON"), (_SECRET_EMAIL, "EMAIL")):
        i = text.find(needle)
        if i != -1:
            spans.append((i, i + len(needle), label))
    return spans


def main():
    print("\n=== Gateway masked telemetry (T037/T042/T044) ===\n")
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
        served = provision_scope(conn, kms, "tenServed")   # serves OK
        capped = provision_scope(conn, kms, "tenCapped")   # tight quota -> 429
        refused = provision_scope(conn, kms, "tenRefused") # egress refused -> 502
        quota.set_quota(conn, served, 1000, 100000, 60)
        quota.set_quota(conn, capped, 1, 100000, 60)       # 1 request then rejects
        quota.set_quota(conn, refused, 1000, 100000, 60)

        # A scope-aware egress that serves the "served" scope but refuses the others,
        # so the 502 blocked-egress path is exercised without a real provider.
        async def egress(scope_id, payload):
            if scope_id == refused:
                raise EgressDenied(f"{_CENTRAL_CRED}: route not approved")
            user = payload["messages"][-1]["content"]
            return {"choices": [{"message": {"role": "assistant", "content": "Re: " + user}}]}

        metrics = Metrics()
        # Block image modalities so a structured part trips the 415 path.
        app = create_app(
            conn=conn, key_provider=kms, detector=_detector,
            scopes=ScopeResolver({"cServed": "tenServed", "cCapped": "tenCapped",
                                  "cRefused": "tenRefused"}),
            scope_ids={"tenServed": served, "tenCapped": capped, "tenRefused": refused},
            egress=egress, metrics=metrics, metrics_enabled=True,
        )
        client = TestClient(app)

        def chat(cred, content):
            return client.post(
                "/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
                json={"messages": [{"role": "user", "content": content}]},
            )

        # 1) Served request with PII -> 200, recorded as a served request.
        rs = chat("cServed", f"Email {_SECRET_NAME} at {_SECRET_EMAIL}")
        check("served request returns 200", rs.status_code == 200)

        # 2) Quota rejection: second capped request -> 429, recorded.
        chat("cCapped", "hi")              # consumes the single allowed request
        rq = chat("cCapped", "hi again")   # over quota
        check("quota-exhausted request returns 429", rq.status_code == 429)

        # 3) Blocked egress: refused scope -> 502, recorded as blocked_egress.
        rb = chat("cRefused", "hello")
        check("refused egress returns 502", rb.status_code == 502)

        # 4) Blocked modality: an image part -> 415, recorded as blocked_egress.
        rm = client.post(
            "/v1/chat/completions", headers={"Authorization": "Bearer cServed"},
            json={"messages": [{"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "http://x/secret.png"}}]}]},
        )
        check("blocked modality returns 415", rm.status_code == 415)

        # Read the config-gated /metrics surface (now operator/auditor authenticated, 009 R2).
        op_headers = {"Authorization": "Bearer cServed", "X-Role": str(rbac.Role.GATEWAY_OPERATOR)}
        rmet = client.get("/metrics", headers=op_headers)
        check("config-gated GET /metrics is exposed to an operator (T044/FR-002)",
              rmet.status_code == 200)
        body = rmet.json()
        scopes = body.get("scopes", {})

        served_snap = scopes.get(str(served), {})
        capped_snap = scopes.get(str(capped), {})
        refused_snap = scopes.get(str(refused), {})
        check("served scope recorded a served request (FR-011)",
              served_snap.get(Metric.REQUESTS.value, 0) >= 1)
        check("capped scope recorded a quota rejection (FR-011)",
              capped_snap.get(Metric.QUOTA_REJECTIONS.value, 0) >= 1)
        check("refused scope recorded a blocked egress (FR-011)",
              refused_snap.get(Metric.BLOCKED_EGRESS.value, 0) >= 1)
        check("served scope recorded the blocked modality as blocked egress (FR-011)",
              served_snap.get(Metric.BLOCKED_EGRESS.value, 0) >= 1)

        # The telemetry must be integer counts only and carry no raw value/secret.
        raw_text = rmet.text
        for secret in (_SECRET_NAME, _SECRET_EMAIL, _CENTRAL_CRED, "secret.png"):
            check(f"telemetry leaks no secret ({secret!r}) (FR-011/FR-012)", secret not in raw_text)
        all_counts = [v for snap in scopes.values() for v in snap.values()]
        check("every telemetry value is an integer count (masked by construction)",
              all_counts and all(isinstance(v, int) for v in all_counts))

        # Telemetry is config-gated: an app without metrics_enabled exposes no /metrics.
        app_off = create_app(
            conn=conn, key_provider=kms, detector=_detector,
            scopes=ScopeResolver({"cServed": "tenServed"}), scope_ids={"tenServed": served},
            egress=egress, metrics=Metrics(),  # metrics_enabled defaults False
        )
        check("GET /metrics is absent unless explicitly enabled (T044)",
              TestClient(app_off).get("/metrics").status_code == 404)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
