"""Gateway request-pipeline integration tests (US1/US2/US3) via FastAPI TestClient.

A stub provider transport captures egress and echoes content back; a deterministic
fake detector replaces the GLiNER daemon. Live Postgres; self-skips without it.
Verifies: token-only egress (SC-001), response restore (US2), cross-tenant tokens
differ (SC-003), and auth rejection (FR-014).
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
_passed = 0
_PERSON = re.compile(r"\[PERSON_\d+_[0-9a-f]+\]")


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def fake_detector(text):
    spans = []
    for needle, label in (("John Smith", "PERSON"), ("john@corp.com", "EMAIL")):
        i = text.find(needle)
        if i != -1:
            spans.append((i, i + len(needle), label))
    return spans


def main():
    print("\n=== Gateway request pipeline (US1/US2/US3) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        a = provision_scope(conn, kms, "tenantA")
        b = provision_scope(conn, kms, "tenantB")
        quota.set_quota(conn, a, 100, 1000, 60)  # generous; the route is fail-closed on quota
        quota.set_quota(conn, b, 100, 1000, 60)

        captured = []

        async def provider_call(payload):
            captured.append(payload)
            user = payload["messages"][-1]["content"]
            return {"choices": [{"message": {"role": "assistant", "content": "Reply to: " + user}}]}

        app = create_app(
            conn=conn, key_provider=kms, detector=fake_detector, provider_call=provider_call,
            scopes=ScopeResolver({"credA": "tenantA", "credB": "tenantB"}),
            scope_ids={"tenantA": a, "tenantB": b},
        )
        client = TestClient(app)

        r = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Email John Smith at john@corp.com today"}]},
            headers={"Authorization": "Bearer credA"},
        )
        check("200 OK for an authed request", r.status_code == 200)
        egress = captured[-1]["messages"][-1]["content"]
        check("no raw PII in egress (US1/SC-001)",
              "John Smith" not in egress and "john@corp.com" not in egress)
        check("egress carries tokens", "[PERSON_" in egress and "[EMAIL_" in egress)
        restored = r.json()["choices"][0]["message"]["content"]
        check("response restored to real values (US2)",
              "John Smith" in restored and "john@corp.com" in restored)

        client.post("/v1/chat/completions",
                    json={"messages": [{"role": "user", "content": "John Smith"}]},
                    headers={"Authorization": "Bearer credA"})
        tok_a = _PERSON.findall(captured[-1]["messages"][-1]["content"])
        client.post("/v1/chat/completions",
                    json={"messages": [{"role": "user", "content": "John Smith"}]},
                    headers={"Authorization": "Bearer credB"})
        tok_b = _PERSON.findall(captured[-1]["messages"][-1]["content"])
        check("cross-tenant tokens for the same value differ (US3/SC-003)",
              tok_a and tok_b and tok_a[0] != tok_b[0])

        check("401 without a valid credential (FR-014)",
              client.post("/v1/chat/completions", json={"messages": []}).status_code == 401)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
