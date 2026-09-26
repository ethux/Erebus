"""Credential injection + approved-route egress (T028; FR-020/021/022).

Verifies the upstream transport injects the central provider credential (not the
client's) and only egresses to an approved route. Live Postgres; self-skips without it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers import credentials
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.transport import EgressDenied, ModelNotAllowed, build_upstream_call

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def main():
    print("\n=== Gateway credential injection + approved-route egress (T028) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    try:
        import anyio
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        a = provision_scope(conn, kms, "tenA")
        crypto = open_store(conn, kms, a)._crypto

        credentials.store_credential(conn, crypto, a, "openai", "CENTRAL-SECRET-123")
        rid = credentials.add_route(conn, a, "openai", "https://api.openai.com")

        captured = {}

        async def fake_post(url, headers, payload):
            captured.update(url=url, headers=headers, payload=payload)
            return {"choices": [{"message": {"content": "ok"}}]}

        # Unapproved route -> egress denied (FR-021).
        call = build_upstream_call(conn, a, crypto, "openai", fake_post)
        denied = False
        try:
            anyio.run(call, {"client_auth": "Bearer USER-KEY"})
        except EgressDenied:
            denied = True
        check("egress denied without an approved route (FR-021)", denied)

        # Approve the route, then egress uses the central credential.
        credentials.approve_route(conn, a, rid)
        anyio.run(call, {"messages": []})
        check("egress goes to the approved route", captured.get("url") == "https://api.openai.com")
        check("central credential injected (FR-020)",
              captured["headers"]["Authorization"] == "Bearer CENTRAL-SECRET-123")
        check("client credential never forwarded (FR-022)",
              "USER-KEY" not in str(captured["headers"]))

        # Egress to a provider with no route at all is denied.
        call2 = build_upstream_call(conn, a, crypto, "anthropic", fake_post)
        denied2 = False
        try:
            anyio.run(call2, {})
        except EgressDenied:
            denied2 = True
        check("egress denied for an unconfigured provider (FR-021)", denied2)

        # Model allowlist (FR-021): an approved route may still restrict which models egress.
        credentials.store_credential(conn, crypto, a, "azure", "AZURE-SECRET")
        az_rid = credentials.add_route(conn, a, "azure", "https://azure.example",
                                       model_allowlist=["gpt-4o"])
        credentials.approve_route(conn, a, az_rid)
        az_call = build_upstream_call(conn, a, crypto, "azure", fake_post)
        anyio.run(az_call, {"model": "gpt-4o", "messages": []})
        check("an allowlisted model egresses to its route", captured.get("url") == "https://azure.example")
        blocked = False
        try:
            anyio.run(az_call, {"model": "gpt-3.5-turbo", "messages": []})
        except ModelNotAllowed:
            blocked = True
        check("a model absent from model_allowlist is blocked (FR-021)", blocked)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
