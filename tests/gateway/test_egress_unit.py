"""Scope-aware egress seam (008 T023; research R1, FR-003/020/021/022).

Proves the live egress path threads scope context into the tested credential-injection
transport: the per-tenant CENTRAL credential reaches the provider in the Authorization
header, a client-supplied credential in the payload is NEVER forwarded, and an
unapproved route / disallowed model is refused fail-closed (EgressDenied). Uses a REAL
MasterKeyKms over its own database and a FAKE async http_post that records the headers it
received. Live Postgres; self-skips without it.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.config import GatewayConfig
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.egress import build_egress
from erebus.gateway.providers import credentials
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.transport import EgressDenied

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_us1_egress")
_KEY = base64.b64encode(os.urandom(32)).decode()
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _config() -> GatewayConfig:
    """A minimal valid config: default provider openai, no model map overrides."""
    return GatewayConfig.from_env({
        "EREBUS_PG_DSN": _DSN,
        "EREBUS_GATEWAY_MASTER_KEY": _KEY,
        "EREBUS_GATEWAY_PROVIDER": "openai",
    })


def main():
    print("\n=== Scope-aware egress seam (T023; FR-003/020/021/022) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    # autocommit so MasterKeyKms's separate pool sees migrations + the provisioned scope.
    conn.autocommit = True
    kms = None
    try:
        import anyio
        from psycopg_pool import ConnectionPool

        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")

        kms = MasterKeyKms(_DSN, _KEY)
        scope_id = provision_scope(conn, kms, "tenA")
        crypto = open_store(conn, kms, scope_id)._crypto

        # Central per-tenant credential + an (unapproved, then approved) route.
        client_secret = "Bearer " + "USER-KEY-SHOULD-NOT-LEAK"
        central_secret = "CENTRAL-EGRESS-SECRET-" + "987654"
        credentials.store_credential(conn, crypto, scope_id, "openai", central_secret)
        rid = credentials.add_route(conn, scope_id, "openai", "https://api.openai.com")

        captured = {}

        async def fake_post(url, headers, payload):
            captured.clear()
            captured.update(url=url, headers=dict(headers), payload=payload)
            return {"choices": [{"message": {"content": "ok"}}]}

        pool = ConnectionPool(_DSN, min_size=1, max_size=2, open=True)
        try:
            egress = build_egress(pool, kms, _config(), fake_post)

            # 1) Unapproved route -> fail-closed EgressDenied (FR-021).
            denied = False
            try:
                anyio.run(egress, scope_id, {"model": "gpt-4o", "authorization": client_secret})
            except EgressDenied:
                denied = True
            check("unapproved route refused fail-closed (FR-021)", denied)
            check("nothing egressed while the route was unapproved", captured == {})

            # 2) Approve the route: the egress call now injects the CENTRAL credential.
            credentials.approve_route(conn, scope_id, rid)
            resp = anyio.run(
                egress, scope_id,
                {"model": "gpt-4o", "messages": [], "authorization": client_secret},
            )
            check("egress returns the upstream response", resp["choices"][0]["message"]["content"] == "ok")
            check("egress reached the approved route", captured["url"] == "https://api.openai.com")
            check("CENTRAL credential injected in Authorization (FR-020)",
                  captured["headers"]["Authorization"] == "Bearer " + central_secret)

            # 3) The client-supplied credential is NEVER forwarded (FR-003).
            check("client credential not in egress headers (FR-003)",
                  "USER-KEY-SHOULD-NOT-LEAK" not in str(captured["headers"]))
            check("egress Authorization is the central secret, not the client's (FR-003)",
                  captured["headers"]["Authorization"] != client_secret)

            # 4) A provider with no route at all is refused fail-closed. Route this
            # request's model to an "anthropic" provider that has no approved route.
            unrouted_config = GatewayConfig.from_env({
                "EREBUS_PG_DSN": _DSN,
                "EREBUS_GATEWAY_MASTER_KEY": _KEY,
                "EREBUS_GATEWAY_PROVIDER": "openai",
                "EREBUS_GATEWAY_MODEL_MAP": '{"claude-3-5-sonnet": "anthropic"}',
            })
            unrouted_egress = build_egress(pool, kms, unrouted_config, fake_post)
            denied_provider = False
            try:
                anyio.run(unrouted_egress, scope_id, {"model": "claude-3-5-sonnet"})
            except EgressDenied:
                denied_provider = True
            check("unrouted provider refused fail-closed (FR-021)", denied_provider)

            # 5) Model-allowlist enforcement: an approved route may still refuse a model.
            credentials.store_credential(conn, crypto, scope_id, "azure", "AZURE-SECRET")
            az_rid = credentials.add_route(conn, scope_id, "azure", "https://azure.example",
                                           model_allowlist=["az-allowed"])
            credentials.approve_route(conn, scope_id, az_rid)
            az_config = GatewayConfig.from_env({
                "EREBUS_PG_DSN": _DSN,
                "EREBUS_GATEWAY_MASTER_KEY": _KEY,
                "EREBUS_GATEWAY_PROVIDER": "openai",
                "EREBUS_GATEWAY_MODEL_MAP": '{"az-allowed": "azure", "az-blocked": "azure"}',
            })
            az_egress = build_egress(pool, kms, az_config, fake_post)
            anyio.run(az_egress, scope_id, {"model": "az-allowed", "messages": []})
            check("an allowlisted model egresses to its route (FR-021)",
                  captured["url"] == "https://azure.example")
            blocked = False
            try:
                anyio.run(az_egress, scope_id, {"model": "az-blocked", "messages": []})
            except EgressDenied:
                blocked = True
            check("a model absent from the allowlist is refused fail-closed (FR-021)", blocked)
        finally:
            pool.close()

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if kms is not None:
            kms.close()
        conn.close()


if __name__ == "__main__":
    main()
