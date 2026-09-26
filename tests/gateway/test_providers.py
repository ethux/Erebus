"""Provider credentials + approved-route tests (FR-020/021/022) against a live Postgres.

Creates its own database (erebus_gw_providers), applies ONLY 0001_core.sql and
0014_providers.sql (other modules are written concurrently, so we never run the
whole schema dir), provisions a scope, and verifies: credentials are encrypted at
rest and round-trip through the scope key; egress is denied until a route is
approved; and rotation changes the stored ciphertext while still decrypting to the
new secret. Set EREBUS_PG_DSN=postgresql:///erebus_gw_providers.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from pathlib import Path

import psycopg

from erebus.gateway.crypto.envelope import ScopeCrypto
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers.credentials import (
    add_route,
    approve_route,
    egress_allowed,
    get_credential,
    rotate_credential,
    select_route,
    store_credential,
)
from erebus.gateway.store.db import _statements
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped

_DBNAME = "erebus_gw_providers"
_DSN = os.environ.get("EREBUS_PG_DSN", f"postgresql:///{_DBNAME}")
_SCHEMA = Path(__file__).resolve().parents[2] / "erebus" / "gateway" / "schema"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _open_crypto(conn, kms, scope_id):
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT wrapped_dek, key_version FROM tenant_keys WHERE scope_id = %s",
            (scope_id,),
        ).fetchone()
    return ScopeCrypto.open(kms, str(scope_id), bytes(row[0]), row[1])


def main():
    print("\n=== Gateway provider credentials + routes (FR-020/021/022) ===\n")
    # Create our own DB; ignore "already exists".
    subprocess.run(["createdb", _DBNAME], capture_output=True)

    conn = psycopg.connect(_DSN)
    conn.autocommit = False
    try:
        # Apply ONLY 0001_core + our own migration (no whole-dir run: concurrent
        # writers). Idempotent: CREATE POLICY has no IF NOT EXISTS, so tolerate
        # "already exists" per statement via a savepoint for clean re-runs.
        for name in ("0001_core.sql", "0014_providers.sql"):
            for stmt in _statements((_SCHEMA / name).read_text()):
                try:
                    with conn.transaction():
                        conn.execute(stmt)
                except psycopg.errors.DuplicateObject:
                    pass
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = LocalKms()
        scope_id = provision_scope(conn, kms, "org1/payments/oncall")
        other_id = provision_scope(conn, kms, "org1/payments/billing")
        crypto = _open_crypto(conn, kms, scope_id)

        # --- Credential at rest ---
        secret = "sk-live-abc123-SUPERSECRET"
        store_credential(conn, crypto, scope_id, "openai", secret)
        check("credential round-trips to original",
              get_credential(conn, crypto, scope_id, "openai") == secret)

        with scoped(conn, scope_id):
            ct = conn.execute(
                "SELECT credential_ciphertext FROM provider_credentials "
                "WHERE scope_id = %s AND provider = %s",
                (scope_id, "openai"),
            ).fetchone()[0]
        check("credential stored as ciphertext, not plaintext (FR-020)",
              secret.encode("utf-8") not in bytes(ct))
        check("missing credential returns None",
              get_credential(conn, crypto, scope_id, "anthropic") is None)

        # --- Approved-route egress gate ---
        check("no route -> egress denied (FR-022)",
              egress_allowed(conn, scope_id, "openai") is False)
        route_id = add_route(
            conn, scope_id, "openai", "https://api.openai.com/v1",
            model_allowlist=["gpt-4o"], residency_region="eu",
        )
        check("unapproved route -> egress still denied (FR-022)",
              egress_allowed(conn, scope_id, "openai") is False)
        check("unapproved route -> select_route returns None",
              select_route(conn, scope_id, "openai") is None)

        check("approve_route succeeds", approve_route(conn, scope_id, route_id) is True)
        check("approved route -> egress allowed (FR-022)",
              egress_allowed(conn, scope_id, "openai") is True)

        route = select_route(conn, scope_id, "openai")
        check("select_route returns the approved route", route is not None and route.approved)
        check("route carries base_url", route.base_url == "https://api.openai.com/v1")
        check("route carries model allowlist", route.model_allowlist == ["gpt-4o"])
        check("route carries residency region", route.residency_region == "eu")

        # Priority: a higher-priority approved route wins.
        hi_id = add_route(
            conn, scope_id, "openai", "https://eu.api.openai.com/v1",
            approved=True, priority=10,
        )
        check("highest-priority approved route is selected",
              select_route(conn, scope_id, "openai").id == hi_id)

        # Cross-scope isolation: the other scope sees no routes/credentials (RLS).
        check("other scope sees no approved route (RLS)",
              egress_allowed(conn, other_id, "openai") is False)
        other_crypto = _open_crypto(conn, kms, other_id)
        check("other scope sees no credential (RLS)",
              get_credential(conn, other_crypto, other_id, "openai") is None)

        # --- Rotation ---
        new_secret = "sk-live-ROTATED-xyz789"
        rotate_credential(conn, crypto, scope_id, "openai", new_secret)
        with scoped(conn, scope_id):
            ct2 = conn.execute(
                "SELECT credential_ciphertext FROM provider_credentials "
                "WHERE scope_id = %s AND provider = %s",
                (scope_id, "openai"),
            ).fetchone()[0]
        check("rotation changes the stored ciphertext", bytes(ct2) != bytes(ct))
        check("rotation: get_credential returns the new secret",
              get_credential(conn, crypto, scope_id, "openai") == new_secret)
        check("rotation: ciphertext is not the new plaintext either",
              new_secret.encode("utf-8") not in bytes(ct2))

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
