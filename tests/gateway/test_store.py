"""Tenant-scoped Postgres store tests (T004/T006-T012/T015) against a live Postgres.

Set EREBUS_PG_DSN (defaults to postgresql:///erebus_gateway_test). Verifies the
state-layer guarantees: round-trip mint/resolve, value->token dedupe, cross-tenant
isolation (RLS + crypto), ciphertext-at-rest, and crypto-erase (FR-005/006/036/040,
SC-003/004/008). Self-skips if no Postgres is reachable.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def main():
    print("\n=== Gateway tenant-scoped store (T004/T006-T012/T015) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres available -> self-skip (matches suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org1/payments/oncall")
        b_id = provision_scope(conn, kms, "org1/payments/billing")

        store_a = open_store(conn, kms, a_id)
        store_b = open_store(conn, kms, b_id)

        tok = store_a.mint("Jan Modaal", "PERSON")
        check("round-trip mint/lookup", store_a.lookup(tok) == "Jan Modaal")
        check("same value reuses the same token (dedupe)", store_a.mint("Jan Modaal", "PERSON") == tok)
        check("casing/space variant dedupes", store_a.mint("  jan   modaal ", "PERSON") == tok)

        check("cross-tenant lookup returns None (RLS+crypto, SC-003/004)", store_b.lookup(tok) is None)
        tok_b = store_b.mint("Jan Modaal", "PERSON")
        check("same value in another scope mints a different token (SC-003)", tok_b != tok)

        # Ciphertext at rest: the stored bytes are not the plaintext (SC-004).
        with scoped(conn, a_id):
            ct = conn.execute(
                "SELECT value_ciphertext FROM token_maps WHERE scope_id = %s AND token = %s",
                (a_id, tok),
            ).fetchone()[0]
        check("value stored as ciphertext, not plaintext (SC-004)", b"Jan Modaal" not in bytes(ct))

        # Crypto-erase: after destroying scope A's key, the store can no longer be opened (FR-040).
        kms.destroy_kek(str(a_id))
        try:
            open_store(conn, kms, a_id)
            erased_ok = False
        except Exception:
            erased_ok = True
        check("crypto-erase makes scope A unrecoverable (FR-040)", erased_ok)
        check("scope B unaffected by A's erase", store_b.lookup(tok_b) == "Jan Modaal")

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
