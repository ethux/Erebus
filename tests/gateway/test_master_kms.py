"""MasterKeyKms: restart-safe persistent key custody (008 T007/T009/T011/T013; FR-040/012).

Proves the fix for 007's fatal flaw: KEKs persist (wrapped by the master key) so they
survive a process restart, rotation keeps prior DEKs unwrappable, crypto-erase is
permanent and surgical, and neither the master key nor a raw KEK is ever stored. Live
Postgres; self-skips without it.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import AesKeyWrapper, CryptoErased, MasterKeyKms
from erebus.gateway.store import db
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_KEY = base64.b64encode(os.urandom(32)).decode()
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _new_scope(conn, key):
    with conn.transaction():
        return conn.execute("INSERT INTO scopes (scope_key) VALUES (%s) RETURNING id", (key,)).fetchone()[0]


def main():
    print("\n=== MasterKeyKms restart-safe key custody (FR-040/012) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    conn.autocommit = True  # commit setup so MasterKeyKms's separate pool sees migrations/scopes
    kms = wrong = None
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        a = str(_new_scope(conn, "tenA"))
        b = str(_new_scope(conn, "tenB"))

        kms = MasterKeyKms(_DSN, _KEY)
        dek_a, wrapped_a = kms.generate_dek(a)
        check("generate_dek returns a 32-byte DEK and a wrapped DEK", len(dek_a) == 32 and wrapped_a != dek_a)
        check("same-instance unwrap round-trips", kms.unwrap_dek(a, wrapped_a) == dek_a)

        # T007: restart safety — a FRESH provider instance (same master key) still unwraps.
        kms_restart = MasterKeyKms(_DSN, _KEY)
        try:
            check("KEK persists across a restart: fresh instance unwraps (T007/FR-040)",
                  kms_restart.unwrap_dek(a, wrapped_a) == dek_a)
        finally:
            kms_restart.close()

        # A wrong master key cannot unwrap (the wrapped KEK is sealed under the master key).
        wrong = MasterKeyKms(_DSN, base64.b64encode(os.urandom(32)).decode())
        denied = False
        try:
            wrong.unwrap_dek(a, wrapped_a)
        except Exception:
            denied = True
        check("a different master key cannot unwrap the KEK", denied)

        # T009: rotation — new wraps use the new KEK; prior wrapped DEKs still unwrap.
        kms.rotate_kek(a)
        dek_a2, wrapped_a2 = kms.generate_dek(a)
        check("after rotation, prior wrapped DEK still unwraps (SC-008)", kms.unwrap_dek(a, wrapped_a) == dek_a)
        check("after rotation, new wrapped DEK unwraps", kms.unwrap_dek(a, wrapped_a2) == dek_a2)
        with scoped(conn, a):
            versions = conn.execute(
                "SELECT count(*), count(*) FILTER (WHERE status='active') FROM scope_keks WHERE scope_id=%s", (a,)
            ).fetchone()
        check("rotation keeps two versions with exactly one active", versions[0] == 2 and versions[1] == 1)

        # T011: crypto-erase — permanent, and surgical (sibling scope untouched).
        _dek_b, wrapped_b = kms.generate_dek(b)
        kms.destroy_kek(b)
        erased = False
        try:
            kms.unwrap_dek(b, wrapped_b)
        except CryptoErased:
            erased = True
        check("crypto-erased scope can never be unwrapped (T011/FR-040)", erased)
        reprovision_blocked = False
        try:
            kms.generate_dek(b)
        except CryptoErased:
            reprovision_blocked = True
        check("crypto-erased scope cannot be re-provisioned", reprovision_blocked)
        check("sibling scope A is untouched by B's erase (surgical)", kms.unwrap_dek(a, wrapped_a) == dek_a)
        kms_after = MasterKeyKms(_DSN, _KEY)
        try:
            still_erased = False
            try:
                kms_after.unwrap_dek(b, wrapped_b)
            except CryptoErased:
                still_erased = True
            check("crypto-erase survives a restart (tombstone persisted)", still_erased)
        finally:
            kms_after.close()

        # T013: secret hygiene — neither the master key nor a raw KEK is ever stored.
        master_raw = base64.b64decode(_KEY)
        with scoped(conn, a):
            row = conn.execute(
                "SELECT wrapped_kek, wrap_nonce FROM scope_keks WHERE scope_id=%s AND status='active'", (a,)
            ).fetchone()
        check("raw master key never appears in the stored KEK row (FR-012)",
              master_raw not in bytes(row[0]) and master_raw not in bytes(row[1]))
        recovered_kek = AesKeyWrapper(master_raw).unwrap(bytes(row[0]), bytes(row[1]))
        check("the stored wrapped KEK unwraps to a 32-byte KEK under the master key",
              len(recovered_kek) == 32 and recovered_kek != master_raw)

        # T038: real custody health probe — True when the store is reachable over the KMS pool.
        check("health() returns True when the custody store is reachable (T038/FR-012)",
              kms.health() is True)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if kms is not None:
            kms.close()
        if wrong is not None:
            wrong.close()
        conn.close()


if __name__ == "__main__":
    main()
