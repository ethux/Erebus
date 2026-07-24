"""Per-subject DEK sub-tier for surgical GDPR erasure (T007/FR-031/032/040).

Set EREBUS_PG_DSN (defaults to postgresql:///erebus_gw_subject). Verifies that two
subjects in a scope are independently provisioned and resolvable; that crypto-erasing
ONE subject makes only that subject irrecoverable while its sibling and a second scope
stay fully recoverable; and that only the WRAPPED DEK (never the raw key) is at rest.

Self-contained: applies ONLY 0001_core.sql and 0018_subject_keys.sql (other module
migrations are written concurrently, so we do NOT run the whole schema dir).
"""
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.governance.subject_keys import (
    crypto_erase_subject,
    provision_subject,
    subject_resolvable,
)
from erebus.gateway.store.db import _statements
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_subject")
_SCHEMA = Path(__file__).resolve().parent.parent.parent / "erebus" / "gateway" / "schema"
_MIGRATIONS = ["0001_core.sql", "0018_subject_keys.sql"]
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _apply_migrations(conn):
    """Apply ONLY 0001_core + 0018_subject_keys (not the whole dir: other modules race).

    Each statement runs in its own savepoint so a re-run tolerates DDL that is already
    present (CREATE POLICY is not IF NOT EXISTS); data is reset by the TRUNCATE in main().
    """
    for name in _MIGRATIONS:
        sql = (_SCHEMA / name).read_text()
        for stmt in _statements(sql):
            try:
                with conn.transaction():
                    conn.execute(stmt)
            except (psycopg.errors.DuplicateObject, psycopg.errors.DuplicateTable):
                pass  # policy/table already created by a prior run


def main():
    print("\n=== Gateway per-subject crypto-erase (T007/FR-031/032/040) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres available -> self-skip (suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        _apply_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org1/support/eu")
        b_id = provision_scope(conn, kms, "org1/support/us")

        # Provision two subjects in scope A and one in scope B.
        ca_alice = provision_subject(conn, kms, a_id, "alice")
        ca_bob = provision_subject(conn, kms, a_id, "bob")
        provision_subject(conn, kms, b_id, "alice")  # second scope, same subject id
        check("provision returns a ScopeCrypto for each subject",
              ca_alice.scope_id == f"{a_id}:alice" and ca_bob.scope_id == f"{a_id}:bob")

        # Both subjects in scope A start resolvable; scope B's subject too.
        check("subject A/alice resolvable after provision", subject_resolvable(conn, kms, a_id, "alice"))
        check("subject A/bob resolvable after provision", subject_resolvable(conn, kms, a_id, "bob"))
        check("subject B/alice resolvable after provision", subject_resolvable(conn, kms, b_id, "alice"))

        # Idempotent: re-provisioning reopens the SAME wrapped DEK (no duplicate row).
        re_alice = provision_subject(conn, kms, a_id, "alice")
        check("re-provision is idempotent (same subject key id)", re_alice.scope_id == ca_alice.scope_id)
        with scoped(conn, a_id):
            rows = conn.execute(
                "SELECT count(*) FROM subject_keys WHERE scope_id = %s AND subject_id = 'alice'",
                (a_id,),
            ).fetchone()[0]
        check("re-provision did not create a duplicate subject_keys row", rows == 1)

        # The DB stores the WRAPPED dek, not the raw 32-byte key (FR-036/040).
        raw_alice_dek = kms.unwrap_dek(f"{a_id}:alice", _wrapped(conn, a_id, "alice"))
        check("a raw subject DEK is 32 bytes (AES-256)", len(raw_alice_dek) == 32)
        check("subject_keys stores the WRAPPED dek, not the raw key",
              _wrapped(conn, a_id, "alice") != raw_alice_dek)

        # Surgical erase: destroy ONLY subject A/alice.
        crypto_erase_subject(conn, kms, a_id, "alice")

        check("erased subject A/alice is NOT resolvable (FR-040)",
              not subject_resolvable(conn, kms, a_id, "alice"))
        check("sibling subject A/bob is STILL resolvable (surgical erase)",
              subject_resolvable(conn, kms, a_id, "bob"))
        check("subject B/alice in a second scope is unaffected",
              subject_resolvable(conn, kms, b_id, "alice"))

        # The row is tombstoned, not deleted (proof of action, not a recovery channel).
        with scoped(conn, a_id):
            status = conn.execute(
                "SELECT status FROM subject_keys WHERE scope_id = %s AND subject_id = 'alice'",
                (a_id,),
            ).fetchone()[0]
        check("erased subject row tombstoned status='crypto_erased'", status == "crypto_erased")

        # Erase is irreversible even though the wrapped bytes still sit at rest: the
        # per-subject KEK is gone, so the wrapped DEK can never unwrap again (FR-040).
        try:
            kms.unwrap_dek(f"{a_id}:alice", _wrapped(conn, a_id, "alice"))
            irreversible = False
        except Exception:
            irreversible = True
        check("erased subject's wrapped DEK can never be unwrapped again (FR-040)", irreversible)

        # Scope-level isolation predicate (test role is superuser; RLS bypassed for it).
        with scoped(conn, a_id):
            a_count = conn.execute(
                "SELECT count(*) FROM subject_keys WHERE scope_id = %s", (a_id,)
            ).fetchone()[0]
        check("scope A owns exactly its two subject keys", a_count == 2)
        check("scope ids are distinct uuids", isinstance(a_id, uuid.UUID) and a_id != b_id)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


def _wrapped(conn, scope_id, subject_id):
    """Read the wrapped DEK bytes at rest for one subject (helper for at-rest assertions)."""
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT wrapped_dek FROM subject_keys WHERE scope_id = %s AND subject_id = %s",
            (scope_id, subject_id),
        ).fetchone()
    return bytes(row[0])


if __name__ == "__main__":
    main()
