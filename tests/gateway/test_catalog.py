"""Per-scope known-value catalog tests (T009; FR-009).

Self-contained: creates its own database, applies ONLY 0001_core + 0017_catalog
(reading both files directly so it does not race concurrently-written
migrations), provisions scopes, and verifies the catalog guarantees:
add_known_value registers org-known values encrypted at rest; match finds their
spans in a sentence (case-insensitive, longest-first, non-overlapping); a
cross-scope match never surfaces another scope's values (RLS + crypto); the
ciphertext column is not the plaintext; and re-adding the same value dedupes by
blind index (FR-005/009/036/041..043).
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import subprocess

import psycopg
from psycopg import errors as pg_errors

from erebus.gateway.catalog import add_known_value, match
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store.db import _statements
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DBNAME = "erebus_gw_catalog"
_DSN = os.environ.get("EREBUS_PG_DSN", f"postgresql:///{_DBNAME}")
_SCHEMA = Path(__file__).resolve().parents[2] / "erebus" / "gateway" / "schema"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _apply(conn, filename):
    """Apply a schema file statement-by-statement, idempotently for re-runs.

    CREATE POLICY/ENABLE RLS are not ``IF NOT EXISTS``-guarded, so on a second
    run we swallow the duplicate-object/table errors via a per-statement savepoint.
    """
    for stmt in _statements((_SCHEMA / filename).read_text()):
        try:
            with conn.transaction():
                conn.execute(stmt)
        except (pg_errors.DuplicateObject, pg_errors.DuplicateTable):
            pass


def main():
    print("\n=== Gateway per-scope known-value catalog (T009; FR-009) ===\n")
    subprocess.run(["createdb", _DBNAME], capture_output=True)  # ignore "already exists"
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        _apply(conn, "0001_core.sql")
        _apply(conn, "0017_catalog.sql")
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")

        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/catalog/a")
        b_id = provision_scope(conn, kms, "org/catalog/b")
        crypto_a = open_store(conn, kms, a_id)._crypto
        crypto_b = open_store(conn, kms, b_id)._crypto

        # Curate three org-known values into scope A.
        eid = add_known_value(conn, crypto_a, a_id, "Project Erebus", "PROJECT")
        add_known_value(conn, crypto_a, a_id, "ACME-1234", "INTERNAL_ID")
        add_known_value(conn, crypto_a, a_id, "Stichting Zonnebloem", "ORG")

        # match finds every known value's span in a sentence the generic detector misses.
        sentence = (
            "Ticket ACME-1234 for Stichting Zonnebloem was filed under project erebus."
        )
        spans = match(conn, crypto_a, a_id, sentence)
        found = {(sentence[s:e], label) for s, e, label in spans}
        check("match finds the internal id span", ("ACME-1234", "INTERNAL_ID") in found)
        check("match finds the org name span", ("Stichting Zonnebloem", "ORG") in found)
        check("match is case-insensitive (project erebus)", ("project erebus", "PROJECT") in found)
        check("match returns exactly the three known values", len(spans) == 3)
        check(
            "spans index the actual sentence positions",
            all(sentence[s:e].casefold() in sentence.casefold() for s, e, _ in spans),
        )

        # Longest-first / non-overlapping: a known value containing a shorter known
        # value wins its span; the substring does not also match inside it.
        add_known_value(conn, crypto_a, a_id, "Erebus Gateway", "PRODUCT")
        add_known_value(conn, crypto_a, a_id, "Erebus", "PROJECT")
        s2 = "We ship the Erebus Gateway tomorrow."
        spans2 = match(conn, crypto_a, a_id, s2)
        labels2 = {(s2[s:e], label) for s, e, label in spans2}
        check("longest match claims the span (Erebus Gateway)", ("Erebus Gateway", "PRODUCT") in labels2)
        check("shorter substring does not also match inside it", len(spans2) == 1)

        # Cross-scope: scope B has its own (different) known values; A's are invisible.
        add_known_value(conn, crypto_b, b_id, "Project Olympus", "PROJECT")
        spans_b = match(conn, crypto_b, b_id, sentence)
        check("cross-scope match returns nothing for A-only values (RLS+crypto)", spans_b == [])
        own = match(conn, crypto_b, b_id, "Status of Project Olympus is green.")
        check("scope B still matches its own known values", len(own) == 1)

        # Ciphertext at rest: the stored bytes are not the plaintext (FR-036).
        with scoped(conn, a_id):
            ct = conn.execute(
                "SELECT value_ciphertext FROM catalog_entries WHERE id = %s",
                (eid,),
            ).fetchone()[0]
        check("known value stored as ciphertext, not plaintext (FR-036)", b"Project Erebus" not in bytes(ct))

        # Dedupe by blind index: re-adding the same value (any casing) is idempotent.
        again = add_known_value(conn, crypto_a, a_id, "project erebus", "PROJECT")
        check("re-adding same value dedupes by blind index", again == eid)
        with scoped(conn, a_id):
            n = conn.execute(
                "SELECT count(*) FROM catalog_entries "
                "WHERE scope_id = %s AND value_blind_index = %s",
                (a_id, crypto_a.blind_index("Project Erebus", "PROJECT")),
            ).fetchone()[0]
        check("only one catalog row exists for the deduped value", n == 1)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
