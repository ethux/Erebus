"""No-raw-egress attestation + tokenization-escape incident tests (FR-003).

Set EREBUS_PG_DSN (defaults to postgresql:///erebus_gw_attestation). Verifies that
attest() certifies clean (token-only) egress, flags egress that still contains a raw
protected value as an incident, and that the persisted row is CONTENT-FREE: it stores
only the verdicts and the escaped value categories, never the raw value (FR-003).

Self-contained: applies ONLY 0001_core.sql and 0016_attestation.sql (other module
migrations are written concurrently, so we do NOT run the whole schema dir).
"""
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.governance.attestation import attest, is_escape
from erebus.gateway.store.db import _statements
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_attestation")
_SCHEMA = Path(__file__).resolve().parent.parent.parent / "erebus" / "gateway" / "schema"
_MIGRATIONS = ["0001_core.sql", "0016_attestation.sql"]
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _apply_migrations(conn):
    """Apply ONLY 0001_core + 0016_attestation (not the whole dir: other modules race).

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
    print("\n=== Gateway no-raw-egress attestation (FR-003) ===\n")
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

        # The raw values the gateway protected this turn, mapped to their categories.
        raw_person = "Jan Modaal"
        raw_email = "jan@example.com"
        known = {raw_person: "PERSON", raw_email: "EMAIL"}

        # 1) Clean (token-only) egress: model output carries only placeholders.
        clean_egress = "Dank je, [PERSON_1_ab12cd]. Mail volgt naar [EMAIL_1_ef34gh]."
        clean = attest(conn, a_id, "req-clean", clean_egress, known)
        check("clean egress -> token_only True", clean["token_only"] is True)
        check("clean egress -> escape_detected False", clean["escape_detected"] is False)
        check("clean egress -> is_escape() False", is_escape(clean) is False)
        check("clean egress -> no escaped categories", clean["escaped_categories"] == [])

        # 2) Escape: egress still contains a raw protected value -> flagged incident.
        leaky_egress = f"Beste {raw_person}, uw aanvraag is goedgekeurd."
        leak = attest(conn, a_id, "req-leak", leaky_egress, known)
        check("leaky egress -> escape_detected True (incident)", leak["escape_detected"] is True)
        check("leaky egress -> token_only False", leak["token_only"] is False)
        check("leaky egress -> is_escape() True", is_escape(leak) is True)
        check("escaped categories name the leaked category only (PERSON)",
              leak["escaped_categories"] == ["PERSON"])

        # Multiple categories escaping are all recorded (sorted, de-duplicated).
        both_egress = f"{raw_person} <{raw_email}> bevestigd."
        both = attest(conn, a_id, "req-both", both_egress, known)
        check("multi-escape records both categories sorted", both["escaped_categories"] == ["EMAIL", "PERSON"])

        # 3) The persisted incident row is CONTENT-FREE: no raw value anywhere (FR-003).
        with scoped(conn, a_id):
            stored = conn.execute(
                "SELECT request_id, token_only, escape_detected, escaped_categories, ts "
                "FROM egress_attestations WHERE id = %s",
                (leak["id"],),
            ).fetchone()
            # Dump the entire incident row as text to prove no raw value is stored.
            blob = conn.execute(
                "SELECT id::text || request_id || token_only::text || escape_detected::text "
                "|| escaped_categories::text || ts::text "
                "FROM egress_attestations WHERE id = %s",
                (leak["id"],),
            ).fetchone()[0]
        check("incident row persisted with escape_detected True", stored is not None and stored[2] is True)
        check("stored row contains NO raw person value (content-free, FR-003)", raw_person not in blob)
        check("stored row contains NO raw email value (content-free, FR-003)", raw_email not in blob)
        check("stored row records only the category label, not the value",
              stored[3] == ["PERSON"] and raw_person not in str(stored[3]))

        # 4) Bare-iterable form of known_raw_values is accepted (generic 'value' category).
        bare = attest(conn, a_id, "req-bare", f"hello {raw_email}", [raw_person, raw_email])
        check("bare-iterable known values -> escape under generic 'value' category",
              bare["escape_detected"] is True and bare["escaped_categories"] == ["value"])

        # 5) Scope isolation: each scope's attestations carry its own scope_id and are
        # confined to it (RLS policy USING scope_id = current_setting(...)). The test
        # role is a Postgres superuser (RLS is bypassed for superusers), so isolation
        # is asserted via the scope_id predicate the policy enforces in production.
        attest(conn, b_id, "req-b", "all good [PERSON_1_zz99]", {raw_person: "PERSON"})
        a_count = conn.execute(
            "SELECT count(*) FROM egress_attestations WHERE scope_id = %s", (a_id,)
        ).fetchone()[0]
        b_count = conn.execute(
            "SELECT count(*) FROM egress_attestations WHERE scope_id = %s", (b_id,)
        ).fetchone()[0]
        cross = conn.execute(
            "SELECT count(*) FROM egress_attestations WHERE scope_id = %s AND request_id = 'req-b'",
            (a_id,),
        ).fetchone()[0]
        check("scope A owns exactly its 4 attestations", a_count == 4)
        check("scope B owns exactly its 1 attestation", b_count == 1)
        check("no scope-B attestation is attributed to scope A (isolation)", cross == 0)
        check("scope ids are distinct uuids", isinstance(a_id, uuid.UUID) and a_id != b_id)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
