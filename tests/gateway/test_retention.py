"""Retention purge with deletion evidence tests (FR-033).

Self-contained: creates its own database, applies every gateway migration,
provisions scopes, inserts aged + fresh token_maps rows, and verifies purge_expired
removes only the aged rows, leaves fresh ones and the tokens of active known values
(spec 015: a known value keeps its token), writes a correct non-PII evidence row (no
token text / plaintext), and respects per-tenant isolation (FR-005/033/041..043).
"""
import os
import subprocess
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.catalog import add_known_value
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.governance.retention import purge_expired
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DBNAME = "erebus_gw_retention"
_DSN = os.environ.get("EREBUS_PG_DSN", f"postgresql:///{_DBNAME}")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _insert_aged(conn, store, scope_id, value, label, age_seconds):
    """Insert one token_maps row with an explicit (possibly old) created_at."""
    crypto = store._crypto
    bidx = crypto.blind_index(value, label)
    nonce, ct = crypto.encrypt(value.encode("utf-8"))
    token = f"[{label}_{uuid.uuid4().hex[:6]}]"
    with scoped(conn, scope_id):
        conn.execute(
            "INSERT INTO token_maps "
            "(scope_id, token, label, value_nonce, value_ciphertext, "
            " value_blind_index, key_version, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, now() - make_interval(secs => %s))",
            (scope_id, token, label, nonce, ct, bidx, crypto.key_version, age_seconds),
        )
    return token


def main():
    print("\n=== Gateway retention purge + evidence (FR-033) ===\n")
    subprocess.run(["createdb", _DBNAME], capture_output=True)  # ignore "already exists"
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")

        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/retention/a")
        b_id = provision_scope(conn, kms, "org/retention/b")
        store_a = open_store(conn, kms, a_id)
        store_b = open_store(conn, kms, b_id)

        # Two aged rows + one fresh row in scope A; one aged row in scope B.
        old1 = _insert_aged(conn, store_a, a_id, "Jan Modaal", "PERSON", 90 * 24 * 3600)
        old2 = _insert_aged(conn, store_a, a_id, "Piet Pluk", "PERSON", 90 * 24 * 3600)
        fresh = store_a.mint("Fresh Person", "PERSON")  # created_at = now()
        b_old = _insert_aged(conn, store_b, b_id, "Other Person", "PERSON", 90 * 24 * 3600)

        # Purge everything older than 30 days in scope A.
        count = purge_expired(conn, a_id, older_than_seconds=30 * 24 * 3600)
        check("purge returns the deleted count (==2)", count == 2)
        check("aged row #1 deleted", store_a.lookup(old1) is None)
        check("aged row #2 deleted", store_a.lookup(old2) is None)
        check("fresh row survives the purge", store_a.lookup(fresh) == "Fresh Person")

        # Evidence row exists with the right shape and contains no PII.
        with scoped(conn, a_id):
            ev = conn.execute(
                'SELECT category, deleted_count, "window", scope_id '
                "FROM retention_deletions WHERE scope_id = %s",
                (a_id,),
            ).fetchall()
        check("exactly one evidence row written", len(ev) == 1)
        category, deleted_count, window, ev_scope = ev[0]
        check("evidence count matches purge result", deleted_count == 2)
        check("evidence window records the interval", window == f"{30 * 24 * 3600}s")
        check("evidence category set ('*' for all labels)", category == "*")
        check("evidence bound to the scope", ev_scope == a_id)
        check(
            "evidence carries no plaintext PII or token text (FR-041..043)",
            all(
                s not in (category, window)
                for s in ("Jan Modaal", "Piet Pluk", old1, old2)
            ),
        )

        # Cross-tenant isolation: A's purge did not touch B; B's evidence is private.
        check("other scope's rows untouched (FR-005)", store_b.lookup(b_old) == "Other Person")
        with scoped(conn, a_id):
            seen_b = conn.execute(
                "SELECT count(*) FROM retention_deletions WHERE scope_id = %s",
                (b_id,),
            ).fetchone()[0]
        check("scope A cannot see scope B evidence under RLS (FR-005)", seen_b == 0)

        # Label-scoped purge: only the matching category is evidenced and removed.
        recent_email = _insert_aged(conn, store_a, a_id, "x@corp.com", "EMAIL", 90 * 24 * 3600)
        recent_person = _insert_aged(conn, store_a, a_id, "Late Person", "PERSON", 90 * 24 * 3600)
        n_email = purge_expired(conn, a_id, older_than_seconds=3600, label="EMAIL")
        check("label-scoped purge deletes only that label", n_email == 1)
        check("EMAIL row gone", store_a.lookup(recent_email) is None)
        check("PERSON row of another category survives", store_a.lookup(recent_person) == "Late Person")
        with scoped(conn, a_id):
            cat = conn.execute(
                "SELECT category FROM retention_deletions "
                "WHERE scope_id = %s ORDER BY ts DESC LIMIT 1",
                (a_id,),
            ).fetchone()[0]
        check("label-scoped evidence records the category", cat == "EMAIL")

        # Known values keep their token: an aged token of an active catalog entry
        # survives; once the entry is retired it ages out like any other.
        kept = _insert_aged(conn, store_a, a_id, "Zyx Qorbel", "PERSON", 90 * 24 * 3600)
        entry = add_known_value(conn, store_a._crypto, a_id, "Zyx Qorbel", "PERSON")
        purge_expired(conn, a_id, older_than_seconds=3600)
        check("an active known value's token survives the purge", store_a.lookup(kept) == "Zyx Qorbel")
        with scoped(conn, a_id):
            conn.execute("UPDATE catalog_entries SET status = 'retired' WHERE id = %s", (entry,))
        purge_expired(conn, a_id, older_than_seconds=3600)
        check("a retired known value's token ages out", store_a.lookup(kept) is None)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
