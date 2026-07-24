"""Subject erasure + per-subject crypto-erase backstop (FR-031/032/040) against live Postgres.

Set EREBUS_PG_DSN (defaults to postgresql:///erebus_gw_erasure). Verifies that
erase_subject resolves a subject by its scope blind index, DELETEs every matching
token_maps row (0 residual), emits a tamper-evident certificate, and crypto-erases
the SUBJECT's own key (FR-040) -- WITHOUT destroying the scope, so sibling subjects
in the same scope stay fully resolvable. A second scope is likewise unaffected.

Uses the recorded, idempotent migration runner so it never applies a migration the
DB already has out-of-band (keeps a shared DB consistent across the suite).
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.governance import subject_keys
from erebus.gateway.governance.erasure import _mask, erase_subject
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_erasure")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def main():
    print("\n=== Gateway subject erasure + per-subject crypto-erase (FR-031/032/040) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres available -> self-skip (suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org1/support/eu")
        b_id = provision_scope(conn, kms, "org1/support/us")

        store_a = open_store(conn, kms, a_id)
        store_b = open_store(conn, kms, b_id)

        # Seed the subject (PERSON + EMAIL) and an unrelated SIBLING subject in scope A,
        # plus the same person in scope B.
        subject = "Jan Modaal"
        sibling = "Kees Anders"
        tok1 = store_a.mint(subject, "PERSON")
        tok2 = store_a.mint(subject, "EMAIL")  # different label => its own blind index
        sibling_tok = store_a.mint(sibling, "PERSON")
        b_tok = store_b.mint(subject, "PERSON")

        bidx_person = store_a._crypto.blind_index(subject, "PERSON")
        with scoped(conn, a_id):
            before = conn.execute(
                "SELECT count(*) FROM token_maps WHERE scope_id = %s AND value_blind_index = %s",
                (a_id, bidx_person),
            ).fetchone()[0]
        check("subject has token rows before erasure", before >= 1 and tok1 != tok2)

        cert = erase_subject(conn, kms, a_id, subject, requested_by="dpo@org1", label="PERSON")

        # 0 residual rows for that blind index (FR-031).
        with scoped(conn, a_id):
            residual = conn.execute(
                "SELECT count(*) FROM token_maps WHERE scope_id = %s AND value_blind_index = %s",
                (a_id, bidx_person),
            ).fetchone()[0]
        check("0 residual token_maps rows for the subject blind index (FR-031)", residual == 0)
        check("certificate reports residual_scan == 0", cert.residual_scan == 0)

        # A certificate row was emitted and persisted with a tamper-evident hash.
        with scoped(conn, a_id):
            crow = conn.execute(
                "SELECT erasure_request_id, residual_scan, key_versions_destroyed, "
                "       certificate_hash, stores_acted_on "
                "FROM erasure_certificates WHERE id = %s",
                (cert.id,),
            ).fetchone()
            req = conn.execute(
                "SELECT subject_masked, requested_by, resolution_method, status "
                "FROM erasure_requests WHERE id = %s",
                (cert.erasure_request_id,),
            ).fetchone()
        check("certificate persisted for the request", crow is not None and crow[0] == cert.erasure_request_id)
        check("certificate carries a non-empty tamper-evident hash", len(bytes(crow[3])) == 32)
        check("certificate names the stores acted on (token_maps + subject_keys)",
              crow[4] == ["token_maps", "subject_keys"] and cert.stores_acted_on == ["token_maps", "subject_keys"])
        check("certificate records exactly one destroyed per-subject key version",
              crow[2] == cert.key_versions_destroyed and len(cert.key_versions_destroyed) == 1)
        check("request stores a masked subject, not plaintext (FR-032/042)",
              "Jan" not in req[0] and "Modaal" not in req[0] and req[0].startswith("subject:"))
        check("request method is blind_index+subject_crypto_erase", req[2] == "blind_index+subject_crypto_erase")

        # Per-subject crypto-erase: the erased subject is no longer resolvable (FR-040)...
        check("erased subject is no longer resolvable (FR-040)",
              not subject_keys.subject_resolvable(conn, kms, a_id, _mask(subject)))

        # ...but the SCOPE survives: open_store still works and the SIBLING token resolves.
        store_a_after = open_store(conn, kms, a_id)
        check("scope A is NOT destroyed: open_store still works (siblings live)",
              store_a_after._crypto.key_version == store_a._crypto.key_version)
        check("sibling subject in scope A is undisrupted (per-subject erasure)",
              store_a_after.lookup(sibling_tok) == sibling)
        check("the erased subject's PERSON token is gone from the live store",
              store_a_after.lookup(tok1) is None)

        # Scope B is completely unaffected and can be independently erased.
        check("scope B store still resolves its own token (isolation)", store_b.lookup(b_tok) == subject)
        b_cert = erase_subject(conn, kms, b_id, subject, requested_by="dpo@org1", label="PERSON")
        check("scope B subject can be independently erased afterwards", b_cert.scope_id == b_id)
        check("scope B remains openable after its subject erasure (siblings live)",
              open_store(conn, kms, b_id)._crypto.key_version == store_b._crypto.key_version)

        # Sanity: certificate scope ids match the targeted scopes (no cross-scope leak).
        check("certificate scopes_acted_on names the right scope", cert.scopes_acted_on == [str(a_id)])
        check("scope ids are distinct uuids", isinstance(a_id, uuid.UUID) and a_id != b_id)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
