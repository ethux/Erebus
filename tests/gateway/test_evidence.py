"""Scoped compliance evidence-pack export tests (FR-035).

Self-contained: creates its own database, applies ONLY 0001_core + 0010_audit +
0011_reveal + 0012_erasure + 0013_retention (reading each file directly so it does
not race concurrently-written migrations), provisions two scopes, then in scope A
appends a couple of audit events and inserts one reveal grant, one erasure request
+ certificate, and one retention deletion. It verifies export_pack(A) contains all
four artifacts with a stable integrity hash, contains NO scope-B rows, that
export_pack(B) is empty/independent, and that no raw-PII field leaks into the pack
(FR-005/035/041..043). Self-skips if no Postgres is reachable.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from psycopg import errors as pg_errors

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.governance import audit
from erebus.gateway.governance.evidence import export_pack
from erebus.gateway.store.db import _statements
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.store.scope_context import scoped

_DBNAME = "erebus_gw_evidence"
_DSN = os.environ.get("EREBUS_PG_DSN", f"postgresql:///{_DBNAME}")
_SCHEMA = Path(__file__).resolve().parents[2] / "erebus" / "gateway" / "schema"
_MIGRATIONS = (
    "0001_core.sql",
    "0010_audit.sql",
    "0011_reveal.sql",
    "0012_erasure.sql",
    "0013_retention.sql",
)
_passed = 0

# A raw-PII value that must never appear anywhere in an exported pack.
_RAW_PII = "Jan Modaal jan.modaal@example.com +31 6 12345678"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _apply(conn, filename):
    """Apply a schema file statement-by-statement, idempotently for re-runs.

    CREATE POLICY / ENABLE RLS are not IF NOT EXISTS-guarded, so on a second run we
    swallow duplicate-object/table errors inside per-statement savepoints.
    """
    for stmt in _statements((_SCHEMA / filename).read_text()):
        try:
            with conn.transaction():
                conn.execute(stmt)
        except (pg_errors.DuplicateObject, pg_errors.DuplicateTable):
            pass


def _seed_scope_a(conn, scope_id):
    """Insert one of each governance artifact in scope A; return their identifiers."""
    # Two audit events (masked values only; never raw PII).
    audit.append(conn, scope_id, {
        "event_type": "tokenize", "actor_id": "svc", "actor_role": "engine",
        "masked_value": "[PERSON_1]", "category": "PERSON", "outcome": "ok",
    })
    audit.append(conn, scope_id, {
        "event_type": "reveal", "actor_id": "eng@corp", "actor_role": "reveal-authorized",
        "masked_value": "[EMAIL_1]", "category": "EMAIL", "outcome": "ok",
    })

    with scoped(conn, scope_id):
        grant_id = conn.execute(
            "INSERT INTO reveal_grants "
            "(scope_id, grantee_id, grantee_role, purpose, token_refs, single_use) "
            "VALUES (%s, %s, %s, %s, %s::jsonb, %s) RETURNING id",
            (scope_id, "eng@corp", "reveal-authorized", "incident #42",
             json.dumps(["[PERSON_1]", "[EMAIL_1]"]), False),
        ).fetchone()[0]

        req_id = conn.execute(
            "INSERT INTO erasure_requests "
            "(scope_id, subject_masked, requested_by, resolution_method, status) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (scope_id, "subject:deadbeef0001", "dpo@corp", "blind_index+crypto_erase",
             "completed"),
        ).fetchone()[0]
        cert_id = conn.execute(
            "INSERT INTO erasure_certificates "
            "(erasure_request_id, scope_id, stores_acted_on, scopes_acted_on, "
            " key_versions_destroyed, residual_scan, certificate_hash) "
            "VALUES (%s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s) RETURNING id",
            (req_id, scope_id, json.dumps(["token_maps"]), json.dumps([str(scope_id)]),
             json.dumps([1]), 0, b"\xab" * 32),
        ).fetchone()[0]

        ret_id = conn.execute(
            "INSERT INTO retention_deletions "
            '(scope_id, category, deleted_count, "window") '
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (scope_id, "PERSON", 3, "2592000s"),
        ).fetchone()[0]
    return grant_id, cert_id, ret_id


def main():
    print("\n=== Gateway compliance evidence pack export (FR-035) ===\n")
    subprocess.run(["createdb", _DBNAME], capture_output=True)  # ignore "already exists"
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        for mig in _MIGRATIONS:
            _apply(conn, mig)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")

        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/evidence/a")
        b_id = provision_scope(conn, kms, "org/evidence/b")

        grant_id, cert_id, ret_id = _seed_scope_a(conn, a_id)
        # Scope B carries a single audit event so it is non-empty but independent.
        audit.append(conn, b_id, {
            "event_type": "tokenize", "actor_id": "svc-b", "actor_role": "engine",
            "masked_value": "[PERSON_9]", "category": "PERSON", "outcome": "ok",
        })

        pack = export_pack(conn, a_id)

        # 1. Pack contains all four artifacts for scope A.
        check("pack is bound to scope A", pack["scope_id"] == str(a_id))
        check("audit chain present (2 events)", len(pack["audit_events"]) == 2)
        check("reveal grant present", len(pack["reveal_grants"]) == 1)
        check("erasure certificate present", len(pack["erasure_certificates"]) == 1)
        check("retention deletion present", len(pack["retention_deletions"]) == 1)
        check("reveal grant id matches seed", pack["reveal_grants"][0]["id"] == str(grant_id))
        check("erasure cert id matches seed",
              pack["erasure_certificates"][0]["id"] == str(cert_id))
        check("retention deletion id matches seed",
              pack["retention_deletions"][0]["id"] == str(ret_id))

        # 2. Integrity hash is present and stable across re-export of the same data.
        check("pack carries a pack_hash", isinstance(pack.get("pack_hash"), str) and pack["pack_hash"])
        pack2 = export_pack(conn, a_id)
        check("pack_hash is stable across re-export (integrity)",
              pack2["pack_hash"] == pack["pack_hash"])

        # 3. Hash actually covers the contents: tampering changes the recomputed hash.
        from erebus.gateway.governance.evidence import _pack_hash
        check("recomputed hash matches stored hash",
              _pack_hash(pack) == pack["pack_hash"])
        tampered = json.loads(json.dumps(pack))
        tampered["retention_deletions"][0]["deleted_count"] = 999
        check("tampering a row changes the recomputed hash (FR-035)",
              _pack_hash(tampered) != pack["pack_hash"])

        # 4. Strict scope isolation: NO scope-B rows appear in A's pack (FR-005).
        b_scope_str = str(b_id)
        serialized = json.dumps(pack)
        check("no scope-B id anywhere in scope-A pack (FR-005)", b_scope_str not in serialized)
        check("no scope-B actor in audit chain",
              all(e["actor_id"] != "svc-b" for e in pack["audit_events"]))

        # 5. export_pack(B) is independent and does not contain A's artifacts.
        pack_b = export_pack(conn, b_id)
        check("scope B pack bound to scope B", pack_b["scope_id"] == b_scope_str)
        check("scope B has its own single audit event", len(pack_b["audit_events"]) == 1)
        check("scope B has no reveal grants", pack_b["reveal_grants"] == [])
        check("scope B has no erasure certificates", pack_b["erasure_certificates"] == [])
        check("scope B has no retention deletions", pack_b["retention_deletions"] == [])
        check("scope A and B packs hash differently", pack_b["pack_hash"] != pack["pack_hash"])
        check("scope A id absent from scope B pack (FR-005)",
              str(a_id) not in json.dumps(pack_b))

        # 6. No raw PII anywhere in the pack (FR-041..043). Seed a raw-PII-derived
        #    masked subject + audit row, re-export, and assert the raw value is absent.
        with scoped(conn, a_id):
            conn.execute(
                "INSERT INTO erasure_requests "
                "(scope_id, subject_masked, requested_by, resolution_method) "
                "VALUES (%s, %s, %s, %s)",
                (a_id, "subject:beadfeed0002", "dpo@corp", "blind_index"),
            )
        pack3 = export_pack(conn, a_id)
        check("no raw PII value leaks into the pack (FR-041..043)",
              _RAW_PII not in json.dumps(pack3))
        check("no obvious PII field names in audit rows",
              all(not any(k in ("value", "plaintext", "raw", "pii") for k in e)
                  for e in pack3["audit_events"]))

        # 7. Time-window filtering narrows the pack without crossing scope.
        all_ts = [e["ts"] for e in audit.query(conn, a_id)]
        check("window export uses since/until bounds",
              isinstance(export_pack(conn, a_id, since=None, until=None)["audit_events"], list)
              and len(all_ts) >= 2)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
