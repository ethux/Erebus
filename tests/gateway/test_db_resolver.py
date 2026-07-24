"""DbScopeResolver + credentials_directory: dynamic, restart-free scope resolution (T018/T019/T014).

Proves the credential -> scope directory: an active credential resolves to its scope_key,
unknown/revoked credentials resolve to nothing (revocation taking effect within the cache
TTL), several credentials can point at one scope, one tenant's credential never resolves to
another tenant, and the credential plaintext is never stored (only its sha256). Live
Postgres; self-skips without it.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.store import credentials_directory, db
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_us1_resolver")
_TTL = 0.5  # short enough to assert revocation latency without a slow test
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _new_scope(conn, key):
    return conn.execute(
        "INSERT INTO scopes (scope_key) VALUES (%s) RETURNING id", (key,)
    ).fetchone()[0]


def _credential_id(conn, credential):
    digest = credentials_directory.hash_credential(credential)
    return conn.execute(
        "SELECT id FROM scope_credentials WHERE credential_hash = %s", (digest,)
    ).fetchone()[0]


def main():
    print("\n=== DbScopeResolver dynamic credential -> scope (T018/T019/T014) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres available -> self-skip (matches suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True  # commit setup so the resolver's separate pool sees it
    resolver = None
    try:
        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        a_id = _new_scope(conn, "org1/payments/ci")
        b_id = _new_scope(conn, "org2/research/ci")

        cred_a = credentials_directory.provision(conn, a_id, "org1/payments/ci", label="team-a")
        cred_a2 = credentials_directory.provision(conn, a_id, "org1/payments/ci", label="team-a-bot")
        cred_b = credentials_directory.provision(conn, b_id, "org2/research/ci", label="team-b")

        check("minted credential carries the egw_ prefix", cred_a.startswith("egw_"))
        check("two provisions mint distinct credentials", cred_a != cred_a2 != cred_b and cred_a != cred_b)

        resolver = DbScopeResolver(_DSN, ttl_s=_TTL)

        check("active credential resolves to its scope_key", resolver.resolve(cred_a) == "org1/payments/ci")
        check("a second credential for the same scope resolves to that scope",
              resolver.resolve(cred_a2) == "org1/payments/ci")
        check("tenant B's credential resolves to tenant B's scope", resolver.resolve(cred_b) == "org2/research/ci")
        check("tenant A's credential never resolves to tenant B",
              resolver.resolve(cred_a) != resolver.resolve(cred_b))

        check("unknown credential resolves to None", resolver.resolve("egw_not-a-real-credential") is None)
        check("empty credential resolves to None", resolver.resolve("") is None)
        check("None credential resolves to None", resolver.resolve(None) is None)

        # Directory-level resolve returns the scope id + key; revoke flips status.
        direct = credentials_directory.resolve(conn, cred_a)
        check("directory resolve returns (scope_id, scope_key)", direct == (a_id, "org1/payments/ci"))
        check("directory resolve of unknown is None", credentials_directory.resolve(conn, "egw_nope") is None)

        # Revocation: flips status; takes effect within the resolver's cache TTL.
        cred_b_id = _credential_id(conn, cred_b)
        check("revoke returns True for an active credential", credentials_directory.revoke(conn, cred_b_id) is True)
        check("directory resolve of a revoked credential is None immediately",
              credentials_directory.resolve(conn, cred_b) is None)
        check("re-revoking an already-revoked credential returns False",
              credentials_directory.revoke(conn, cred_b_id) is False)

        time.sleep(_TTL + 0.2)  # let the cached entry expire so the resolver re-reads the directory
        check("revoked credential resolves to None after the cache TTL", resolver.resolve(cred_b) is None)
        check("non-revoked sibling still resolves after a revoke", resolver.resolve(cred_a) == "org1/payments/ci")

        # Plaintext is never stored: no column holds the credential, and the hash != the plaintext.
        row = conn.execute(
            "SELECT credential_hash, credential_salt, scope_key, label FROM scope_credentials "
            "WHERE credential_hash = %s", (credentials_directory.hash_credential(cred_a),)
        ).fetchone()
        stored_hash, stored_salt, stored_scope_key, stored_label = bytes(row[0]), bytes(row[1]), row[2], row[3]
        cred_bytes = cred_a.encode("utf-8")
        check("stored hash is not the plaintext credential", stored_hash != cred_bytes)
        check("no stored column contains the plaintext credential",
              cred_a not in stored_scope_key and cred_a not in stored_label
              and cred_bytes not in stored_hash and cred_bytes not in stored_salt)
        check("stored hash is the deterministic sha256 of the credential",
              stored_hash == credentials_directory.hash_credential(cred_a))

        # Whole-table sweep: the plaintext must not appear anywhere in scope_credentials.
        leaked = conn.execute(
            "SELECT count(*) FROM scope_credentials WHERE "
            "position(%s in encode(credential_hash, 'escape')) > 0 "
            "OR scope_key = %s OR label = %s", (cred_a, cred_a, cred_a)
        ).fetchone()[0]
        check("plaintext credential appears in no scope_credentials column", leaked == 0)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if resolver is not None:
            resolver.close()
        conn.close()


if __name__ == "__main__":
    main()
