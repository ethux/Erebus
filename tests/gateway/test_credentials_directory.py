"""credentials_directory: hashed credential -> scope, never plaintext (008 T030/T014).

Proves the directory module in isolation: provision() stores ONLY a salted sha256 hash of
the credential (a whole-table sweep confirms the plaintext lands in no column), resolve()
finds active credentials and returns None for unknown/empty/revoked ones, and revoke() flips
status so the credential stops resolving. Live Postgres; self-skips without it.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.store import credentials_directory, db

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_us3_credsdir")
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


def _privilege_of(conn, credential):
    digest = credentials_directory.hash_credential(credential)
    return conn.execute(
        "SELECT privilege FROM scope_credentials WHERE credential_hash = %s", (digest,)
    ).fetchone()[0]


def _check_privilege(conn, b_id, cred_b):
    """010: each row carries the privilege it was issued with; only the directory sets it."""
    default = conn.execute(
        "SELECT column_default FROM information_schema.columns "
        "WHERE table_name = 'scope_credentials' AND column_name = 'privilege'"
    ).fetchone()
    check("privilege column exists with a 'tenant' default (0020)",
          default is not None and "tenant" in (default[0] or ""))
    check("provision() without a privilege stores 'tenant'", _privilege_of(conn, cred_b) == "tenant")

    cred_id, token = credentials_directory.issue(conn, b_id, "org/b", label="ops", privilege="operator")
    check("issue() returns (credential id, egw_ plaintext)", token.startswith("egw_"))
    check("issue() id is the stored row id", _credential_id(conn, token) == cred_id)
    check("issue(privilege='operator') stores 'operator'", _privilege_of(conn, token) == "operator")

    before = conn.execute("SELECT count(*) FROM scope_credentials").fetchone()[0]
    try:
        credentials_directory.issue(conn, b_id, "org/b", privilege="root")
        refused = False
    except ValueError:
        refused = True
    after = conn.execute("SELECT count(*) FROM scope_credentials").fetchone()[0]
    check("issue() refuses an unknown privilege and inserts nothing", refused and before == after)

    try:
        conn.execute(
            "INSERT INTO scope_credentials (credential_hash, credential_salt, scope_id, scope_key, privilege) "
            "VALUES (%s, %s, %s, 'org/b', 'root')", (b"x" * 32, b"", b_id))
        rejected = False
    except psycopg.errors.CheckViolation:
        rejected = True
    check("the CHECK constraint rejects a raw 'root' privilege", rejected)

    record = credentials_directory.lookup(conn, token)
    check("lookup() returns the full record (id, scope, privilege)",
          record == (cred_id, b_id, "org/b", "operator")
          and record.credential_id == cred_id and record.privilege == "operator")
    check("lookup() of a tenant credential reports 'tenant'",
          credentials_directory.lookup(conn, cred_b).privilege == "tenant")
    check("lookup() of unknown/empty is None",
          credentials_directory.lookup(conn, "egw_nope") is None and credentials_directory.lookup(conn, "") is None)
    credentials_directory.revoke(conn, cred_id)
    check("lookup() of a revoked credential is None", credentials_directory.lookup(conn, token) is None)
    check("resolve() keeps its 2-tuple contract", credentials_directory.resolve(conn, cred_b) == (b_id, "org/b"))
    check("OPERATOR_SCOPE_KEY is the reserved '_operators' home scope",
          credentials_directory.OPERATOR_SCOPE_KEY == "_operators")


def main():
    print("\n=== credentials_directory hashed credential -> scope (T030/T014) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres -> self-skip (matches suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True
    try:
        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        a_id = _new_scope(conn, "org/a")
        b_id = _new_scope(conn, "org/b")

        # --- provision() returns the plaintext ONCE and stores only a hash. ---
        cred_a = credentials_directory.provision(conn, a_id, "org/a", label="team-a-ci")
        cred_b = credentials_directory.provision(conn, b_id, "org/b", label="team-b-ci")
        check("provision mints a prefixed credential", cred_a.startswith("egw_"))
        check("two provisions mint distinct credentials", cred_a != cred_b)

        row = conn.execute(
            "SELECT credential_hash, credential_salt, scope_id, scope_key, status, label "
            "FROM scope_credentials WHERE credential_hash = %s",
            (credentials_directory.hash_credential(cred_a),),
        ).fetchone()
        stored_hash, stored_salt = bytes(row[0]), bytes(row[1])
        check("provision stored the active credential for the right scope",
              row[2] == a_id and row[3] == "org/a" and row[4] == "active" and row[5] == "team-a-ci")
        check("stored hash is the deterministic salted sha256 of the credential",
              stored_hash == credentials_directory.hash_credential(cred_a))
        check("stored hash is NOT the plaintext", stored_hash != cred_a.encode("utf-8"))

        # Whole-table sweep: the plaintext must not appear in ANY column of scope_credentials.
        cred_bytes = cred_a.encode("utf-8")
        check("no row column holds the plaintext credential (hash/salt)",
              cred_bytes not in stored_hash and cred_bytes not in stored_salt)
        leaked = conn.execute(
            "SELECT count(*) FROM scope_credentials WHERE "
            "position(%s in encode(credential_hash, 'escape')) > 0 "
            "OR position(%s in encode(credential_salt, 'escape')) > 0 "
            "OR scope_key = %s OR label = %s",
            (cred_a, cred_a, cred_a, cred_a),
        ).fetchone()[0]
        check("plaintext credential appears in no scope_credentials column (whole-table sweep)",
              leaked == 0)

        # --- resolve() finds active credentials; None for unknown/empty. ---
        check("resolve() finds an active credential -> (scope_id, scope_key)",
              credentials_directory.resolve(conn, cred_a) == (a_id, "org/a"))
        check("resolve() of tenant B's credential maps to tenant B",
              credentials_directory.resolve(conn, cred_b) == (b_id, "org/b"))
        check("resolve() of an unknown credential is None",
              credentials_directory.resolve(conn, "egw_not-a-real-credential") is None)
        check("resolve() of empty is None", credentials_directory.resolve(conn, "") is None)
        check("resolve() of None is None", credentials_directory.resolve(conn, None) is None)

        # --- revoke() flips status; a revoked credential stops resolving. ---
        cred_a_id = _credential_id(conn, cred_a)
        check("revoke() returns True for an active credential",
              credentials_directory.revoke(conn, cred_a_id) is True)
        status = conn.execute(
            "SELECT status FROM scope_credentials WHERE id = %s", (cred_a_id,)
        ).fetchone()[0]
        check("revoke() flips status to 'revoked'", status == "revoked")
        check("resolve() of a revoked credential is None",
              credentials_directory.resolve(conn, cred_a) is None)
        check("re-revoking an already-revoked credential returns False",
              credentials_directory.revoke(conn, cred_a_id) is False)
        check("revoking an unknown credential id returns False",
              credentials_directory.revoke(conn, b_id) is False)
        check("a sibling tenant's credential still resolves after the revoke",
              credentials_directory.resolve(conn, cred_b) == (b_id, "org/b"))

        _check_privilege(conn, b_id, cred_b)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
