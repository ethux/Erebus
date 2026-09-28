"""Privileged reveal-grant tests (FR-015/016/019) against a live Postgres.

Set EREBUS_PG_DSN (defaults to postgresql:///erebus_gw_reveal). Applies ONLY
0001_core.sql and 0011_reveal.sql (other modules are written concurrently, so we
do not run the whole schema dir). Verifies default-deny break-glass: no role is
denied, no covering grant is denied, a valid grant authorizes, an expired grant
is denied, and a single-use grant consumes then denies on reuse. Self-skips if no
Postgres is reachable.
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.governance.reveal import REVEAL_ROLE, authorize_reveal, grant
from erebus.gateway.store.db import _statements
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_reveal")
_SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..",
    "erebus", "gateway", "schema",
)
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _apply(conn, filename):
    with open(os.path.join(_SCHEMA, filename)) as f:
        sql = f.read()
    with conn.transaction():
        for stmt in _statements(sql):
            conn.execute(stmt)


def main():
    print("\n=== Gateway privileged reveal grants (FR-015/016/019) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres available -> self-skip (matches suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        # Apply only our two migrations (idempotent CREATE ... IF NOT EXISTS / policies).
        try:
            _apply(conn, "0001_core.sql")
        except psycopg.errors.DuplicateObject:
            conn.rollback()  # policies already exist from a prior run
        try:
            _apply(conn, "0011_reveal.sql")
        except psycopg.errors.DuplicateObject:
            conn.rollback()
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = LocalKms()
        scope = provision_scope(conn, kms, "org1/payments/oncall")
        other = provision_scope(conn, kms, "org1/payments/billing")

        tok_a, tok_b, tok_c = "[PERSON_1_aa]", "[PERSON_2_bb]", "[EMAIL_1_cc]"
        eng = "engineer@corp"

        # Default-deny: right tokens but wrong role.
        check(
            "deny without reveal-authorized role (FR-016)",
            authorize_reveal(conn, scope, eng, "viewer", [tok_a]) is False,
        )
        # Default-deny: correct role but no grant at all.
        check(
            "deny with role but no covering grant (FR-015/016)",
            authorize_reveal(conn, scope, eng, REVEAL_ROLE, [tok_a]) is False,
        )

        # A non-empty purpose is mandatory at issue time (FR-019).
        empty_purpose_rejected = False
        try:
            grant(conn, scope, eng, REVEAL_ROLE, "  ", [tok_a], ttl_seconds=60)
        except ValueError:
            empty_purpose_rejected = True
            conn.rollback()
        check("grant requires a non-empty purpose (FR-019)", empty_purpose_rejected)

        # Issue a covering grant, then authorize.
        grant(conn, scope, eng, REVEAL_ROLE, "incident #42 oncall lookup",
              [tok_a, tok_b], ttl_seconds=300)
        check(
            "grant then authorize succeeds for covered token (FR-015)",
            authorize_reveal(conn, scope, eng, REVEAL_ROLE, [tok_a]) is True,
        )
        check(
            "authorize succeeds for a subset of covered tokens",
            authorize_reveal(conn, scope, eng, REVEAL_ROLE, [tok_a, tok_b]) is True,
        )
        # A token outside the grant's refs is still denied (least privilege).
        check(
            "deny token not covered by the grant (FR-015)",
            authorize_reveal(conn, scope, eng, REVEAL_ROLE, [tok_a, tok_c]) is False,
        )
        # Cross-scope: the same grantee/role in another scope sees no grant (RLS).
        check(
            "deny in a different scope (RLS isolation)",
            authorize_reveal(conn, other, eng, REVEAL_ROLE, [tok_a]) is False,
        )

        # Expired grant is denied.
        exp = grant(conn, scope, "oncall@corp", REVEAL_ROLE, "expired window",
                    [tok_a], ttl_seconds=1)
        time.sleep(1.2)
        check(
            "expired grant is denied (FR-015)",
            authorize_reveal(conn, scope, "oncall@corp", REVEAL_ROLE, [tok_a]) is False,
        )
        with scoped(conn, scope):
            still_active = conn.execute(
                "SELECT (expires_at > now()) FROM reveal_grants WHERE id = %s", (exp,),
            ).fetchone()[0]
        check("expired grant's window is in the past", still_active is False)

        # Single-use: consumes on first reveal, denies on reuse (FR-015).
        grant(conn, scope, "su@corp", REVEAL_ROLE, "break-glass once",
              [tok_a], ttl_seconds=300, single_use=True)
        check(
            "single-use grant authorizes the first reveal",
            authorize_reveal(conn, scope, "su@corp", REVEAL_ROLE, [tok_a]) is True,
        )
        check(
            "single-use grant is denied on reuse (consumed)",
            authorize_reveal(conn, scope, "su@corp", REVEAL_ROLE, [tok_a]) is False,
        )
        with scoped(conn, scope):
            st, consumed = conn.execute(
                "SELECT status, (consumed_at IS NOT NULL) FROM reveal_grants "
                "WHERE grantee_id = 'su@corp'",
            ).fetchone()
        check("consumed single-use grant is marked consumed", st == "consumed" and consumed)

        # FR-041: the grant stores token references only, never the plaintext value.
        with scoped(conn, scope):
            refs = conn.execute(
                "SELECT token_refs FROM reveal_grants WHERE grantee_id = %s LIMIT 1", (eng,),
            ).fetchone()[0]
        check(
            "grant holds token references, not plaintext values (FR-041)",
            isinstance(refs, list) and tok_a in refs and all(r.startswith("[") for r in refs),
        )

        # FR-008: KnownValueStore.resolve() must batch a multi-token reveal into one
        # RLS-scoped query and return exactly the same {token: value} map as the
        # equivalent per-token lookups, while staying scope-confined.
        store = open_store(conn, kms, scope)
        store_other = open_store(conn, kms, other)
        minted = {
            store.mint("Jan Modaal", "PERSON"): "Jan Modaal",
            store.mint("jan@corp.example", "EMAIL"): "jan@corp.example",
            store.mint("Stichting Zonnebloem", "ORG"): "Stichting Zonnebloem",
        }
        all_tokens = list(minted.keys())

        # Count the token_maps SELECTs resolve() issues: a multi-token reveal must
        # be a SINGLE RLS-scoped round-trip (token = ANY(...)), not one SELECT per
        # token. We wrap the connection's execute to tally the resolving queries.
        real_execute = store._conn.execute
        resolve_selects = 0

        def _counting_execute(query, *args, **kwargs):
            nonlocal resolve_selects
            q = query if isinstance(query, str) else query.decode("utf-8", "ignore")
            if "token_maps" in q and " token" in q and q.lstrip().upper().startswith("SELECT"):
                resolve_selects += 1
            return real_execute(query, *args, **kwargs)

        store._conn.execute = _counting_execute
        try:
            batched = store.resolve(all_tokens)
        finally:
            store._conn.execute = real_execute
        check(
            "batched resolve returns every minted token's value",
            batched == minted,
        )
        check(
            "multi-token resolve issues a single token_maps query, not one per token (FR-008)",
            resolve_selects == 1,
        )
        per_token = {t: store.lookup(t) for t in all_tokens}
        check(
            "batched resolve matches per-token lookups exactly",
            batched == per_token,
        )
        # An unknown token is simply absent from the result (no error, no leak).
        unknown = "[PERSON_999_abcdef]"
        mixed = store.resolve([all_tokens[0], unknown])
        check(
            "batched resolve omits unknown tokens (returns only matches)",
            mixed == {all_tokens[0]: minted[all_tokens[0]]},
        )
        # RLS confinement: another scope resolves none of scope's tokens.
        cross = store_other.resolve(all_tokens)
        check(
            "batched resolve is scope-confined (RLS): other scope sees no matches",
            cross == {},
        )
        # Duplicate tokens in the input collapse to a single mapping (set semantics).
        dup = store.resolve([all_tokens[0], all_tokens[0]])
        check(
            "batched resolve handles duplicate input tokens",
            dup == {all_tokens[0]: minted[all_tokens[0]]},
        )
        # An empty request resolves to an empty map without touching the database.
        check("batched resolve of no tokens is an empty map", store.resolve([]) == {})

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
