"""Batch token minting (spec 015 "Data model": Tokens; SC-2 query count).

Live Postgres on its own database. ``KnownValueStore.mint_many`` mints every span of one
request at once: one query when every value already has a token, at most four
otherwise (select, sorted advisory locks, re-read with per-label counts, insert).
Concurrent mints of the same new values make one row each (no duplicate tokens), the
oldest row wins where duplicates predate the locks, and ``mint`` agrees with it.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
from helpers import fresh_db

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store.known_value_store import KnownValueStore, open_store, provision_scope
from erebus.gateway.store.scope_context import scoped

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_mint_batch")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _Counting:
    """Connection proxy counting statements other than the RLS scope binding."""

    def __init__(self, conn):
        self._conn = conn
        self.n = 0

    def execute(self, query, params=None):
        if "set_config" not in query:
            self.n += 1
        return self._conn.execute(query, params)

    def transaction(self):
        return self._conn.transaction()


def _counted(conn, store):
    proxy = _Counting(conn)
    return proxy, KnownValueStore(proxy, store._scope_id, store._crypto)


def _rows(conn, scope_id, crypto, value, label):
    with scoped(conn, scope_id):
        return conn.execute(
            "SELECT count(*) FROM token_maps WHERE scope_id = %s AND value_blind_index = %s",
            (scope_id, crypto.blind_index(value, label)),
        ).fetchone()[0]


def _check_counts(conn, store, a_id):
    proxy, counted = _counted(conn, store)
    check("an empty batch sends no query", counted.mint_many([]) == {} and proxy.n == 0)
    spans = [("Zyx Qorbel", "PERSON"), ("zyx.qorbel@acme.com", "EMAIL_ADDRESS"), ("Jan de Vries", "person")]
    first = counted.mint_many(spans)
    check("minting new values takes at most 4 queries", proxy.n <= 4)
    check("every span gets a token", set(first) == set(spans))
    check("the label is normalized into the token", first[("Jan de Vries", "person")].startswith("[PERSON_"))
    check("new tokens of one label are numbered apart",
          len({first[("Zyx Qorbel", "PERSON")].split("_")[1], first[("Jan de Vries", "person")].split("_")[1]}) == 2)
    proxy.n = 0
    again = counted.mint_many([*spans, ("ZYX  qorbel", "PERSON")])
    check("when every value has a token it takes 1 query", proxy.n == 1)
    check("tokens are stable, variants included",
          all(again[k] == first[k] for k in spans) and again[("ZYX  qorbel", "PERSON")] == first[spans[0]])
    proxy.n = 0
    mixed = counted.mint_many([("Zyx Qorbel", "PERSON"), ("Zyx Qorbel", "ORGANIZATION")])
    check("a batch with misses stays within 4 queries", proxy.n <= 4)
    check("one value under two labels gets two tokens",
          mixed[("Zyx Qorbel", "ORGANIZATION")] != mixed[("Zyx Qorbel", "PERSON")])
    check("mint agrees with mint_many", store.mint("Zyx Qorbel", "PERSON") == first[("Zyx Qorbel", "PERSON")])


def _check_legacy_duplicates(conn, store, a_id):
    crypto = store._crypto
    bidx = crypto.blind_index("Old Twin", "PERSON")
    for token, age in (("[PERSON_90_aaaaaa]", 10), ("[PERSON_91_bbbbbb]", 20)):
        nonce, ct = crypto.encrypt(b"Old Twin")
        with scoped(conn, a_id):
            conn.execute(
                "INSERT INTO token_maps (scope_id, token, label, value_nonce, value_ciphertext, value_blind_index, "
                "created_at) VALUES (%s, %s, 'PERSON', %s, %s, %s, now() - make_interval(secs => %s))",
                (a_id, token, nonce, ct, bidx, age),
            )
    check("the oldest row wins among legacy duplicates",
          store.mint_many([("Old Twin", "PERSON")])[("Old Twin", "PERSON")] == "[PERSON_91_bbbbbb]")


def _check_race(kms, a_id):
    for round_no in range(5):
        names = [(f"Race Name {round_no}", "PERSON"), (f"Other Name {round_no}", "PERSON")]
        out = []
        barrier = threading.Barrier(6)

        def racer(order, barrier=barrier, out=out):
            c = psycopg.connect(_DSN, autocommit=True)
            s = open_store(c, kms, a_id)
            barrier.wait()
            out.append(s.mint_many(order))
            c.close()

        threads = [threading.Thread(target=racer, args=(names if i % 2 else names[::-1],)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(20)
        check(f"round {round_no}: six concurrent mints agree on each token",
              len(out) == 6 and all(o == out[0] for o in out))
        c = psycopg.connect(_DSN, autocommit=True)
        crypto = open_store(c, kms, a_id)._crypto
        check(f"round {round_no}: one token_maps row per new value",
              all(_rows(c, a_id, crypto, v, lab) == 1 for v, lab in names))
        c.close()


def main():
    print("\n=== Batch token minting (spec 015 Tokens, SC-2) ===\n")
    try:
        conn = fresh_db("erebus_gw_mint_batch")
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.commit()
    conn.autocommit = True
    try:
        kms = LocalKms()
        a_id = provision_scope(conn, kms, "org/mint/a")
        store = open_store(conn, kms, a_id)
        _check_counts(conn, store, a_id)
        _check_legacy_duplicates(conn, store, a_id)
        _check_race(kms, a_id)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
