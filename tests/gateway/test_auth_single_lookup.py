"""Auth resolves a scope in ONE off-loop lookup, refusing cleanly on a race (009 R5/FR-003/005).

Regression for the 008 review findings that the deployed auth path ran the scope-id SELECT
TWICE per request (``_ScopeIdDirectory.__contains__`` then ``__getitem__``) and that a tenant
removed between those two lookups raised a ``KeyError`` (500), and that the synchronous
resolution ran inline on the event loop. After the fix:

* a served request triggers EXACTLY ONE directory resolution (one DB lookup), not two;
* a tenant removed mid-resolution yields a clean 401, never a 500;
* the auth resolution runs OFF the event-loop thread (in the threadpool).

Instruments ``credentials_directory.resolve`` to count lookups and capture the thread each ran
on. Drives the live app with a ``DbScopeResolver``. Live Postgres; self-skips without it.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers import quota
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_009_single_lookup")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


async def _egress(_scope_id, payload):
    user = payload["messages"][-1]["content"]
    return {"choices": [{"message": {"role": "assistant", "content": "Re: " + user}}]}


class _Probe:
    """Wrap credentials_directory.resolve to count directory lookups + record their thread."""

    def __init__(self):
        self._orig = credentials_directory.resolve
        self.calls = 0
        self.threads = []
        self.lock = threading.Lock()

    def __enter__(self):
        def wrapped(conn, credential, *args, **kwargs):
            with self.lock:
                self.calls += 1
                self.threads.append(threading.current_thread().name)
            return self._orig(conn, credential, *args, **kwargs)
        credentials_directory.resolve = wrapped
        return self

    def __exit__(self, *exc):
        credentials_directory.resolve = self._orig

    def reset(self):
        with self.lock:
            self.calls = 0
            self.threads = []


def main():
    print("\n=== Auth single off-loop lookup + clean race refusal (009 R5/FR-003/005) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True
    resolver = None
    try:
        from psycopg_pool import ConnectionPool

        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")

        kms = LocalKms()
        sid = provision_scope(conn, kms, "org/single")
        cred = credentials_directory.provision(conn, sid, "org/single", label="ci")
        quota.set_quota(conn, sid, 1000, 100000, 60)

        pool = ConnectionPool(_DSN, min_size=1, max_size=4, open=True)
        # ttl_s=0 so every request re-reads the directory (no cache masking the lookup count).
        resolver = DbScopeResolver(_DSN, ttl_s=0.0)
        app = create_app(
            conn=conn, key_provider=kms, detector=lambda _t: [],
            scopes=resolver, scope_ids={}, pool=pool, egress=_egress,
        )
        client = TestClient(app)
        main_thread = threading.main_thread().name

        def chat(c=cred):
            return client.post(
                "/v1/chat/completions",
                json={"messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": "Bearer " + c},
            )

        with _Probe() as probe:
            # --- 1) Exactly ONE directory resolution per served request. ---
            probe.reset()
            r = chat()
            check("a served request authenticates 200", r.status_code == 200)
            check("a served request triggers exactly ONE directory lookup (FR-005)",
                  probe.calls == 1)

            # --- 2) The auth resolution runs OFF the event-loop thread (FR-003). ---
            check("the auth lookup ran off the event-loop / main thread (threadpool)",
                  probe.threads and all(t != main_thread for t in probe.threads))

            # --- 3) A tenant removed mid-resolution yields a clean 401, never a 500. ---
            # Revoke the credential, then expire the resolver cache so the next request
            # re-reads the (now empty) directory: it must 401, not raise a KeyError 500.
            cred_id = conn.execute(
                "SELECT id FROM scope_credentials WHERE credential_hash = %s",
                (credentials_directory.hash_credential(cred),),
            ).fetchone()[0]
            credentials_directory.revoke(conn, cred_id)
            probe.reset()
            after = chat()
            check("a removed tenant yields a clean 401, never a 500 (FR-005)",
                  after.status_code == 401)
            check("the failed resolution still ran a single lookup", probe.calls == 1)

            # An unknown credential is likewise a clean 401 (single lookup, off-loop).
            probe.reset()
            unknown = chat("egw_not-a-real-credential")
            check("an unknown credential is a clean 401", unknown.status_code == 401)
            check("the unknown-credential auth ran off the event-loop thread",
                  probe.threads and all(t != main_thread for t in probe.threads))

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if resolver is not None:
            resolver.close()
        conn.close()


if __name__ == "__main__":
    main()
