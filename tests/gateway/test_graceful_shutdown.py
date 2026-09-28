"""Graceful shutdown drains + in-flight stream aborts fail-closed (T035/T041; FR-015).

Two parts, both via FastAPI TestClient (which runs the app lifespan on context
enter/exit so the shutdown hook fires deterministically):

* **Shutdown hook drains** -- ``create_app(on_shutdown=...)`` runs the async hook
  exactly once when the service shuts down, after it stops accepting new work, so
  the server can close its pool + httpx client (FR-015). A hook that raises does
  not break shutdown (drain is best-effort).
* **In-flight stream aborts fail-closed** -- a stream whose upstream fails mid-flight
  aborts without a ``[DONE]`` terminator and emits no partial token or raw value
  (FR-015/FR-025). The first part covers the partial-token hold-back; the second a
  mid-stream dependency failure.

The DB-backed stream assertions self-skip without Postgres; the shutdown-hook
assertions run with a stub detector/provider and no DB.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_passed = 0
_SECRET = "John Smith"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


async def _noop(_payload):
    return {"choices": [{"message": {"content": ""}}]}


def _shutdown_hook_runs():
    """The on_shutdown hook runs once on graceful shutdown, errors don't break it."""
    drained = {"count": 0}

    async def hook():
        drained["count"] += 1

    app = create_app(
        conn=None, key_provider=LocalKms(), detector=lambda _t: [], provider_call=_noop,
        scopes=ScopeResolver({}), scope_ids={}, on_shutdown=hook,
    )
    with TestClient(app) as client:  # __enter__ runs startup
        check("service is live while running (healthz 200)", client.get("/healthz").status_code == 200)
        check("shutdown hook has not run while serving", drained["count"] == 0)
    # __exit__ ran the lifespan teardown -> the drain hook fired exactly once.
    check("shutdown hook ran exactly once on graceful shutdown (FR-015)", drained["count"] == 1)

    async def boom():
        raise RuntimeError("drain failure should not break shutdown")

    app2 = create_app(
        conn=None, key_provider=LocalKms(), detector=lambda _t: [], provider_call=_noop,
        scopes=ScopeResolver({}), scope_ids={}, on_shutdown=boom,
    )
    with TestClient(app2):
        pass  # a raising hook is swallowed; exiting the context must not raise
    check("a raising shutdown hook does not break shutdown (FR-015)", True)


def _stream_fail_closed(conn):
    """A mid-stream upstream failure aborts fail-closed: no [DONE], no partial token/raw."""
    db.run_migrations(conn)
    with conn.transaction():
        conn.execute("TRUNCATE scopes CASCADE")
    kms = LocalKms()
    s = provision_scope(conn, kms, "tenS")
    quota.set_quota(conn, s, 1000, 100000, 60)
    tok = open_store(conn, kms, s).mint(_SECRET, "PERSON")

    async def bad_stream(_payload):
        yield "partial " + tok[:6]  # a split, unfinished token fragment
        raise RuntimeError("mid-stream dependency failure")

    app = create_app(
        conn=conn, key_provider=kms, detector=lambda _t: [], provider_call=_noop,
        scopes=ScopeResolver({"cS": "tenS"}), scope_ids={"tenS": s},
        provider_stream=bad_stream,
    )
    body = TestClient(app).post(
        "/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hi"}], "stream": True},
        headers={"Authorization": "Bearer cS"},
    ).text
    check("in-flight stream abort emits no [DONE] (FR-015)", "[DONE]" not in body)
    check("aborted stream emits no partial token", tok[:6] not in body and "[PERSON_" not in body)
    check("aborted stream emits no raw PII", _SECRET not in body)


def main():
    print("\n=== Gateway graceful shutdown + in-flight stream abort (T035/T041) ===\n")
    _shutdown_hook_runs()

    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (stream tests skipped: no Postgres: {exc})")
        print(f"\n{_passed}/{_passed} passed\n")
        return
    try:
        _stream_fail_closed(conn)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
