"""Streaming restore + mid-stream fail-closed (T027/T029/T037; FR-002/SC-002/FR-025).

Unit-tests the split-token hold-back, then a route round-trip and a mid-stream
abort via TestClient. Live Postgres for the route tests; self-skips without it.
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
from erebus.gateway.streaming_restore import StreamRestorer
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


async def _noop(_payload):
    return {"choices": [{"message": {"content": ""}}]}


def main():
    print("\n=== Gateway streaming restore (T027/T029/T037) ===\n")

    # Unit: split-token hold-back never emits a partial token. The token is built
    # at runtime (a literal token string in source is not safe to write).
    tok = "[" + "PERSON_1_abcdef" + "]"
    r = StreamRestorer({tok: "John Smith"}.get)
    chunks = ["Hi ", tok[:5], tok[5:10], tok[10:] + " bye"]
    emits = [r.feed(c) for c in chunks] + [r.flush()]
    check("no partial token in any emitted fragment (SC-002)",
          all(tok[:5] not in e for e in emits))
    check("split token restored across chunks", "".join(emits) == "Hi John Smith bye")

    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (route tests skipped: no Postgres: {exc})")
        print(f"\n{_passed}/{_passed} passed\n")
        return
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        s = provision_scope(conn, kms, "tenS")
        quota.set_quota(conn, s, 100, 1000, 60)
        tok = open_store(conn, kms, s).mint("John Smith", "PERSON")

        async def good_stream(_payload):
            full = "Reply: " + tok + " done"
            for i in range(0, len(full), 5):  # split the token across 5-char chunks
                yield full[i:i + 5]

        app = create_app(conn=conn, key_provider=kms, detector=lambda _t: [], provider_call=_noop,
                         scopes=ScopeResolver({"cS": "tenS"}), scope_ids={"tenS": s},
                         provider_stream=good_stream)
        body = TestClient(app).post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "hi"}], "stream": True},
            headers={"Authorization": "Bearer cS"}).text
        check("streamed response restored to real value (US2 stream)",
              "John Smith" in body and tok not in body)
        check("stream completes with [DONE]", "[DONE]" in body)

        async def bad_stream(_payload):
            yield "partial " + tok
            raise RuntimeError("mid-stream dependency failure")

        app2 = create_app(conn=conn, key_provider=kms, detector=lambda _t: [], provider_call=_noop,
                          scopes=ScopeResolver({"cS": "tenS"}), scope_ids={"tenS": s},
                          provider_stream=bad_stream)
        body2 = TestClient(app2).post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "hi"}], "stream": True},
            headers={"Authorization": "Bearer cS"}).text
        check("mid-stream failure aborts fail-closed, no [DONE] (T037/FR-025)", "[DONE]" not in body2)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
