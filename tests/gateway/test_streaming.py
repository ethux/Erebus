"""Streaming restore + mid-stream fail-closed (T027/T029/T037; FR-002/SC-002/FR-025).

Unit-tests the split-token hold-back, then a route round-trip and a mid-stream
abort via TestClient. Live Postgres for the route tests; self-skips without it.
"""
import json
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


def _frame(delta, finish=None, index=0):
    choice = {"index": index, "delta": delta, "finish_reason": finish}
    return json.dumps({"id": "c1", "model": "m", "choices": [choice]}, separators=(",", ":"))


def _run(frames, lookup):
    """Feed whole SSE JSON frames (as http_stream yields them); return raw emits and parsed frames."""
    r = StreamRestorer(lookup)
    raw = [r.feed(f) for f in frames] + [r.flush()]
    raw = [e for e in raw if e]
    parsed = []
    for e in raw:
        try:
            parsed.append(json.loads(e))
        except ValueError:
            parsed.append(None)
    return raw, parsed


def _joined(parsed, index=0):
    """Reassemble content and per-call arguments the way an OpenAI client does."""
    content, args = "", {}
    for frame in parsed:
        for choice in frame["choices"]:
            if choice["index"] != index:
                continue
            delta = choice.get("delta") or {}
            content += delta.get("content") or ""
            for call in delta.get("tool_calls") or []:
                args[call["index"]] = args.get(call["index"], "") + call["function"].get("arguments", "")
    return content, args


def _check_frames():
    """A token split inside itself across JSON frames is held per field and restored."""
    pw, mail = "[" + "PASSWORD_1_abcdef" + "]", "[" + "EMAIL_ADDRESS_2_a1b2c3" + "]"
    secret = 'Pa"ss\\word1'
    lookup = {pw: secret, mail: "jan@voorbeeld.test"}.get

    frames = [_frame({"content": "Mail " + mail[:9]}), _frame({"content": mail[9:] + " now"}),
              _frame({}, "stop")]
    raw, parsed = _run(frames, lookup)
    check("content: every emitted frame is valid JSON", all(p is not None for p in parsed))
    check("content: no emitted frame carries a partial token", not any(mail[:5] in e for e in raw))
    check("content: a token split across deltas is restored",
          _joined(parsed)[0] == "Mail jan@voorbeeld.test now")

    call = {"index": 0, "id": "call_1", "type": "function", "function": {"name": "run", "arguments": ""}}
    parts = ['{"cmd":"', pw[:5], pw[5:14], pw[14:], '"}']
    frames = ([_frame({"role": "assistant", "content": None, "tool_calls": [call]})]
              + [_frame({"tool_calls": [{"index": 0, "function": {"arguments": a}}]}) for a in parts]
              + [_frame({}, "tool_calls")])
    raw, parsed = _run(frames, lookup)
    args = _joined(parsed)[1].get(0, "")
    check("arguments: every emitted frame is valid JSON", all(p is not None for p in parsed))
    check("arguments: no emitted frame carries a partial token", not any(pw[:5] in e for e in raw))
    check("arguments: a token split across BPE-sized deltas is restored",
          json.loads(args) == {"cmd": secret})

    two = [_frame({"tool_calls": [{"index": i, "function": {"arguments": a}}]})
           for i, a in ((0, '{"a":"' + pw[:8]), (1, '{"b":"' + mail[:4]), (0, pw[8:] + '"}'),
                        (1, mail[4:] + '"}'))] + [_frame({}, "tool_calls")]
    check("arguments: two interleaved calls are held apart",
          _joined(_run(two, lookup)[1])[1] == {0: json.dumps({"a": secret}, separators=(",", ":")),
                                                1: '{"b":"jan@voorbeeld.test"}'})

    _raw, parsed = _run([_frame({"content": "see " + pw[:6]}), _frame({}, "stop")], lookup)
    check("finish_reason flushes a held prefix as text", _joined(parsed)[0] == "see " + pw[:6])
    _raw, parsed = _run([_frame({"content": "see " + pw[:6]})], lookup)
    check("stream end flushes a held prefix as a valid frame",
          _joined(parsed)[0] == "see " + pw[:6] and parsed[-1]["id"] == "c1")
    raw, _parsed = _run([_frame({"content": "arr[i"})], lookup)
    check("a bracket that cannot start a token is not held", len(raw) == 1 and "arr[i" in raw[0])
    plain = _frame({"content": "hello"})
    check("a frame with nothing to restore keeps its bytes", _run([plain], lookup)[0] == [plain])


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
    _check_frames()

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
