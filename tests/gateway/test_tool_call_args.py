"""Tool-call arguments stay valid JSON through the gate and back (FR-004).

OpenAI tool calls carry ``function.arguments`` as one JSON string. The values inside it
must be tokenized without a ``key=value`` tail swallowing the closing quote and brace,
and a token coming back in a response (whole or streamed) must be restored JSON-escaped,
so a restored quote or backslash never breaks the JSON. Uses the production regex-only
detector. Live Postgres for the route; self-skips without it.
"""
import copy
import json
import os
import re
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.detection import build_detector
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_HDR = {"Authorization": "Bearer cT"}
_EDGE = {"Authorization": "Bearer cE"}
_CMD = "export API_KEY=abcd1234efgh"
_EMAIL = "jan.jansen@voorbeeld-bv.test"
_IBAN = "NL91ABNA0417164300"
# A PASSWORD span holding a quote and a backslash: restored inside a JSON string it
# must come back escaped, or the arguments stop being JSON.
_QUOTED = 'password=Pa"ss\\word1'
_TOKEN = r"\[{label}_\d+_[0-9a-f]{{6,}}\]"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _is_token(value, label):
    return isinstance(value, str) and re.fullmatch(_TOKEN.format(label=label), value) is not None


def _loads(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _body(arguments, stream=False):
    call = {"id": "call_1", "type": "function", "function": {"name": "run", "arguments": arguments}}
    body = {"messages": [{"role": "assistant", "content": None, "tool_calls": [call]}]}
    if stream:
        body["stream"] = True
    return body


def _sent_args(captured):
    return captured[-1]["messages"][0]["tool_calls"][0]["function"]["arguments"]


def _frames(args, content):
    """OpenAI-style chunks with the token itself split across deltas, in the arguments and
    in the content, as BPE-sized deltas do."""
    a, c = args.index("[") + 5, content.index("[") + 9
    deltas = [{"role": "assistant", "tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                                    "function": {"name": "run", "arguments": ""}}]},
              {"tool_calls": [{"index": 0, "function": {"arguments": args[:a]}}]},
              {"tool_calls": [{"index": 0, "function": {"arguments": args[a:]}}]},
              {"content": content[:c]}, {"content": content[c:]}]
    return [json.dumps({"choices": [{"index": 0, "delta": d}]}, separators=(",", ":")) for d in deltas]


def _check_request(client, captured):
    compact = json.dumps({"cmd": _CMD, "to": _EMAIL, "iban": _IBAN}, separators=(",", ":"))
    for style, raw in (("default", json.dumps({"cmd": _CMD, "to": _EMAIL, "iban": _IBAN})),
                       ("compact", compact)):
        client.post("/v1/chat/completions", headers=_HDR, json=_body(raw))
        sent = _sent_args(captured)
        parsed = _loads(sent)
        check(f"{style} arguments reach the provider as valid JSON", isinstance(parsed, dict))
        parsed = parsed or {}
        check(f"{style}: API_KEY=... inside the arguments is a token",
              re.fullmatch(r"export " + _TOKEN.format(label="API_KEY"), parsed.get("cmd", "")) is not None)
        check(f"{style}: the email inside the arguments is a token", _is_token(parsed.get("to"), "EMAIL_ADDRESS"))
        check(f"{style}: the IBAN inside the arguments is a token", _is_token(parsed.get("iban"), "IBAN"))
        check(f"{style}: no raw value reached the provider",
              not any(v in sent for v in ("abcd1234efgh", _EMAIL, _IBAN)))
        separators = (",", ":") if style == "compact" else (", ", ": ")
        check(f"{style}: the client's JSON layout is kept",
              sent == json.dumps(parsed, separators=separators))

    client.post("/v1/chat/completions", headers=_HDR, json=_body(_CMD))
    check("non-JSON arguments are still tokenized as one string",
          re.fullmatch(r"export " + _TOKEN.format(label="API_KEY"), _sent_args(captured)) is not None)
    broken = '{"cmd": "export API_KEY=abcd1234efgh"'
    client.post("/v1/chat/completions", headers=_HDR, json=_body(broken))
    check("broken JSON arguments are still tokenized as one string",
          "abcd1234efgh" not in _sent_args(captured) and "[API_KEY_" in _sent_args(captured))


def _check_legacy_function_call(client, captured):
    """The deprecated OpenAI ``function_call`` field is gated like ``tool_calls``."""
    raw = json.dumps({"cmd": _CMD, "to": _EMAIL})
    body = {"messages": [{"role": "assistant", "content": None,
                          "function_call": {"name": "run", "arguments": raw}}]}
    client.post("/v1/chat/completions", headers=_HDR, json=body)
    sent = captured[-1]["messages"][0]["function_call"]["arguments"]
    parsed = _loads(sent) or {}
    check("legacy function_call arguments reach the provider as valid JSON", bool(parsed))
    check("legacy function_call: the email is a token", _is_token(parsed.get("to"), "EMAIL_ADDRESS"))
    check("legacy function_call: no raw value reached the provider",
          not any(v in sent for v in ("abcd1234efgh", _EMAIL)))


def _check_keys(client, captured):
    """Keys used as data (email -> role) are gated too; plain parameter names are not."""
    keyed = json.dumps({"recipients": {_EMAIL: "cc"}, "api_key": "x", "password": "y"})
    resp = client.post("/v1/chat/completions", headers=_HDR, json=_body(keyed))
    sent = _sent_args(captured)
    parsed = _loads(sent) or {}
    check("an email used as an object key never reaches the provider", _EMAIL not in sent)
    check("an email used as an object key goes up as a token",
          [_is_token(k, "EMAIL_ADDRESS") for k in parsed.get("recipients", {})] == [True])
    check("plain parameter names keep their bytes", sorted(parsed) == ["api_key", "password", "recipients"])
    args = resp.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    check("a tokenized key comes back restored", _loads(args) == _loads(keyed))

    refused = client.post("/v1/chat/completions", headers=_EDGE, json=_body(keyed))
    check("edge mode refuses an email used as an object key", refused.status_code == 400)
    clean = client.post("/v1/chat/completions", headers=_EDGE,
                        json=_body(json.dumps({"api_key": "x", "password": "y"})))
    check("edge mode passes plain parameter names", clean.status_code == 200)


def _check_restore(client, captured):
    raw = json.dumps({"cmd": _QUOTED})
    resp = client.post("/v1/chat/completions", headers=_HDR, json=_body(raw))
    sent = _loads(_sent_args(captured)) or {}
    check("a value with a quote and a backslash goes up as a token",
          _is_token(sent.get("cmd"), "PASSWORD"))
    args = resp.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    check("non-streamed: tool-call arguments come back as valid JSON", _loads(args) is not None)
    check("non-streamed: the token in the arguments is restored to the original value",
          (_loads(args) or {}).get("cmd") == _QUOTED)

    text = client.post("/v1/chat/completions", headers=_HDR, json=_body(raw, stream=True)).text
    frames = [line[len("data: "):] for line in text.split("\n\n") if line.startswith("data: ")]
    check("streamed: the stream completes", frames[-1:] == ["[DONE]"])
    chunks = [_loads(f) for f in frames[:-1]]
    check("streamed: every frame is valid JSON", bool(chunks) and all(c is not None for c in chunks))
    deltas = [c["choices"][0]["delta"] for c in chunks if c]
    streamed = "".join(tc["function"].get("arguments", "")
                       for d in deltas for tc in d.get("tool_calls", []))
    check("streamed: the reassembled arguments are valid JSON", _loads(streamed) is not None)
    check("streamed: the token in the arguments is restored to the original value",
          (_loads(streamed) or {}).get("cmd") == _QUOTED)
    check("streamed: a token split across content deltas is restored too",
          "".join(d["content"] for d in deltas if "content" in d) == f"ran {_QUOTED}")


def main():
    print("\n=== Tool-call arguments stay valid JSON (FR-004) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        scope = provision_scope(conn, kms, "tenT")
        edge = provision_scope(conn, kms, "tenE")
        for sid in (scope, edge):
            quota.set_quota(conn, sid, 1000, 100000, 60)
        captured = []

        async def echo(payload):
            captured.append(copy.deepcopy(payload))
            calls = payload["messages"][-1].get("tool_calls") or []
            return {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": calls}}]}

        async def echo_stream(payload):
            captured.append(copy.deepcopy(payload))
            args = _sent_args(captured)
            token = (_loads(args) or {}).get("cmd", "")
            for frame in _frames(args, f"ran {token}"):
                yield frame

        app = create_app(conn=conn, key_provider=kms,
                         detector=build_detector(SimpleNamespace(detection_disabled=True)),
                         provider_call=echo, provider_stream=echo_stream,
                         scopes=ScopeResolver({"cT": "tenT", "cE": "tenE"}),
                         scope_ids={"tenT": scope, "tenE": edge}, modes={"tenE": "edge"})
        client = TestClient(app)
        _check_request(client, captured)
        _check_legacy_function_call(client, captured)
        _check_keys(client, captured)
        _check_restore(client, captured)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
