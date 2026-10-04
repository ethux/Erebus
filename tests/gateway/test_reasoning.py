"""Reasoning models through the gateway: thinking parts, reasoning_content, reasoning.

Mistral returns thinking as a content part (``{"type": "thinking", "thinking": [text
parts]}``) and editors send it back in the next turn; DeepSeek uses a ``reasoning_content``
string and vLLM/OpenRouter a ``reasoning`` string. Checks: such history is gated
(tokenized, never refused, never sent raw, refused in edge mode when raw) and tokens in
the reasoning of a whole response are restored. Streamed reasoning is covered in
test_streaming. Live Postgres; self-skips without it.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_NAME = "Alice Adams"
_TOKEN = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6,}\]")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _thinking(text, **extra):
    return {"type": "thinking", "thinking": [{"type": "text", "text": text}], **extra}


def detector(text):
    i = text.find(_NAME)
    return [(i, i + len(_NAME), "PERSON")] if i != -1 else []


def _history():
    """A second turn as an editor sends it: the reasoning model's first answer replayed."""
    return [
        {"role": "user", "content": f"Who is {_NAME}?"},
        {"role": "assistant", "content": [_thinking(f"The user asks about {_NAME}."),
                                          {"type": "text", "text": f"{_NAME} is a client."}]},
        {"role": "user", "content": "And then?"},
    ]


def _check_request(client, captured, hdr):
    r = client.post("/v1/chat/completions", headers=hdr, json={"messages": _history()})
    check("history with a thinking part is not refused (was 415 'modality blocked: thinking')",
          r.status_code == 200)
    sent = captured[-1]["messages"][1]["content"]
    check("the raw name never reached the provider", _NAME not in json.dumps(captured[-1]))
    check("the provider got the thinking part back in its own shape",
          sent[0]["type"] == "thinking" and sent[0]["thinking"][0]["type"] == "text")
    check("the thinking text reached the provider as a token", "[PERSON_" in sent[0]["thinking"][0]["text"])
    check("the text part next to it is tokenized too", "[PERSON_" in sent[1]["text"])

    msg = {"role": "assistant", "content": "done", "reasoning_content": f"Look up {_NAME}",
           "reasoning": f"{_NAME} again"}
    r = client.post("/v1/chat/completions", headers=hdr, json={"messages": [msg, {"role": "user", "content": "go"}]})
    sent = captured[-1]["messages"][0]
    check("history with reasoning_content and reasoning is 200", r.status_code == 200)
    check("reasoning_content and reasoning never reach the provider raw", _NAME not in json.dumps(captured[-1]))
    check("reasoning_content and reasoning reach the provider as tokens",
          "[PERSON_" in sent["reasoning_content"] and "[PERSON_" in sent["reasoning"])

    msg = {"role": "user", "content": [f"Mail {_NAME}", {"type": "text", "text": "today"}]}
    client.post("/v1/chat/completions", headers=hdr, json={"messages": [msg]})
    check("a plain string inside a content list never reaches the provider raw",
          _NAME not in json.dumps(captured[-1]) and "[PERSON_" in captured[-1]["messages"][0]["content"][0])


def _check_response(client, hdr):
    r = client.post("/v1/chat/completions", headers=hdr, json={"messages": [
        {"role": "user", "content": f"Tell me about {_NAME}"}]})
    msg = r.json()["choices"][0]["message"]
    check("a reasoning answer is 200", r.status_code == 200)
    check("tokens inside a thinking part come back restored",
          msg["content"][0]["thinking"][0]["text"] == f"Thinking about {_NAME}")
    check("the text part next to it is restored", msg["content"][1]["text"] == f"{_NAME} it is")
    check("reasoning_content comes back restored", msg["reasoning_content"] == f"Why {_NAME}")
    check("reasoning comes back restored", msg["reasoning"] == f"{_NAME} because")
    check("no token is left anywhere in the answer", not _TOKEN.search(r.text))


def _check_edge(conn, kms, ids, prov):
    app = create_app(conn=conn, key_provider=kms, detector=detector, provider_call=prov,
                     scopes=ScopeResolver({"cM": "tenM"}), scope_ids=ids, modes={"tenM": "edge"})
    client = TestClient(app)
    hdr = {"Authorization": "Bearer cM"}
    # Only the reasoning carries the raw name, so a 400 proves the reasoning itself was gated.
    r = client.post("/v1/chat/completions", headers=hdr, json={"messages": [
        {"role": "assistant", "content": [_thinking(f"about {_NAME}"), {"type": "text", "text": "x"}]}]})
    check("edge mode: raw PII inside a thinking part is refused (400), not forwarded", r.status_code == 400)
    r = client.post("/v1/chat/completions", headers=hdr, json={"messages": [
        {"role": "assistant", "content": "x", "reasoning_content": f"about {_NAME}"}]})
    check("edge mode: raw PII in reasoning_content is refused (400), not forwarded", r.status_code == 400)


def main():
    print("\n=== Reasoning models: thinking parts, reasoning_content, reasoning ===\n")
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
        m = provision_scope(conn, kms, "tenM")
        quota.set_quota(conn, m, 1000, 100000, 60)
        ids = {"tenM": m}
        hdr = {"Authorization": "Bearer cM"}
        captured = []

        async def prov(payload):
            captured.append(json.loads(json.dumps(payload)))
            tok = (_TOKEN.findall(json.dumps(payload)) or ["none"])[0]
            return {"choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant",
                "content": [_thinking(f"Thinking about {tok}"), {"type": "text", "text": f"{tok} it is"}],
                "reasoning_content": f"Why {tok}", "reasoning": f"{tok} because"}}]}

        app = create_app(conn=conn, key_provider=kms, detector=detector, provider_call=prov,
                         scopes=ScopeResolver({"cM": "tenM"}), scope_ids=ids)
        client = TestClient(app)
        _check_request(client, captured, hdr)
        _check_response(client, hdr)
        before = len(captured)
        _check_edge(conn, kms, ids, prov)
        check("edge refusals sent nothing to the provider", len(captured) == before)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
