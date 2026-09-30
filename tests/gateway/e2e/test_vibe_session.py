"""A Vibe-style editor session through the gateway over real HTTP.

Mirrors the manual Mistral Vibe test of this release: an OpenAI-style client talks to a
real uvicorn gateway with GLiNER enabled (a seeded stand-in finds one name), and an
OpenAI-style mock provider records every upstream body. The mock streams JSON delta
frames and splits a token across frames, like real providers do, and can answer with a
tool call. Checks: forged roles grant nothing; names, emails, phone numbers, IBANs and
secrets reach the provider only as tokens and come back restored; streamed replies never
show a partial token; tool-call arguments stay valid JSON both ways. Self-skips only
without Postgres.
"""
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

import helpers
import httpx
import psycopg
import test_end_to_end as e2e

from erebus.core import detect as core_detect
from erebus.gateway.config import GatewayConfig
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.store import db

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_e2e_vibe")
_NAME = "Annelies Kloosterman"
_RAW = {
    "PERSON": _NAME,
    "EMAIL_ADDRESS": "annelies@voorbeeld-bv.test",
    "PHONE_NUMBER": "+31 6 23456789",
    "IBAN": "NL91ABNA0417164300",
}
_API_KEY = "sk-" + "Zq7" * 14
_TOKEN = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6,}\]")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _seeded_ner(text: str) -> list[dict]:
    """Stand-in for the GLiNER daemon: finds the seeded name, nothing else."""
    start = text.find(_NAME)
    if start == -1:
        return []
    return [{"start": start, "end": start + len(_NAME), "label": "person", "text": _NAME}]


class _OpenAIMock:
    """OpenAI-style provider: records bodies, echoes the last user message.

    Streams as JSON delta frames and cuts the first token in the echo across three frames.
    A last message starting with 'CALL:' is answered with a tool call whose arguments carry
    the first token of that message.
    """

    def __init__(self) -> None:
        self.requests: list[dict] = []
        recorder = self.requests

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                body = json.loads(raw.decode() or "{}")
                recorder.append(body)
                last = (body.get("messages") or [{}])[-1].get("content") or ""
                if last.startswith("CALL:"):
                    token = (_TOKEN.findall(last) or ["none"])[0]
                    msg = {"role": "assistant", "content": None, "tool_calls": [{
                        "id": "call_1", "type": "function",
                        "function": {"name": "send_mail", "arguments": json.dumps({"to": token, "cc": [token]})}}]}
                    return self._json({"choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls"}]})
                if body.get("stream"):
                    return self._stream(last)
                return self._json({"choices": [{"index": 0, "message": {"role": "assistant", "content": last}}]})

            def _json(self, payload):
                data = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _stream(self, content):
                match = _TOKEN.search(content)
                if match:
                    a = match.start() + 2
                    b = match.start() + (match.end() - match.start()) // 2 + 1
                    pieces = [content[:a], content[a:b], content[b:]]
                else:
                    pieces = [content]
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for piece in pieces:
                    frame = {"choices": [{"index": 0, "delta": {"content": piece}}]}
                    self.wfile.write(f"data: {json.dumps(frame)}\n\n".encode())
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}/v1/chat/completions"

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


def _chat(client, base, cred, messages, stream=False):
    return client.post(f"{base}/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
                       json={"model": "gpt-4o", "stream": stream, "messages": messages})


def _check_authorization(client, base, tenant, operator):
    check("forged X-Role without a credential is 401",
          client.get(f"{base}/metrics", headers={"X-Role": "AUDITOR"}).status_code == 401)
    r = client.get(f"{base}/metrics", headers={"Authorization": f"Bearer {tenant}", "X-Role": "AUDITOR"})
    check("tenant credential + forged X-Role on /metrics is 403 and discloses nothing",
          r.status_code == 403 and "scopes" not in r.text)
    r = client.post(f"{base}/v1/admin/tenants", headers={"Authorization": f"Bearer {tenant}"},
                    json={"scope_key": "evil", "provider": "openai", "central_credential": "x",
                          "role": "GATEWAY_OPERATOR"})
    check("tenant credential + body role cannot onboard a tenant (403)", r.status_code == 403)
    check("operator credential reads /metrics", client.get(
        f"{base}/metrics", headers={"Authorization": f"Bearer {operator}"}).status_code == 200)


def _check_chat(client, base, cred, mock):
    prompt = (f"Mail {_RAW['PERSON']} at {_RAW['EMAIL_ADDRESS']}, call {_RAW['PHONE_NUMBER']}, "
              f"pay to {_RAW['IBAN']}.")
    r = _chat(client, base, cred, [{"role": "user", "content": prompt}])
    check("chat is 200", r.status_code == 200)
    sent = mock.requests[-1]["messages"][-1]["content"]
    for label, raw in _RAW.items():
        check(f"{label}: raw value never reached the provider", raw not in json.dumps(mock.requests[-1]))
        check(f"{label}: the provider saw a {label} token", f"[{label}_" in sent)
    check("the client gets the prompt back exactly", r.json()["choices"][0]["message"]["content"] == prompt)


def _check_stream(client, base, cred, mock):
    prompt = f"Thanks {_NAME}, reply to {_RAW['EMAIL_ADDRESS']}."
    frames, text = [], ""
    with client.stream("POST", f"{base}/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
                       json={"model": "gpt-4o", "stream": True,
                             "messages": [{"role": "user", "content": prompt}]}) as r:
        check("streamed chat is 200", r.status_code == 200)
        for line in r.iter_lines():
            if line.startswith("data:") and "[DONE]" not in line:
                frames.append(line[5:].strip())
    parsed = [json.loads(f) for f in frames]
    check("every streamed frame is valid JSON", len(parsed) == len(frames) and frames)
    for p in parsed:
        for ch in p.get("choices", []):
            text += (ch.get("delta") or {}).get("content") or ""
    upstream = mock.requests[-1]["messages"][-1]["content"]
    check("the provider streamed a token split across frames", _TOKEN.search(upstream))
    check("the streamed reply restores to the exact prompt", text == prompt)
    check("no frame shows a partial or whole token", not any("[PERSON" in f or "[EMAIL" in f for f in frames))


def _check_tool_calls(client, base, cred, mock):
    args = json.dumps({"cmd": f"export API_KEY={_API_KEY}", _RAW["EMAIL_ADDRESS"]: "cc", "count": 3})
    history = [
        {"role": "user", "content": "run it"},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "run", "arguments": args}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "done"},
        {"role": "user", "content": "ok?"},
    ]
    r = _chat(client, base, cred, history)
    check("tool-call history with a secret and an email key is 200", r.status_code == 200)
    upstream_args = mock.requests[-1]["messages"][1]["tool_calls"][0]["function"]["arguments"]
    try:
        parsed = json.loads(upstream_args)
    except ValueError:
        parsed = None
    check("upstream tool-call arguments are still valid JSON", isinstance(parsed, dict))
    check("the API key never reached the provider", _API_KEY not in upstream_args)
    check("an email used as a JSON key never reached the provider", _RAW["EMAIL_ADDRESS"] not in upstream_args)
    check("non-string argument values are untouched", parsed.get("count") == 3)

    r = _chat(client, base, cred, [{"role": "user", "content": f"CALL: write to {_RAW['EMAIL_ADDRESS']}"}])
    check("a tool-call answer is 200", r.status_code == 200)
    call = r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    restored = json.loads(call)
    check("the returned tool-call arguments are valid JSON with the real email restored",
          restored == {"to": _RAW["EMAIL_ADDRESS"], "cc": [_RAW["EMAIL_ADDRESS"]]})


def main():
    print("\n=== Vibe-style session over real HTTP ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True
    mock = gateway = kms = None
    original = core_detect._predict_entities
    core_detect._predict_entities = _seeded_ner
    try:
        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")
        mock = _OpenAIMock()
        mock.start()
        kms = MasterKeyKms(_DSN, e2e._KEY)
        _sid, tenant = e2e._provision_tenant(conn, kms, "e2e/vibe", "openai", mock.base_url, ["gpt-4o"])
        operator = helpers.operator_bearer(conn)
        gateway = e2e._GatewayServer(GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN, "EREBUS_GATEWAY_MASTER_KEY": e2e._KEY, "EREBUS_GATEWAY_PROVIDER": "openai"}))
        gateway.start()
        base = gateway.base_url
        with httpx.Client(timeout=30.0) as client:
            ready = client.get(f"{base}/readyz").json()
            check("readyz reports full detection ('available')", ready.get("detection") == "available")
            _check_authorization(client, base, tenant, operator)
            _check_chat(client, base, tenant, mock)
            _check_stream(client, base, tenant, mock)
            _check_tool_calls(client, base, tenant, mock)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        core_detect._predict_entities = original
        for closer in (gateway and gateway.stop, mock and mock.stop, kms and kms.close, conn.close):
            if closer:
                closer()


if __name__ == "__main__":
    main()
