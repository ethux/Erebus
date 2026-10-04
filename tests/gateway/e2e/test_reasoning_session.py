"""A reasoning-model session through the gateway over real HTTP.

A real uvicorn gateway talks to a mock OpenAI-compatible provider that answers like a
reasoning model: Mistral-style thinking content parts for ``zai-glm-5-3`` and a
DeepSeek-style ``reasoning_content`` string for ``deepseek-reasoner``, whole and streamed,
with tokens cut across stream frames. The client replays the answer in the next turn, as
editors do. Checks: the replay is not refused, raw values never reach the provider, the
client gets them back in the reasoning and the answer, and every streamed frame is valid
JSON without a partial token. Self-skips only without Postgres.
"""
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

import httpx
import psycopg
import test_end_to_end as e2e

from erebus.core import detect as core_detect
from erebus.gateway.config import GatewayConfig
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.store import db

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_e2e_reasoning")
_NAME = "Annelies Kloosterman"
_EMAIL = "annelies@voorbeeld-bv.test"
_MISTRAL, _DEEPSEEK = "zai-glm-5-3", "deepseek-reasoner"
_TOKEN = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6,}\]")
_TOKEN_START = re.compile(r"\[[A-Z]")  # a whole or partial token; JSON arrays open with "[{"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _seeded_ner(text: str) -> list[dict]:
    start = text.find(_NAME)
    if start == -1:
        return []
    return [{"start": start, "end": start + len(_NAME), "label": "person", "text": _NAME}]


def _thinking(text: str, **extra) -> dict:
    return {"type": "thinking", "thinking": [{"type": "text", "text": text}], **extra}


def _cut(text: str) -> list[str]:
    """Three pieces, both cuts inside the first token, like a provider's BPE deltas."""
    match = _TOKEN.search(text)
    if not match:
        return [text]
    a, b = match.start() + 2, match.start() + (match.end() - match.start()) // 2 + 1
    return [text[:a], text[a:b], text[b:]]


def _mistral_frames(last: str) -> list[dict]:
    """Thinking chunks, a transition list (closing thinking + first text), then strings."""
    think, answer = _cut("Thinking about " + last), _cut(last)
    deltas = [{"role": "assistant", "content": [_thinking(think[0])]}]
    deltas += [{"content": [_thinking(p)]} for p in think[1:]]
    deltas.append({"content": [_thinking(" done", closed=True), {"type": "text", "text": answer[0]}]})
    deltas += [{"content": p} for p in answer[1:]]
    return deltas


def _deepseek_frames(last: str) -> list[dict]:
    deltas = [{"reasoning_content": p} for p in _cut("Thinking about " + last)]
    return [{"role": "assistant", **deltas[0]}, *deltas[1:], *({"content": p} for p in _cut(last))]


class _ReasoningMock:
    """Records every upstream body; answers about the last user message like a reasoning model."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        recorder = self.requests

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                recorder.append(body)
                last = (body.get("messages") or [{}])[-1].get("content") or ""
                deepseek = body.get("model") == _DEEPSEEK
                if body.get("stream"):
                    return self._stream(_deepseek_frames(last) if deepseek else _mistral_frames(last))
                if deepseek:
                    msg = {"role": "assistant", "reasoning_content": "Thinking about " + last, "content": last}
                else:
                    msg = {"role": "assistant", "content": [_thinking("Thinking about " + last),
                                                            {"type": "text", "text": last}]}
                data = json.dumps({"choices": [{"index": 0, "message": msg, "finish_reason": "stop"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return None

            def _stream(self, deltas):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                choices = [{"index": 0, "delta": d, "finish_reason": None} for d in deltas]
                choices.append({"index": 0, "delta": {}, "finish_reason": "stop"})
                for choice in choices:
                    self.wfile.write(f"data: {json.dumps({'id': 'r1', 'choices': [choice]})}\n\n".encode())
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


def _post(client, base, cred, model, messages):
    return client.post(f"{base}/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
                       json={"model": model, "messages": messages})


def _stream(client, base, cred, model, messages):
    """Stream a chat; return the raw frames and what a client reassembles from them."""
    frames = []
    with client.stream("POST", f"{base}/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
                       json={"model": model, "stream": True, "messages": messages}) as r:
        check(f"{model}: streamed chat is 200", r.status_code == 200)
        frames = [line[5:].strip() for line in r.iter_lines() if line.startswith("data:") and "[DONE]" not in line]
    parsed = [json.loads(f) for f in frames]
    out = {"content": "", "thinking": "", "reasoning_content": ""}
    for frame in parsed:
        delta = frame["choices"][0].get("delta") or {}
        content = delta.get("content")
        out["content"] += content if isinstance(content, str) else ""
        for part in content if isinstance(content, list) else []:
            if part["type"] == "text":
                out["content"] += part["text"]
            else:
                out["thinking"] += "".join(sub["text"] for sub in part["thinking"])
        out["reasoning_content"] += delta.get("reasoning_content") or ""
    return frames, out


def _no_raw_upstream(mock) -> bool:
    sent = json.dumps(mock.requests[-1])
    return _NAME not in sent and _EMAIL not in sent


def _check_mistral(client, base, cred, mock):
    prompt = f"Mail {_NAME} at {_EMAIL}."
    r = _post(client, base, cred, _MISTRAL, [{"role": "user", "content": prompt}])
    check("thinking answer is 200", r.status_code == 200)
    check("raw values never reached the provider", _no_raw_upstream(mock))
    answer = r.json()["choices"][0]["message"]
    check("the thinking comes back restored", answer["content"][0]["thinking"][0]["text"] == "Thinking about " + prompt)
    check("the answer text comes back restored", answer["content"][1]["text"] == prompt)
    check("no token is left in the answer", not _TOKEN.search(r.text))

    history = [{"role": "user", "content": prompt}, answer, {"role": "user", "content": "And her phone?"}]
    r = _post(client, base, cred, _MISTRAL, history)
    check("the next turn, replaying the thinking, is not refused (was 415)", r.status_code == 200)
    check("the replayed thinking never reached the provider raw", _no_raw_upstream(mock))
    replayed = mock.requests[-1]["messages"][1]["content"]
    check("the provider got the replayed thinking as tokens, in its own shape",
          replayed[0]["type"] == "thinking" and "[PERSON_" in replayed[0]["thinking"][0]["text"]
          and "[EMAIL_ADDRESS_" in replayed[0]["thinking"][0]["text"])

    frames, out = _stream(client, base, cred, _MISTRAL, [{"role": "user", "content": prompt}])
    check("thinking stream: the provider saw only tokens", _no_raw_upstream(mock))
    check("thinking stream: every frame is valid JSON (parsed above)", len(frames) > 4)
    check("thinking stream: no frame shows a partial or whole token",
          not any(_TOKEN_START.search(f) for f in frames))
    check("thinking stream: the thinking restores exactly", out["thinking"] == "Thinking about " + prompt + " done")
    check("thinking stream: the answer restores exactly", out["content"] == prompt)


def _check_deepseek(client, base, cred, mock):
    prompt = f"Who is {_NAME}?"
    r = _post(client, base, cred, _DEEPSEEK, [{"role": "user", "content": prompt}])
    answer = r.json()["choices"][0]["message"]
    check("reasoning_content answer is 200", r.status_code == 200)
    check("reasoning_content comes back restored", answer["reasoning_content"] == "Thinking about " + prompt)
    check("reasoning_content: no token is left in the answer", not _TOKEN.search(r.text))

    r = _post(client, base, cred, _DEEPSEEK, [{"role": "user", "content": prompt}, answer,
                                             {"role": "user", "content": "More?"}])
    check("the next turn, replaying reasoning_content, is 200", r.status_code == 200)
    check("the replayed reasoning_content never reached the provider raw", _no_raw_upstream(mock))
    check("the provider got the replayed reasoning_content as a token",
          "[PERSON_" in mock.requests[-1]["messages"][1]["reasoning_content"])

    frames, out = _stream(client, base, cred, _DEEPSEEK, [{"role": "user", "content": prompt}])
    check("reasoning_content stream: no frame shows a partial or whole token",
          not any(_TOKEN_START.search(f) for f in frames))
    check("reasoning_content stream: the reasoning restores exactly",
          out["reasoning_content"] == "Thinking about " + prompt)
    check("reasoning_content stream: the answer restores exactly", out["content"] == prompt)


def main():
    print("\n=== Reasoning-model session over real HTTP ===\n")
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
        mock = _ReasoningMock()
        mock.start()
        kms = MasterKeyKms(_DSN, e2e._KEY)
        _sid, tenant = e2e._provision_tenant(conn, kms, "e2e/reasoning", "openai", mock.base_url,
                                             [_MISTRAL, _DEEPSEEK])
        gateway = e2e._GatewayServer(GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN, "EREBUS_GATEWAY_MASTER_KEY": e2e._KEY, "EREBUS_GATEWAY_PROVIDER": "openai"}))
        gateway.start()
        base = gateway.base_url
        with httpx.Client(timeout=30.0) as client:
            e2e._wait_until(lambda: client.get(f"{base}/readyz").status_code == 200, "gateway never became ready")
            _check_mistral(client, base, tenant, mock)
            _check_deepseek(client, base, tenant, mock)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        core_detect._predict_entities = original
        for closer in (gateway and gateway.stop, mock and mock.stop, kms and kms.close, conn.close):
            if closer:
                closer()


if __name__ == "__main__":
    main()
