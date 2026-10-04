"""A client that hangs up on a stream must give its database connection back.

Real uvicorn gateway with a pool of 2 connections and a provider that streams slowly. A
client reads the first chunk and hangs up, or sends a request and closes the socket
before any response, more times than the pool holds. A normal chat afterwards must still
be served at once: if hung-up streams kept their connections, it would wait for the pool
and fail. Self-skips only without Postgres.
"""
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

import httpx
import psycopg
import test_end_to_end as e2e

from erebus.gateway.config import GatewayConfig
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.store import db

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_e2e_stream_disconnect")
_HANGUPS = 5  # more than the pool's 2 connections
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _SlowProvider:
    """Streams one frame, then waits before finishing; answers plain calls at once."""

    def __init__(self) -> None:
        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                if not body.get("stream"):
                    data = json.dumps({"choices": [{"index": 0, "message": {"role": "assistant",
                                                                            "content": "ok"}}]}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                frame = {"choices": [{"index": 0, "delta": {"content": "first"}}]}
                try:
                    self.wfile.write(f"data: {json.dumps(frame)}\n\n".encode())
                    self.wfile.flush()
                    time.sleep(3)
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except OSError:
                    return

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


def _hang_up_mid_stream(base, cred):
    """Read the first streamed chunk, then close the connection."""
    with httpx.Client(timeout=10.0) as client, client.stream(
            "POST", f"{base}/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
            json={"model": "gpt-4o", "stream": True, "messages": [{"role": "user", "content": "hi"}]}) as r:
        for line in r.iter_lines():
            if line.startswith("data:"):
                return r.status_code
    return None


def _hang_up_before_response(base, cred):
    """Send a streaming request and close the socket without reading anything."""
    parts = urlsplit(base)
    body = json.dumps({"model": "gpt-4o", "stream": True, "messages": [{"role": "user", "content": "hi"}]})
    request = (f"POST /v1/chat/completions HTTP/1.1\r\nHost: {parts.netloc}\r\n"
               f"Authorization: Bearer {cred}\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
    with socket.create_connection((parts.hostname, parts.port), timeout=5) as sock:
        sock.sendall(request.encode())
    time.sleep(0.3)  # let the gateway reach the point of sending headers


def _chat_is_served(base, cred):
    started = time.monotonic()
    with httpx.Client(timeout=20.0) as client:
        r = client.post(f"{base}/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
                        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
    return r.status_code == 200, time.monotonic() - started


def main():
    print("\n=== Streams the client hangs up on give their connection back ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True
    provider = gateway = kms = None
    try:
        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")
        provider = _SlowProvider()
        provider.start()
        kms = MasterKeyKms(_DSN, e2e._KEY)
        _sid, cred = e2e._provision_tenant(conn, kms, "e2e/hangup", "openai", provider.base_url, ["gpt-4o"])
        gateway = e2e._GatewayServer(GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN, "EREBUS_GATEWAY_MASTER_KEY": e2e._KEY, "EREBUS_GATEWAY_PROVIDER": "openai",
            "EREBUS_DISABLE_GLINER": "1", "EREBUS_GATEWAY_POOL_MIN": "1", "EREBUS_GATEWAY_POOL_MAX": "2"}))
        gateway.start()
        base = gateway.base_url

        statuses = [_hang_up_mid_stream(base, cred) for _ in range(_HANGUPS)]
        check(f"{_HANGUPS} streams started and were hung up on mid-stream", statuses == [200] * _HANGUPS)
        time.sleep(0.5)
        served, took = _chat_is_served(base, cred)
        check(f"a chat is still served after {_HANGUPS} mid-stream hang-ups (pool of 2)", served and took < 10)

        for _ in range(_HANGUPS):
            _hang_up_before_response(base, cred)
        time.sleep(0.5)
        served, took = _chat_is_served(base, cred)
        check(f"a chat is still served after {_HANGUPS} hang-ups before any response", served and took < 10)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        for closer in (gateway and gateway.stop, provider and provider.stop, kms and kms.close, conn.close):
            if closer:
                closer()


if __name__ == "__main__":
    main()
