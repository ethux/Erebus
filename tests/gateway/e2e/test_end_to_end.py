"""Network-level end-to-end acceptance gate for the deployable gateway (008 US6; T049).

This is the prod-readiness capstone (FR-014 / SC-002 / SC-007): it exercises the INTEGRATED
gateway over REAL HTTP, not an in-process ``TestClient``. Two real servers are stood up in
THIS process on ephemeral ports:

* a MOCK upstream provider (``http.server`` in a thread) that RECORDS every request's JSON
  body + headers and echoes ``{"choices":[{"message":{"content": <received content>}}]}`` so
  the gateway has tokens to restore on the response (and, for ``stream: true``, emits the same
  content as SSE split across frames so the streaming restorer is exercised), and
* the GATEWAY assembled via :func:`build_app_from_config` (real ``MasterKeyKms`` over its own
  DB, the production scope-aware httpx egress, a ``DbScopeResolver``) and served via a real
  ``uvicorn.Server`` running in a background THREAD, so ``erebus.core.detect`` can be
  monkeypatched in-process to detect a seeded name (real tokenization without a GLiNER daemon).

A real ``httpx`` client drives requests at the running gateway and the test ASSERTS (SC-002):

* a request carrying the seeded raw PII makes the provider record ONLY a token, never the raw
  value (token-only egress);
* the provider request carried the tenant CENTRAL credential, and a client-supplied
  Authorization (header AND body) is NEVER forwarded (FR-003);
* the client's RESPONSE has the real value restored, with no leftover token;
* a streaming request restores the value in the stream (and the provider still saw only a
  token);
* two fail-closed cases -- an unapproved model and detection forced unavailable -- send no raw
  PII to the provider and return a fail-closed status.

Both servers are torn down cleanly. Per the suite convention this self-skips with a clear
message ONLY if Postgres is unreachable; otherwise it runs fully (no other silent skips).
"""
import base64
import json
import os
import re
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

import httpx
import psycopg
import uvicorn

from erebus.core import detect as core_detect
from erebus.core import state as core_state
from erebus.gateway.config import GatewayConfig
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.providers import credentials, quota
from erebus.gateway.server import build_app_from_config
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import open_store, provision_scope

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_e2e")
_KEY = base64.b64encode(os.urandom(32)).decode()
_PERSON_TOKEN = re.compile(r"\[PERSON_\d+_[0-9a-f]+\]")
_SEEDED_NAME = "John Smith"  # the raw PII that must NEVER reach the provider
_CLIENT_SECRET = "USER-KEY-SHOULD-NOT-LEAK-" + "abc"  # a client-supplied credential
_CENTRAL_SECRET = "CENTRAL-EGRESS-SECRET-" + "xyz"     # the tenant's central credential

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


# --------------------------------------------------------------------------------------------
# Mock upstream provider: records each request, echoes the received content (whole or as SSE).
# --------------------------------------------------------------------------------------------
class _MockProvider:
    """A real local HTTP server recording requests and echoing the content it received."""

    def __init__(self) -> None:
        self.requests: list[dict] = []  # one {"headers", "body"} record per upstream call
        recorder = self.requests

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):  # silence the default stderr access log
                return

            def do_POST(self):  # BaseHTTPRequestHandler dispatch hook
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except ValueError:
                    body = {"_unparsed": raw.decode("utf-8", "replace")}
                recorder.append({"headers": dict(self.headers), "body": body})
                content = ""
                messages = body.get("messages") or []
                if messages and isinstance(messages[-1].get("content"), str):
                    content = messages[-1]["content"]
                if body.get("stream"):
                    self._reply_stream(content)
                else:
                    self._reply_json(content)

            def _reply_json(self, content: str) -> None:
                payload = {"choices": [{"message": {"role": "assistant", "content": content}}]}
                data = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _reply_stream(self, content: str) -> None:
                # Echo the (tokenized) content back as SSE. The gateway's ``http_stream``
                # treats each ``data:`` field value as a raw text fragment to restore, so we
                # emit the content directly (not wrapped in a JSON delta) and split it INSIDE
                # the token so the gateway's split-token hold-back restorer is genuinely
                # exercised: a token fragment must never be emitted partially or raw.
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                cut = self._split_inside_token(content)
                for piece in (content[:cut], content[cut:]):
                    self.wfile.write(f"data: {piece}\n\n".encode())
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

            @staticmethod
            def _split_inside_token(content: str) -> int:
                """Pick a cut index landing INSIDE the ``[PERSON_..]`` token, else the middle."""
                match = _PERSON_TOKEN.search(content)
                if match:
                    return match.start() + max(1, (match.end() - match.start()) // 2)
                return len(content) // 2

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


# --------------------------------------------------------------------------------------------
# Gateway under test: built via build_app_from_config, served by a real uvicorn in a thread.
# --------------------------------------------------------------------------------------------
class _GatewayServer:
    """Run the assembled FastAPI app under a real uvicorn.Server in a background thread."""

    def __init__(self, config: GatewayConfig) -> None:
        self._app, self._assembly = build_app_from_config(config)
        uconfig = uvicorn.Config(self._app, host="127.0.0.1", port=0, log_level="warning",
                                 timeout_graceful_shutdown=2)
        self._server = uvicorn.Server(uconfig)
        self._server.config.load()  # so lifespan + handlers are ready before serving
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    @property
    def base_url(self) -> str:
        # uvicorn binds the ephemeral port lazily; read it back from the bound socket.
        for server in self._server.servers or []:
            for sock in server.sockets:
                port = sock.getsockname()[1]
                return f"http://127.0.0.1:{port}"
        raise RuntimeError("gateway server has no bound socket yet")

    def start(self) -> None:
        self._thread.start()
        _wait_until(lambda: self._server.started and bool(self._server.servers),
                    "gateway uvicorn did not start in time")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


def _wait_until(predicate, message: str, timeout: float = 20.0) -> None:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception:
            pass
        time.sleep(0.05)
    raise RuntimeError(message)


# --------------------------------------------------------------------------------------------
# In-process detection: detect the seeded name, never marking the call degraded.
# --------------------------------------------------------------------------------------------
def _seeded_predict_entities(text: str) -> list[dict]:
    """Stand in for the GLiNER daemon: find the seeded name, never mark degraded.

    ``_CoreDetector`` calls ``core_state._reset_detector_state()`` then
    ``core_detect.predict_entities(text)`` (which resolves ``_predict_entities`` at call
    time) and only fails closed if ``core_state.detector_degraded()`` is set. This stand-in
    returns real PERSON spans without marking degraded, so the gateway tokenizes for real.
    """
    out = []
    start = text.find(_SEEDED_NAME)
    if start != -1:
        out.append({"start": start, "end": start + len(_SEEDED_NAME),
                    "label": "person", "text": _SEEDED_NAME})
    return out


def _force_detection_unavailable(text: str) -> list[dict]:
    """A detector that marks the call degraded so the gateway must fail closed (FR-007)."""
    core_state._mark_detector_degraded("forced_unavailable")
    return []


# --------------------------------------------------------------------------------------------
# Provisioning: a tenant with a CENTRAL credential + an approved route at the mock provider.
# --------------------------------------------------------------------------------------------
def _provision_tenant(conn, kms, scope_key: str, provider: str, base_url: str,
                      model_allowlist: list[str]) -> tuple[uuid.UUID, str]:
    """Provision a scope with a central credential + approved route + quota; return its cred."""
    sid = provision_scope(conn, kms, scope_key)
    crypto = open_store(conn, kms, sid)._crypto
    api_credential = credentials_directory.provision(conn, sid, scope_key, label="e2e")
    credentials.store_credential(conn, crypto, sid, provider, _CENTRAL_SECRET)
    rid = credentials.add_route(conn, sid, provider, base_url, model_allowlist=model_allowlist)
    credentials.approve_route(conn, sid, rid)
    quota.set_quota(conn, sid, 1000, 1000, 60)
    return sid, api_credential


def main():
    print("\n=== Network end-to-end acceptance gate (US6 / T049; FR-014 / SC-002 / SC-007) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True  # so the KMS/resolver/egress pools see migrations + provisioned rows

    provider = None
    gateway = None
    kms_setup = None
    original_predict = core_detect._predict_entities
    try:
        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        # Real detection, in-process: the gateway's _CoreDetector calls predict_entities,
        # which resolves _predict_entities at call time -- patch it to detect the seeded name.
        core_detect._predict_entities = _seeded_predict_entities

        # 1) Stand up the mock upstream provider on an ephemeral port.
        provider = _MockProvider()
        provider.start()

        # 2) Provision a tenant whose approved route points at the mock provider, with a
        #    CENTRAL credential. Done over the same shared state the gateway will resolve.
        kms_setup = MasterKeyKms(_DSN, _KEY)
        _sid, api_credential = _provision_tenant(
            conn, kms_setup, "e2e/tenant", "openai", provider.base_url, ["gpt-4o"])
        # A second tenant with a DIFFERENT model allowlist, used to drive the fail-closed
        # unapproved-model case against a real, fully-wired tenant.
        _sid2, api_credential_strict = _provision_tenant(
            conn, kms_setup, "e2e/strict", "openai", provider.base_url, ["only-this-model"])

        # 3) Assemble + launch the real gateway via the production config path. The default
        #    provider is "openai", so every request's model routes to the mock's approved route.
        #    Detection is left ENABLED (no EREBUS_DISABLE_GLINER) so build_app_from_config wires
        #    the production _CoreDetector, which calls our patched predict_entities -- exercising
        #    the real fail-closed detection path end-to-end rather than a no-op disabled detector.
        config = GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN,
            "EREBUS_GATEWAY_MASTER_KEY": _KEY,
            "EREBUS_GATEWAY_PROVIDER": "openai",
        })
        gateway = _GatewayServer(config)
        gateway.start()

        base = gateway.base_url
        with httpx.Client(timeout=30.0) as client:
            # readiness should report ready (state + custody healthy; detection available).
            ready = client.get(f"{base}/readyz")
            check("the running gateway reports ready (FR-008)", ready.status_code == 200)

            # --- SC-002: a request carrying raw PII egresses token-only and restores. ---
            provider.requests.clear()
            resp = client.post(
                f"{base}/v1/chat/completions",
                # The client smuggles its own credential in BOTH a header and the body; neither
                # may be forwarded (FR-003).
                headers={"Authorization": f"Bearer {api_credential}",
                         "X-Api-Key": _CLIENT_SECRET},
                json={"model": "gpt-4o", "authorization": f"Bearer {_CLIENT_SECRET}",
                      "api_key": _CLIENT_SECRET,
                      "messages": [{"role": "user",
                                    "content": f"Please contact {_SEEDED_NAME} today"}]},
            )
            check("chat request over real HTTP succeeds 200", resp.status_code == 200)
            check("the gateway made exactly one upstream call", len(provider.requests) == 1)

            rec = provider.requests[-1]
            egressed = rec["body"]["messages"][-1]["content"]
            check("the provider recorded ONLY a token, never the raw seeded value (SC-002)",
                  _SEEDED_NAME not in egressed and bool(_PERSON_TOKEN.search(egressed)))
            check("the raw seeded value appears NOWHERE in the recorded upstream request",
                  _SEEDED_NAME not in json.dumps(rec))

            # The CENTRAL credential rode upstream; the client's never did (FR-003).
            auth = rec["headers"].get("Authorization", "")
            check("the upstream request carried the tenant CENTRAL credential (FR-003)",
                  auth == f"Bearer {_CENTRAL_SECRET}")
            check("the client-supplied Authorization was NOT forwarded (FR-003)",
                  _CLIENT_SECRET not in json.dumps(rec))
            check("the client api_key/authorization body fields never egressed (FR-003)",
                  "api_key" not in rec["body"] and "authorization" not in rec["body"])

            # The client gets the RESTORED real value back, with no leftover token.
            restored = resp.json()["choices"][0]["message"]["content"]
            check("the client response has the real seeded value RESTORED (SC-002)",
                  _SEEDED_NAME in restored)
            check("the restored response carries no leftover token",
                  not _PERSON_TOKEN.search(restored))

            # --- Streaming: the value is restored in the stream; provider still saw a token. ---
            provider.requests.clear()
            with client.stream(
                "POST", f"{base}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_credential}"},
                json={"model": "gpt-4o", "stream": True,
                      "messages": [{"role": "user",
                                    "content": f"Email {_SEEDED_NAME} now"}]},
            ) as sresp:
                check("streaming chat request succeeds 200", sresp.status_code == 200)
                stream_text = "".join(sresp.iter_text())
            check("the streamed response restores the real value (FR-002)",
                  _SEEDED_NAME in stream_text)
            check("the streamed response carries no leftover token",
                  not _PERSON_TOKEN.search(stream_text))
            check("the streaming upstream call recorded ONLY a token, never the raw value (SC-002)",
                  len(provider.requests) == 1
                  and _SEEDED_NAME not in json.dumps(provider.requests[-1]))

            # --- Fail-closed (a): an UNAPPROVED model sends no raw PII and is refused. ---
            provider.requests.clear()
            bad = client.post(
                f"{base}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_credential_strict}"},
                json={"model": "gpt-4o",  # not on the strict tenant's allowlist
                      "messages": [{"role": "user",
                                    "content": f"Contact {_SEEDED_NAME}"}]},
            )
            check("an unapproved model is refused fail-closed (no 2xx)",
                  bad.status_code >= 400)
            check("the unapproved-model refusal sent NOTHING to the provider (no raw PII)",
                  provider.requests == [])
            check("the fail-closed response body carries no raw seeded value",
                  _SEEDED_NAME not in bad.text)

            # --- Fail-closed (b): detection forced UNAVAILABLE sends no raw PII (FR-007). ---
            core_detect._predict_entities = _force_detection_unavailable
            provider.requests.clear()
            degraded = client.post(
                f"{base}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_credential}"},
                json={"model": "gpt-4o",
                      "messages": [{"role": "user",
                                    "content": f"Reach {_SEEDED_NAME} please"}]},
            )
            check("a request with detection unavailable is refused fail-closed (no 2xx)",
                  degraded.status_code >= 400)
            check("detection-unavailable refusal sent NOTHING to the provider (no raw PII; FR-007)",
                  provider.requests == [])
            check("the detection-unavailable response body carries no raw seeded value",
                  _SEEDED_NAME not in degraded.text)
            core_detect._predict_entities = _seeded_predict_entities  # restore for any re-use

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        core_detect._predict_entities = original_predict
        if gateway is not None:
            gateway.stop()
        if provider is not None:
            provider.stop()
        if kms_setup is not None:
            kms_setup.close()
        conn.close()


if __name__ == "__main__":
    main()
