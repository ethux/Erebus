"""HTTP provider transport unit tests (T020; 008 R5).

Pure transport, no network and no database: an ``httpx.MockTransport`` stands in
for the upstream so we can assert the request shape (method, url, headers, json
body) and the decoded JSON return without leaving the process. Also asserts that a
non-2xx upstream surfaces as an error (fail-closed) rather than a fake completion,
and that the streaming variant yields the SSE ``data:`` payloads.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import anyio
import httpx

from erebus.gateway.config import GatewayConfig
from erebus.gateway.http_provider import build_client, build_http_post, close_client

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _config() -> GatewayConfig:
    # 32-byte (AES-256) base64 master key; no DB / network is touched by these tests.
    key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    return GatewayConfig.from_env({
        "EREBUS_PG_DSN": "postgresql:///unused",
        "EREBUS_GATEWAY_MASTER_KEY": key,
        "EREBUS_GATEWAY_PROVIDER": "openai",
        "EREBUS_GATEWAY_HTTP_TIMEOUT": "7",
    })


def _mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def main():
    print("\n=== HTTP provider transport (T020) ===\n")
    config = _config()

    # --- http_post issues the expected POST and returns the decoded JSON. ---
    seen = {}

    def ok_handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["ctype"] = request.headers.get("content-type")
        seen["body"] = request.content
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    async def run_post():
        http_post, _stream, client = build_http_post(config, client=_mock_client(ok_handler))
        try:
            return await http_post(
                "https://api.example/v1/chat/completions",
                {"Authorization": "Bearer CENTRAL-SECRET"},
                {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
            )
        finally:
            await close_client(client)

    result = anyio.run(run_post)
    check("http_post issues a POST", seen.get("method") == "POST")
    check("http_post hits the given url", seen.get("url") == "https://api.example/v1/chat/completions")
    check("http_post forwards the given headers", seen.get("auth") == "Bearer CENTRAL-SECRET")
    check("http_post sends the payload as JSON", seen.get("ctype", "").startswith("application/json"))
    check("http_post body carries the model", b'"gpt-4o"' in (seen.get("body") or b""))
    check("http_post returns the decoded JSON",
          result == {"choices": [{"message": {"content": "ok"}}]})

    # --- A non-2xx upstream surfaces as an error (fail-closed), not a completion. ---
    def err_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "upstream boom"})

    async def run_err():
        http_post, _stream, client = build_http_post(config, client=_mock_client(err_handler))
        try:
            raised = False
            try:
                await http_post("https://api.example/x", {}, {"model": "m"})
            except httpx.HTTPStatusError:
                raised = True
            return raised
        finally:
            await close_client(client)

    check("non-2xx upstream raises an error", anyio.run(run_err))

    # --- http_stream yields the upstream SSE data payloads (skipping [DONE]). ---
    sse = (
        "data: alpha\n\n"
        "data: beta\n\n"
        "data: [DONE]\n\n"
    )

    def stream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})

    async def run_stream():
        _post, http_stream, client = build_http_post(config, client=_mock_client(stream_handler))
        try:
            return [frag async for frag in http_stream("https://api.example/s", {}, {})]
        finally:
            await close_client(client)

    frags = anyio.run(run_stream)
    check("http_stream yields each data payload and skips [DONE]", frags == ["alpha", "beta"])

    # --- build_client honours the configured timeout (no network needed). ---
    real = build_client(config)
    check("build_client uses the configured http_timeout_s", real.timeout.read == 7.0)
    anyio.run(close_client, real)

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
