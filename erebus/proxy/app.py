"""App wiring: request handler, /health, create_app, CLI entry point."""
from __future__ import annotations

import argparse
import asyncio
import errno
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from ..audit.logger import init_db, log_event
from ..config import load_repo_config
from ..perf import PerfTimer, log_perf_event
from ..runtime.ports import describe_port_holder
from .chat import tokenize_chat_request
from .http import (
    PROXY_CLIENT_MAX_SIZE,
    _get_target_url,
    _is_chat_endpoint,
    _is_responses_endpoint,
    forwardable_request_headers,
    httpx,
    web,
)
from .regular import _handle_regular
from .responses import tokenize_responses_request
from .stream import _handle_streaming
from .telemetry import SESSION_ID, log_request_tokenize_metrics
from .tokenmap import TOKEN_MAP, get_boundary


def _tokenize_request_body(endpoint: str, parsed_body: dict, repo_config, is_chat: bool):
    """Tokenize one filterable request body in place; log PII findings."""
    if is_chat:
        new_tokens, turn_type, log_subject = tokenize_chat_request(parsed_body, repo_config)
    else:
        parsed_body, new_tokens, turn_type = tokenize_responses_request(parsed_body, repo_config)
        log_subject = parsed_body

    if new_tokens and repo_config.log_enabled:
        log_event(SESSION_ID, event_type="pii_detected",
                  sanitized=json.dumps(log_subject)[:500],
                  tokens_map=new_tokens,
                  metadata={"cwd": os.getcwd(), "source": "proxy",
                            "endpoint": endpoint, "token_count": len(new_tokens)})
    return parsed_body, new_tokens, turn_type


def _tokenize_turn(endpoint: str, method: str, body: bytes, repo_config,
                   boundary) -> tuple[bytes, str, str, bool]:
    """One request's synchronous tokenize pass: (body, turn_type, degraded_reason, is_streaming).

    Runs on the app's single tokenize worker thread, never on the event loop:
    a Codex turn's pass takes seconds (history replay, detector, audit log),
    and on the loop it froze every other in-flight stream until Codex hit its
    SSE idle timeout. One worker keeps turns serialized, so the thread-local
    degraded signal the Boundary turn reads stays that turn's own.
    """
    request_body_bytes = len(body)
    is_chat = _is_chat_endpoint(endpoint)
    turn_type = "chat"
    degraded_reason = ""
    is_streaming = False
    # The turn resets the turn-scoped degraded signal before any tokenization
    # for this request and warns (debounced) on exit if the turn degraded.
    with boundary.turn() as turn_state:
        tok_timer = PerfTimer()
        tokenize_error = ""
        try:
            parsed_body = json.loads(body)
            is_streaming = bool(parsed_body.get("stream", False))
            parsed_body, new_tokens, turn_type = _tokenize_request_body(
                endpoint, parsed_body, repo_config, is_chat)
            body = json.dumps(parsed_body).encode()
        except (json.JSONDecodeError, KeyError):
            new_tokens = {}
            tokenize_error = "json_or_key"

        log_request_tokenize_metrics(
            repo_config, tok_timer.finish(),
            endpoint=endpoint, method=method,
            request_body_bytes=request_body_bytes, response_body_bytes=len(body),
            turn_type=turn_type, api_family="chat" if is_chat else "responses",
            new_tokens=new_tokens, error=tokenize_error)

        if turn_state.degraded:
            degraded_reason = turn_state.degraded_reason

    if degraded_reason:
        log_perf_event("detector_degraded", reason=degraded_reason,
                       endpoint=endpoint, turn_type=turn_type)
    return body, turn_type, degraded_reason, is_streaming


async def handle_proxy(request: web.Request) -> web.StreamResponse:
    """Proxy any request, tokenizing PII in chat completions."""
    target_base = _get_target_url(request)
    target_url = f"{target_base}{request.path}"
    if request.query_string:
        target_url += f"?{request.query_string}"

    repo_config = request.app["repo_config"]
    body = await request.read()
    method = request.method
    headers = forwardable_request_headers(request)

    # Tokenize PII in model requests (off the loop; see _tokenize_turn).
    is_filterable = _is_chat_endpoint(request.path) or _is_responses_endpoint(request.path)
    is_streaming = False
    turn_type = "chat"
    degraded_reason = ""
    if is_filterable and body and method in ("POST", "PUT"):
        boundary = get_boundary(repo_config)
        body, turn_type, degraded_reason, is_streaming = await asyncio.get_running_loop().run_in_executor(
            request.app["tokenize_executor"], _tokenize_turn,
            request.path, method, body, repo_config, boundary)

    # Forward request
    client: httpx.AsyncClient = request.app["http_client"]
    t_turn_start = time.perf_counter()

    if is_streaming and is_filterable:
        return await _handle_streaming(client, method, target_url, headers, body, repo_config, request, t_turn_start, turn_type, degraded_reason)  # noqa: E501
    else:
        return await _handle_regular(client, method, target_url, headers, body, is_filterable, repo_config, t_turn_start, turn_type, degraded_reason)  # noqa: E501


async def health(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({
        "status": "ok",
        "session_id": SESSION_ID,
        "tokens_active": len(TOKEN_MAP),
        "target": request.app["target_url"],
    })


def create_app(target_url: str = "https://api.mistral.ai") -> web.Application:
    """Create the proxy AIOHTTP app."""
    if web is None or httpx is None:
        raise RuntimeError("erebus-proxy requires the 'aiohttp' and 'httpx' packages")
    app = web.Application(client_max_size=PROXY_CLIENT_MAX_SIZE)
    app["target_url"] = target_url
    app["repo_config"] = load_repo_config()
    # One Boundary per process (module-level fallback covers helper/test calls).
    app["boundary"] = get_boundary(app["repo_config"])
    # Exactly one worker: tokenize passes stay serialized (shared caches, the
    # thread-local turn signal) while the loop keeps streaming other responses.
    app["tokenize_executor"] = ThreadPoolExecutor(max_workers=1, thread_name_prefix="erebus-tokenize")

    async def on_startup(app):
        app["http_client"] = httpx.AsyncClient(timeout=120.0, follow_redirects=True)
        init_db()
        # Warm the GLiNER daemon at startup so the first request does not race
        # model loading and fail open (specs/003-proxy-tokenize-latency).
        try:
            from ..filter import preload_gliner
            preload_gliner()
        except Exception:
            pass
        log_event(SESSION_ID, event_type="proxy_start",
                  metadata={"target": target_url, "cwd": os.getcwd()})

    async def on_cleanup(app):
        await app["http_client"].aclose()
        app["tokenize_executor"].shutdown(wait=True)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    app.router.add_get("/health", health)
    app.router.add_route("*", "/{path:.*}", handle_proxy)

    return app


def main():
    parser = argparse.ArgumentParser(description="PII-filtering reverse proxy for AI APIs")
    parser.add_argument("--port", type=int, default=4747, help="Port to listen on (default: 4747)")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--target", default="https://api.mistral.ai",
                        help="Default upstream API URL (default: https://api.mistral.ai)")
    args = parser.parse_args()

    from ..ui.colors import bold, info
    print(bold("\nerebus-proxy\n"))
    print(info(f"Listening on http://{args.host}:{args.port}"))
    print(info(f"Target: {args.target}"))
    print(info("Set X-Target-URL header to override per-request\n"))

    app = create_app(target_url=args.target)
    try:
        web.run_app(app, host=args.host, port=args.port, print=None)
    except OSError as exc:
        if exc.errno != errno.EADDRINUSE:
            raise
        holder = describe_port_holder(args.port)
        print(f"[erebus-proxy] port {args.port} is already in use"
              f"{f' by {holder}' if holder else ''} — exiting so the "
              "service manager can retry once the port is free.",
              file=sys.stderr, flush=True)
        raise SystemExit(1) from exc
