"""
HTTP reverse proxy for OpenAI/Anthropic-compatible API endpoints.

Acts as a transparent man-in-the-middle: intercepts all requests,
tokenizes PII in message content, forwards to the real API,
detokenizes the response, and returns it to the editor.

Supports streaming (SSE) and non-streaming responses.

Usage:
    erebus-proxy                          # default: localhost:4747
    erebus-proxy --port 4747 --target https://api.mistral.ai
"""

import asyncio
import json
import os
import sys
import uuid
import argparse
from pathlib import Path

import httpx
from aiohttp import web

from .filter import tokenize, detokenize, preload_gliner
from .logger import init_db, log_event
from .config import load_repo_config, OLLAMA_MODEL

SESSION_ID = str(uuid.uuid4())[:8]
TOKEN_MAP: dict = {}
_TOKEN_MAP_PATH = Path.home() / ".erebus" / "token_map.json"


def _persist_token_map():
    """Write token map to shared file so MCP server and CLI can read it."""
    _TOKEN_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    _TOKEN_MAP_PATH.write_text(json.dumps(TOKEN_MAP, indent=2))


def _get_target_url(request: web.Request) -> str:
    """Determine the real upstream URL from the request headers or config."""
    # X-Target-URL header allows per-request override
    target = request.headers.get("X-Target-URL")
    if target:
        return target.rstrip("/")
    # Fall back to app-level default
    return request.app["target_url"]


def _tokenize_messages(messages: list, repo_config) -> dict:
    """Tokenize PII in chat completion message content. Returns new tokens found."""
    mode = getattr(repo_config, "mode", "balanced")
    new_tokens = {}
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str) and content:
            sanitized, tokens = tokenize(content, repo_config.sensitive_entities, repo_config.allowed_names, mode=mode)
            if tokens:
                msg["content"] = sanitized
                TOKEN_MAP.update(tokens)
                new_tokens.update(tokens)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and part.get("text"):
                    sanitized, tokens = tokenize(part["text"], repo_config.sensitive_entities, repo_config.allowed_names, mode=mode)
                    if tokens:
                        part["text"] = sanitized
                        TOKEN_MAP.update(tokens)
                        new_tokens.update(tokens)
    if new_tokens:
        _persist_token_map()
    return new_tokens


def _detokenize_text(text: str) -> str:
    """Replace tokens with real values in response text."""
    if not TOKEN_MAP:
        return text
    return detokenize(text, TOKEN_MAP)


async def handle_proxy(request: web.Request) -> web.StreamResponse:
    """Proxy any request, tokenizing PII in chat completions."""
    target_base = _get_target_url(request)
    target_url = f"{target_base}{request.path}"
    if request.query_string:
        target_url += f"?{request.query_string}"

    repo_config = request.app["repo_config"]
    body = await request.read()
    method = request.method

    # Copy headers, skip hop-by-hop
    skip_headers = {"host", "content-length", "transfer-encoding", "connection"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in skip_headers}

    # Tokenize PII in chat completion requests
    is_chat = "/chat/completions" in request.path or "/messages" in request.path
    is_streaming = False
    parsed_body = None

    if is_chat and body and method in ("POST", "PUT"):
        try:
            parsed_body = json.loads(body)
            is_streaming = parsed_body.get("stream", False)
            messages = parsed_body.get("messages", [])
            new_tokens = _tokenize_messages(messages, repo_config)

            if new_tokens and repo_config.log_enabled:
                log_event(SESSION_ID, event_type="pii_detected",
                          sanitized=json.dumps(messages)[:500],
                          tokens_map=new_tokens,
                          metadata={"cwd": os.getcwd(), "source": "proxy",
                                    "endpoint": request.path, "token_count": len(new_tokens)})

            body = json.dumps(parsed_body).encode()
        except (json.JSONDecodeError, KeyError):
            pass

    # Forward request
    client: httpx.AsyncClient = request.app["http_client"]

    if is_streaming and is_chat:
        return await _handle_streaming(client, method, target_url, headers, body, repo_config, request)
    else:
        return await _handle_regular(client, method, target_url, headers, body, is_chat, repo_config)


async def _handle_regular(client, method, url, headers, body, is_chat, repo_config):
    """Handle non-streaming request."""
    resp = await client.request(method, url, headers=headers, content=body)

    # Detokenize response body if it's a chat completion
    resp_body = resp.content
    if is_chat and TOKEN_MAP:
        try:
            data = json.loads(resp_body)
            raw = json.dumps(data)
            restored = _detokenize_text(raw)
            if raw != restored:
                data = json.loads(restored)
                resp_body = json.dumps(data).encode()
                if repo_config.log_enabled:
                    log_event(SESSION_ID, event_type="response",
                              sanitized=raw[:500], raw=restored[:500],
                              metadata={"cwd": os.getcwd(), "source": "proxy"})
        except (json.JSONDecodeError, KeyError):
            pass

    response = web.Response(
        status=resp.status_code,
        body=resp_body,
    )
    # Copy response headers
    for k, v in resp.headers.items():
        if k.lower() not in ("content-length", "transfer-encoding", "connection", "content-encoding"):
            response.headers[k] = v
    return response


async def _handle_streaming(client, method, url, headers, body, repo_config,
                            request: web.Request = None):
    """Handle SSE streaming response — buffer content to detokenize across chunks.

    Tokens like [PERSON_1_abc123] arrive split across many SSE chunks.
    We accumulate the assistant's content text, detokenize the buffer,
    and emit the difference so the client sees real values, not tokens.
    """
    response = web.StreamResponse(
        status=200,
        headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"},
    )

    # Buffer: accumulate raw content text from all chunks
    content_buffer = ""     # raw tokenized text accumulated so far
    emitted_len = 0         # how many chars of detokenized output we've already sent
    has_tokens = bool(TOKEN_MAP)

    async with client.stream(method, url, headers=headers, content=body) as resp:
        response.set_status(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() not in ("content-length", "transfer-encoding", "connection", "content-encoding"):
                response.headers[k] = v

        await response.prepare(request)

        async for line in resp.aiter_lines():
            if not line:
                await response.write(b"\n")
                continue

            if not line.startswith("data: "):
                await response.write(f"{line}\n".encode())
                continue

            json_part = line[6:]
            if json_part.strip() == "[DONE]":
                # Flush any remaining buffered content
                if has_tokens and content_buffer:
                    detok = _detokenize_text(content_buffer)
                    remaining = detok[emitted_len:]
                    if remaining:
                        done_chunk = {"choices": [{"delta": {"content": remaining}}]}
                        await response.write(f"data: {json.dumps(done_chunk)}\n".encode())
                await response.write(f"{line}\n".encode())
                continue

            try:
                chunk = json.loads(json_part)
            except json.JSONDecodeError:
                await response.write(f"{line}\n".encode())
                continue

            if not has_tokens:
                await response.write(f"data: {json.dumps(chunk)}\n".encode())
                continue

            # Extract the content delta (where tokens appear)
            delta_content = None
            try:
                delta_content = chunk["choices"][0]["delta"].get("content")
            except (KeyError, IndexError, TypeError):
                pass

            if delta_content is None:
                # Non-content chunk (role, tool_calls, etc.) — pass through
                await response.write(f"data: {json.dumps(chunk)}\n".encode())
                continue

            # Accumulate raw content
            content_buffer += delta_content

            # Detokenize the full buffer
            detok = _detokenize_text(content_buffer)

            # Only emit text we're confident is complete (not mid-token).
            # If buffer ends with '[' or contains an unclosed '[', hold back.
            safe_end = len(detok)
            bracket_pos = detok.rfind("[", emitted_len)
            if bracket_pos >= 0 and "]" not in detok[bracket_pos:]:
                # Potential partial token — hold back from the bracket
                safe_end = bracket_pos

            to_emit = detok[emitted_len:safe_end]
            if to_emit:
                chunk["choices"][0]["delta"]["content"] = to_emit
                await response.write(f"data: {json.dumps(chunk)}\n".encode())
                emitted_len = safe_end
            # else: buffering — don't emit this chunk yet

    return response


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
    app = web.Application()
    app["target_url"] = target_url
    app["repo_config"] = load_repo_config()

    async def on_startup(app):
        app["http_client"] = httpx.AsyncClient(timeout=120.0, follow_redirects=True)
        init_db()
        preload_gliner()
        log_event(SESSION_ID, event_type="proxy_start",
                  metadata={"target": target_url, "cwd": os.getcwd()})

    async def on_cleanup(app):
        await app["http_client"].aclose()

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

    from .ui.colors import ok, info, bold
    print(bold("\nerebus-proxy\n"))
    print(info(f"Listening on http://{args.host}:{args.port}"))
    print(info(f"Target: {args.target}"))
    print(info("Set X-Target-URL header to override per-request\n"))

    app = create_app(target_url=args.target)
    web.run_app(app, host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
