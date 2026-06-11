"""SSE streaming responses: detokenize across chunks with token hold-back.

Tokens like Jansen arrive split across SSE chunks. Every delta
family (assistant content, tool-call arguments, Responses API deltas) keeps a
per-key buffer and emits only the increment that cannot end in a partial
token. The hold-back rule itself lives in core.streaming.StreamDetokenizer;
this module feeds it through the proxy's TOKEN_MAP-backed resolver.
"""
from __future__ import annotations

import json
import time

from ..core import StreamDetokenizer
from .http import copy_response_headers, web
from .telemetry import _log_usage_from_response
from .tokenmap import (
    _TOKEN_RE,
    TOKEN_MAP,
    _detokenize_payload,
    _detokenize_text,
    _ensure_response_tokens_loaded,
    _sync_mirror,
)


class _TokenMapResolver:
    """Duck-typed Boundary for StreamDetokenizer.

    Streaming detokenization must resolve through the proxy's TOKEN_MAP mirror
    (which also holds chain entries and process-local pairs seeded by tests),
    not the DB view alone; _detokenize_text already layers recovery on top.
    """

    def _detokenize(self, text: str) -> tuple[str, list[str]]:
        return _detokenize_text(text), []

    def from_model(self, text: str) -> tuple[str, list[str]]:
        return _detokenize_text(text), []


_RESOLVER = _TokenMapResolver()


def _safe_detokenized_increment(buffer: str, emitted_len: int) -> tuple[str, int]:
    """Return the next detokenized slice, holding back partial token text."""
    holdback = StreamDetokenizer(_RESOLVER)
    safe_prefix = holdback.feed("buffer", buffer)  # fresh key: emits the full safe prefix
    return safe_prefix[emitted_len:], len(safe_prefix)


def _detokenize_streaming_tool_calls(chunk: dict, buffers: dict,
                                     emitted_lens: dict) -> None:
    """Mutate OpenAI-style streaming tool-call argument deltas in place.

    File-write arguments often arrive split across chunks, so a token such as
    Jansen may be incomplete in any one SSE event. Track one buffer
    per streamed tool call and emit only the newly safe detokenized suffix.
    """
    choices = chunk.get("choices")
    if not isinstance(choices, list):
        return

    for choice_pos, choice in enumerate(choices):
        delta = choice.get("delta") if isinstance(choice, dict) else None
        if not isinstance(delta, dict):
            continue
        tool_calls = delta.get("tool_calls")
        if not isinstance(tool_calls, list):
            continue

        for list_pos, tool_call in enumerate(tool_calls):
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if not isinstance(function, dict):
                continue
            arguments = function.get("arguments")
            if not isinstance(arguments, str) or not arguments:
                continue

            tool_index = tool_call.get("index", list_pos)
            key = (choice_pos, tool_index)
            buffers[key] = buffers.get(key, "") + arguments
            next_text, next_len = _safe_detokenized_increment(
                buffers[key],
                emitted_lens.get(key, 0),
            )
            emitted_lens[key] = next_len
            function["arguments"] = next_text


def _responses_delta_key(chunk: dict) -> tuple | None:
    event_type = chunk.get("type")
    delta = chunk.get("delta")
    if not isinstance(event_type, str) or not event_type.startswith("response."):
        return None
    if not event_type.endswith(".delta") or not isinstance(delta, str):
        return None
    return (
        event_type,
        chunk.get("item_id"),
        chunk.get("output_index"),
        chunk.get("content_index"),
    )


def _detokenize_responses_streaming_chunk(chunk: dict, buffers: dict,
                                          emitted_lens: dict) -> bool:
    """Mutate OpenAI Responses API SSE deltas in place.

    Responses streams send text and function-call arguments as `delta` fields.
    Tokens can be split across events, so track a buffer per streamed item and
    replace each delta with only the next safe detokenized slice.
    """
    key = _responses_delta_key(chunk)
    if key is None:
        return False

    buffers[key] = buffers.get(key, "") + chunk["delta"]
    next_text, next_len = _safe_detokenized_increment(
        buffers[key],
        emitted_lens.get(key, 0),
    )
    emitted_lens[key] = next_len
    chunk["delta"] = next_text
    return True


async def _handle_streaming(client, method, url, headers, body, repo_config,  # noqa: C901
                            request: web.Request | None = None, t_turn_start: float = 0.0,
                            turn_type: str = "chat", degraded_reason: str = ""):
    """Handle SSE streaming response — buffer content to detokenize across chunks.

    Tokens like Jansen arrive split across many SSE chunks.
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
    tool_call_buffers = {}
    tool_call_emitted_lens = {}
    responses_delta_buffers = {}
    responses_delta_emitted_lens = {}
    body_text = (
        body.decode("utf-8", errors="ignore")
        if isinstance(body, (bytes, bytearray))
        else str(body or "")
    )
    if TOKEN_MAP or _TOKEN_RE.search(body_text):
        _sync_mirror()
    has_tokens = bool(TOKEN_MAP)
    # Streaming usage: Anthropic and OpenAI both emit cumulative usage in
    # the final chunk(s). We capture the latest non-empty one and log once
    # on stream close.
    final_usage_data: dict = {}

    async with client.stream(method, url, headers=headers, content=body) as resp:
        response.set_status(resp.status_code)
        copy_response_headers(resp.headers, response, degraded_reason)

        assert request is not None
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
                if final_usage_data and repo_config.log_enabled:
                    turn_ms = round((time.perf_counter() - t_turn_start) * 1000, 1) if t_turn_start else None
                    _log_usage_from_response(final_usage_data, turn_latency_ms=turn_ms, turn_type=turn_type)
                    final_usage_data = {}  # prevent double-log via fallback
                await response.write(f"{line}\n".encode())
                continue

            try:
                chunk = json.loads(json_part)
            except json.JSONDecodeError:
                await response.write(f"{line}\n".encode())
                continue

            # Track cumulative usage from each chunk — the last non-empty
            # wins (Anthropic's message_delta carries final totals; OpenAI
            # emits a final chunk with usage when stream_options requests it).
            chunk_usage = chunk.get("usage") if isinstance(chunk, dict) else None
            if isinstance(chunk_usage, dict) and any(v for v in chunk_usage.values() if isinstance(v, int)):
                final_usage_data = {"usage": chunk_usage, "model": chunk.get("model")}

            if not has_tokens:
                has_tokens = _ensure_response_tokens_loaded(json_part)

            if not has_tokens:
                await response.write(f"data: {json.dumps(chunk)}\n".encode())
                continue

            _detokenize_streaming_tool_calls(
                chunk,
                tool_call_buffers,
                tool_call_emitted_lens,
            )

            if _detokenize_responses_streaming_chunk(
                chunk,
                responses_delta_buffers,
                responses_delta_emitted_lens,
            ):
                await response.write(f"data: {json.dumps(chunk)}\n".encode())
                continue

            # Extract the content delta (where tokens appear)
            delta_content = None
            try:
                delta_content = chunk["choices"][0]["delta"].get("content")
            except (KeyError, IndexError, TypeError):
                pass

            if delta_content is None:
                # Non-content chunk (role, tool_calls, completed Responses events, etc.)
                chunk = _detokenize_payload(chunk)
                await response.write(f"data: {json.dumps(chunk)}\n".encode())
                continue

            # Mistral may send content as a list of blocks instead of a
            # plain string.  Flatten to string for the buffering logic.
            if isinstance(delta_content, list):
                parts = []
                for part in delta_content:
                    if isinstance(part, dict):
                        parts.append(part.get("text", ""))
                    elif isinstance(part, str):
                        parts.append(part)
                delta_content = "".join(parts)
                chunk["choices"][0]["delta"]["content"] = delta_content

            # Accumulate raw content
            content_buffer += delta_content

            # Only emit text we're confident is complete (not mid-token).
            to_emit, safe_end = _safe_detokenized_increment(
                content_buffer,
                emitted_len,
            )
            if to_emit:
                chunk["choices"][0]["delta"]["content"] = to_emit
                await response.write(f"data: {json.dumps(chunk)}\n".encode())
                emitted_len = safe_end
            # else: buffering — don't emit this chunk yet  # noqa: ERA001

    # Fallback flush for streams that end without an explicit [DONE] marker.
    if final_usage_data and repo_config.log_enabled:
        turn_ms = round((time.perf_counter() - t_turn_start) * 1000, 1) if t_turn_start else None
        _log_usage_from_response(final_usage_data, turn_latency_ms=turn_ms, turn_type=turn_type)

    return response
