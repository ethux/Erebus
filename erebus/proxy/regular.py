"""Non-streaming proxy responses: forward, log usage, detokenize, reply."""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

from ..audit.logger import log_event
from .http import copy_response_headers, web
from .telemetry import SESSION_ID, _log_ai_written_loc_from_response, _log_usage_from_response
from .tokenmap import _TOKEN_RE, TOKEN_MAP, _detokenize_payload


@dataclass
class _FallbackResponse:
    """Minimal response used by helper tests when aiohttp is not installed."""

    status: int
    body: bytes
    headers: dict = field(default_factory=dict)


def _make_response(status: int, body: bytes):
    if web is not None:
        return web.Response(status=status, body=body)
    return _FallbackResponse(status=status, body=body)


async def _handle_regular(client, method, url, headers, body, is_filterable, repo_config,
                          t_turn_start: float = 0.0, turn_type: str = "chat",
                          degraded_reason: str = ""):
    """Handle non-streaming request."""
    resp = await client.request(method, url, headers=headers, content=body)

    # Detokenize model response bodies.
    resp_body = resp.content
    if is_filterable:
        try:
            data = json.loads(resp_body)
        except (json.JSONDecodeError, ValueError):
            data = None

        # Token usage logging — runs for every chat completion regardless of
        # whether PII was detected. Source of truth for token counts.
        if data is not None and repo_config.log_enabled:
            turn_ms = round((time.perf_counter() - t_turn_start) * 1000, 1) if t_turn_start else None
            _log_usage_from_response(data, turn_latency_ms=turn_ms, turn_type=turn_type)
            _log_ai_written_loc_from_response(data)

        raw: str | None = None
        if data is not None:
            raw = json.dumps(data)
            if not TOKEN_MAP and not _TOKEN_RE.search(raw):
                raw = None

        if data is not None and raw is not None:
            restored_data = _detokenize_payload(data)
            if restored_data != data:
                restored = json.dumps(restored_data)
                resp_body = restored.encode()
                if repo_config.log_enabled:
                    log_event(SESSION_ID, event_type="response",
                              sanitized=raw[:500], raw=restored[:500],
                              metadata={"cwd": os.getcwd(), "source": "proxy"})

    response = _make_response(
        status=resp.status_code,
        body=resp_body,
    )
    copy_response_headers(resp.headers, response, degraded_reason)
    return response
