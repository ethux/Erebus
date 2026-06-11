"""Usage, AI-written-LOC, and tokenize-latency logging for the proxy."""
from __future__ import annotations

import os
import uuid

from ..audit.loc import AI_LOC_EVENT, ai_write_events_from_payload
from ..audit.logger import log_event
from ..perf import log_perf_event

SESSION_ID = str(uuid.uuid4())[:8]


def _log_usage_from_response(data: dict, turn_latency_ms: float | None = None, turn_type: str | None = None):
    """Extract and log token usage from a non-streaming API response body.

    Normalizes Anthropic (input_tokens/output_tokens/cache_*) and OpenAI
    (prompt_tokens/completion_tokens) shapes into the same four-field log.
    Only invoked for final, complete responses — no delta double-counting.
    """
    if not isinstance(data, dict):
        return
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return

    counts = {
        "input_tokens": int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0),
        "output_tokens": int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0),
        "cache_creation_input_tokens": int(usage.get("cache_creation_input_tokens", 0) or 0),
        "cache_read_input_tokens": int(usage.get("cache_read_input_tokens", 0) or 0),
    }
    if not any(counts.values()):
        return

    metadata = {"cwd": os.getcwd(), "source": "proxy", **counts}
    if data.get("model"):
        metadata["model"] = data["model"]
    if turn_latency_ms is not None:
        metadata["turn_latency_ms"] = turn_latency_ms
    if turn_type:
        metadata["turn_type"] = turn_type
    cc = usage.get("cache_creation")
    if isinstance(cc, dict):
        metadata["cache_creation"] = cc

    log_event(SESSION_ID, event_type="token_usage", metadata=metadata)


def _log_ai_written_loc_from_response(data: dict) -> None:
    for metadata in ai_write_events_from_payload(data, source="proxy"):
        log_event(
            SESSION_ID,
            event_type=AI_LOC_EVENT,
            metadata={"cwd": os.getcwd(), **metadata},
        )


def log_request_tokenize_metrics(repo_config, perf_metrics: dict, *, endpoint: str, method: str,
                                 request_body_bytes: int, response_body_bytes: int,
                                 turn_type: str, api_family: str, new_tokens: dict,
                                 error: str) -> None:
    """Per-request tokenize latency: audit-log event + privacy-safe perf event."""
    latency_ms = round(perf_metrics["wall_ms"], 1)
    if repo_config.log_enabled:
        log_event(SESSION_ID, event_type="tokenize_latency",
                  metadata={"cwd": os.getcwd(), "source": "proxy",
                            "latency_ms": latency_ms,
                            "turn_type": turn_type,
                            "pii_found": bool(new_tokens),
                            "token_count": len(new_tokens),
                            "endpoint": endpoint})
    log_perf_event(
        "proxy_tokenize_request",
        **perf_metrics,
        endpoint=endpoint,
        method=method,
        request_body_bytes=request_body_bytes,
        response_body_bytes=response_body_bytes,
        turn_type=turn_type,
        api_family=api_family,
        pii_found=bool(new_tokens),
        token_count=len(new_tokens),
        error=error,
    )
