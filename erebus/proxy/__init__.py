"""HTTP reverse proxy for OpenAI/Anthropic-compatible API endpoints.

Acts as a transparent man-in-the-middle: intercepts all requests,
tokenizes PII in message content (through the core Boundary facade),
forwards to the real API, detokenizes the response, and returns it
to the editor. Supports streaming (SSE) and non-streaming responses.

Usage:
    erebus-proxy                          # default: localhost:4747
    erebus-proxy --port 4747 --target https://api.mistral.ai

Package layout (specs/004-core-pii-boundary T047):
    app.py        handle_proxy, /health, create_app, main
    http.py       guarded aiohttp/httpx imports, endpoint + header helpers
    chat.py       chat-completions walk -> Boundary.to_model
    responses.py  Responses API walk -> Boundary.to_model_many
    regular.py    non-streaming responses (incl. X-Erebus-Degraded)
    stream.py     SSE detokenization via core.streaming.StreamDetokenizer
    telemetry.py  usage / AI-LOC / tokenize-latency logging
    tokenmap.py   Boundary wiring + TOKEN_MAP compat mirror

This module re-exports the public entry points plus the compat names tests
and external callers still use; mutable message-cache state and detector
patch targets are forwarded live (see _CompatProxyModule below).
"""
from __future__ import annotations

import sys
import types

from ..core import (  # moved in specs/004 T028; re-exported (via erebus.core) for compat
    _set_path_value,
    apply_text_span_patches,
    collect_text_patches,
    collect_token_span_patch,
    drop_message_cache_file,
    get_path_value,
    load_message_cache,
    message_cache_file_is_too_large,
    message_cache_key,
    normalize_message_cache_entry,
    normalize_message_cache_patch,
    repo_config_cache_signature,
    save_message_cache,
    stable_json_hash,
    stable_json_size,
    store_message_cache_entry,
    token_keys_from_patches,
)
from ..core import cache as _detector_cache  # patch-forwarding seam only; see _CompatProxyModule
from ..core import message_cache as _message_cache
from ..filter import cached_tokenize, cached_tokenize_many
from .app import create_app, handle_proxy, health, main
from .chat import _tokenize_messages, _tokenize_proxy_text, _tokenize_proxy_texts, tokenize_chat_request
from .http import PROXY_CLIENT_MAX_SIZE, _get_target_url, _is_chat_endpoint, _is_responses_endpoint, httpx, web
from .regular import _handle_regular
from .responses import _tokenize_responses_payload, tokenize_responses_request
from .stream import (
    _detokenize_responses_streaming_chunk,
    _detokenize_streaming_tool_calls,
    _handle_streaming,
    _responses_delta_key,
    _safe_detokenized_increment,
)
from .telemetry import SESSION_ID, _log_ai_written_loc_from_response, _log_usage_from_response
from .tokenmap import (
    _TOKEN_RE,
    TOKEN_MAP,
    _detokenize_payload,
    _detokenize_text,
    _ensure_response_tokens_loaded,
    _persist_mirror,
    _resolve_missing_tokens,
    _sync_mirror,
    apply_message_cache_entry,
    get_boundary,
    record_cached_token_keys,
    reload_token_map,
)

__all__ = [
    "PROXY_CLIENT_MAX_SIZE",
    "SESSION_ID",
    "TOKEN_MAP",
    "_TOKEN_RE",
    "_detokenize_payload",
    "_detokenize_responses_streaming_chunk",
    "_detokenize_streaming_tool_calls",
    "_detokenize_text",
    "_ensure_response_tokens_loaded",
    "_get_target_url",
    "_handle_regular",
    "_handle_streaming",
    "_is_chat_endpoint",
    "_is_responses_endpoint",
    "_log_ai_written_loc_from_response",
    "_log_usage_from_response",
    "_persist_mirror",
    "_resolve_missing_tokens",
    "_responses_delta_key",
    "_safe_detokenized_increment",
    "_set_path_value",
    "_sync_mirror",
    "_tokenize_messages",
    "_tokenize_proxy_text",
    "_tokenize_proxy_texts",
    "_tokenize_responses_payload",
    "apply_message_cache_entry",
    "apply_text_span_patches",
    "cached_tokenize",
    "cached_tokenize_many",
    "collect_text_patches",
    "collect_token_span_patch",
    "create_app",
    "drop_message_cache_file",
    "get_boundary",
    "get_path_value",
    "handle_proxy",
    "health",
    "httpx",
    "load_message_cache",
    "main",
    "message_cache_file_is_too_large",
    "message_cache_key",
    "normalize_message_cache_entry",
    "normalize_message_cache_patch",
    "record_cached_token_keys",
    "reload_token_map",
    "repo_config_cache_signature",
    "save_message_cache",
    "stable_json_hash",
    "stable_json_size",
    "store_message_cache_entry",
    "token_keys_from_patches",
    "tokenize_chat_request",
    "tokenize_responses_request",
    "web",
]

# The message cache lives in erebus/core/message_cache.py (specs/004 T028).
# Its mutable state (_MSG_CACHE, _MSG_CACHE_PATH, flags) is owned there; the
# module-class swap below forwards reads AND writes of the _MSG_CACHE* names
# so existing callers/tests targeting erebus.proxy keep working this phase.
_MSG_CACHE_STATE_ATTRS = frozenset({
    "_MSG_CACHE", "_MSG_CACHE_PATH", "_MSG_CACHE_LOADED", "_MSG_CACHE_DIRTY",
    "_MSG_CACHE_DIRTY_KEYS", "_MSG_CACHE_VERSION", "_MSG_CACHE_MAX",
    "_MSG_CACHE_MAX_BYTES", "_MSG_CACHE_MAX_PATCH_CHARS", "_MSG_CACHE_MAX_PATCHES",
    "_MSG_CACHE_MAX_SPANS",
})

# Tests patch erebus.proxy.cached_tokenize(_many); the Boundary resolves the
# detector through erebus.core.cache at call time, so patches (and their
# restores) are mirrored into the owning module to stay effective.
_DETECTOR_PATCH_ATTRS = frozenset({"cached_tokenize", "cached_tokenize_many"})


class _CompatProxyModule(types.ModuleType):
    """Forward _MSG_CACHE* state and detector patches to their core owners."""

    def __getattr__(self, name: str):
        if name in _MSG_CACHE_STATE_ATTRS:
            return getattr(_message_cache, name)
        raise AttributeError(f"module {self.__name__!r} has no attribute {name!r}")

    def __setattr__(self, name: str, value) -> None:
        if name in _MSG_CACHE_STATE_ATTRS:
            setattr(_message_cache, name, value)
            return
        if name in _DETECTOR_PATCH_ATTRS:
            setattr(_detector_cache, name, value)
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _CompatProxyModule

# Load persisted tokens now (and on importlib.reload), matching the old
# module-level `TOKEN_MAP = _load_initial_token_map()` semantics.
reload_token_map()
