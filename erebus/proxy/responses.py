"""OpenAI Responses API request walk: payload text -> Boundary.to_model_many."""
from __future__ import annotations

import json

from ..core import message_cache_key, save_message_cache, store_message_cache_entry
from .chat import _tokenize_payload_text
from .tokenmap import _persist_mirror, _record_new_tokens, apply_message_cache_entry


def _tokenize_responses_payload(value, repo_config, parent_key: str | None = None) -> tuple[object, dict]:
    """Tokenize model-visible text in an OpenAI Responses API payload."""
    return _tokenize_payload_text(value, repo_config, parent_key)


def _tokenize_responses_input(inp: list, repo_config) -> dict:
    """Cache input items the same way _tokenize_messages caches messages."""
    new_tokens: dict = {}
    for idx, item in enumerate(inp):
        if not isinstance(item, dict):
            continue
        cache_key = message_cache_key("responses-input", item, repo_config)
        if apply_message_cache_entry(cache_key, item, new_tokens, "responses_input"):
            continue
        original = json.loads(json.dumps(item))
        item, item_tokens = _tokenize_responses_payload(item, repo_config)
        inp[idx] = item
        store_message_cache_entry(cache_key, original, item, item_tokens)
        _record_new_tokens(item_tokens, new_tokens)
    save_message_cache()
    return new_tokens


def _tokenize_responses_non_input(parsed_body: dict, repo_config, new_tokens: dict) -> None:
    """Tokenize non-input fields (instructions, etc.) with content-hash caching.

    The Codex instructions block (system prompt + tool schemas) is large and
    stable across a session, so cache it by content hash instead of
    re-detecting it every turn (specs/003-proxy-tokenize-latency).
    """
    non_input_item = {k: v for k, v in parsed_body.items() if k != "input"}
    non_input_key = message_cache_key("responses-non-input", non_input_item, repo_config)
    if apply_message_cache_entry(non_input_key, non_input_item, new_tokens, "responses_non_input"):
        for k, v in non_input_item.items():
            parsed_body[k] = v
        return
    non_input_original = json.loads(json.dumps(non_input_item))
    non_input_result, extra_tokens = _tokenize_responses_payload(non_input_item, repo_config)
    non_input_body: dict = non_input_result  # type: ignore[assignment]
    store_message_cache_entry(
        non_input_key, non_input_original, non_input_body, extra_tokens, save=True)
    for k, v in non_input_body.items():
        parsed_body[k] = v
    _record_new_tokens(extra_tokens, new_tokens)


def tokenize_responses_request(parsed_body: dict, repo_config) -> tuple[dict, dict, str]:
    """Tokenize a Responses API request body. Returns (body, new_tokens, turn_type)."""
    turn_type = "chat"
    inp = parsed_body.get("input", [])
    if isinstance(inp, list) and inp:
        last = inp[-1] if inp else {}
        if isinstance(last, dict) and last.get("type") == "function_call_output":
            turn_type = "tool"
        new_tokens = _tokenize_responses_input(inp, repo_config)
        parsed_body["input"] = inp
    else:
        parsed_body_result, new_tokens = _tokenize_responses_payload(parsed_body, repo_config)
        assert isinstance(parsed_body_result, dict)
        parsed_body = parsed_body_result
    _tokenize_responses_non_input(parsed_body, repo_config, new_tokens)
    if new_tokens:
        _persist_mirror()
    return parsed_body, new_tokens, turn_type
