"""Chat-completions request walk: message content -> Boundary.to_model."""
from __future__ import annotations

import json

from ..core import _set_path_value, message_cache_key, save_message_cache, store_message_cache_entry
from .payload import collect_text_paths
from .tokenmap import _persist_mirror, _record_new_tokens, apply_message_cache_entry, get_boundary


def _tokenize_proxy_text(text: str, repo_config) -> tuple[str, dict]:
    """Tokenize one model-visible string through the Boundary facade."""
    return get_boundary(repo_config).to_model(text)


def _tokenize_proxy_texts(texts: list[str], repo_config) -> list[tuple[str, dict]]:
    """Tokenize several model-visible strings, batching uncached misses."""
    return get_boundary(repo_config).to_model_many(texts)


def _tokenize_payload_text(value, repo_config, parent_key: str | None = None) -> tuple[object, dict]:
    """Tokenize every model-bound text field in a nested payload region.

    Shared by both adapters (chat ``system``/``tools``, Responses payloads):
    collect text paths, batch-tokenize, write the sanitized text back.
    ``parent_key`` lets a caller tokenize a BARE string whose containing key
    is known (e.g. a top-level Responses ``input`` string)."""
    targets = collect_text_paths(value, parent_key)
    if not targets:
        return value, {}
    new_tokens: dict = {}
    tokenized = _tokenize_proxy_texts([text for _path, text in targets], repo_config)
    for (path, _text), (sanitized, tokens) in zip(targets, tokenized):  # noqa: B905
        value = _set_path_value(value, path, sanitized)
        _record_new_tokens(tokens, new_tokens)
    return value, new_tokens


def _tokenize_messages(messages: list, repo_config) -> dict:
    """Tokenize PII in chat completion message content. Returns new tokens found."""
    new_tokens = {}
    for i, msg in enumerate(messages):  # noqa: B007
        if not isinstance(msg, dict):
            continue
        cache_key = message_cache_key("chat", msg, repo_config)
        if apply_message_cache_entry(cache_key, msg, new_tokens, "chat"):
            continue

        original = json.loads(json.dumps(msg))
        content = msg.get("content")
        msg_tokens = {}
        # Always apply the sanitized text: a Boundary result-cache hit or
        # known-value retokenization can rewrite text without minting tokens.
        if isinstance(content, str) and content:
            sanitized, tokens = _tokenize_proxy_text(content, repo_config)
            msg["content"] = sanitized
            _record_new_tokens(tokens, msg_tokens)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and part.get("text"):
                    sanitized, tokens = _tokenize_proxy_text(part["text"], repo_config)
                    part["text"] = sanitized
                    _record_new_tokens(tokens, msg_tokens)
        # Prior-turn assistant tool calls carry function.arguments (a JSON
        # string). Normally model-generated and already token-only, but a
        # client/IDE can replay raw values there — tokenize for parity with
        # the Responses adapter's `arguments` handling.
        tool_calls = msg.get("tool_calls")
        if isinstance(tool_calls, list):
            _, tc_tokens = _tokenize_payload_text(tool_calls, repo_config)
            _record_new_tokens(tc_tokens, msg_tokens)
        store_message_cache_entry(cache_key, original, msg, msg_tokens)
        _record_new_tokens(msg_tokens, new_tokens)
    save_message_cache()
    if new_tokens:
        _persist_mirror()
    return new_tokens


def _tokenize_chat_non_message_fields(parsed_body: dict, repo_config) -> dict:
    """Tokenize model-bound text OUTSIDE `messages`.

    Anthropic /messages carries the system prompt as a top-level `system`
    (string or list of {type:'text', text:...} blocks), and both OpenAI and
    Anthropic carry `tools` definitions whose `description` text the model
    reads. Neither lives inside `messages`, so without this they reached the
    model raw (the Responses adapter already tokenizes its `instructions` and
    `tools` via the non-input walk; this restores parity)."""
    new_tokens: dict = {}
    system = parsed_body.get("system")
    if isinstance(system, str) and system:
        sanitized, tokens = _tokenize_proxy_text(system, repo_config)
        parsed_body["system"] = sanitized
        _record_new_tokens(tokens, new_tokens)
    elif isinstance(system, list):
        parsed_body["system"], tokens = _tokenize_payload_text(system, repo_config)
        _record_new_tokens(tokens, new_tokens)
    tools = parsed_body.get("tools")
    if isinstance(tools, list) and tools:
        parsed_body["tools"], tokens = _tokenize_payload_text(tools, repo_config)
        _record_new_tokens(tokens, new_tokens)
    return new_tokens


def tokenize_chat_request(parsed_body: dict, repo_config) -> tuple[dict, str, list]:
    """Tokenize a chat-completions request body in place.

    Returns (new_tokens, turn_type, log_subject).
    """
    messages = parsed_body.get("messages", [])
    turn_type = "chat"
    # Detect turn type: tool turn if last message has tool role
    if messages and isinstance(messages[-1], dict):
        last_role = messages[-1].get("role", "")
        if last_role == "tool" or messages[-1].get("tool_call_id"):
            turn_type = "tool"
    new_tokens = _tokenize_messages(messages, repo_config)
    new_tokens.update(_tokenize_chat_non_message_fields(parsed_body, repo_config))
    return new_tokens, turn_type, messages
