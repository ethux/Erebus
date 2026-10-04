"""Modality + tokenization gate for the chat path (FR-004; extracted from app.py).

Pure request-shaping helpers: every cloud-bound message part (string content, a
structured content array, tool-call arguments, or a reasoning model's reasoning sent back
in history) is routed through the gate so text is tokenized and any non-text modality is
blocked by default, and upstream responses are restored. Lives in its own module so the
FastAPI app module stays within the line budget.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from .crypto.keyprovider import KeyProvider
from .modalities import Decision, classify_part
from .store.known_value_store import open_store
from .tokenizer import Detector, Matcher, Tokenizer
from .toolargs import map_json_strings, restore_arguments, restore_tree

# Part types whose natural-language text is tokenized in place.
_TEXT_PART_TYPES = frozenset({"text", "input_text", "output_text"})
# Structured tool-call / function parts: every string leaf is tokenized.
_STRUCTURED_PART_TYPES = frozenset({"tool_call", "tool_use", "function", "function_call"})
# Keys of a structured part that name it rather than carry content (no known-value match).
_CALL_IDENTIFIERS = frozenset({"id", "type"})
# Reasoning as a string on a message (DeepSeek ``reasoning_content``; vLLM and OpenRouter
# ``reasoning``). Mistral's reasoning is a ``thinking`` content part instead.
_REASONING_FIELDS = ("reasoning_content", "reasoning")


class EdgeRawError(Exception):
    """An edge-mode payload still contained raw PII (FR-011)."""


class BlockedModality(Exception):
    """A non-text modality was refused by the gate (FR-004)."""


def gate_text(tok: Tokenizer, text: str, mode: str, known: bool = True) -> str:
    """Edge mode must arrive clean (FR-011); gateway mode tokenizes (FR-001).

    A known-value hit counts as raw PII in edge mode, like a detector hit (spec 015).
    """
    if mode == "edge":
        if tok.spans(text, known):
            raise EdgeRawError()
        return text
    return tok.tokenize(text, known)


def gate_args(tok: Tokenizer, value: Any, mode: str, known: bool = True) -> Any:
    """Recursively tokenize every string leaf of a structured argument blob (FR-004).

    A raw value must not ride to the provider hidden inside a tool-call's JSON
    arguments, so the gate walks the structure and tokenizes each string in place.
    An ``arguments`` string that is JSON is gated per string literal inside it, keys too.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "arguments" and isinstance(item, str):
                value[key] = _gate_arguments(tok, item, mode, known)
            else:
                value[key] = gate_args(tok, item, mode, known)
        return value
    if isinstance(value, list):
        return [gate_args(tok, item, mode, known) for item in value]
    if isinstance(value, str):
        return gate_text(tok, value, mode, known)
    return value


def _gate_arguments(tok: Tokenizer, raw: str, mode: str, known: bool) -> str:
    """Gate a JSON ``arguments`` string per literal so no span swallows its quotes; else whole."""
    gated = map_json_strings(raw, lambda text: gate_text(tok, text, mode, known))
    return gate_text(tok, raw, mode, known) if gated is None else gated


def _gate_call(tok: Tokenizer, part: dict, mode: str) -> None:
    """Gate a structured part; its ``id``, ``type`` and ``function.name`` skip known values.

    They are identifiers the provider must get back verbatim: a customer called "Search"
    must not rename a tool. The detector still runs on them (spec 015 "Request path").
    """
    for key, item in part.items():
        if key == "function" and isinstance(item, dict):
            for fkey, fitem in item.items():
                item[fkey] = gate_args(tok, {fkey: fitem}, mode, fkey != "name")[fkey]
        else:
            part[key] = gate_args(tok, {key: item}, mode, key not in _CALL_IDENTIFIERS)[key]


def gate_part(tok: Tokenizer, part: dict, mode: str, policy: dict[str, Decision]) -> None:
    """Route one structured message part through the modality gate (FR-004)."""
    if "block" in classify_part(part, policy):  # image/file/audio/unknown -> refuse
        raise BlockedModality(str(part.get("type")))
    ptype = (part.get("type") or "").strip().casefold()
    if ptype in _TEXT_PART_TYPES and isinstance(part.get("text"), str):
        part["text"] = gate_text(tok, part["text"], mode)
    elif ptype in _STRUCTURED_PART_TYPES:
        _gate_call(tok, part, mode)
    elif ptype == "thinking" and "thinking" in part:
        part["thinking"] = _gate_nested(tok, part["thinking"], mode, policy)


def _gate_nested(tok: Tokenizer, value: Any, mode: str, policy: dict[str, Decision]) -> Any:
    """Gate a thinking payload the way ``classify_part`` routed it: each string, each typed part."""
    if isinstance(value, str):
        return gate_text(tok, value, mode)
    if isinstance(value, list):
        return [_gate_nested(tok, item, mode, policy) for item in value]
    if isinstance(value, dict):
        if isinstance(value.get("type"), str):
            gate_part(tok, value, mode, policy)
        else:
            for key, item in value.items():
                value[key] = _gate_nested(tok, item, mode, policy)
    return value


def _gate_messages(tok: Tokenizer, policy: dict[str, Decision], mode: str, payload: dict) -> None:
    for msg in payload.get("messages", []):
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = gate_text(tok, content, mode)
        elif isinstance(content, list):  # structured content array (FR-004)
            for i, part in enumerate(content):
                if isinstance(part, dict):
                    gate_part(tok, part, mode, policy)
                elif isinstance(part, str):  # not a valid part, but it would still reach the provider
                    content[i] = gate_text(tok, part, mode)
        for call in msg.get("tool_calls") or []:  # tool-call arguments never bypass the gate
            if isinstance(call, dict):
                gate_part(tok, call, mode, policy)
        fc = msg.get("function_call")
        if isinstance(fc, dict):  # deprecated OpenAI field: same gate, its name stays verbatim
            _gate_call(tok, {"function": fc}, mode)
        for field in _REASONING_FIELDS:  # a reasoning model's reasoning, replayed by the client
            if isinstance(msg.get(field), str):
                msg[field] = gate_text(tok, msg[field], mode)


def tokenize_payload(key_provider: KeyProvider, detector: Detector, policy: dict[str, Decision],
                     conn, scope_id: uuid.UUID, mode: str, payload: dict, *,
                     matcher: Matcher | None = None, on_known: Callable[[int], None] | None = None) -> dict:
    """Gate every message part before egress: text tokenized, non-text blocked (FR-004).

    Two walks over the payload: the first plans every text's spans (known values from
    ``matcher`` plus the detector, merged on the original text) and refuses a blocked
    part or, in edge mode, any hit; then one batch mint; the second walk substitutes.
    ``on_known`` gets the number of known-value spans replaced (metrics).
    """
    tok = Tokenizer(open_store(conn, key_provider, scope_id), detector, matcher)
    tok.collect()
    _gate_messages(tok, policy, mode, payload)
    if mode == "edge":
        return payload
    tok.mint_collected()
    _gate_messages(tok, policy, mode, payload)
    if on_known is not None and tok.known_hits:
        on_known(tok.known_hits)
    return payload


def restore_payload(key_provider: KeyProvider, detector: Detector,
                    conn, scope_id: uuid.UUID, upstream: dict) -> dict:
    """Restore tokens in an upstream response back to the real values.

    Tool-call ``arguments`` are restored JSON-escaped, so a restored quote or
    backslash keeps them valid JSON. Reasoning is restored too: every string inside a
    ``thinking`` part and the ``reasoning_content`` / ``reasoning`` strings.
    """
    store = open_store(conn, key_provider, scope_id)
    tok = Tokenizer(store, detector)
    for choice in upstream.get("choices", []):
        msg = choice.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = tok.restore(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part["text"] = tok.restore(part["text"])
                if isinstance(part, dict) and part.get("type") == "thinking" and "thinking" in part:
                    part["thinking"] = restore_tree(part["thinking"], store.lookup)
        for field in _REASONING_FIELDS:
            if isinstance(msg.get(field), str):
                msg[field] = tok.restore(msg[field])
        calls = [c.get("function") for c in msg.get("tool_calls") or [] if isinstance(c, dict)]
        for fn in [*calls, msg.get("function_call")]:
            if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                fn["arguments"] = restore_arguments(fn["arguments"], store.lookup)
    return upstream
