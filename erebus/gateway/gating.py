"""Modality + tokenization gate for the chat path (FR-004; extracted from app.py).

Pure request-shaping helpers: every cloud-bound message part (string content, a
structured content array, or tool-call arguments) is routed through the gate so text is
tokenized and any non-text modality is blocked by default, and upstream responses are
restored. Lives in its own module so the FastAPI app module stays within the line budget.
"""
from __future__ import annotations

import uuid
from typing import Any

from .crypto.keyprovider import KeyProvider
from .modalities import Decision, classify_part
from .store.known_value_store import open_store
from .tokenizer import Detector, Tokenizer

# Part types whose natural-language text is tokenized in place.
_TEXT_PART_TYPES = frozenset({"text", "input_text", "output_text"})
# Structured tool-call / function parts: every string leaf is tokenized.
_STRUCTURED_PART_TYPES = frozenset({"tool_call", "tool_use", "function", "function_call"})


class EdgeRawError(Exception):
    """An edge-mode payload still contained raw PII (FR-011)."""


class BlockedModality(Exception):
    """A non-text modality was refused by the gate (FR-004)."""


def gate_text(tok: Tokenizer, detector: Detector, text: str, mode: str) -> str:
    """Edge mode must arrive clean (FR-011); gateway mode tokenizes (FR-001)."""
    if mode == "edge":
        if detector(text):
            raise EdgeRawError()
        return text
    return tok.tokenize(text)


def gate_args(tok: Tokenizer, detector: Detector, value: Any, mode: str) -> Any:
    """Recursively tokenize every string leaf of a structured argument blob (FR-004).

    A raw value must not ride to the provider hidden inside a tool-call's JSON
    arguments, so the gate walks the structure and tokenizes each string in place.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            value[key] = gate_args(tok, detector, item, mode)
        return value
    if isinstance(value, list):
        return [gate_args(tok, detector, item, mode) for item in value]
    if isinstance(value, str):
        return gate_text(tok, detector, value, mode)
    return value


def gate_part(tok: Tokenizer, detector: Detector, part: dict, mode: str,
              policy: dict[str, Decision]) -> None:
    """Route one structured message part through the modality gate (FR-004)."""
    if "block" in classify_part(part, policy):  # image/file/audio/unknown -> refuse
        raise BlockedModality(str(part.get("type")))
    ptype = (part.get("type") or "").strip().casefold()
    if ptype in _TEXT_PART_TYPES and isinstance(part.get("text"), str):
        part["text"] = gate_text(tok, detector, part["text"], mode)
    elif ptype in _STRUCTURED_PART_TYPES:
        gate_args(tok, detector, part, mode)


def tokenize_payload(key_provider: KeyProvider, detector: Detector, policy: dict[str, Decision],
                     conn, scope_id: uuid.UUID, mode: str, payload: dict) -> dict:
    """Gate every message part before egress: text tokenized, non-text blocked (FR-004)."""
    tok = Tokenizer(open_store(conn, key_provider, scope_id), detector)
    for msg in payload.get("messages", []):
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = gate_text(tok, detector, content, mode)
        elif isinstance(content, list):  # structured content array (FR-004)
            for part in content:
                if isinstance(part, dict):
                    gate_part(tok, detector, part, mode, policy)
        for call in msg.get("tool_calls") or []:  # tool-call arguments never bypass the gate
            if isinstance(call, dict):
                gate_part(tok, detector, call, mode, policy)
    return payload


def restore_payload(key_provider: KeyProvider, detector: Detector,
                    conn, scope_id: uuid.UUID, upstream: dict) -> dict:
    """Restore tokens in an upstream response back to the real values."""
    tok = Tokenizer(open_store(conn, key_provider, scope_id), detector)
    for choice in upstream.get("choices", []):
        msg = choice.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = tok.restore(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part["text"] = tok.restore(part["text"])
    return upstream
