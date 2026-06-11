"""World -> model: tokenize user prompts and tool results (process_outgoing).

Every model-bound string crosses the Boundary facade (boundary.to_model),
which owns the catalog matcher, known-value retokenization, detector + cache,
and token persistence. This module only walks the Claude wire format, mirrors
new tokens into the compat TOKEN_MAP, injects the token hint, and logs the
tokenize-latency / degraded telemetry.
"""
from __future__ import annotations

import json
import time

from ..core import TOKEN_RE
from . import _state
from ._state import CWD, REPO_CONFIG, SESSION_ID, TOKEN_MAP, _safe_log_event

_TOKEN_HINT_PREFIX = (
    "\n\n<pii-filter>"
    "A privacy filter replaced sensitive values with tokens. "
    "Use these tokens naturally as if they were the real values — "
    "do NOT ask the user about them or mention they are redacted. "
    "Do NOT save token values to memory or files. "
    "They are automatically resolved to real values in tool calls. "
    "Tokens: "
)


def _tokenize_value(text: str) -> tuple[str, dict]:
    """Tokenize one model-bound string through the Boundary; mirror new tokens."""
    with _state._KV_LOCK:
        sanitized, new_tokens = _state.get_boundary().to_model(text)
        if new_tokens:
            TOKEN_MAP.update(new_tokens)
    return sanitized, new_tokens


def _process_text_block(block: dict) -> tuple[dict, bool]:
    """User-typed text. Returns (tokens minted, whether the text was rewritten)."""
    original = block["text"]
    sanitized, new_tokens = _tokenize_value(original)
    # Always apply the sanitized text when it changed: a known-value
    # retokenization or result-cache hit rewrites text while minting ZERO new
    # tokens (same rule as the proxy adapter). Gating the swap on new_tokens
    # sent raw known values to the model and logged nothing.
    if sanitized == original:
        return {}, False
    block["text"] = sanitized
    if REPO_CONFIG.log_enabled:
        _safe_log_event(
            SESSION_ID,
            event_type="pii_detected",
            raw=original,
            sanitized=sanitized,
            tokens_map=new_tokens,
            metadata={"cwd": CWD, "source": "user_text", "token_count": len(new_tokens),
                      "retokenized_only": not new_tokens},
        )
    return new_tokens, True


def _process_tool_result_block(block: dict) -> tuple[dict, bool]:
    """Tool results (file reads, directory listings, command output)."""
    content = block.get("content", "")
    if isinstance(content, str) and content:
        sanitized, new_tokens = _tokenize_value(content)
        # Same rule as _process_text_block: apply on change, not on new mints.
        if sanitized == content:
            return {}, False
        block["content"] = sanitized
        if REPO_CONFIG.log_enabled:
            _safe_log_event(
                SESSION_ID,
                event_type="pii_detected",
                raw=content[:500],
                sanitized=sanitized[:500],
                tokens_map=new_tokens,
                metadata={"cwd": CWD, "source": "tool_result", "mode": REPO_CONFIG.mode,
                          "token_count": len(new_tokens), "retokenized_only": not new_tokens},
            )
        return new_tokens, True
    collected: dict = {}
    rewrote = False
    if isinstance(content, list):
        for sub in content:
            if isinstance(sub, dict) and sub.get("type") == "text":
                sanitized, new_tokens = _tokenize_value(sub["text"])
                if sanitized != sub["text"]:
                    sub["text"] = sanitized
                    rewrote = True
                if new_tokens:
                    collected.update(new_tokens)
    return collected, rewrote


def _tokens_in_message(blocks: list) -> list[str]:
    """All token-shaped strings present in the message's sanitized text."""
    found: set[str] = set()
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            found.update(TOKEN_RE.findall(block.get("text", "")))
        elif block.get("type") == "tool_result":
            content = block.get("content", "")
            if isinstance(content, str):
                found.update(TOKEN_RE.findall(content))
            elif isinstance(content, list):
                for sub in content:
                    if isinstance(sub, dict) and sub.get("type") == "text":
                        found.update(TOKEN_RE.findall(sub.get("text", "")))
    return sorted(found)


def _inject_token_hint(msg: dict, new_session_tokens: dict) -> None:
    """Append the token hint to the first text block so Claude understands tokens."""
    hint = _TOKEN_HINT_PREFIX + ", ".join(new_session_tokens.keys()) + "</pii-filter>"
    content = msg.get("message", {}).get("content", [])
    if isinstance(content, str):
        msg["message"]["content"] = content + hint
        return
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            block["text"] += hint
            break


def _log_clean_prompt(msg: dict) -> None:
    """Log the first text block as the prompt when no PII was found."""
    for block in msg.get("message", {}).get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            _safe_log_event(SESSION_ID, event_type="prompt",
                            sanitized=block["text"], metadata={"cwd": CWD})
            break


def process_outgoing(line: str) -> str:
    """
    Process a line going FROM VSCode TO Claude.
    Tokenizes PII in user prompts AND tool results.
    """
    t_start = time.perf_counter()

    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return line  # not JSON, pass through

    if msg.get("type") != "user":
        return json.dumps(msg) + "\n"

    # Detect turn type: if any block is a tool_result, this is a tool turn.
    # Content may be a plain string instead of a block list (Claude wire
    # format allows both); string content is tokenized as one text block.
    content = msg.get("message", {}).get("content", [])
    blocks = content if isinstance(content, list) else []
    has_tool_result = any(
        isinstance(b, dict) and b.get("type") == "tool_result" for b in blocks
    )
    turn_type = "tool" if has_tool_result else "chat"

    new_session_tokens: dict = {}
    rewrote_any = False

    # One outgoing user message = one detection turn for the degraded signal;
    # boundary.turn() resets it on enter and warns (debounced) on exit.
    with _state.get_boundary().turn() as turn_state:
        if isinstance(content, str) and content:
            holder = {"text": content}
            minted, rewrote = _process_text_block(holder)
            if rewrote:
                msg["message"]["content"] = holder["text"]
            new_session_tokens.update(minted)
            rewrote_any = rewrote_any or rewrote
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                minted, rewrote = _process_text_block(block)
            elif block.get("type") == "tool_result":
                minted, rewrote = _process_tool_result_block(block)
            else:
                continue
            new_session_tokens.update(minted)
            rewrote_any = rewrote_any or rewrote

        if new_session_tokens:
            _inject_token_hint(msg, new_session_tokens)
            _state._persist_mirror()
        elif rewrote_any:
            # Known-value retokenization only: no new mints, but the model
            # still needs the token hint or it will ask about the brackets.
            content_now = msg.get("message", {}).get("content", [])
            reused = (sorted(set(TOKEN_RE.findall(content_now)))
                      if isinstance(content_now, str) else _tokens_in_message(content_now))
            if reused:
                _inject_token_hint(msg, dict.fromkeys(reused))
        elif REPO_CONFIG.log_enabled:
            _log_clean_prompt(msg)

        if turn_state.degraded and REPO_CONFIG.log_enabled:
            # Policy: allow but warn — the message is still forwarded with only
            # the regex/blacklist passes applied.
            _safe_log_event(SESSION_ID, event_type="detector_degraded",
                            metadata={"cwd": CWD, "source": "shim",
                                      "reason": turn_state.degraded_reason,
                                      "turn_type": turn_type})

    latency_ms = round((time.perf_counter() - t_start) * 1000, 1)
    if REPO_CONFIG.log_enabled:
        _safe_log_event(SESSION_ID, event_type="tokenize_latency",
                        metadata={"cwd": CWD, "source": "shim",
                                  "latency_ms": latency_ms,
                                  "turn_type": turn_type,
                                  "pii_found": bool(new_session_tokens) or rewrote_any,
                                  "retokenized_only": rewrote_any and not new_session_tokens,
                                  "token_count": len(new_session_tokens)})

    _state.mark_outgoing_sent(turn_type)

    return json.dumps(msg) + "\n"
