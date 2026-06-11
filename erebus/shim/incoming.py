"""Model -> world: detokenize Claude output and fix written files (process_incoming).

Detokenization goes through the Boundary facade (boundary.from_model), which
resolves tokens from the known-value store and recovers unknown ones from the
audit log (FR-017/FR-018). The compat TOKEN_MAP mirror is synced around each
call so tests (and the interactive PTY path) that read or seed it keep working.
Also home to the per-turn token-usage and AI-written-LOC logging.
"""
from __future__ import annotations

import json
import os
import re

from ..audit.loc import AI_LOC_EVENT, ai_write_events_from_payload
from ..filter import TOKEN_RE as _TOKEN_RE
from ..filter import detokenize
from . import _state
from ._state import CWD, REPO_CONFIG, SESSION_ID, TOKEN_MAP, _safe_log_event

_WRITE_TOOL_NAMES = {"Write", "Edit", "write_file", "edit_file", "write", "create_file"}
_PENDING_WRITE_PATHS: dict[str, str] = {}  # tool_use_id -> file_path


def _track_pending_writes(msg: dict) -> None:
    """When the assistant requests a Write/Edit tool, remember the file path."""
    for block in msg.get("message", {}).get("content", []):
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        name = block.get("name", "")
        if name not in _WRITE_TOOL_NAMES:
            continue
        inp = block.get("input", {})
        if not isinstance(inp, dict):
            continue
        file_path = inp.get("file_path") or inp.get("path")
        if file_path and isinstance(file_path, str):
            _PENDING_WRITE_PATHS[block.get("id", "")] = file_path


def _detokenize_file(file_path: str) -> None:
    """Replace PII tokens in a file on disk with their real values."""
    if not TOKEN_MAP:
        return
    try:
        path = os.path.join(CWD, file_path) if not os.path.isabs(file_path) else file_path
        if not os.path.isfile(path):
            return
        data = open(path, encoding="utf-8", errors="replace").read()  # noqa: SIM115
        if not _TOKEN_RE.search(data):
            return
        with _state._KV_LOCK:
            boundary = _state.get_boundary()
            fixed, unresolved = boundary.from_model(data)
        if unresolved:
            # Mirror entries the store has not ingested yet (e.g. test-seeded).
            fixed = detokenize(fixed, TOKEN_MAP)
            unresolved = [t for t in unresolved if t in fixed]
        if unresolved and boundary.block_on_unresolved():
            # FR-018 policy=block: refuse to finalize a write that would still
            # contain unresolved tokens. Leave the file as the AI wrote it and
            # surface a blocked event rather than silently passing tokens on.
            _state._safe_log_event(
                _state.SESSION_ID, event_type="unresolved_blocked",
                metadata={"cwd": CWD, "source": "shim", "path": file_path,
                          "unresolved_count": len(unresolved)})
            return
        if fixed != data:
            open(path, "w", encoding="utf-8").write(fixed)  # noqa: SIM115
    except Exception:
        pass


def _detokenize_completed_writes(msg: dict) -> None:
    """After a Write/Edit tool executes, fix tokens in the written file.

    Two strategies, both scoped to files the assistant ACTUALLY asked to write:
      1. Match tool_result IDs against tracked tool_use file paths.
      2. Fallback (when the id didn't correlate): scan tool_result content for
         paths, but rewrite ONLY ones that were tracked Write/Edit targets.

    Strategy 2 used to detokenize any path it found in tool output, which
    silently rewrote unrelated source files merely mentioned there (e.g. a
    test runner echoing `tests/foo.py`), replacing token literals with their
    values. It is now gated on the tracked-target set so it can never touch a
    file the assistant did not write.

    This runs in process_incoming when the Claude binary reports tool results.
    """
    if not TOKEN_MAP:
        return

    tracked_targets = set(_PENDING_WRITE_PATHS.values())
    tracked_basenames = {os.path.basename(p) for p in tracked_targets}

    for block in msg.get("message", {}).get("content", []):
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue

        # Strategy 1: tracked tool_use ID
        tool_id = block.get("tool_use_id", "")
        tracked_path = _PENDING_WRITE_PATHS.pop(tool_id, None)
        if tracked_path:
            _detokenize_file(tracked_path)
            continue

        # Strategy 2: fallback, but ONLY for tracked write targets.
        content = block.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                p.get("text", "") for p in content if isinstance(p, dict)
            )
        if not isinstance(content, str):
            continue
        for candidate in re.findall(r'(?:^|[\s"])(/[^\s"]+|[^\s"]+\.\w{1,10})', content):
            if candidate in tracked_targets or os.path.basename(candidate) in tracked_basenames:
                _detokenize_file(candidate)


def _detokenize_response(raw: str) -> str:
    """Detokenize one serialized response line through the Boundary."""
    with _state._KV_LOCK:
        # Honor mirror entries set from outside (legacy JSON, tests) by
        # ingesting them into the store before the boundary resolves.
        _state._persist_mirror()
        restored, _unresolved = _state.get_boundary().from_model(raw)
        # Sync the mirror with whatever the boundary recovered (audit log
        # recovery re-exports the legacy JSON, so this also re-merges it).
        _state._sync_mirror()
    return restored


def process_incoming(line: str) -> str:
    """
    Process a line going FROM Claude TO VSCode.
    De-tokenizes any tokens back to real values, and logs API token usage
    for every response message that carries a `usage` block.
    """
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return line

    # Token usage logging — runs for every message that carries a usage block,
    # regardless of whether PII was detected. This is our source of truth for
    # input/output/cache token counts; chat transcripts are NOT sufficient
    # because cache-read tokens aren't visible in the text at all.
    if REPO_CONFIG.log_enabled:
        _log_usage_if_present(msg)

    if msg.get("type") == "assistant":
        _track_pending_writes(msg)

    if msg.get("type") == "user":
        _detokenize_completed_writes(msg)

    raw = json.dumps(msg)

    restored = _detokenize_response(raw) if _TOKEN_RE.search(raw) else raw

    if REPO_CONFIG.log_enabled:
        try:
            loc_payload = json.loads(restored)
        except json.JSONDecodeError:
            loc_payload = msg
        _log_ai_written_loc(loc_payload)

    if restored == raw:
        return line

    if REPO_CONFIG.log_enabled:
        _safe_log_event(SESSION_ID, event_type="response",
                        sanitized=raw, raw=restored,
                        tokens_map=TOKEN_MAP, metadata={"cwd": CWD})

    return restored + "\n"


def _log_ai_written_loc(payload: dict) -> None:
    if not REPO_CONFIG.log_enabled:
        return
    for metadata in ai_write_events_from_payload(payload, source="shim"):
        _safe_log_event(
            SESSION_ID,
            event_type=AI_LOC_EVENT,
            metadata={"cwd": CWD, **metadata},
        )


def _log_usage_if_present(msg: dict):
    """Extract `usage` from an Anthropic stream message and log it — once per turn.

    Anthropic streams cumulative usage across many message_delta events, so we
    only log when the message is final (has `stop_reason`). That gives exactly
    one token_usage event per API turn with the complete totals.
    """
    if not isinstance(msg, dict):
        return

    usage = None
    model = None
    is_final = False

    # Claude Code wrapper: {"type": "assistant", "message": {...}}
    # This wrapper format is always a complete turn — not a streaming delta —
    # so log whenever usage is present regardless of stop_reason.
    inner = msg.get("message")
    if isinstance(inner, dict):
        u = inner.get("usage")
        if isinstance(u, dict):
            usage = u
            model = inner.get("model")
            is_final = True
    # Raw Anthropic message_delta: usage + delta.stop_reason at top level
    if usage is None:
        u = msg.get("usage")
        if isinstance(u, dict):
            usage = u
            model = msg.get("model")
            delta = msg.get("delta")
            if isinstance(delta, dict) and delta.get("stop_reason") is not None:
                is_final = True
            elif msg.get("type") == "message_start":
                # message_start carries initial input/cache counts — log it too,
                # output_tokens will be 0 but we still want the input side.
                is_final = True

    if not usage or not is_final:
        return

    fields = ("input_tokens", "output_tokens",
              "cache_creation_input_tokens", "cache_read_input_tokens")
    counts = {f: int(usage.get(f, 0) or 0) for f in fields}
    if not any(counts.values()):
        return

    metadata = {"cwd": CWD, "source": "shim", **counts}
    if model:
        metadata["model"] = model
    cc = usage.get("cache_creation")
    if isinstance(cc, dict):
        metadata["cache_creation"] = cc

    timing = _state.take_turn_timing()
    if timing is not None:
        metadata["turn_latency_ms"], metadata["turn_type"] = timing

    _safe_log_event(SESSION_ID, event_type="token_usage", metadata=metadata)
