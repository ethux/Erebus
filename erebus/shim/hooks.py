"""Claude Code tool hooks served by the shim: tool output -> model, model -> tool input.

Claude Code runs tools itself and sends their output straight to the API, so
the stdio shim never sees it. Instead the shim registers two HTTP hooks on its
own child Claude: PostToolUse tokenizes every tool output before the model
reads it, PreToolUse restores real values in the input of tools that run on
this machine. Served from the shim process so both share its Boundary and
TOKEN_MAP. Needs no ANTHROPIC_BASE_URL, so Remote Control keeps working.

Not covered: a failed tool call (for example a command that exits non-zero)
reaches the model through PostToolUseFailure, which hooks cannot rewrite.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import _state
from ._state import CWD, REPO_CONFIG, SESSION_ID, TOKEN_MAP, _safe_log_event
from .outgoing import _TOKEN_HINT_PREFIX

SECRET_ENV = "EREBUS_HOOK_SECRET"
# Tools that run on this machine, where a token in the input breaks the call
# (an Edit old_string, a grep pattern). Model-facing tools such as Agent keep
# their tokens, or the real value would reach a model through a subagent prompt.
_LOCAL_TOOLS = "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|Grep|Glob"
_LOCAL_TOOL_NAMES = frozenset(_LOCAL_TOOLS.split("|"))
# Binary payloads: tokenizing inside base64 would corrupt the image or PDF.
_BINARY_TYPES = frozenset({"image", "pdf"})
# `type` values are the output shape Claude Code validates the rewrite against.
_SKIP_KEYS = frozenset({"type", "base64", "image_data"})
_WITHHELD = "[erebus: output withheld, the PII filter failed]"


def _map_strings(value, fn):
    """Apply ``fn`` to every model-bound string, leaving shape and binary data alone."""
    if isinstance(value, str):
        return value if value.startswith("data:") and ";base64," in value[:100] else fn(value)
    if isinstance(value, list):
        return [_map_strings(item, fn) for item in value]
    if isinstance(value, dict) and value.get("type") not in _BINARY_TYPES:
        return {k: v if k in _SKIP_KEYS else _map_strings(v, fn) for k, v in value.items()}
    return value


def _tokenize_output(event: dict) -> dict:
    t_start = time.perf_counter()
    response = event.get("tool_response")
    texts: list[str] = []
    _map_strings(response, lambda s: texts.append(s) or s)
    texts = list(dict.fromkeys(t for t in texts if t))
    if not texts:
        return {}
    boundary = _state.get_boundary()
    # Lock first: turn() exit saves shared caches, which the pipe threads also touch.
    with _state._KV_LOCK, boundary.turn():
        results = boundary.to_model_many(texts)
        minted: dict = {}
        for _sanitized, tokens in results:
            minted.update(tokens)
        if minted:
            TOKEN_MAP.update(minted)
            _state._persist_mirror()
    rewritten = {text: sanitized for text, (sanitized, _) in zip(texts, results, strict=True)
                 if sanitized != text}
    if REPO_CONFIG.log_enabled:
        _safe_log_event(SESSION_ID, event_type="tokenize_latency",
                        metadata={"cwd": CWD, "source": "shim_hook", "turn_type": "tool",
                                  "tool": event.get("tool_name"), "pii_found": bool(rewritten),
                                  "token_count": len(minted),
                                  "latency_ms": round((time.perf_counter() - t_start) * 1000, 1)})
    if not rewritten:
        return {}
    out = {"hookEventName": "PostToolUse",
           "updatedToolOutput": _map_strings(response, lambda s: rewritten.get(s, s))}
    if minted:
        out["additionalContext"] = _TOKEN_HINT_PREFIX.lstrip() + ", ".join(minted) + "</pii-filter>"
    return {"hookSpecificOutput": out}


def post_tool_use(event: dict) -> dict:
    """Tokenize the tool's output before the model reads it; withhold it if that fails."""
    try:
        return _tokenize_output(event)
    except Exception as exc:
        _safe_log_event(SESSION_ID, event_type="hook_error", metadata={"cwd": CWD, "error": str(exc)})
        withheld = _map_strings(event.get("tool_response"), lambda s: _WITHHELD if s else s)
        return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": withheld}}


def _edit_applies(tool_input: dict) -> bool:
    """Whether an Edit/MultiEdit with these strings would succeed. A failing edit
    echoes its old_string to the model, which must then not hold real values."""
    try:
        with open(tool_input["file_path"], encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, KeyError, TypeError, UnicodeDecodeError):
        return False
    for edit in tool_input.get("edits") or [tool_input]:
        old, new = edit.get("old_string") or "", edit.get("new_string") or ""
        count = text.count(old) if old else 0
        if count == 0 or (count > 1 and not edit.get("replace_all")):
            return False
        text = text.replace(old, new, -1 if edit.get("replace_all") else 1)
    return True


def pre_tool_use(event: dict) -> dict:
    """Restore real values in a local tool's input."""
    tool = event.get("tool_name")
    if tool not in _LOCAL_TOOL_NAMES:
        return {}
    tool_input = event.get("tool_input")
    with _state._KV_LOCK:
        restored, _unresolved = _state.get_boundary().from_model_payload(tool_input)
    if restored == tool_input:
        return {}
    if tool in ("Edit", "MultiEdit") and not _edit_applies(restored):
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": restored}}


_HANDLERS = {"PostToolUse": post_tool_use, "PreToolUse": pre_tool_use}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        expected = f"Bearer {self.server.secret}".encode()
        if not hmac.compare_digest(self.headers.get("Authorization", "").encode(), expected):
            self.send_error(403)
            return
        try:
            event = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            handler = _HANDLERS.get(event.get("hook_event_name"))
            body = json.dumps(handler(event) if handler else {}).encode()
        except Exception as exc:
            # PreToolUse lands here: the tool then keeps its tokens, which leaks nothing.
            _safe_log_event(SESSION_ID, event_type="hook_error", metadata={"cwd": CWD, "error": str(exc)})
            body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def start() -> dict:
    """Serve the hooks on a random localhost port and return the ``--settings``
    payload for the child Claude. The secret goes through the child's
    environment (header interpolation), not argv, which other users can read."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.secret = secrets.token_urlsafe(32)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    os.environ[SECRET_ENV] = server.secret
    hook = {"type": "http", "url": f"http://127.0.0.1:{server.server_port}/",
            "headers": {"Authorization": f"Bearer ${SECRET_ENV}"},
            "allowedEnvVars": [SECRET_ENV], "timeout": 60}
    return {"hooks": {"PreToolUse": [{"matcher": _LOCAL_TOOLS, "hooks": [hook]}],
                      "PostToolUse": [{"matcher": "*", "hooks": [hook]}]}}
